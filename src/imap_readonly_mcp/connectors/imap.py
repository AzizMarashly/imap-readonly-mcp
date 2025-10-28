"""IMAP connector implementation for the read-only MCP mail server."""

from __future__ import annotations

import contextlib
import imaplib
import re
import socket
from collections.abc import Iterable
from datetime import datetime
from email.message import Message
from typing import Any

from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

from ..config import MailAccountConfig
from ..exceptions import AttachmentNotFoundError, MessageNotFoundError
from ..models import (
    AttachmentContent,
    AttachmentMetadata,
    FolderInfo,
    MailboxRole,
    MessageDetail,
    MessageFlags,
    MessageSearchFilters,
    MessageSummary,
)
from ..utils.email_parser import (
    create_summary_from_message,
    extract_attachments,
    extract_body,
    get_attachment_payload,
    parse_rfc822_message,
)
from ..utils.identifiers import encode_folder_path
from .base import ConnectorCapabilities, ReadOnlyMailConnector


DATE_FORMAT = "%d-%b-%Y"
_FLAGS_PATTERN = re.compile(r"FLAGS \((?P<flags>[^)]*)\)")
_UID_PATTERN = re.compile(r"UID (\d+)")
_SIZE_PATTERN = re.compile(r"RFC822\.SIZE (\d+)")


def _encode_mailbox(value: str) -> str:
    return value.encode("imap4-utf-7").decode("ascii")


def _decode_mailbox(value: str) -> str:
    return value.encode("ascii").decode("imap4-utf-7")


class IMAPReadOnlyConnector(ReadOnlyMailConnector):
    """Read-only IMAP connector that avoids mutating message state when fetching data."""

    def __init__(self, config: MailAccountConfig) -> None:
        super().__init__(config)

    @property
    def capabilities(self) -> ConnectorCapabilities:
        return ConnectorCapabilities(
            supports_folders=True,
            supports_search=True,
            supports_semantic=True,
            supports_attachments=True,
        )

    @contextlib.contextmanager
    def _connection(self) -> Iterable[imaplib.IMAP4]:
        conn: imaplib.IMAP4
        timeout = self.config.timeout_seconds
        socket.setdefaulttimeout(timeout)
        if self.config.security.use_ssl:
            conn = imaplib.IMAP4_SSL(self.config.host, self.config.port or 993)
        else:
            conn = imaplib.IMAP4(self.config.host, self.config.port or 143)
            if self.config.security.starttls:
                conn.starttls()

        try:
            assert self.config.password is not None
            conn.login(self.config.username, self.config.password.get_secret_value())
            yield conn
        finally:
            with contextlib.suppress(Exception):
                conn.logout()

    def list_folders(self) -> list[FolderInfo]:
        folders: list[FolderInfo] = []
        with self._connection() as conn:
            typ, data = conn.list()
            if typ != "OK" or data is None:
                return folders
            for raw in data:
                if raw is None:
                    continue
                decoded = raw.decode("utf-8", errors="replace")
                match = re.match(r'\((?P<flags>[^)]*)\)\s+"(?P<delimiter>.+?)"\s+(?P<name>.+)', decoded)
                if not match:
                    continue
                flags_str = match.group("flags")
                mailbox_name = match.group("name").strip('"')
                mailbox = _decode_mailbox(mailbox_name)
                flags = set(flags_str.split())
                role = _infer_mailbox_role(mailbox)
                selectable = "\\Noselect" not in flags
                folder = FolderInfo(
                    account_id=self.config.id,
                    path=mailbox,
                    encoded_path=encode_folder_path(mailbox),
                    role=role,
                    selectable=selectable,
                    total_messages=None,
                    unread_messages=None,
                )
                folders.append(folder)
        return folders

    def search_messages(self, filters: MessageSearchFilters) -> list[MessageSummary]:
        folder = filters.folder or self.config.default_folder or "INBOX"
        uids = self._search_uids(folder, filters)
        summaries: list[MessageSummary] = []
        limit = filters.limit
        if limit is not None:
            uids = uids[:limit]
        for uid in uids:
            try:
                detail = self.fetch_message(folder, uid)
            except MessageNotFoundError:
                continue
            summaries.append(MessageSummary.model_validate(detail.model_dump()))
        return summaries

    def fetch_message(self, folder_path: str, uid: str) -> MessageDetail:
        with self._connection() as conn:
            self._select_mailbox(conn, folder_path)
            resp = self._fetch_uid(conn, uid, "(BODY.PEEK[] FLAGS RFC822.SIZE UID)")
            if not resp:
                raise MessageNotFoundError(f"Message UID {uid} not found in {folder_path}")
            raw_bytes = resp["raw"]
            message = parse_rfc822_message(raw_bytes)
            flags = resp["flags"]
            summary = create_summary_from_message(
                account_id=self.config.id,
                folder_path=folder_path,
                uid=uid,
                message=message,
                snippet=resp.get("snippet"),
                flags=flags,
            )
            body = extract_body(message)
            attachments = extract_attachments(
                message,
                account_id=self.config.id,
                folder_path=folder_path,
                uid=uid,
            )
            detail = MessageDetail(
                **summary.model_dump(),
                body=body,
                attachments=attachments,
                headers=_collect_headers(message),
                raw_source=raw_bytes.decode("utf-8", errors="replace"),
                size=resp.get("size"),
            )
            return detail

    def fetch_raw_message(self, folder_path: str, uid: str) -> bytes:
        with self._connection() as conn:
            self._select_mailbox(conn, folder_path)
            resp = self._fetch_uid(conn, uid, "(BODY.PEEK[])")
            if not resp:
                raise MessageNotFoundError(f"Message UID {uid} not found in {folder_path}")
            return resp["raw"]

    def fetch_attachment(self, folder_path: str, uid: str, attachment_index: int) -> AttachmentContent:
        with self._connection() as conn:
            self._select_mailbox(conn, folder_path)
            resp = self._fetch_uid(conn, uid, "(BODY.PEEK[])")
            if not resp:
                raise MessageNotFoundError(f"Message UID {uid} not found in {folder_path}")
            message = parse_rfc822_message(resp["raw"])
            try:
                metadata, payload = get_attachment_payload(message, attachment_index)
            except IndexError as exc:
                raise AttachmentNotFoundError(
                    f"Attachment index {attachment_index} not found for message {uid}"
                ) from exc
            return AttachmentContent(
                metadata=metadata,
                data=payload,
                mime_type=metadata.content_type,
                file_name=metadata.filename,
                download_url=None,
            )

    def _select_mailbox(self, conn: imaplib.IMAP4, folder_path: str) -> None:
        encoded = _encode_mailbox(folder_path)
        typ, _ = conn.select(f'"{encoded}"', readonly=True)
        if typ != "OK":
            raise MessageNotFoundError(f"Unable to select mailbox {folder_path}")

    @retry(
        wait=wait_exponential(multiplier=0.3, min=0.5, max=5),
        stop=stop_after_attempt(3),
        retry=retry_if_exception_type((socket.error, imaplib.IMAP4.abort)),
    )
    def _search_uids(self, folder_path: str, filters: MessageSearchFilters) -> list[str]:
        criteria = _build_search_criteria(filters)
        with self._connection() as conn:
            self._select_mailbox(conn, folder_path)
            typ, data = conn.uid("SEARCH", None, *criteria)
            if typ != "OK" or not data:
                return []
            raw_uids = data[0].decode("ascii", errors="ignore").strip()
            if not raw_uids:
                return []
            uids = list(reversed(raw_uids.split()))
            return uids

    def _fetch_uid(self, conn: imaplib.IMAP4, uid: str, query: str) -> dict[str, Any] | None:
        typ, data = conn.uid("FETCH", uid, query)
        if typ != "OK" or not data:
            return None
        raw_bytes: bytes | None = None
        flags = MessageFlags()
        size = None
        for item in data:
            if not isinstance(item, tuple):
                continue
            meta = item[0].decode("utf-8", errors="replace")
            content = item[1]
            if content:
                raw_bytes = content
            flags = _parse_flags(meta)
            size = _parse_size(meta)
        if raw_bytes is None:
            return None
        snippet = raw_bytes[:2048].decode("utf-8", errors="ignore")
        return {"raw": raw_bytes, "flags": flags, "size": size, "snippet": snippet}


def _build_search_criteria(filters: MessageSearchFilters) -> list[str]:
    criteria: list[str] = []
    if filters.unread_only:
        criteria.append("UNSEEN")
    if filters.since:
        criteria.extend(["SINCE", filters.since.strftime(DATE_FORMAT)])
    if filters.until:
        criteria.extend(["BEFORE", filters.until.strftime(DATE_FORMAT)])
    if filters.sender:
        criteria.extend(["FROM", f'"{_escape(filters.sender)}"'])
    if filters.recipient:
        criteria.extend(["TO", f'"{_escape(filters.recipient)}"'])
    if filters.text:
        criteria.extend(["TEXT", f'"{_escape(filters.text)}"'])
    if filters.has_attachments:
        criteria.extend(["HAS", "ATTACHMENT"])
    if not criteria:
        criteria.append("ALL")
    return criteria


def _escape(value: str) -> str:
    return value.replace('"', '\\"')


def _parse_flags(meta: str) -> MessageFlags:
    match = _FLAGS_PATTERN.search(meta)
    if not match:
        return MessageFlags()
    flag_tokens = match.group("flags").split()
    flags = MessageFlags(
        seen="\\Seen" in flag_tokens,
        flagged="\\Flagged" in flag_tokens,
        answered="\\Answered" in flag_tokens,
        draft="\\Draft" in flag_tokens,
        recent="\\Recent" in flag_tokens,
        other=[flag for flag in flag_tokens if not flag.startswith("\\")],
    )
    return flags


def _parse_size(meta: str) -> int | None:
    match = _SIZE_PATTERN.search(meta)
    if not match:
        return None
    return int(match.group(1))


def _collect_headers(message: Message) -> dict[str, list[str]]:
    headers: dict[str, list[str]] = {}
    for key, value in message.items():
        headers.setdefault(key, []).append(value)
    return headers


def _infer_mailbox_role(name: str) -> MailboxRole:
    lowered = name.lower()
    if lowered == "inbox":
        return MailboxRole.INBOX
    if "sent" in lowered:
        return MailboxRole.SENT
    if "draft" in lowered:
        return MailboxRole.DRAFTS
    if "junk" in lowered or "spam" in lowered:
        return MailboxRole.JUNK
    if "trash" in lowered or "deleted" in lowered:
        return MailboxRole.TRASH
    if "archive" in lowered:
        return MailboxRole.ARCHIVE
    return MailboxRole.CUSTOM
