"""POP3 connector implementation."""

from __future__ import annotations

import contextlib
import poplib
import socket
from typing import Iterable

from ..config import MailAccountConfig
from ..exceptions import AttachmentNotFoundError, MessageNotFoundError
from ..models import (
    AttachmentContent,
    FolderInfo,
    MailboxRole,
    MessageDetail,
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


class POP3ReadOnlyConnector(ReadOnlyMailConnector):
    """Read-only POP3 connector."""

    def __init__(self, config: MailAccountConfig) -> None:
        super().__init__(config)

    @property
    def capabilities(self) -> ConnectorCapabilities:
        return ConnectorCapabilities(
            supports_folders=False,
            supports_search=True,
            supports_attachments=True,
        )

    @contextlib.contextmanager
    def _connection(self) -> Iterable[poplib.POP3]:
        timeout = self.config.timeout_seconds
        socket.setdefaulttimeout(timeout)
        if self.config.security.use_ssl:
            conn = poplib.POP3_SSL(self.config.host, self.config.port or 995, timeout=timeout)
        else:
            conn = poplib.POP3(self.config.host, self.config.port or 110, timeout=timeout)
            if self.config.security.starttls:
                conn.stls()
        conn.user(self.config.username)
        assert self.config.password is not None
        conn.pass_(self.config.password.get_secret_value())
        try:
            yield conn
        finally:
            with contextlib.suppress(Exception):
                conn.quit()

    def list_folders(self) -> list[FolderInfo]:
        return [
            FolderInfo(
                path="INBOX",
                encoded_path=encode_folder_path("INBOX"),
                role=MailboxRole.INBOX,
                selectable=True,
                total_messages=None,
                unread_messages=None,
            )
        ]

    def search_messages(self, filters: MessageSearchFilters) -> list[MessageSummary]:
        limit = filters.limit or 50
        offset = filters.offset or 0
        summaries: list[MessageSummary] = []
        with self._connection() as conn:
            stat = conn.stat()
            message_count = stat[0]
            indices = list(range(message_count, 0, -1))
            if offset:
                indices = indices[offset:]
            if limit is not None:
                indices = indices[:limit]
            for index in indices:
                raw = self._retrieve_message(conn, index)
                message = parse_rfc822_message(raw)
                summary = create_summary_from_message(
                    folder_path="INBOX",
                    uid=str(index),
                    message=message,
                )
                if not _matches_filters(summary, filters):
                    continue
                summaries.append(summary)
        return summaries

    def fetch_message(self, folder_path: str, uid: str) -> MessageDetail:
        with self._connection() as conn:
            raw = self._retrieve_message(conn, int(uid))
            message = parse_rfc822_message(raw)
            summary = create_summary_from_message(
                folder_path="INBOX",
                uid=uid,
                message=message,
            )
            return MessageDetail(
                **summary.model_dump(),
                body=extract_body(message),
                attachments=extract_attachments(
                    message,
                    folder_path="INBOX",
                    uid=uid,
                ),
                headers=_collect_headers(message),
                raw_source=raw.decode("utf-8", errors="replace"),
            )

    def fetch_raw_message(self, folder_path: str, uid: str) -> bytes:
        with self._connection() as conn:
            return self._retrieve_message(conn, int(uid))

    def fetch_attachment(self, folder_path: str, uid: str, attachment_index: int) -> AttachmentContent:
        with self._connection() as conn:
            raw = self._retrieve_message(conn, int(uid))
            message = parse_rfc822_message(raw)
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

    def _retrieve_message(self, conn: poplib.POP3, index: int) -> bytes:
        try:
            response, lines, _ = conn.retr(index)
        except poplib.error_proto as exc:
            raise MessageNotFoundError(f"Message {index} not found on POP3 server") from exc
        raw_message = b"\r\n".join(lines)
        return raw_message


def _matches_filters(summary: MessageSummary, filters: MessageSearchFilters) -> bool:
    if filters.sender and not any(addr.address == filters.sender.lower() for addr in summary.from_):
        return False
    if filters.recipient:
        recipient_match = any(addr.address == filters.recipient.lower() for addr in summary.to + summary.cc)
        if not recipient_match:
            return False
    if filters.text:
        candidate = " ".join(
            [
                summary.subject or "",
                summary.snippet or "",
            ]
        ).lower()
        if filters.text.lower() not in candidate:
            return False
    if filters.unread_only:
        # POP3 does not expose unread state, so treat as match-all when requested.
        pass
    return True


def _collect_headers(message):
    headers: dict[str, list[str]] = {}
    for key, value in message.items():
        headers.setdefault(key, []).append(value)
    return headers

