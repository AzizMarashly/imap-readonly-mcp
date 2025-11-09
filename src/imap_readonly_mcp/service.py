"""Mail service orchestration for MCP tools and resources."""

from __future__ import annotations

import json
import os
import re
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import UTC, datetime, timedelta
from pathlib import Path

from dateparser import parse as parse_datetime

from .config import AccountProtocol, MailSettings
from .connectors import (
    GraphReadOnlyConnector,
    IMAPReadOnlyConnector,
    POP3ReadOnlyConnector,
    ReadOnlyMailConnector,
)
from .exceptions import (
    ConnectorNotAvailableError,
)
from .models import (
    AttachmentContent,
    FolderInfo,
    MailboxRole,
    MessageDetail,
    MessageSearchFilters,
    MessageSummary,
)
from .utils.identifiers import decode_folder_token


class MailService:
    """High level façade used by the MCP server to service tool/resource requests."""

    def __init__(self, settings: MailSettings) -> None:
        self.settings = settings
        self._connector: ReadOnlyMailConnector | None = None
        self._cache = _MessageCache(settings.cache_path)
        self._executor = ThreadPoolExecutor(
            max_workers=settings.fetch_concurrency,
            thread_name_prefix="mail-fetch",
        )

    def list_folders(self) -> list[FolderInfo]:
        connector = self._get_connector()
        return connector.list_folders()

    def search_messages(self, filters: MessageSearchFilters) -> list[MessageSummary]:
        connector = self._get_connector()
        normalized_filters = self._normalize_filters(filters)
        if normalized_filters.folder is None:
            return self._search_all_folders(connector, normalized_filters)
        return connector.search_messages(normalized_filters)

    def fetch_message(self, folder_token: str, uid: str) -> MessageDetail:
        cached = self._cache.get(folder_token, uid)
        if cached:
            return cached
        detail = self._fetch_message_uncached(folder_token, uid)
        self._cache.set(folder_token, uid, detail)
        return detail

    def fetch_raw_message(self, folder_token: str, uid: str) -> bytes:
        connector = self._get_connector()
        folder_path = decode_folder_token(folder_token)
        return connector.fetch_raw_message(folder_path, uid)

    def fetch_attachment(
        self,
        folder_token: str,
        uid: str,
        attachment_identifier: int | str,
    ) -> AttachmentContent:
        connector = self._get_connector()
        folder_path = decode_folder_token(folder_token)
        return connector.fetch_attachment(folder_path, uid, attachment_identifier)

    def fetch_details_bulk(self, requests: list[tuple[str, str, str]]) -> dict[str, MessageDetail]:
        """Fetch message details for a collection of (resource_uri, folder_token, uid)."""
        results: dict[str, MessageDetail] = {}
        missing: list[tuple[str, str, str]] = []

        for resource_uri, folder_token, uid in requests:
            cached = self._cache.get(folder_token, uid)
            if cached:
                results[resource_uri] = cached
            else:
                missing.append((resource_uri, folder_token, uid))

        if not missing:
            return results

        futures = {
            self._executor.submit(self._fetch_and_cache, folder_token, uid): resource_uri
            for resource_uri, folder_token, uid in missing
        }
        for future in as_completed(futures):
            resource_uri = futures[future]
            try:
                detail = future.result()
            except Exception:
                detail = None
            if detail:
                results[resource_uri] = detail
        return results

    def _get_connector(self) -> ReadOnlyMailConnector:
        if self._connector:
            return self._connector
        account = self.settings.account
        connector_cls_map: dict[AccountProtocol, type[ReadOnlyMailConnector]] = {
            AccountProtocol.IMAP: IMAPReadOnlyConnector,
            AccountProtocol.POP3: POP3ReadOnlyConnector,
            AccountProtocol.GRAPH: GraphReadOnlyConnector,
        }
        connector_cls = connector_cls_map.get(account.protocol)
        if not connector_cls:
            raise ConnectorNotAvailableError(f"No connector registered for protocol {account.protocol.value}")
        connector = connector_cls(account)
        self._connector = connector
        return connector

    def _normalize_filters(self, filters: MessageSearchFilters) -> MessageSearchFilters:
        limit = filters.limit or self.settings.default_search_limit
        limit = min(limit, self.settings.maximum_search_limit)
        since = _ensure_datetime(filters.since)
        until = _ensure_datetime(filters.until)
        offset = filters.offset or 0
        if filters.time_frame:
            frame_since, frame_until = _resolve_time_frame(filters.time_frame)
            if since is None:
                since = frame_since
            if until is None:
                until = frame_until
        folder_path = filters.folder
        if folder_path and folder_path.startswith("mail://"):
            folder_path = decode_folder_token(folder_path)
        return MessageSearchFilters(
            folder=folder_path,
            text=filters.text,
            sender=filters.sender,
            recipient=filters.recipient,
            since=since,
            until=until,
            unread_only=filters.unread_only,
            has_attachments=filters.has_attachments,
            limit=limit,
            time_frame=None,
            offset=offset,
        )

    def _search_all_folders(
        self,
        connector: ReadOnlyMailConnector,
        filters: MessageSearchFilters,
    ) -> list[MessageSummary]:
        if not connector.capabilities.supports_folders:
            return connector.search_messages(filters)

        folder_infos = [folder for folder in self.list_folders() if folder.selectable]
        if not folder_infos:
            return []

        all_mail_folder = self._find_all_mail_folder(folder_infos)
        if all_mail_folder:
            return connector.search_messages(
                filters.model_copy(update={"folder": all_mail_folder, "offset": filters.offset})
            )

        folders = [folder.path for folder in folder_infos]
        if not folders:
            return []

        offset = filters.offset or 0
        limit = filters.limit or self.settings.default_search_limit
        if limit <= 0:
            return []

        remaining_budget = limit + offset
        summaries: list[MessageSummary] = []

        for folder_path in folders:
            if remaining_budget <= 0:
                break
            per_folder_limit = min(remaining_budget, self.settings.maximum_search_limit)
            adjusted_filters = filters.model_copy(
                update={
                    "folder": folder_path,
                    "offset": 0,
                    "limit": per_folder_limit,
                }
            )
            folder_summaries = connector.search_messages(adjusted_filters)
            if not folder_summaries:
                continue
            summaries.extend(folder_summaries)
            remaining_budget = max(remaining_budget - len(folder_summaries), 0)

        if not summaries:
            return []

        def _sort_key(summary: MessageSummary) -> datetime:
            dt = summary.date
            if dt is None:
                return datetime.min.replace(tzinfo=UTC)
            if dt.tzinfo is None:
                return dt.replace(tzinfo=UTC)
            return dt.astimezone(UTC)

        summaries.sort(key=_sort_key, reverse=True)

        if offset:
            summaries = summaries[offset:]
        if limit:
            summaries = summaries[:limit]
        return summaries

    def _find_all_mail_folder(self, folders: list[FolderInfo]) -> str | None:
        scored: list[tuple[int, FolderInfo]] = []
        for folder in folders:
            if not folder.selectable:
                continue
            name = folder.path
            normalized = re.sub(r"[^a-z0-9]+", " ", name.lower()).strip()
            tokens = set(normalized.split())

            if folder.role == MailboxRole.ARCHIVE:
                scored.append((0, folder))
                continue

            if "all mail" in normalized:
                scored.append((1, folder))
                continue

            if "all messages" in normalized or "all items" in normalized:
                scored.append((2, folder))
                continue

            if "all" in tokens and ({"mail", "mails", "mailbox"} & tokens or {"messages", "items"} & tokens):
                scored.append((3, folder))

        if not scored:
            return None

        scored.sort(key=lambda item: item[0])
        return scored[0][1].path

    def _fetch_and_cache(self, folder_token: str, uid: str) -> MessageDetail | None:
        try:
            detail = self._fetch_message_uncached(folder_token, uid)
            self._cache.set(folder_token, uid, detail)
            return detail
        except Exception:
            return None

    def _fetch_message_uncached(self, folder_token: str, uid: str) -> MessageDetail:
        connector = self._get_connector()
        folder_path = decode_folder_token(folder_token)
        return connector.fetch_message(folder_path, uid)


class _MessageCache:
    """Lightweight SQLite-backed cache keyed by folder token and UID."""

    def __init__(self, db_path: Path | None) -> None:
        if db_path is None:
            db_path = Path(os.environ.get("MAIL_CACHE_PATH", "email_cache.sqlite"))
        self._path = Path(db_path)
        self._lock = threading.Lock()
        if self._path.parent and not self._path.parent.exists():
            self._path.parent.mkdir(parents=True, exist_ok=True)
        self._ensure_schema()

    def _connect(self) -> sqlite3.Connection:
        con = sqlite3.connect(self._path)
        con.row_factory = sqlite3.Row
        return con

    def _ensure_schema(self) -> None:
        with self._connect() as con:
            con.execute(
                """
                create table if not exists messages (
                    folder_token text not null,
                    uid text not null,
                    updated_at real not null,
                    payload blob not null,
                    primary key(folder_token, uid)
                )
                """
            )
            con.execute("create index if not exists idx_messages_folder on messages(folder_token)")

    def get(self, folder_token: str, uid: str) -> MessageDetail | None:
        with self._lock, self._connect() as con:
            row = con.execute(
                "select payload from messages where folder_token=? and uid=?",
                (folder_token, uid),
            ).fetchone()
        if not row:
            return None
        try:
            payload = json.loads(row["payload"].decode("utf-8"))
            return MessageDetail.model_validate(payload)
        except Exception:
            return None

    def set(self, folder_token: str, uid: str, detail: MessageDetail) -> None:
        payload = json.dumps(detail.model_dump(mode="json", by_alias=True), ensure_ascii=False)
        with self._lock, self._connect() as con:
            con.execute(
                """
                insert into messages(folder_token, uid, updated_at, payload)
                values(?, ?, strftime('%s','now'), ?)
                on conflict(folder_token, uid)
                do update set updated_at=excluded.updated_at, payload=excluded.payload
                """,
                (folder_token, uid, payload.encode("utf-8")),
            )


def _ensure_datetime(value: datetime | str | None) -> datetime | None:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    if value is None:
        return None
    parsed = parse_datetime(value)
    if parsed and parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed


def _resolve_time_frame(label: str) -> tuple[datetime, datetime]:
    now = datetime.now(UTC)
    mapping = {
        "last_hour": now - timedelta(hours=1),
        "last_24_hours": now - timedelta(hours=24),
        "last_7_days": now - timedelta(days=7),
        "last_30_days": now - timedelta(days=30),
        "last_90_days": now - timedelta(days=90),
    }
    start = mapping.get(label)
    if not start:
        raise ValueError(f"Unsupported time_frame value: {label}")
    return start, now
