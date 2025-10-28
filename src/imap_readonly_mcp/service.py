"""Mail service orchestration for MCP tools and resources."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from dateparser import parse as parse_datetime

from .config import AccountProtocol, MailSettings
from .connectors import (
    GraphReadOnlyConnector,
    IMAPReadOnlyConnector,
    POP3ReadOnlyConnector,
    ReadOnlyMailConnector,
)
from .exceptions import (
    AttachmentNotFoundError,
    ConnectorNotAvailableError,
    MessageNotFoundError,
)
from .models import (
    AccountInfo,
    AttachmentContent,
    FolderInfo,
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

    def list_accounts(self) -> list[AccountInfo]:
        account = self.settings.account
        return [
            AccountInfo(
                id=account.id,
                protocol=account.protocol.value,
                description=account.description,
                default_folder=account.default_folder,
                oauth_scopes=account.oauth.scopes if account.oauth else None,
            )
        ]

    def list_folders(self) -> list[FolderInfo]:
        connector = self._get_connector()
        return connector.list_folders()

    def search_messages(self, filters: MessageSearchFilters) -> list[MessageSummary]:
        connector = self._get_connector()
        normalized_filters = self._normalize_filters(filters)
        return connector.search_messages(normalized_filters)

    def fetch_message(self, folder_token: str, uid: str) -> MessageDetail:
        connector = self._get_connector()
        folder_path = decode_folder_token(folder_token)
        detail = connector.fetch_message(folder_path, uid)
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


def _ensure_datetime(value: datetime | str | None) -> datetime | None:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if value is None:
        return None
    parsed = parse_datetime(value)
    if parsed and parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _resolve_time_frame(label: str) -> tuple[datetime, datetime]:
    now = datetime.now(timezone.utc)
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
