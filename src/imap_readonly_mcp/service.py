"""Mail service orchestration for MCP tools and resources."""

from __future__ import annotations

from datetime import datetime
from functools import cached_property
from typing import Iterable

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
    SemanticMatch,
)
from .semantic.index import SemanticIndexer
from .utils.identifiers import decode_folder_token


CONNECTOR_REGISTRY: dict[AccountProtocol, type[ReadOnlyMailConnector]] = {
    AccountProtocol.IMAP: IMAPReadOnlyConnector,
    AccountProtocol.POP3: POP3ReadOnlyConnector,
    AccountProtocol.GRAPH: GraphReadOnlyConnector,
}


class MailService:
    """High level façade used by the MCP server to service tool/resource requests."""

    def __init__(self, settings: MailSettings) -> None:
        self.settings = settings
        self._connectors: dict[str, ReadOnlyMailConnector] = {}
        self._semantic = SemanticIndexer(
            enabled=settings.semantic_search.enabled,
            model_name=settings.semantic_search.model_name,
            batch_size=settings.semantic_search.batch_size,
        )

    def list_accounts(self) -> list[AccountInfo]:
        accounts = []
        for account in self.settings.accounts:
            accounts.append(
                AccountInfo(
                    id=account.id,
                    protocol=account.protocol.value,
                    description=account.description,
                    default_folder=account.default_folder,
                    oauth_scopes=account.oauth.scopes if account.oauth else None,
                )
            )
        return accounts

    def list_folders(self, account_id: str) -> list[FolderInfo]:
        connector = self._get_connector(account_id)
        return connector.list_folders()

    def search_messages(self, account_id: str, filters: MessageSearchFilters) -> list[MessageSummary]:
        connector = self._get_connector(account_id)
        normalized_filters = self._normalize_filters(filters)
        return connector.search_messages(normalized_filters)

    def fetch_message(self, account_id: str, folder_token: str, uid: str) -> MessageDetail:
        connector = self._get_connector(account_id)
        folder_path = decode_folder_token(folder_token)
        detail = connector.fetch_message(folder_path, uid)
        if self.settings.semantic_search.auto_index_on_fetch:
            self._semantic.add_message(detail, account_id=account_id)
        return detail

    def fetch_raw_message(self, account_id: str, folder_token: str, uid: str) -> bytes:
        connector = self._get_connector(account_id)
        folder_path = decode_folder_token(folder_token)
        return connector.fetch_raw_message(folder_path, uid)

    def fetch_attachment(
        self,
        account_id: str,
        folder_token: str,
        uid: str,
        attachment_identifier: int | str,
    ) -> AttachmentContent:
        connector = self._get_connector(account_id)
        folder_path = decode_folder_token(folder_token)
        return connector.fetch_attachment(folder_path, uid, attachment_identifier)

    def semantic_search(
        self,
        account_id: str,
        query: str,
        folder_token: str | None = None,
        top_k: int = 5,
    ) -> list[SemanticMatch]:
        return self._semantic.search(account_id=account_id, folder_token=folder_token, query=query, top_k=top_k)

    def _get_connector(self, account_id: str) -> ReadOnlyMailConnector:
        if account_id in self._connectors:
            return self._connectors[account_id]
        account = next((acct for acct in self.settings.accounts if acct.id == account_id), None)
        if not account:
            raise ConnectorNotAvailableError(f"Account {account_id} is not configured.")
        connector_cls = CONNECTOR_REGISTRY.get(account.protocol)
        if not connector_cls:
            raise ConnectorNotAvailableError(f"No connector registered for protocol {account.protocol.value}")
        connector = connector_cls(account)
        self._connectors[account_id] = connector
        return connector

    def _normalize_filters(self, filters: MessageSearchFilters) -> MessageSearchFilters:
        limit = filters.limit or self.settings.default_search_limit
        limit = min(limit, self.settings.maximum_search_limit)
        since = _ensure_datetime(filters.since)
        until = _ensure_datetime(filters.until)
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
        )


def _ensure_datetime(value: datetime | str | None) -> datetime | None:
    if isinstance(value, datetime):
        return value
    if value is None:
        return None
    parsed = parse_datetime(value)
    return parsed
