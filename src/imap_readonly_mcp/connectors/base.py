"""Abstract base classes and helper models for mail connectors."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Iterable

from ..config import MailAccountConfig
from ..models import (
    AttachmentContent,
    AttachmentMetadata,
    FolderInfo,
    MessageDetail,
    MessageSearchFilters,
    MessageSummary,
)


class ConnectorCapabilities:
    """Capabilities exposed by a connector implementation."""

    def __init__(
        self,
        *,
        supports_folders: bool = True,
        supports_search: bool = True,
        supports_attachments: bool = True,
    ) -> None:
        self.supports_folders = supports_folders
        self.supports_search = supports_search
        self.supports_attachments = supports_attachments


class ReadOnlyMailConnector(ABC):
    """Abstraction implemented by protocol specific mail connectors."""

    def __init__(self, config: MailAccountConfig) -> None:
        self.config = config

    @property
    def capabilities(self) -> ConnectorCapabilities:
        """Return capability envelope for the connector."""
        return ConnectorCapabilities()

    @abstractmethod
    def list_folders(self) -> list[FolderInfo]:
        """List folders/mailboxes available for this account."""

    @abstractmethod
    def search_messages(self, filters: MessageSearchFilters) -> list[MessageSummary]:
        """Search for messages that match the provided filters."""

    def search_all_folders(self, filters: MessageSearchFilters) -> list[MessageSummary]:
        """Search for messages across all folders (default falls back to single-folder search)."""
        return self.search_messages(filters)

    @abstractmethod
    def fetch_message(self, folder_path: str, uid: str) -> MessageDetail:
        """Return full message details."""

    @abstractmethod
    def fetch_raw_message(self, folder_path: str, uid: str) -> bytes:
        """Return the raw RFC822 message bytes."""

    @abstractmethod
    def fetch_attachment(self, folder_path: str, uid: str, attachment_index: int) -> AttachmentContent:
        """Return a specific attachment payload."""

    def prefetch_messages(self, folder_path: str, uids: Iterable[str]) -> None:
        """Optional hook allowing connectors to optimize repeated message retrieval."""
        # Default implementation does nothing. Protocol specific connectors can override.
        return None

