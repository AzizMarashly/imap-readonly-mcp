"""Shared data models used by the mail MCP server."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, HttpUrl


class MailboxRole(str, Enum):
    """Common mailbox roles."""

    INBOX = "inbox"
    SENT = "sent"
    ARCHIVE = "archive"
    JUNK = "junk"
    TRASH = "trash"
    DRAFTS = "drafts"
    CUSTOM = "custom"


class FolderInfo(BaseModel):
    """Metadata describing an accessible folder/mailbox."""

    path: str = Field(description="IMAP style folder path or POP3 virtual identifier.")
    encoded_path: str = Field(
        description="URL-safe encoded folder identifier used in resource URIs. Consumers should treat as opaque."
    )
    role: MailboxRole = Field(default=MailboxRole.CUSTOM, description="Best-effort role classification.")
    selectable: bool = Field(default=True, description="Whether the folder can be selected for searching.")
    total_messages: int | None = Field(default=None, description="Total messages if available from the protocol.")
    unread_messages: int | None = Field(default=None, description="Unread messages count when available.")


class EmailAddress(BaseModel):
    """Simple representation of an email address."""

    display_name: str | None = Field(default=None, description="Display name if provided.")
    address: str = Field(description="Normalized email address.")


class AttachmentMetadata(BaseModel):
    """Metadata for a message attachment."""

    attachment_id: str = Field(description="Connector specific attachment identifier.")
    filename: str = Field(description="Attachment file name.")
    content_type: str = Field(default="application/octet-stream", description="Attachment MIME type.")
    size: int | None = Field(default=None, description="Attachment size in bytes if known.")
    resource_uri: str | None = Field(
        default=None,
        description="Resource URI that can be resolved via MCP to retrieve the attachment bytes.",
    )


class MessageFlags(BaseModel):
    """Flags describing the state of the message."""

    seen: bool = Field(default=False, description="True if the message is marked as seen/read on the server.")
    flagged: bool = Field(default=False, description="True if flagged/starred.")
    answered: bool = Field(default=False, description="True if replied to.")
    draft: bool = Field(default=False, description="True if the message is a draft.")
    recent: bool = Field(default=False, description="True if the message is marked as recent (IMAP).")
    other: list[str] = Field(default_factory=list, description="Connector specific flag strings.")


class MessageSummary(BaseModel):
    """High level metadata about a message returned by search/list operations."""

    folder_path: str = Field(description="Original folder path from the connector.")
    folder_token: str = Field(description="URL-safe token used to address the folder in resource URIs.")
    uid: str = Field(description="Protocol specific message unique identifier.")
    subject: str | None = Field(default=None, description="Decoded message subject.")
    from_: list[EmailAddress] = Field(default_factory=list, alias="from", description="Sender addresses.")
    to: list[EmailAddress] = Field(default_factory=list, description="Recipient (To) addresses.")
    cc: list[EmailAddress] = Field(default_factory=list, description="Carbon copy recipients.")
    bcc: list[EmailAddress] = Field(default_factory=list, description="Blind carbon copy recipients (if available).")
    reply_to: list[EmailAddress] = Field(default_factory=list, description="Reply-to addresses when provided.")
    date: datetime | None = Field(default=None, description="Message date in UTC.")
    size: int | None = Field(default=None, description="Message size in bytes where available.")
    snippet: str | None = Field(default=None, description="Short preview of the message body.")
    has_attachments: bool = Field(default=False, description="True when the message has at least one attachment.")
    flags: MessageFlags = Field(default_factory=MessageFlags, description="Message flag state.")
    resource_uri: str = Field(description="URI that resolves to message body resource via MCP.")
    raw_resource_uri: str = Field(
        description="URI that resolves to the raw RFC822 message body for ingestion contexts."
    )

    class Config:
        populate_by_name = True


class MessageBody(BaseModel):
    """Body payload of an email message in multiple formats."""

    text: str | None = Field(default=None, description="Plain text representation.")
    html: str | None = Field(default=None, description="HTML representation if supplied.")
    charset: str | None = Field(default=None, description="Declared charset used to decode the payload.")


class MessageDetail(MessageSummary):
    """Full details of a message including body and attachments."""

    body: MessageBody = Field(default_factory=MessageBody, description="Message body in text/html variants.")
    attachments: list[AttachmentMetadata] = Field(default_factory=list, description="Attachment metadata entries.")
    headers: dict[str, list[str]] = Field(default_factory=dict, description="Multi-valued header mapping.")
    raw_source: str | None = Field(
        default=None, description="Raw RFC822 source (decoded as UTF-8 with surrogate escapes)."
    )


class MessageSearchFilters(BaseModel):
    """Normalized search filters used across connectors."""

    folder: str | None = Field(default=None, description="Folder/mailbox path to search within.")
    text: str | None = Field(default=None, description="Free text query to match across subject/body.")
    sender: str | None = Field(default=None, description="Filter by sender email address.")
    recipient: str | None = Field(default=None, description="Filter by recipient email address.")
    since: datetime | None = Field(default=None, description="Only include messages on or after this datetime.")
    until: datetime | None = Field(default=None, description="Only include messages before this datetime.")
    unread_only: bool = Field(default=False, description="Restrict results to unread messages where supported.")
    has_attachments: bool | None = Field(default=None, description="Filter by presence of attachments.")
    limit: int | None = Field(default=None, description="Maximum number of results to return.")
    time_frame: str | None = Field(
        default=None,
        description="Optional relative timeframe label used to derive since/until when those are omitted.",
    )
    offset: int | None = Field(default=None, description="Number of results to skip (for pagination).")


class ToolRuntimeDiagnostics(BaseModel):
    """Diagnostic metadata returned along with tool results."""

    duration_seconds: float | None = Field(default=None, description="Run duration in seconds.")
    connector_latency_ms: float | None = Field(default=None, description="Connector round trip latency.")
    warnings: list[str] = Field(default_factory=list, description="Optional warnings produced while running the tool.")
    extra: dict[str, Any] = Field(default_factory=dict, description="Any additional structured metadata.")


class AttachmentContent(BaseModel):
    """Structured response containing attachment data."""

    metadata: AttachmentMetadata
    data: bytes = Field(description="Attachment binary content.")
    mime_type: str = Field(description="Attachment MIME type.")
    file_name: str = Field(description="Attachment file name.")
    download_url: HttpUrl | None = Field(
        default=None, description="If available, direct download link produced by the provider."
    )

