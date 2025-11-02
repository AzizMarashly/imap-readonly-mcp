"""Pydantic models describing tool inputs for MCP tools."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


def _nullable_string_field(*, description: str, examples: list[str] | None = None) -> Any:
    return Field(
        default=None,
        description=description,
        examples=examples,
        json_schema_extra={"type": "string", "nullable": True},
    )


def _nullable_string_list_field(*, description: str) -> Any:
    return Field(
        default=None,
        description=description,
        json_schema_extra={
            "type": "array",
            "nullable": True,
            "items": {"type": "string"},
        },
    )


class MailFetchInput(BaseModel):
    """Consolidated request payload for the mail.fetch tool."""

    model_config = ConfigDict(
        title="mail.fetch request",
        json_schema_extra={
            "examples": [
                {
                    "folder": "INBOX",
                    "limit": 25,
                    "include": "headers",
                    "include_attachments": "none",
                },
                {
                    "query": "from:billing@example.com newer_than:7d",
                    "include": "full",
                    "include_attachments": "meta",
                },
                {
                    "ids": ["mail://primary/SU5CT1g=/12345"],
                    "include": "full",
                    "include_attachments": "inline",
                    "expand_thread": True,
                },
            ]
        },
    )

    ids: list[str] | None = _nullable_string_list_field(
        description="If provided, fetch exactly these message identifiers (use the `id` field from prior calls).",
    )
    query: str | None = _nullable_string_field(
        description="Free-text or provider-specific mail query. Leave empty to list the most recent messages.",
        examples=["from:billing@example.com newer_than:7d"],
    )
    folder: str | None = _nullable_string_field(
        description="Folder/mailbox name (e.g. 'INBOX') or encoded token returned previously. Defaults to the configured inbox.",
        examples=["INBOX", "SU5CT1g="],
    )
    since: str | None = _nullable_string_field(
        description='Lower bound timestamp (ISO-8601 or natural language such as "2025-05-01" or "last monday").',
        examples=["2025-05-01T00:00:00Z", "last monday"],
    )
    until: str | None = _nullable_string_field(
        description='Upper bound timestamp (ISO-8601 or natural language such as "yesterday").',
        examples=["2025-05-31T23:59:00Z", "yesterday"],
    )
    limit: int | None = Field(
        default=None,
        ge=1,
        le=500,
        description="Maximum number of messages to return (defaults to server configuration, typically 50).",
        json_schema_extra={"type": "integer", "nullable": True},
    )
    cursor: str | None = _nullable_string_field(
        description="Opaque cursor returned by a previous response (`next_cursor` or `sync_cursor`).",
    )
    include: Literal["headers", "full"] = Field(
        default="headers",
        description='Payload depth: "headers" yields summaries, "full" also includes bodies and expanded headers.',
        examples=["headers", "full"],
    )
    expand_thread: bool = Field(
        default=False,
        description="When true, include other messages from matching threads (best effort per provider).",
    )
    include_attachments: Literal["none", "meta", "inline"] = Field(
        default="none",
        description='Attachment mode: "none" omits them, "meta" returns metadata, "inline" includes small base64 payloads.',
        examples=["none", "meta", "inline"],
    )

    @field_validator("limit")
    @classmethod
    def _ensure_positive(cls, value: int | None) -> int | None:
        if value is not None and value <= 0:
            raise ValueError("limit must be positive")
        return value


class MailContact(BaseModel):
    """Simple representation of a mailbox participant."""

    name: str | None = Field(default=None, description="Display name when present.")
    email: str = Field(description="Email address.")


class MailAttachment(BaseModel):
    """Attachment payload returned by mail.fetch or mail.download_attachment."""

    id: str | None = Field(default=None, description="Attachment identifier.")
    filename: str | None = Field(default=None, description="Filename where provided.")
    size: int | None = Field(default=None, description="Attachment size in bytes if known.")
    mime: str | None = Field(default=None, description="MIME/content type.")
    download_url: str | None = Field(
        default=None,
        description="Direct download URL when supplied by the provider.",
    )
    data_base64: str | None = Field(
        default=None,
        description="Base64 encoded bytes when inline payloads are requested.",
    )
    inline_bytes: int | None = Field(
        default=None,
        description="Number of bytes included inline (useful when truncated).",
    )
    inline_truncated: bool | None = Field(
        default=None,
        description="True when the inline payload was truncated due to size limits.",
    )
    inline_error: str | None = Field(
        default=None,
        description="Error encountered while attempting to inline the attachment (if any).",
    )


class MailMessageItem(BaseModel):
    """Structured representation of a fetched email."""

    id: str = Field(description="Unique resource identifier for the message.")
    thread_id: str | None = Field(default=None, description="Provider-specific thread/conversation identifier.")
    account_id: str = Field(description="Owning account identifier.")
    folder: str = Field(description="Folder/mailbox display path.")
    folder_token: str = Field(description="Opaque folder token usable with other mail tools.")
    uid: str = Field(description="Provider-specific message identifier within the folder.")
    resource_uri: str = Field(description="Resource URI for retrieving message body via MCP.")
    raw_resource_uri: str = Field(description="Resource URI for fetching RFC822 bytes via MCP.")
    date: str | None = Field(default=None, description="Message delivery timestamp in ISO-8601 format.")
    from_: list[MailContact] = Field(default_factory=list, alias="from", description="Sender addresses.")
    to: list[MailContact] = Field(default_factory=list, description="Primary recipient list.")
    cc: list[MailContact] = Field(default_factory=list, description="Carbon copy recipients.")
    bcc: list[MailContact] = Field(default_factory=list, description="Blind carbon copy recipients when available.")
    reply_to: list[MailContact] = Field(default_factory=list, description="Reply-To addresses if provided.")
    subject: str | None = Field(default=None, description="Decoded message subject.")
    is_read: bool = Field(default=False, description="True when the message is marked read on the server.")
    snippet: str | None = Field(default=None, description="Short preview of the body content.")
    has_attachments: bool | None = Field(
        default=None,
        description="True when the message has at least one attachment (as reported by the provider).",
    )
    body_text: str | None = Field(default=None, description="Plain text body (when include='full').")
    body_html: str | None = Field(default=None, description="HTML body (when include='full').")
    headers: dict[str, list[str]] | None = Field(
        default=None,
        description="Complete header mapping when include='full'.",
    )
    flags: dict[str, Any] | None = Field(
        default=None,
        description="Raw flag state from the provider (seen, flagged, etc.).",
    )
    attachments: list[MailAttachment] = Field(default_factory=list, description="Attachment metadata/payload entries.")
    thread: list["MailMessageItem"] | None = Field(
        default=None,
        description="Other messages in the same thread when expand_thread=true.",
    )
    error: str | None = Field(
        default=None,
        description="Populated when the message could not be fetched; other fields may be blank in that case.",
    )


class MailFetchResult(BaseModel):
    """Response envelope returned by mail.fetch."""

    items: list[MailMessageItem] = Field(default_factory=list, description="Fetched message entries.")
    next_cursor: str | None = _nullable_string_field(
        description="Cursor for pagination (pass back as `cursor` to continue where you left off)."
    )
    sync_cursor: str | None = _nullable_string_field(
        description="Cursor for incremental sync (pass back later to fetch only new/updated messages)."
    )
    errors: list[dict[str, str]] | None = Field(
        default=None,
        description="Optional collection of per-item errors (e.g. invalid ids).",
    )


class MailDownloadAttachmentInput(BaseModel):
    """Download request payload for the mail.download_attachment tool."""

    model_config = ConfigDict(
        title="mail.download_attachment request",
        json_schema_extra={
            "examples": [
                {
                    "message_id": "mail://primary/SU5CT1g=/12345",
                    "attachment_id": "att-001",
                }
            ]
        },
    )

    message_id: str = Field(
        description="Message identifier taken from the `id` field returned by mail.fetch.",
        examples=["mail://primary/SU5CT1g=/12345"],
    )
    attachment_id: str | int = Field(
        description="Attachment identifier (provider ID or numeric index for legacy protocols).",
        examples=["att-001", 0],
    )


class MailDownloadAttachmentResult(BaseModel):
    """Response payload for mail.download_attachment."""

    message_id: str = Field(description="Source message identifier (echo of the request).")
    attachment: MailAttachment = Field(description="Attachment metadata and payload data.")


# Resolve forward references
MailMessageItem.model_rebuild()
