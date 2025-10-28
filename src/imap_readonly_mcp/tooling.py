"""Pydantic models describing tool inputs for MCP tools."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator


def _example_account() -> str:
    return "corporate-imap"


def _example_folder_token() -> str:
    return "SU5CT1g="  # Base64 for "INBOX"


class ListFoldersInput(BaseModel):
    """Request payload for the list_folders tool."""

    model_config = ConfigDict(title="List Folders Request")

    account_id: str = Field(
        description="Identifier of the configured mail account.",
        examples=[_example_account()],
    )


class SearchMessagesInput(BaseModel):
    """Search filters accepted by the search_messages tool."""

    model_config = ConfigDict(
        title="Search Messages Request",
        json_schema_extra={
            "examples": [
                {
                    "account_id": _example_account(),
                    "folder_token": _example_folder_token(),
                    "text": "invoice",
                    "sender": "billing@example.com",
                    "since": "2025-01-01T00:00:00Z",
                    "limit": 25,
                }
            ]
        },
    )

    account_id: str = Field(
        description="Identifier of the configured mail account.",
        examples=[_example_account()],
    )
    folder_token: str | None = Field(
        default=None,
        description="Opaque folder token obtained from list_folders. Leave empty to use the account default.",
        examples=[_example_folder_token()],
    )
    text: str | None = Field(
        default=None,
        description="Free-text query applied to subject, body, and address fields.",
        examples=["status update"],
    )
    sender: str | None = Field(
        default=None,
        description="Filter by sender email address (case-insensitive).",
        examples=["alice@example.com"],
    )
    recipient: str | None = Field(
        default=None,
        description="Filter by recipient email address.",
        examples=["team@example.com"],
    )
    since: datetime | str | None = Field(
        default=None,
        description="Return messages received on or after this timestamp (ISO-8601 string).",
        examples=["2025-05-01T00:00:00Z"],
    )
    until: datetime | str | None = Field(
        default=None,
        description="Return messages received up to and including this timestamp (ISO-8601 string).",
        examples=["2025-05-31T23:59:59Z"],
    )
    unread_only: bool = Field(
        default=False,
        description="Restrict to unread messages (where supported).",
        examples=[True],
    )
    has_attachments: bool | None = Field(
        default=None,
        description="Restrict to messages that contain attachments.",
        examples=[True],
    )
    limit: int | None = Field(
        default=None,
        ge=1,
        le=500,
        description="Maximum number of results to return (defaults to server limit).",
        examples=[50],
    )

    @field_validator("limit")
    @classmethod
    def _ensure_positive(cls, value: int | None) -> int | None:
        if value is not None and value <= 0:
            raise ValueError("limit must be positive")
        return value


class GetMessageInput(BaseModel):
    """Arguments required to fetch a message."""

    model_config = ConfigDict(title="Get Message Request")

    account_id: str = Field(
        description="Identifier of the configured mail account.",
        examples=[_example_account()],
    )
    folder_token: str = Field(
        description="Opaque folder token from list_folders.",
        examples=[_example_folder_token()],
    )
    uid: str = Field(
        description="Protocol-specific UID for the message.",
        examples=["12345"],
    )


class GetAttachmentInput(BaseModel):
    """Arguments required to download a specific attachment."""

    model_config = ConfigDict(title="Get Attachment Request")

    account_id: str = Field(
        description="Identifier of the configured mail account.",
        examples=[_example_account()],
    )
    folder_token: str = Field(
        description="Opaque folder token from list_folders.",
        examples=[_example_folder_token()],
    )
    uid: str = Field(
        description="Protocol-specific UID for the source message.",
        examples=["12345"],
    )
    attachment_identifier: int | str = Field(
        description="Attachment index (integer for IMAP/POP3) or provider-specific ID (string).",
        examples=[0, "att-001"],
    )


class SemanticSearchInput(BaseModel):
    """Arguments for semantic search across indexed mail."""

    model_config = ConfigDict(title="Semantic Search Request")

    account_id: str = Field(
        description="Identifier of the configured mail account.",
        examples=[_example_account()],
    )
    query: str = Field(
        description="Natural language search query.",
        examples=["multilingual invoice status"],
    )
    folder_token: str | None = Field(
        default=None,
        description="Optional folder token. Search all indexed folders when omitted.",
        examples=[_example_folder_token()],
    )
    top_k: int = Field(
        default=5,
        gt=0,
        le=25,
        description="Maximum number of semantic matches to return.",
        examples=[5],
    )
