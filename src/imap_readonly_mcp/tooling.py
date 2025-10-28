"""Pydantic models describing tool inputs for MCP tools."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator



def _example_folder_token() -> str:
    return "SU5CT1g="  # Base64 for "INBOX"


class SearchMessagesInput(BaseModel):
    """Search filters accepted by the search_messages tool."""

    model_config = ConfigDict(
        title="Search Messages Request",
        json_schema_extra={
            "examples": [
                {
                    "folder_token": _example_folder_token(),
                    "time_frame": "last_7_days",
                    "text": "invoice",
                    "sender": "billing@example.com",
                    "offset": 0,
                    "since": "2025-01-01T00:00:00Z",
                    "limit": 25,
                }
            ]
        },
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
    time_frame: TimeFrameLiteral | None = Field(
        default=None,
        description="Optional relative timeframe. When provided, automatically sets missing since/until fields.",
        examples=["last_7_days"],
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
        description='Return messages received on or after this timestamp. Accepts ISO-8601 dates or natural language (e.g. "last monday").',
        examples=["2025-05-01T00:00:00Z", "last monday"],
    )
    until: datetime | str | None = Field(
        default=None,
        description='Return messages received up to and including this timestamp. Accepts ISO-8601 dates or natural language (e.g. "yesterday").',
        examples=["2025-05-31T23:59:59Z", "yesterday"],
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
    offset: int | None = Field(
        default=None,
        ge=0,
        description="Number of results to skip (use with limit for pagination).",
        examples=[20],
    )
    limit: int | None = Field(
        default=20,
        ge=1,
        le=500,
        description="Maximum number of results to return for this page (defaults to 20, capped by server).",
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


TimeFrameLiteral = Literal[
    "last_hour",
    "last_24_hours",
    "last_7_days",
    "last_30_days",
    "last_90_days",
]

