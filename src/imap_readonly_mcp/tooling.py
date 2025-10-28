"""Pydantic models describing tool inputs and structured outputs."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field, field_validator


class ListFoldersInput(BaseModel):
    account_id: str = Field(description="Identifier of the configured mail account.")


class SearchMessagesInput(BaseModel):
    account_id: str = Field(description="Identifier of the configured mail account.")
    folder_token: str | None = Field(
        default=None,
        description="Opaque folder token obtained from the folder listing tool.",
    )
    text: str | None = Field(default=None, description="Free text query to match against subject and body.")
    sender: str | None = Field(default=None, description="Filter by sender email address.")
    recipient: str | None = Field(default=None, description="Filter by recipient email address.")
    since: datetime | str | None = Field(
        default=None,
        description="Return messages on or after this timestamp. ISO 8601 string if not passing a datetime.",
    )
    until: datetime | str | None = Field(
        default=None,
        description="Return messages up to and including this timestamp.",
    )
    unread_only: bool = Field(default=False, description="Restrict to unread messages where supported.")
    has_attachments: bool | None = Field(default=None, description="Restrict to messages with attachments.")
    limit: int | None = Field(default=None, description="Maximum number of messages to return (default 50).")

    @field_validator("limit")
    @classmethod
    def _ensure_positive(cls, value: int | None) -> int | None:
        if value is not None and value <= 0:
            raise ValueError("limit must be positive")
        return value


class GetMessageInput(BaseModel):
    account_id: str = Field(description="Identifier of the configured mail account.")
    folder_token: str = Field(description="Opaque folder token from folder listing tool.")
    uid: str = Field(description="Protocol specific UID for the message.")


class GetAttachmentInput(BaseModel):
    account_id: str
    folder_token: str
    uid: str
    attachment_identifier: int | str = Field(
        description="Attachment index (integer) or provider specific ID (string)."
    )


class SemanticSearchInput(BaseModel):
    account_id: str
    query: str = Field(description="Search query text.")
    folder_token: str | None = Field(
        default=None, description="Optional folder token. Searches all indexed folders when omitted."
    )
    top_k: int = Field(default=5, gt=0, le=25, description="Maximum number of matches to return.")
