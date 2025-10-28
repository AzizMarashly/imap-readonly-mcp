"""Stdio entrypoint for the read-only mail MCP server."""

from __future__ import annotations

import argparse
import base64
import os
import time
from pathlib import Path
from typing import Any, Iterable

import anyio
from mcp.server.fastmcp import FastMCP
from mcp.types import Icon

from .config import MailSettings, load_settings
from .exceptions import AttachmentNotFoundError, MailServiceError, MessageNotFoundError
from .models import AttachmentContent, MessageSearchFilters
from .service import MailService
from .tooling import (
    GetAttachmentInput,
    GetMessageInput,
    ListFoldersInput,
    SearchMessagesInput,
    SemanticSearchInput,
)


def create_server(settings: MailSettings) -> FastMCP:
    """Create a configured FastMCP application instance."""

    service = MailService(settings)
    mcp = FastMCP(
        "imap-readonly-mail",
        icon=Icon(type="emoji", value="mail"),
    )

    async def _run(func, *args, **kwargs):
        return await anyio.to_thread.run_sync(func, *args, **kwargs)

    @mcp.tool(name="list_accounts", description="List configured read-only mail accounts.")
    async def list_accounts() -> list[dict[str, Any]]:
        accounts = await _run(service.list_accounts)
        return [_to_dict(account) for account in accounts]

    @mcp.tool(name="list_folders", description="List folders available for a mail account.")
    async def list_folders(payload: ListFoldersInput) -> list[dict[str, Any]]:
        folders = await _run(service.list_folders, payload.account_id)
        return [_to_dict(folder) for folder in folders]

    @mcp.tool(name="search_messages", description="Search messages in a folder with optional filters.")
    async def search_messages(payload: SearchMessagesInput) -> dict[str, Any]:
        filters = MessageSearchFilters(
            folder=payload.folder_token,
            text=payload.text,
            sender=payload.sender,
            recipient=payload.recipient,
            since=payload.since,
            until=payload.until,
            unread_only=payload.unread_only,
            has_attachments=payload.has_attachments,
            limit=payload.limit,
        )
        start = time.perf_counter()
        summaries = await _run(service.search_messages, payload.account_id, filters)
        duration = time.perf_counter() - start
        return {
            "messages": [_to_dict(summary) for summary in summaries],
            "diagnostics": {"duration_seconds": duration, "count": len(summaries)},
        }

    @mcp.tool(name="get_message", description="Fetch full message details including body and attachments.")
    async def get_message(payload: GetMessageInput) -> dict[str, Any]:
        detail = await _run(service.fetch_message, payload.account_id, payload.folder_token, payload.uid)
        return _to_dict(detail)

    @mcp.tool(
        name="get_raw_message",
        description="Download the RFC822 source of a message as Base64 encoded content.",
    )
    async def get_raw_message(payload: GetMessageInput) -> dict[str, Any]:
        raw = await _run(service.fetch_raw_message, payload.account_id, payload.folder_token, payload.uid)
        encoded = base64.b64encode(raw).decode("ascii")
        return {
            "account_id": payload.account_id,
            "folder_token": payload.folder_token,
            "uid": payload.uid,
            "mime_type": "message/rfc822",
            "data_base64": encoded,
        }

    @mcp.tool(
        name="download_attachment",
        description="Download an attachment from a message. Returns Base64 encoded payload.",
    )
    async def download_attachment(payload: GetAttachmentInput) -> dict[str, Any]:
        try:
            attachment = await _run(
                service.fetch_attachment,
                payload.account_id,
                payload.folder_token,
                payload.uid,
                payload.attachment_identifier,
            )
        except AttachmentNotFoundError as exc:
            return {"error": str(exc)}
        return _serialise_attachment(attachment)

    @mcp.tool(
        name="semantic_search",
        description="Run a semantic search across indexed messages using multilingual embeddings.",
    )
    async def semantic_search(payload: SemanticSearchInput) -> dict[str, Any]:
        matches = await _run(
            service.semantic_search,
            payload.account_id,
            payload.query,
            payload.folder_token,
            payload.top_k,
        )
        return {
            "matches": [_to_dict(match) for match in matches],
            "query": payload.query,
        }

    @mcp.resource(
        "mail://{account_id}/{folder_token}/{uid}",
        description="Plain text representation of the message body.",
        mime_type="text/plain",
    )
    async def message_text(account_id: str, folder_token: str, uid: str) -> str:
        detail = await _run(service.fetch_message, account_id, folder_token, uid)
        body = detail.body.text or detail.body.html or "(no body)"
        return body

    @mcp.resource(
        "mail+html://{account_id}/{folder_token}/{uid}",
        description="HTML representation of the message body if available.",
        mime_type="text/html",
    )
    async def message_html(account_id: str, folder_token: str, uid: str) -> str:
        detail = await _run(service.fetch_message, account_id, folder_token, uid)
        return detail.body.html or detail.body.text or "<p>(no html body)</p>"

    @mcp.resource(
        "mail+raw://{account_id}/{folder_token}/{uid}",
        description="Raw RFC822 message source.",
        mime_type="message/rfc822",
    )
    async def message_raw(account_id: str, folder_token: str, uid: str) -> bytes:
        raw = await _run(service.fetch_raw_message, account_id, folder_token, uid)
        return raw

    @mcp.resource(
        "mail+attachment://{account_id}/{folder_token}/{uid}/{attachment_identifier}",
        description="Binary attachment payload.",
        mime_type="application/octet-stream",
    )
    async def attachment_resource(
        account_id: str,
        folder_token: str,
        uid: str,
        attachment_identifier: str,
    ) -> bytes:
        identifier: int | str
        if attachment_identifier.isdigit():
            identifier = int(attachment_identifier)
        else:
            identifier = attachment_identifier
        attachment = await _run(
            service.fetch_attachment,
            account_id,
            folder_token,
            uid,
            identifier,
        )
        return attachment.data

    return mcp


def _to_dict(model: Any) -> Any:
    if hasattr(model, "model_dump"):
        return model.model_dump()
    if isinstance(model, (list, tuple)):
        return [_to_dict(item) for item in model]
    if isinstance(model, dict):
        return {key: _to_dict(value) for key, value in model.items()}
    return model


def _serialise_attachment(attachment: AttachmentContent) -> dict[str, Any]:
    encoded = base64.b64encode(attachment.data).decode("ascii")
    return {
        "metadata": attachment.metadata.model_dump(),
        "mime_type": attachment.mime_type,
        "file_name": attachment.file_name,
        "data_base64": encoded,
        "download_url": attachment.download_url,
    }


def parse_args(argv: Iterable[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the read-only email MCP server.")
    parser.add_argument(
        "--config",
        default=os.environ.get("MAIL_CONFIG_FILE", "config/accounts.yaml"),
        help="Path to the configuration YAML file.",
    )
    return parser.parse_args(argv)


def main(argv: Iterable[str] | None = None) -> None:
    args = parse_args(argv)
    settings = load_settings(Path(args.config))
    server = create_server(settings)
    server.run()


if __name__ == "__main__":
    main()
