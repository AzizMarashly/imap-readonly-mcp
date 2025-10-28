"""Stdio entrypoint for the read-only mail MCP server."""

from __future__ import annotations

import argparse
import base64
import os
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Annotated, Iterable

import anyio
from mcp.server.fastmcp import FastMCP
from mcp.types import Icon
from pydantic import Field

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
    host = os.environ.get("FASTMCP_HOST", "127.0.0.1")
    port = _coerce_int(os.environ.get("FASTMCP_PORT"), default=8000)
    sse_path = os.environ.get("FASTMCP_SSE_PATH", "/sse")
    message_path = os.environ.get("FASTMCP_MESSAGE_PATH", "/messages/")
    streamable_path = os.environ.get("FASTMCP_STREAMABLE_HTTP__PATH", "/mcp")
    mount_path = os.environ.get("FASTMCP_MOUNT_PATH", "/")

    mcp = FastMCP(
        "imap-readonly-mail",
        host=host,
        port=port,
        sse_path=sse_path,
        message_path=message_path,
        streamable_http_path=streamable_path,
        mount_path=mount_path,
    )

    async def _run(func, *args, **kwargs):
        return await anyio.to_thread.run_sync(func, *args, **kwargs)

    @mcp.tool(name="list_accounts", description="List configured read-only mail accounts.")
    async def list_accounts() -> list[dict[str, Any]]:
        accounts = await _run(service.list_accounts)
        return [_to_dict(account) for account in accounts]

    @mcp.tool(name="list_folders", description="List folders available for a mail account.")
    async def list_folders(
        account_id: Annotated[str, Field(description="Identifier of the configured mail account.", examples=["corporate-imap"])]
    ) -> list[dict[str, Any]]:
        payload = ListFoldersInput(account_id=account_id)
        folders = await _run(service.list_folders, payload.account_id)
        return [_to_dict(folder) for folder in folders]

    @mcp.tool(name="search_messages", description="Search messages in a folder with optional filters.")
    async def search_messages(
        account_id: Annotated[str, Field(description="Identifier of the configured mail account.", examples=["corporate-imap"])],
        folder_token: Annotated[str | None, Field(default=None, description="Folder token from list_folders; leave blank for the default folder.", examples=["SU5CT1g="])] = None,
        text: Annotated[str | None, Field(default=None, description="Free text query applied to subject, body, and addresses.", examples=["status update"])] = None,
        sender: Annotated[str | None, Field(default=None, description="Filter by sender email address.", examples=["alice@example.com"])] = None,
        recipient: Annotated[str | None, Field(default=None, description="Filter by recipient email address.", examples=["team@example.com"])] = None,
        since: Annotated[datetime | str | None, Field(default=None, description="Only include messages on or after this timestamp (ISO-8601).", examples=["2025-05-01T00:00:00Z"])] = None,
        until: Annotated[datetime | str | None, Field(default=None, description="Only include messages up to and including this timestamp (ISO-8601).", examples=["2025-05-31T23:59:59Z"])] = None,
        unread_only: Annotated[bool, Field(default=False, description="Restrict to unread messages where supported.", examples=[True])] = False,
        has_attachments: Annotated[bool | None, Field(default=None, description="Restrict to messages containing attachments.", examples=[True])] = None,
        limit: Annotated[int | None, Field(default=None, ge=1, le=500, description="Maximum number of results to return (defaults to server limit).", examples=[50])] = None,
    ) -> dict[str, Any]:
        payload = SearchMessagesInput(
            account_id=account_id,
            folder_token=folder_token,
            text=text,
            sender=sender,
            recipient=recipient,
            since=since,
            until=until,
            unread_only=unread_only,
            has_attachments=has_attachments,
            limit=limit,
        )
        filters = MessageSearchFilters(**payload.model_dump(exclude_none=True))
        start = time.perf_counter()
        summaries = await _run(service.search_messages, payload.account_id, filters)
        duration = time.perf_counter() - start
        return {
            "messages": [_to_dict(summary) for summary in summaries],
            "diagnostics": {"duration_seconds": duration, "count": len(summaries)},
        }

    @mcp.tool(name="get_message", description="Fetch full message details including body and attachments.")
    async def get_message(
        account_id: Annotated[str, Field(description="Identifier of the configured mail account.", examples=["corporate-imap"])],
        folder_token: Annotated[str, Field(description="Folder token from list_folders.", examples=["SU5CT1g="])],
        uid: Annotated[str, Field(description="Protocol-specific UID for the message.", examples=["12345"])],
    ) -> dict[str, Any]:
        payload = GetMessageInput(account_id=account_id, folder_token=folder_token, uid=uid)
        detail = await _run(service.fetch_message, payload.account_id, payload.folder_token, payload.uid)
        return _to_dict(detail)

    @mcp.tool(
        name="get_raw_message",
        description="Download the RFC822 source of a message as Base64 encoded content.",
    )
    async def get_raw_message(
        account_id: Annotated[str, Field(description="Identifier of the configured mail account.", examples=["corporate-imap"])],
        folder_token: Annotated[str, Field(description="Folder token from list_folders.", examples=["SU5CT1g="])],
        uid: Annotated[str, Field(description="Protocol-specific UID for the message.", examples=["12345"])],
    ) -> dict[str, Any]:
        payload = GetMessageInput(account_id=account_id, folder_token=folder_token, uid=uid)
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
    async def download_attachment(
        account_id: Annotated[str, Field(description="Identifier of the configured mail account.", examples=["corporate-imap"])],
        folder_token: Annotated[str, Field(description="Folder token from list_folders.", examples=["SU5CT1g="])],
        uid: Annotated[str, Field(description="Protocol-specific UID for the message.", examples=["12345"])],
        attachment_identifier: Annotated[int | str, Field(description="Attachment index (integer) or provider-specific ID (string).", examples=[0, "att-001"])],
    ) -> dict[str, Any]:
        payload = GetAttachmentInput(
            account_id=account_id,
            folder_token=folder_token,
            uid=uid,
            attachment_identifier=attachment_identifier,
        )
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
    async def semantic_search(
        account_id: Annotated[str, Field(description="Identifier of the configured mail account.", examples=["corporate-imap"])],
        query: Annotated[str, Field(description="Natural language search query.", examples=["multilingual invoice status"])],
        folder_token: Annotated[str | None, Field(default=None, description="Optional folder token; search all indexed folders when omitted.", examples=["SU5CT1g="])] = None,
        top_k: Annotated[int, Field(default=5, gt=0, le=25, description="Maximum number of semantic matches to return.", examples=[5])] = 5,
    ) -> dict[str, Any]:
        payload = SemanticSearchInput(
            account_id=account_id,
            query=query,
            folder_token=folder_token,
            top_k=top_k,
        )
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


TRANSPORT_CHOICES = ("stdio", "sse", "streamable-http")


def parse_args(argv: Iterable[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the read-only email MCP server.")
    parser.add_argument(
        "--config",
        default=os.environ.get("MAIL_CONFIG_FILE", "config/accounts.yaml"),
        help="Path to the configuration YAML file.",
    )
    parser.add_argument(
        "--transport",
        choices=TRANSPORT_CHOICES,
        default=None,
        help="MCP transport to run (overrides FASTMCP_TRANSPORT).",
    )
    return parser.parse_args(argv)


def main(argv: Iterable[str] | None = None) -> None:
    args = parse_args(argv)
    settings = load_settings(Path(args.config))
    server = create_server(settings)

    transport = (args.transport or os.environ.get("FASTMCP_TRANSPORT", "stdio")).lower()
    if transport not in TRANSPORT_CHOICES:
        raise ValueError(f"Unsupported transport '{transport}'. Expected one of {TRANSPORT_CHOICES}.")

    if transport == "streamable-http":
        print(
            f"[imap-readonly-mcp] Starting StreamableHTTP server on "
            f"{server.settings.host}:{server.settings.port} (path={server.settings.streamable_http_path})",
            flush=True,
        )
    elif transport == "sse":
        print(
            f"[imap-readonly-mcp] Starting SSE server on {server.settings.host}:{server.settings.port} "
            f"(path={server.settings.sse_path})",
            flush=True,
        )
    else:
        print("[imap-readonly-mcp] Starting stdio transport", flush=True)

    mount_path = None
    if transport == "sse":
        mount_path = os.environ.get("FASTMCP_SSE_MOUNT_PATH", server.settings.mount_path)

    server.run(transport=transport, mount_path=mount_path)


def _coerce_int(value: str | None, default: int) -> int:
    if value is None:
        return default
    try:
        return int(value)
    except ValueError:
        print(
            f"[imap-readonly-mcp] Invalid integer for environment override: {value!r}; using default {default}",
            flush=True,
        )
        return default


if __name__ == "__main__":
    main()
