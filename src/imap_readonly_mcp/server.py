"""Stdio entrypoint for the single-account read-only mail MCP server."""

from __future__ import annotations

import argparse
import base64
import os
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Annotated, Iterable, Literal

import anyio
from mcp.server.fastmcp import FastMCP
from pydantic import Field

from .config import MailSettings, load_settings
from .exceptions import AttachmentNotFoundError, MessageNotFoundError
from .models import AttachmentContent, MessageSearchFilters
from .service import MailService
from .tooling import (
    GetAttachmentInput,
    GetMessageInput,
    SearchMessagesInput,
    TimeFrameLiteral,
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

    @mcp.tool(name="list_folders", description="List folders available in the configured account.")
    async def list_folders() -> list[dict[str, Any]]:
        folders = await _run(service.list_folders)
        return [_to_dict(folder) for folder in folders]

    @mcp.tool(name="search_messages", description="Search messages optionally filtered by folder, text, dates, or quick time frames.")
    async def search_messages(
        folder_token: Annotated[str | None, Field(default=None, description="Folder token from list_folders; leave blank for the default folder.", examples=["SU5CT1g="])] = None,
        text: Annotated[str | None, Field(default=None, description="Free-text query applied to subject, body, and addresses.", examples=["status update"])] = None,
        time_frame: Annotated[TimeFrameLiteral | None, Field(default=None, description="Optional quick range such as 'last_7_days'. Automatically sets missing since/until.", examples=["last_7_days"])] = None,
        sender: Annotated[str | None, Field(default=None, description="Filter by sender email address.", examples=["alice@example.com"])] = None,
        recipient: Annotated[str | None, Field(default=None, description="Filter by recipient email address.", examples=["team@example.com"])] = None,
        since: Annotated[str | None, Field(default=None, description="Optional start time (natural language allowed, e.g. '2025-05-01' or 'last monday').")] = None,
        until: Annotated[str | None, Field(default=None, description="Optional end time (natural language allowed, e.g. '2025-05-31' or 'yesterday').")] = None,
        unread_only: Annotated[bool, Field(default=False, description="Restrict to unread messages where supported.", examples=[True])] = False,
        has_attachments: Annotated[bool | None, Field(default=None, description="Restrict to messages containing attachments.", examples=[True])] = None,
        offset: Annotated[int | None, Field(default=0, ge=0, description="Number of results to skip for pagination.", examples=[20])] = 0,
        limit: Annotated[int | None, Field(default=20, ge=1, le=500, description="Maximum number of results to return for this page (defaults to 20, capped by the server).", examples=[50])] = 20,
    ) -> dict[str, Any]:
        payload = SearchMessagesInput(
            folder_token=folder_token,
            text=text,
            time_frame=time_frame,
            sender=sender,
            recipient=recipient,
            since=since,
            until=until,
            unread_only=unread_only,
            has_attachments=has_attachments,
            offset=offset,
            limit=limit,
        )
        filters = MessageSearchFilters(**payload.model_dump(exclude_none=True))
        start = time.perf_counter()
        summaries = await _run(service.search_messages, filters)
        duration = time.perf_counter() - start
        base_offset = payload.offset or 0
        page_size = payload.limit or len(summaries)
        next_offset = None
        if page_size and len(summaries) == page_size:
            next_offset = base_offset + len(summaries)
        return {
            "messages": [_to_dict(summary) for summary in summaries],
            "diagnostics": {
                "duration_seconds": duration,
                "count": len(summaries),
                "offset": base_offset,
                "next_offset": next_offset,
            },
        }

    @mcp.tool(name="get_message", description="Fetch full message details including body and attachments.")
    async def get_message(
        folder_token: Annotated[str, Field(description="Folder token from list_folders.", examples=["SU5CT1g="])],
        uid: Annotated[str, Field(description="Protocol-specific UID for the message.", examples=["12345"])],
    ) -> dict[str, Any]:
        payload = GetMessageInput(folder_token=folder_token, uid=uid)
        detail = await _run(service.fetch_message, payload.folder_token, payload.uid)
        return _to_dict(detail)

    @mcp.tool(name="get_raw_message", description="Download the RFC822 source of a message as Base64 encoded content.")
    async def get_raw_message(
        folder_token: Annotated[str, Field(description="Folder token from list_folders.", examples=["SU5CT1g="])],
        uid: Annotated[str, Field(description="Protocol-specific UID for the message.", examples=["12345"])],
    ) -> dict[str, Any]:
        payload = GetMessageInput(folder_token=folder_token, uid=uid)
        raw = await _run(service.fetch_raw_message, payload.folder_token, payload.uid)
        encoded = base64.b64encode(raw).decode("ascii")
        return {
            "account_id": settings.account.id,
            "folder_token": payload.folder_token,
            "uid": payload.uid,
            "mime_type": "message/rfc822",
            "data_base64": encoded,
        }

    @mcp.tool(name="download_attachment", description="Download an attachment from a message. Returns Base64 encoded payload.")
    async def download_attachment(
        folder_token: Annotated[str, Field(description="Folder token from list_folders.", examples=["SU5CT1g="])],
        uid: Annotated[str, Field(description="Protocol-specific UID for the message.", examples=["12345"])],
        attachment_identifier: Annotated[int | str, Field(description="Attachment index (integer) or provider-specific ID (string).", examples=[0, "att-001"])],
    ) -> dict[str, Any]:
        payload = GetAttachmentInput(
            folder_token=folder_token,
            uid=uid,
            attachment_identifier=attachment_identifier,
        )
        try:
            attachment = await _run(
                service.fetch_attachment,
                payload.folder_token,
                payload.uid,
                payload.attachment_identifier,
            )
        except AttachmentNotFoundError as exc:
            return {"error": str(exc)}
        return _serialise_attachment(attachment)

    @mcp.resource(
        "mail://{account_id}/{folder_token}/{uid}",
        description="Plain text representation of the message body.",
        mime_type="text/plain",
    )
    async def message_text(account_id: str, folder_token: str, uid: str) -> str:
        detail = await _run(service.fetch_message, folder_token, uid)
        body = detail.body.text or detail.body.html or "(no body)"
        return body

    @mcp.resource(
        "mail+html://{account_id}/{folder_token}/{uid}",
        description="HTML representation of the message body if available.",
        mime_type="text/html",
    )
    async def message_html(account_id: str, folder_token: str, uid: str) -> str:
        detail = await _run(service.fetch_message, folder_token, uid)
        return detail.body.html or detail.body.text or "<p>(no html body)</p>"

    @mcp.resource(
        "mail+raw://{account_id}/{folder_token}/{uid}",
        description="Raw RFC822 message source.",
        mime_type="message/rfc822",
    )
    async def message_raw(account_id: str, folder_token: str, uid: str) -> bytes:
        raw = await _run(service.fetch_raw_message, folder_token, uid)
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

