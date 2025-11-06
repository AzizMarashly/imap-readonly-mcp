"""Stdio entrypoint for the single-account read-only mail MCP server."""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Annotated, Iterable, Literal

import anyio
from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.utilities.logging import get_logger
from pydantic import Field

from .config import MailSettings, load_settings
from .exceptions import AttachmentNotFoundError, MessageNotFoundError
from .models import AttachmentContent, MessageSearchFilters
from .service import MailService
from .tooling import (
    MailAttachment,
    MailContact,
    MailDownloadAttachmentInput,
    MailDownloadAttachmentResult,
    MailFetchError,
    MailFetchInput,
    MailFetchResult,
    MailMessageItem,
)
from .utils.email_parser import _html_to_text
from .utils.identifiers import decode_folder_token

logger = get_logger(__name__)

def create_server(settings: MailSettings) -> FastMCP:
    """Create a configured FastMCP application instance."""

    service = MailService(settings)
    host = os.environ.get("FASTMCP_HOST", "127.0.0.1")
    port = _coerce_int(os.environ.get("FASTMCP_PORT"), default=8000)
    sse_path = os.environ.get("FASTMCP_SSE_PATH", "/sse")
    message_path = os.environ.get("FASTMCP_MESSAGE_PATH", "/messages/")
    streamable_path = os.environ.get("FASTMCP_STREAMABLE_HTTP__PATH", "/mcp")
    mount_path = os.environ.get("FASTMCP_MOUNT_PATH", "/")

    requested_log_level = os.environ.get("FASTMCP_LOG_LEVEL", "INFO").upper()
    allowed_log_levels = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
    if requested_log_level == "TRACE":
        print("[imap-readonly-mcp] TRACE is not supported; using DEBUG instead for verbose logging.", flush=True)
        log_level = "DEBUG"
    elif requested_log_level not in allowed_log_levels:
        print(
            f"[imap-readonly-mcp] Unsupported FASTMCP_LOG_LEVEL '{requested_log_level}'. "
            "Falling back to INFO. Valid values: DEBUG, INFO, WARNING, ERROR, CRITICAL.",
            flush=True,
        )
        log_level = "INFO"
    else:
        log_level = requested_log_level
    debug = os.environ.get("FASTMCP_DEBUG", "false").lower() in ("1", "true", "yes", "on")

    mcp = FastMCP(
        "imap-readonly-mail",
        host=host,
        port=port,
        sse_path=sse_path,
        message_path=message_path,
        streamable_http_path=streamable_path,
        mount_path=mount_path,
        log_level=log_level,  # type: ignore[arg-type]
        debug=debug,
    )

    async def _run(func, *args, **kwargs):
        return await anyio.to_thread.run_sync(func, *args, **kwargs)

    INLINE_ATTACHMENT_MAX_BYTES = 1_000_000
    SYNC_CURSOR_SEEN_CAP = 50
    INCLUDE_OPTIONS = {
        "metadata": {"text": False, "html": False, "headers": False},
        "text": {"text": True, "html": False, "headers": False},
        "html": {"text": False, "html": True, "headers": False},
        "full": {"text": True, "html": True, "headers": True},
    }

    def _format_datetime(value: datetime | None) -> str | None:
        if value is None:
            return None
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")

    def _resolve_folder_input(folder: str | None) -> str | None:
        if not folder:
            return None
        try:
            return decode_folder_token(folder)
        except Exception:
            return folder

    def _encode_cursor(payload: dict[str, Any]) -> str:
        raw = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        return base64.urlsafe_b64encode(raw).decode("ascii")

    def _decode_cursor_value(cursor: str) -> dict[str, Any]:
        try:
            decoded = base64.urlsafe_b64decode(cursor.encode("ascii"))
            payload = json.loads(decoded.decode("utf-8"))
        except (ValueError, json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ValueError("Invalid cursor payload") from exc
        if not isinstance(payload, dict):
            raise ValueError("Invalid cursor payload")
        return payload

    def _cursor_request_snapshot(effective: dict[str, Any]) -> dict[str, Any]:
        snapshot: dict[str, Any] = {}
        for key in ("query", "folder", "since", "until", "limit", "include", "expand_thread", "include_attachments"):
            value = effective.get(key)
            if value is None:
                continue
            if isinstance(value, datetime):
                snapshot[key] = _format_datetime(value)
            else:
                snapshot[key] = value
        return snapshot

    def _merge_cursor(payload: MailFetchInput) -> tuple[dict[str, Any], dict[str, Any] | None]:
        cursor_data: dict[str, Any] | None = None
        effective: dict[str, Any] = {}
        if payload.cursor:
            cursor_data = _decode_cursor_value(payload.cursor)
            effective.update(cursor_data.get("request", {}))
        fields_set = payload.model_fields_set
        for field_name in payload.model_fields:
            if field_name == "cursor":
                continue
            if field_name in fields_set:
                effective[field_name] = getattr(payload, field_name)
        for field_name in payload.model_fields:
            if field_name == "cursor":
                continue
            effective.setdefault(field_name, getattr(payload, field_name))
        if "ids" not in fields_set:
            effective["ids"] = None
        if cursor_data and cursor_data.get("mode") == "sync" and "since" not in fields_set:
            cursor_since = cursor_data.get("since")
            if cursor_since:
                effective["since"] = cursor_since
        return effective, cursor_data

    def _parse_message_id(message_id: str) -> tuple[str, str]:
        if not message_id.startswith("mail://"):
            raise ValueError("Unsupported message_id format; expected mail://{folder_token}/{uid}")
        without_scheme = message_id.split("://", 1)[1]
        folder_token, sep, uid = without_scheme.partition("/")
        if not sep or not folder_token or not uid:
            raise ValueError("message_id is missing folder token or uid components")
        return folder_token, uid

    def _ensure_required_summary_fields(summary: Any) -> tuple[bool, str | None]:
        missing: list[str] = []
        if not summary.folder_path:
            missing.append("folder_path")
        if not summary.folder_token:
            missing.append("folder_token")
        if not summary.uid:
            missing.append("uid")
        if not summary.resource_uri:
            missing.append("resource_uri")
        if not summary.raw_resource_uri:
            missing.append("raw_resource_uri")
        if missing:
            message_id = getattr(summary, "resource_uri", None) or getattr(summary, "uid", "unknown")
            return False, f"Connector returned incomplete metadata for {message_id}: missing {', '.join(missing)}"
        return True, None

    def _address_to_contact(address: Any) -> MailContact:
        return MailContact(name=address.display_name, email=address.address)

    async def _render_attachments(detail: Any, attachments_mode: str) -> list[MailAttachment]:
        if attachments_mode == "none" or not detail:
            return []
        results: list[MailAttachment] = []
        for index, metadata in enumerate(detail.attachments):
            entry = MailAttachment(
                id=(metadata.attachment_id or str(index)),
                filename=metadata.filename,
                size=metadata.size,
                mime=metadata.content_type,
                download_url=metadata.resource_uri,
            )
            if attachments_mode == "inline":
                identifier: int | str
                if metadata.attachment_id is None:
                    identifier = index
                else:
                    identifier = metadata.attachment_id
                if isinstance(identifier, str) and identifier.isdigit():
                    identifier = int(identifier)
                size_hint = metadata.size
                include_payload = size_hint is None or size_hint <= INLINE_ATTACHMENT_MAX_BYTES
                if include_payload:
                    try:
                        content = await _run(
                            service.fetch_attachment,
                            detail.folder_token,
                            detail.uid,
                            identifier,
                        )
                        data = content.data
                        entry.inline_bytes = len(data)
                        if len(data) <= INLINE_ATTACHMENT_MAX_BYTES:
                            entry.data_base64 = base64.b64encode(data).decode("ascii")
                        else:
                            entry.inline_truncated = True
                    except AttachmentNotFoundError as exc:
                        entry.inline_error = str(exc)
                else:
                    entry.inline_truncated = True
            results.append(entry)
        return results

    def _build_message_item(
        summary: Any,
        detail: Any,
        attachments: list[MailAttachment],
        include_mode: str,
        attachments_mode: str,
        expand_thread: bool,
    ) -> tuple[MailMessageItem, datetime | None]:
        source = detail or summary
        message_date = getattr(source, "date", None)
        snippet_source: str | None = None
        if detail and getattr(detail, "body", None):
            snippet_source = detail.body.text or detail.body.html
        if not snippet_source:
            snippet_source = summary.snippet
        snippet_value = None
        if snippet_source:
            normalised = _normalise_snippet(snippet_source)
            if normalised:
                snippet_value = normalised

        include_flags = INCLUDE_OPTIONS.get(include_mode, INCLUDE_OPTIONS["metadata"])

        body_text_value: str | None = None
        body_html_value: str | None = None
        headers_value: dict[str, list[str]] | None = None
        if detail:
            if include_flags["text"]:
                body_text_value = detail.body.text
                if not body_text_value and detail.body.html:
                    body_text_value = _html_to_text(detail.body.html)
            if include_flags["html"]:
                body_html_value = detail.body.html
            if include_flags["headers"]:
                headers_value = detail.headers

        data: dict[str, Any] = {
            "id": summary.resource_uri,
            "thread_id": getattr(summary, "thread_id", None) or summary.uid,
            "folder": summary.folder_path,
            "folder_token": summary.folder_token,
            "uid": summary.uid,
            "resource_uri": summary.resource_uri,
            "raw_resource_uri": summary.raw_resource_uri,
            "date": _format_datetime(message_date),
            "from_": [_address_to_contact(addr) for addr in summary.from_],
            "to": [_address_to_contact(addr) for addr in summary.to],
            "cc": [_address_to_contact(addr) for addr in summary.cc],
            "bcc": [_address_to_contact(addr) for addr in summary.bcc],
            "reply_to": [_address_to_contact(addr) for addr in summary.reply_to],
            "subject": summary.subject,
            "is_read": summary.flags.seen,
            "snippet": snippet_value,
            "has_attachments": summary.has_attachments,
            "flags": summary.flags.model_dump(),
            "attachments": attachments if attachments_mode != "none" else [],
            "thread": [] if expand_thread else None,
            "body_text": body_text_value if include_flags["text"] else None,
            "body_html": body_html_value if include_flags["html"] else None,
            "headers": headers_value if include_flags["headers"] else None,
        }
        item = MailMessageItem(**data)
        return item, message_date

    mailbox_description = ""
    if settings.account.description:
        mailbox_description = f"Mailbox: {settings.account.description}\n"

    @mcp.tool(
        name="mail.fetch",
        description=(
            f"{mailbox_description}"
            "List, search, or read messages from the mailbox with controllable body detail and attachment metadata."
        ),
        structured_output=True,
    )
    async def mail_fetch(
        ids: Annotated[
            list[str] | None,
            Field(
                default=None,
                description="Fetch these specific message ids (from prior responses).",
                json_schema_extra={"type": "array", "nullable": True, "items": {"type": "string"}},
            ),
        ] = None,
        query: Annotated[
            str | None,
            Field(
                default=None,
                description="Free-text or provider-specific search query.",
                json_schema_extra={"type": "string", "nullable": True},
            ),
        ] = None,
        folder: Annotated[
            str | None,
            Field(
                default=None,
                description="Folder name (e.g. INBOX) or encoded token.",
                json_schema_extra={"type": "string", "nullable": True},
            ),
        ] = None,
        since: Annotated[
            str | None,
            Field(
                default=None,
                description="Return messages on/after this timestamp (ISO-8601 or natural language).",
                json_schema_extra={"type": "string", "nullable": True},
            ),
        ] = None,
        until: Annotated[
            str | None,
            Field(
                default=None,
                description="Return messages up to this timestamp (ISO-8601 or natural language).",
                json_schema_extra={"type": "string", "nullable": True},
            ),
        ] = None,
        limit: Annotated[
            int | None,
            Field(
                default=None,
                ge=1,
                le=500,
                description="Maximum messages to return (defaults to a sensible server limit).",
                json_schema_extra={"type": "integer", "nullable": True},
            ),
        ] = None,
        cursor: Annotated[
            str | None,
            Field(
                default=None,
                description="Cursor from `next_cursor` or `sync_cursor` to continue paging or delta sync.",
                json_schema_extra={"type": "string", "nullable": True},
            ),
        ] = None,
        include: Annotated[
            Literal["metadata", "text", "html", "full"],
            Field(
                default="metadata",
                description="Controls body content: `metadata`, `text`, `html`, or `full`.",
            ),
        ] = "metadata",
        expand_thread: Annotated[
            bool, Field(default=False, description="If true, also request best-effort thread expansion.")
        ] = False,
        include_attachments: Annotated[
            Literal["none", "meta", "inline"],
            Field(default="none", description='`none`, `meta`, or `inline` (small base64 payloads).'),
        ] = "none",
    ) -> MailFetchResult:
        payload = MailFetchInput(
            ids=ids,
            query=query,
            folder=folder,
            since=since,
            until=until,
            limit=limit,
            cursor=cursor,
            include=include,
            expand_thread=expand_thread,
            include_attachments=include_attachments,
        )
        try:
            effective, cursor_state = _merge_cursor(payload)
        except ValueError as exc:
            return MailFetchResult(items=[], next_cursor=None, sync_cursor=None, errors=[MailFetchError(error=str(exc))])

        include_mode = (effective.get("include") or "metadata").lower()
        if include_mode not in INCLUDE_OPTIONS:
            include_mode = "metadata"
        attachments_mode = (effective.get("include_attachments") or "none").lower()
        expand_threads = bool(effective.get("expand_thread"))

        errors: list[MailFetchError] = []

        explicit_ids = effective.get("ids") or []
        if explicit_ids:
            items: list[MailMessageItem] = []
            requests: list[tuple[str, str, str]] = []
            for message_id in explicit_ids:
                try:
                    folder_token, uid = _parse_message_id(message_id)
                except ValueError as exc:
                    errors.append(MailFetchError(id=message_id, error=str(exc)))
                    continue
                requests.append((message_id, folder_token, uid))

            detail_map = await _run(service.fetch_details_bulk, requests)

            for message_id, folder_token, uid in requests:
                detail = detail_map.get(message_id)
                if detail is None:
                    try:
                        detail = await _run(service.fetch_message, folder_token, uid)
                        detail_map[message_id] = detail
                    except MessageNotFoundError as exc:
                        errors.append(MailFetchError(id=message_id, error=str(exc)))
                        continue

                ok, warning = _ensure_required_summary_fields(detail)
                if not ok:
                    errors.append(MailFetchError(id=message_id, error=warning or "Incomplete connector metadata"))
                    continue

                attachments_payload: list[MailAttachment] = []
                if attachments_mode != "none":
                    attachments_payload = await _render_attachments(detail, attachments_mode)

                item, _ = _build_message_item(
                    detail,
                    detail,
                    attachments_payload,
                    include_mode,
                    attachments_mode,
                    expand_threads,
                )
                items.append(item)
            result = MailFetchResult(
                items=items,
                next_cursor=None,
                sync_cursor=None,
                errors=errors or None,
            )
            return result

        folder_input = effective.get("folder")
        resolved_folder = _resolve_folder_input(folder_input)
        limit_value = effective.get("limit")
        if limit_value is None:
            limit_value = settings.default_search_limit
        else:
            limit_value = max(1, min(int(limit_value), settings.maximum_search_limit))
        offset = 0
        if cursor_state and cursor_state.get("mode") == "page":
            offset = int(cursor_state.get("offset", 0))
        seen_ids = set()
        if cursor_state and cursor_state.get("mode") == "sync":
            seen_ids = set(cursor_state.get("seen_ids", []))

        filters = MessageSearchFilters(
            folder=resolved_folder,
            text=effective.get("query"),
            sender=None,
            recipient=None,
            since=effective.get("since"),
            until=effective.get("until"),
            unread_only=False,
            has_attachments=None,
            limit=limit_value,
            time_frame=None,
            offset=offset,
        )

        summaries = await _run(service.search_messages, filters)
        raw_count = len(summaries)
        items: list[MailMessageItem] = []
        latest_dt: datetime | None = None
        returned_ids: list[str] = []
        detail_requests = [
            (summary.resource_uri, summary.folder_token, summary.uid)
            for summary in summaries
        ]
        detail_map = await _run(service.fetch_details_bulk, detail_requests)
        for summary in summaries:
            if summary.resource_uri in seen_ids:
                continue
            ok, warning = _ensure_required_summary_fields(summary)
            if not ok:
                errors.append(MailFetchError(id=summary.resource_uri, error=warning or "Incomplete connector metadata"))
                continue
            detail = detail_map.get(summary.resource_uri)
            if detail is None:
                try:
                    detail = await _run(service.fetch_message, summary.folder_token, summary.uid)
                    detail_map[summary.resource_uri] = detail
                except MessageNotFoundError as exc:
                    errors.append(MailFetchError(id=summary.resource_uri, error=str(exc)))
                    continue

            attachments_payload: list[MailAttachment] = []
            if attachments_mode != "none":
                attachments_payload = await _render_attachments(detail, attachments_mode)
            item, message_dt = _build_message_item(
                summary,
                detail,
                attachments_payload,
                include_mode,
                attachments_mode,
                expand_threads,
            )
            items.append(item)
            returned_ids.append(item.id)
            if message_dt:
                if latest_dt is None or message_dt > latest_dt:
                    latest_dt = message_dt

        request_snapshot = _cursor_request_snapshot(effective)
        next_cursor = None
        if limit_value and raw_count >= limit_value:
            next_cursor = _encode_cursor(
                {
                    "mode": "page",
                    "offset": offset + raw_count,
                    "request": request_snapshot,
                }
            )

        latest_iso = _format_datetime(latest_dt)
        if latest_iso is None:
            if cursor_state and cursor_state.get("mode") == "sync" and cursor_state.get("since"):
                latest_iso = cursor_state["since"]
            else:
                latest_iso = _format_datetime(datetime.now(timezone.utc))

        seen_for_sync = returned_ids[:SYNC_CURSOR_SEEN_CAP]
        sync_request = dict(request_snapshot)
        sync_request["since"] = latest_iso
        sync_cursor = _encode_cursor(
            {
                "mode": "sync",
                "since": latest_iso,
                "seen_ids": seen_for_sync,
                "request": sync_request,
            }
        )

        try:
            result = MailFetchResult(
                items=items,
                next_cursor=next_cursor,
                sync_cursor=sync_cursor,
                errors=errors or None,
            )
        except Exception as exc:
            logger.exception(
                "mail.fetch response failed validation: %s\nitems=%r\nerrors=%r\nnext_cursor=%r\nsync_cursor=%r",
                exc,
                items,
                errors,
                next_cursor,
                sync_cursor,
            )
            raise
        logger.debug("mail.fetch returning payload: %s", json.dumps(result.model_dump(by_alias=True, exclude_none=False)))
        return result

    @mcp.tool(
        name="mail.download_attachment",
        description=(
            f"{mailbox_description}"
            "Download a single attachment for a message, returning metadata plus Base64 content."
        ),
        structured_output=True,
    )
    async def mail_download_attachment(
        message_id: Annotated[str, Field(description="Message identifier from mail.fetch (`id` field).")],
        attachment_id: Annotated[str | int, Field(description="Attachment identifier (string id or positional index).")],
    ) -> MailDownloadAttachmentResult:
        payload = MailDownloadAttachmentInput(message_id=message_id, attachment_id=attachment_id)
        try:
            folder_token, uid = _parse_message_id(payload.message_id)
        except ValueError as exc:
            raise ValueError(str(exc)) from exc
        identifier: int | str = payload.attachment_id
        if isinstance(identifier, str) and identifier.isdigit():
            identifier = int(identifier)
        attachment = await _run(
            service.fetch_attachment,
            folder_token,
            uid,
            identifier,
        )

        attachment_payload = _serialise_attachment(attachment)
        try:
            result = MailDownloadAttachmentResult(
                message_id=payload.message_id,
                attachment=attachment_payload,
            )
        except Exception as exc:
            logger.exception(
                "mail.download_attachment response failed validation: %s\nmessage_id=%s\nattachment=%r",
                exc,
                payload.message_id,
                attachment_payload,
            )
            raise
        logger.debug(
            "mail.download_attachment returning payload: %s",
            json.dumps(result.model_dump(by_alias=True, exclude_none=False)),
        )
        return result

    @mcp.resource(
        "mail://{folder_token}/{uid}",
        description="Plain text representation of the message body.",
        mime_type="text/plain",
    )
    async def message_text(folder_token: str, uid: str) -> str:
        detail = await _run(service.fetch_message, folder_token, uid)
        body = detail.body.text or detail.body.html or "(no body)"
        return body

    @mcp.resource(
        "mail+html://{folder_token}/{uid}",
        description="HTML representation of the message body if available.",
        mime_type="text/html",
    )
    async def message_html(folder_token: str, uid: str) -> str:
        detail = await _run(service.fetch_message, folder_token, uid)
        return detail.body.html or detail.body.text or "<p>(no html body)</p>"

    @mcp.resource(
        "mail+raw://{folder_token}/{uid}",
        description="Raw RFC822 message source.",
        mime_type="message/rfc822",
    )
    async def message_raw(folder_token: str, uid: str) -> bytes:
        raw = await _run(service.fetch_raw_message, folder_token, uid)
        return raw

    @mcp.resource(
        "mail+attachment://{folder_token}/{uid}/{attachment_identifier}",
        description="Binary attachment payload.",
        mime_type="application/octet-stream",
    )
    async def attachment_resource(
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

    @mcp.resource(
        "mail+folders://default",
        description="JSON list of folders available in the mailbox.",
        mime_type="application/json",
    )
    async def folders_resource() -> str:
        folders = await _run(service.list_folders)
        payload = [_to_dict(folder) for folder in folders]
        return json.dumps(payload, ensure_ascii=False, indent=2)

    return mcp


def _to_dict(model: Any) -> Any:
    if hasattr(model, "model_dump"):
        return model.model_dump()
    if isinstance(model, (list, tuple)):
        return [_to_dict(item) for item in model]
    if isinstance(model, dict):
        return {key: _to_dict(value) for key, value in model.items()}
    return model


def _serialise_attachment(attachment: AttachmentContent) -> MailAttachment:
    encoded = base64.b64encode(attachment.data).decode("ascii")
    return MailAttachment(
        id=attachment.metadata.attachment_id,
        filename=attachment.file_name or attachment.metadata.filename,
        size=attachment.metadata.size,
        mime=attachment.mime_type,
        download_url=attachment.download_url or attachment.metadata.resource_uri,
        data_base64=encoded,
        inline_bytes=len(attachment.data),
    )


TRANSPORT_CHOICES = ("stdio", "sse", "streamable-http")


def _normalise_snippet(text: str, max_length: int = 240) -> str:
    cleaned = _html_to_text(text)
    cleaned = cleaned.strip()
    if not cleaned:
        return ""
    cleaned = re.sub(r"\s+", " ", cleaned)
    return cleaned[:max_length]


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

