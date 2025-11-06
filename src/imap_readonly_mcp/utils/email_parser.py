"""Utilities for parsing RFC822 messages into structured data models."""

from __future__ import annotations

import email
from email.header import decode_header, make_header
from email.message import Message
from email.policy import default as default_policy
from email.utils import getaddresses, parsedate_to_datetime
from typing import Iterable
import html
import re

from charset_normalizer import from_bytes

from ..models import (
    AttachmentMetadata,
    EmailAddress,
    MessageBody,
    MessageFlags,
    MessageSummary,
)
from .identifiers import encode_folder_path


def decode_mime_words(value: str | None) -> str | None:
    """Decode a MIME encoded string into UTF-8."""
    if value is None:
        return None
    try:
        decoded = str(make_header(decode_header(value)))
        return decoded.strip()
    except Exception:
        return value


def parse_address_list(value: str | Iterable[str] | None) -> list[EmailAddress]:
    """Parse a header value into normalized EmailAddress objects."""
    if value is None:
        return []
    if isinstance(value, str):
        candidates = getaddresses([value])
    else:
        candidates = getaddresses([v for v in value if v])
    addresses: list[EmailAddress] = []
    for display, addr in candidates:
        if not addr:
            continue
        addresses.append(EmailAddress(display_name=decode_mime_words(display) or None, address=addr.lower()))
    return addresses


def parse_message_date(value: str | None):
    """Parse the Date header into a timezone-aware datetime when possible."""
    if not value:
        return None
    try:
        return parsedate_to_datetime(value)
    except Exception:
        return None


def _extract_text_from_part(part: Message) -> tuple[str | None, str | None]:
    payload = part.get_payload(decode=True)
    if payload is None:
        return None, None
    charset = part.get_content_charset(failobj=None) or part.get_param("charset")
    if charset:
        try:
            text = payload.decode(charset, errors="replace")
            return text, charset
        except Exception:
            pass
    detection = from_bytes(payload).best()
    if detection is None:
        return payload.decode("utf-8", errors="replace"), charset
    return str(detection), detection.encoding


def extract_body(message: Message) -> MessageBody:
    """Extract plain text and HTML bodies from a message."""
    if message.is_multipart():
        text_part, html_part = None, None
        charset = None
        for part in message.walk():
            if part.is_multipart():
                continue
            content_type = part.get_content_type()
            disposition = part.get_content_disposition()
            if disposition == "attachment":
                continue
            if content_type == "text/plain" and text_part is None:
                text_part, charset = _extract_text_from_part(part)
            elif content_type == "text/html" and html_part is None:
                html_part, charset = _extract_text_from_part(part)
        body = MessageBody(text=text_part, html=html_part, charset=charset)
    else:
        text, charset = _extract_text_from_part(message)
        body = MessageBody(text=text, html=None, charset=charset)

    if body.text is None and body.html:
        converted = _html_to_text(body.html)
        body.text = converted or None
    return body


def extract_attachments(
    message: Message,
    *,
    folder_path: str,
    uid: str,
) -> list[AttachmentMetadata]:
    """Return attachment metadata entries from the message."""
    attachments: list[AttachmentMetadata] = []
    folder_token = encode_folder_path(folder_path)
    index = 0
    for part in message.walk():
        disposition = part.get_content_disposition()
        if disposition not in {"attachment", "inline"}:
            continue
        filename = decode_mime_words(part.get_filename()) or f"attachment-{index}"
        attachment_id = part.get("Content-ID") or f"{uid}-{index}"
        attachments.append(
            AttachmentMetadata(
                attachment_id=attachment_id,
                filename=filename,
                content_type=part.get_content_type() or "application/octet-stream",
                size=len(part.get_payload(decode=True) or b""),
                resource_uri=f"mail+attachment://{folder_token}/{uid}/{index}",
            )
        )
        index += 1
    return attachments


def get_attachment_payload(message: Message, attachment_index: int) -> tuple[AttachmentMetadata, bytes]:
    """Return metadata and payload bytes for a given attachment index."""
    current_index = -1
    for part in message.walk():
        disposition = part.get_content_disposition()
        if disposition not in {"attachment", "inline"}:
            continue
        current_index += 1
        if current_index != attachment_index:
            continue
        filename = decode_mime_words(part.get_filename()) or f"attachment-{attachment_index}"
        attachment_id = part.get("Content-ID") or f"{attachment_index}"
        payload = part.get_payload(decode=True) or b""
        metadata = AttachmentMetadata(
            attachment_id=attachment_id,
            filename=filename,
            content_type=part.get_content_type() or "application/octet-stream",
            size=len(payload),
            resource_uri=None,
        )
        return metadata, payload
    raise IndexError(f"Attachment index {attachment_index} not found")


def create_summary_from_message(
    *,
    folder_path: str,
    uid: str,
    message: Message,
    snippet: str | None = None,
    flags: MessageFlags | None = None,
) -> MessageSummary:
    """Build a MessageSummary object from a parsed message."""
    folder_token = encode_folder_path(folder_path)
    subject = decode_mime_words(message.get("Subject"))
    summary_snippet = snippet or _build_snippet_from_message(message)
    return MessageSummary(
        folder_path=folder_path,
        folder_token=folder_token,
        uid=uid,
        subject=subject,
        from_=parse_address_list(message.get_all("From")),
        to=parse_address_list(message.get_all("To")),
        cc=parse_address_list(message.get_all("Cc")),
        bcc=parse_address_list(message.get_all("Bcc")),
        reply_to=parse_address_list(message.get_all("Reply-To")),
        date=parse_message_date(message.get("Date")),
        snippet=summary_snippet,
        has_attachments=any(part.get_content_disposition() == "attachment" for part in message.walk()),
        flags=flags or MessageFlags(),
        resource_uri=f"mail://{folder_token}/{uid}",
        raw_resource_uri=f"mail+raw://{folder_token}/{uid}",
    )


def parse_rfc822_message(raw: bytes) -> Message:
    """Parse raw RFC822 bytes into an email.message.Message instance."""
    return email.message_from_bytes(raw, policy=default_policy)


def _build_snippet_from_message(message: Message, max_length: int = 240) -> str | None:
    """Construct a lightweight snippet from the message text body."""
    body = extract_body(message)
    if body.text:
        snippet = body.text.strip().replace("\r", "").replace("\n", " ")
        return snippet[:max_length]
    if body.html:
        text = _html_to_text(body.html)
        if text:
            return text[:max_length]
    return None


def _strip_html(value: str) -> str:
    """Very small HTML stripper to keep dependencies light."""
    inside_tag = False
    result_chars: list[str] = []
    for char in value:
        if char == "<":
            inside_tag = True
            continue
        if char == ">":
            inside_tag = False
            continue
        if not inside_tag:
            result_chars.append(char)
    return "".join(result_chars)


def _html_to_text(value: str) -> str:
    """Convert HTML content into a readable plain text approximation."""
    if not value:
        return ""
    cleaned = re.sub(r"(?is)<(script|style).*?>.*?</\1>", " ", value)
    cleaned = re.sub(r"(?i)<br\s*/?>", "\n", cleaned)
    cleaned = re.sub(r"(?i)</p\s*>", "\n", cleaned)
    cleaned = html.unescape(cleaned)

    # Drop boundary markers and MIME headers that may still be present.
    lines: list[str] = []
    for raw_line in cleaned.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        lower = line.lower()
        if line.startswith("--") and "=" in line:
            continue
        if lower.startswith("content-type:") or lower.startswith("content-transfer-encoding:") or lower.startswith(
            "content-disposition:"
        ) or lower.startswith("mime-version:"):
            continue
        lines.append(line)

    cleaned = "\n".join(lines)
    # Remove residual CSS blocks (e.g. ".class { ... }", "@media ... { ... }").
    cleaned = re.sub(r"@media[^{]*\{[^}]*\}", " ", cleaned, flags=re.IGNORECASE | re.DOTALL)
    cleaned = re.sub(r"\.[\w\-]+\s*\{[^}]*\}", " ", cleaned, flags=re.DOTALL)
    cleaned = _strip_html(cleaned)
    cleaned = re.sub(r"\s+", " ", cleaned)
    return cleaned.strip()
