import base64

from imap_readonly_mcp.models import AttachmentContent, AttachmentMetadata
from imap_readonly_mcp.server import _serialise_attachment


def _build_attachment(data: bytes, mime: str, attachment_id: str = "att-1") -> AttachmentContent:
    metadata = AttachmentMetadata(
        attachment_id=attachment_id,
        filename="file.bin",
        content_type=mime,
        size=len(data),
        resource_uri="mail+attachment://token/uid/0",
    )
    return AttachmentContent(
        metadata=metadata,
        data=data,
        mime_type=mime,
        file_name=metadata.filename,
        download_url=None,
    )


def test_serialise_attachment_textual_sets_data_text():
    raw = "hello café".encode()
    content = _build_attachment(raw, "text/plain")

    result = _serialise_attachment(content)

    assert result.data_text == "hello café"
    assert result.data_base64 is None
    assert result.inline_bytes == len(raw)


def test_serialise_attachment_binary_keeps_base64():
    raw = b"\x00\x01\x02pdf"
    content = _build_attachment(raw, "application/pdf")

    result = _serialise_attachment(content)

    assert result.data_base64 == base64.b64encode(raw).decode("ascii")
    assert result.data_text is None
    assert result.inline_bytes == len(raw)


def test_serialise_attachment_octet_stream_text_detected():
    raw = "olá mundo".encode("latin-1")
    content = _build_attachment(raw, "application/octet-stream")

    result = _serialise_attachment(content)

    assert "olá mundo" in (result.data_text or "")
    assert result.data_base64 is None
    assert result.inline_bytes == len(raw)
