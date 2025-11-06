from email.message import EmailMessage

from imap_readonly_mcp.models import MessageFlags
from imap_readonly_mcp.utils.email_parser import create_summary_from_message, extract_body, parse_rfc822_message


def build_message(subject: str = "Hello") -> bytes:
    msg = EmailMessage()
    msg["From"] = "Alice <alice@example.com>"
    msg["To"] = "Bob <bob@example.com>"
    msg["Subject"] = subject
    msg.set_content("This is a test message body.")
    return msg.as_bytes()


def test_create_summary_from_message():
    raw = build_message()
    message = parse_rfc822_message(raw)
    summary = create_summary_from_message(
        folder_path="INBOX",
        uid="123",
        message=message,
        flags=MessageFlags(seen=False),
    )
    assert summary.subject == "Hello"
    assert summary.from_[0].address == "alice@example.com"
    assert summary.flags.seen is False


def test_extract_body():
    raw = build_message()
    message = parse_rfc822_message(raw)
    body = extract_body(message)
    assert "test message" in (body.text or "").lower()
