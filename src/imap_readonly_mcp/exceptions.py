"""Custom exceptions for the read-only MCP mail server."""


class MailServiceError(Exception):
    """Base exception for mail service failures."""


class ConfigurationError(MailServiceError):
    """Raised when configuration is invalid or incomplete."""


class ConnectorNotAvailableError(MailServiceError):
    """Raised when a connector cannot be created for a configured account."""


class MessageNotFoundError(MailServiceError):
    """Raised when a message cannot be located."""


class AttachmentNotFoundError(MailServiceError):
    """Raised when an attachment cannot be located for a message."""
