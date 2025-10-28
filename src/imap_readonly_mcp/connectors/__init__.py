"""Connector implementations for supported mail protocols."""

from .base import ConnectorCapabilities, ReadOnlyMailConnector
from .graph import GraphReadOnlyConnector
from .imap import IMAPReadOnlyConnector
from .pop3 import POP3ReadOnlyConnector

__all__ = [
    "ReadOnlyMailConnector",
    "ConnectorCapabilities",
    "IMAPReadOnlyConnector",
    "POP3ReadOnlyConnector",
    "GraphReadOnlyConnector",
]
