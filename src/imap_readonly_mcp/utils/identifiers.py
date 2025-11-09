"""Helper utilities for generating opaque identifiers used in resource URIs."""

from __future__ import annotations

import base64


def encode_folder_path(path: str) -> str:
    """Encode a folder path to a URL-safe token without padding."""
    encoded = base64.urlsafe_b64encode(path.encode("utf-8")).decode("ascii")
    return encoded.rstrip("=")


def decode_folder_token(token: str) -> str:
    """Decode a folder token produced by :func:`encode_folder_path`."""
    padding = "=" * (-len(token) % 4)
    return base64.urlsafe_b64decode(f"{token}{padding}".encode("ascii")).decode("utf-8")
