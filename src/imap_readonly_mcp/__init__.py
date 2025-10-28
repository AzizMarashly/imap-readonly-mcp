"""imap-readonly-mcp package."""

from importlib.metadata import PackageNotFoundError, version as _version

__all__ = ["__version__"]
try:
    __version__ = _version("imap-readonly-mcp")
except PackageNotFoundError:
    __version__ = "0.0.0"
