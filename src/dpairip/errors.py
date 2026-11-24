"""Error types used across :mod:`dpairip`."""

from __future__ import annotations


class DpairipError(Exception):
    """Base class for every expected failure."""


class DexError(DpairipError):
    """A dex file could not be parsed or rebuilt."""


class AxmlError(DpairipError, ValueError):
    """A binary XML document is malformed."""


class ZipError(DpairipError, ValueError):
    """An APK/ZIP archive is malformed."""


class PatchError(DpairipError):
    """A patch could not be applied to the input."""


class ToolError(DpairipError):
    """A required external capability is missing."""
