"""dpairip - a pure Python PairIP/VMRunner unpacker.

The public API is intentionally small: :func:`merge_bundle`, :func:`patch_logging`
and :func:`patch_translation` are the same operations exposed by the CLI.
"""

from __future__ import annotations

from .apks import Module, merge_bundle
from .patches import patch_logging, patch_translation

__version__ = "1.0.0"
__author__ = "baba01hacker"

__all__ = [
    "Module",
    "merge_bundle",
    "patch_logging",
    "patch_translation",
    "__version__",
    "__author__",
]
