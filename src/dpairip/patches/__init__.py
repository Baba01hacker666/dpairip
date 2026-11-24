"""The two patch modes."""

from .gadget import embed_gadget
from .logging import apply as patch_logging, find_junk_classes
from .translation import apply as patch_translation

__all__ = ["patch_logging", "patch_translation", "find_junk_classes", "embed_gadget"]
