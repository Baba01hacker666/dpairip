"""Console output helpers.

The tool is meant to be readable in a terminal but also usable from scripts, so
every message goes to stderr and colour is disabled automatically when the
stream is not a TTY or ``NO_COLOR`` is set.
"""

from __future__ import annotations

import os
import sys
from typing import Optional

_RESET = "\x1b[0m"
_CODES = {
    "info": "\x1b[36m",
    "merge": "\x1b[33m",
    "build": "\x1b[32m",
    "warn": "\x1b[33m",
    "error": "\x1b[31m",
    "debug": "\x1b[90m",
}

_colour: Optional[bool] = None
_verbose = False


def configure(verbose: bool = False, colour: Optional[bool] = None) -> None:
    global _verbose, _colour
    _verbose = verbose
    if colour is None:
        colour = sys.stderr.isatty() and not os.environ.get("NO_COLOR")
    _colour = colour


def _emit(kind: str, message: str) -> None:
    label = f"[{kind.upper()}]"
    if _colour:
        label = f"{_CODES[kind]}{label}{_RESET}"
    print(f"{label} {message}", file=sys.stderr)


def info(message: str) -> None:
    _emit("info", message)


def merge(message: str) -> None:
    _emit("merge", message)


def build(message: str) -> None:
    _emit("build", message)


def warn(message: str) -> None:
    _emit("warn", message)


def error(message: str) -> None:
    _emit("error", message)


def debug(message: str) -> None:
    if _verbose:
        _emit("debug", message)
