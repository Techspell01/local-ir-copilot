"""Strip terminal escape sequences and invisible control characters from untrusted text."""

from __future__ import annotations

import re

# CSI, OSC (terminated by BEL or ST) and other two-byte escape sequences.
_ANSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)?|\x1b[@-Z\\-_]")
# C0/C1 controls except tab/newline, plus zero-width and bidi override characters.
_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f​-‏‪-‮⁠-⁤⁦-⁩﻿]")


def clean_text(text: str) -> str:
    """Remove escape sequences and control characters; normalise line endings."""
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = _ANSI_RE.sub("", text)
    return _CTRL_RE.sub("", text)


def truncate(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: max(limit - 1, 0)] + "…"
