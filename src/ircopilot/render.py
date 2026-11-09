"""Readable terminal output: wrapped, spaced and lightly styled.

Model text is sanitised (clean_text) before this runs, so the only escape codes printed are our own.
"""

from __future__ import annotations

import os
import re
import shutil
import sys
import textwrap
from typing import TextIO

_CITE = re.compile(r"(\s*)(\[S\d+(?:\s*,\s*S\d+)*\])")
_HEADING = re.compile(r"^(?:#{1,4}\s*)?\**\s*(cause|likely cause|diagnosis|steps|fix|commands?|summary)\s*:?\s*\**\s*:?\s*(.*)$", re.I)
_ITEM = re.compile(r"^(\d+[.)]|[-*•])\s+(.*)$")
_BOLD = re.compile(r"\*\*(.+?)\*\*")


def use_color(stream: TextIO = sys.stdout) -> bool:
    return stream.isatty() and "NO_COLOR" not in os.environ and os.environ.get("TERM") != "dumb"


class Style:
    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    def _wrap(self, code: str, s: str) -> str:
        return f"\x1b[{code}m{s}\x1b[0m" if self.enabled and s else s

    def bold(self, s: str) -> str:
        return self._wrap("1", s)

    def dim(self, s: str) -> str:
        return self._wrap("2", s)

    def cyan(self, s: str) -> str:
        return self._wrap("36", s)

    def yellow(self, s: str) -> str:
        return self._wrap("33", s)


def width() -> int:
    return max(60, min(shutil.get_terminal_size((100, 24)).columns - 2, 100))


def _dim_citations(line: str, st: Style) -> str:
    return _CITE.sub(lambda m: m.group(1) + st.dim(m.group(2)), line)


def _wrap(text: str, first: str, rest: str, w: int, st: Style) -> list[str]:
    lines = textwrap.wrap(text, width=w, initial_indent=first, subsequent_indent=rest, break_on_hyphens=False) or [first]
    return [_dim_citations(ln, st) for ln in lines]


def render_answer(text: str, st: Style, w: int | None = None) -> str:
    """Turn the model's markdown-ish answer into spaced, wrapped terminal text."""
    w = w or width()
    out: list[str] = []
    in_code = False

    def blank() -> None:
        if out and out[-1] != "":
            out.append("")

    for raw in text.split("\n"):
        stripped = raw.strip()
        if stripped.startswith("```"):
            in_code = not in_code
            if in_code:
                blank()
            continue
        if in_code:
            if stripped:
                out.append("    " + st.cyan(raw.rstrip()))
            continue
        if not stripped:
            blank()
            continue
        line = _BOLD.sub(r"\1", stripped)
        if m := _HEADING.match(line):
            blank()
            out.append(st.bold(m.group(1).capitalize()))
            if m.group(2):
                out.extend(_wrap(m.group(2), "  ", "  ", w, st))
            continue
        if m := _ITEM.match(line):
            marker = m.group(1) if m.group(1)[0].isdigit() else "-"
            blank()
            pad = " " * (len(marker) + 3)
            out.extend(_wrap(m.group(2), f"  {marker} ", pad, w, st))
            continue
        out.extend(_wrap(line, "  ", "  ", w, st))
    while out and out[-1] == "":
        out.pop()
    return "\n".join(out)
