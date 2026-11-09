"""Extract readable sections from documentation HTML using only the standard library."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from html.parser import HTMLParser

from ircopilot.safety.text import clean_text

_SKIP = {"script", "style", "noscript", "svg", "nav", "header", "footer", "aside", "form", "button", "iframe", "template", "select"}
_HEADINGS = {"h1", "h2", "h3", "h4"}
_NOISE_LINES = {"table of contents", "on this page", "copy", "edit this page", "request changes"}
_BLOCK = {"p", "li", "pre", "tr", "div", "br", "dt", "dd", "table", "blockquote", "section", "ul", "ol", *_HEADINGS}


@dataclass
class Section:
    heading: str
    text: str


@dataclass
class ExtractedPage:
    title: str
    sections: list[Section] = field(default_factory=list)


class _Extractor(HTMLParser):
    def __init__(self, main_only: bool) -> None:
        super().__init__(convert_charrefs=True)
        self.main_only = main_only
        self.main_depth = 0
        self.skip_depth = 0
        self.pre_depth = 0
        self.in_title = False
        self.heading: list[str] | None = None
        self.title = ""
        self.sections: list[tuple[str, list[str]]] = [("", [])]

    def _capturing(self) -> bool:
        return self.skip_depth == 0 and (not self.main_only or self.main_depth > 0)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in ("main", "article"):
            self.main_depth += 1
        if tag == "title":
            self.in_title = True
        if tag in _SKIP:
            self.skip_depth += 1
            return
        if tag == "pre":
            self.pre_depth += 1
        if not self._capturing():
            return
        if tag in _HEADINGS:
            self.heading = []
        elif tag in _BLOCK:
            self.sections[-1][1].append("\n")
        elif tag in ("td", "th"):
            self.sections[-1][1].append(" | ")

    def handle_endtag(self, tag: str) -> None:
        if tag in ("main", "article") and self.main_depth:
            self.main_depth -= 1
        if tag == "title":
            self.in_title = False
        if tag in _SKIP:
            self.skip_depth = max(self.skip_depth - 1, 0)
            return
        if tag == "pre" and self.pre_depth:
            self.pre_depth -= 1
        if tag in _HEADINGS and self.heading is not None:
            heading = re.sub(r"\s+", " ", "".join(self.heading)).strip()
            self.heading = None
            if heading:
                self.sections.append((heading, []))
        elif tag in _BLOCK and self._capturing():
            self.sections[-1][1].append("\n")

    def handle_data(self, data: str) -> None:
        if self.in_title:
            self.title += data
            return
        if not self._capturing():
            return
        if self.heading is not None:
            self.heading.append(data)
        else:
            self.sections[-1][1].append(data if self.pre_depth else re.sub(r"\s+", " ", data))


def _tidy(text: str) -> str:
    # Drop the single leading space left by whitespace collapsing, but keep code indentation.
    lines = [ln.rstrip()[1:] if ln.startswith(" ") and not ln.startswith("  ") else ln.rstrip() for ln in text.split("\n")]
    lines = [ln for ln in lines if ln.lower() not in _NOISE_LINES]
    out = "\n".join(lines)
    return re.sub(r"\n{3,}", "\n\n", out).strip()


def _run(html: str, main_only: bool) -> ExtractedPage:
    parser = _Extractor(main_only)
    parser.feed(html)
    parser.close()
    title = re.sub(r"\s+", " ", parser.title).strip()
    title = re.split(r"\s+[|\-–]\s+", title)[0] if title else ""
    sections = [Section(h, _tidy("".join(parts))) for h, parts in parser.sections]
    # Text before the first heading is usually breadcrumbs; drop it when short.
    if len(sections) > 1 and not sections[0].heading and len(sections[0].text) < 300:
        sections = sections[1:]
    return ExtractedPage(title=clean_text(title), sections=[Section(clean_text(s.heading), clean_text(s.text)) for s in sections if s.text])


def extract_page(html: str) -> ExtractedPage:
    """Prefer <main>/<article> content; fall back to the whole body when that yields little text."""
    has_main = re.search(r"<(main|article)[\s>]", html, re.IGNORECASE) is not None
    page = _run(html, main_only=has_main)
    if has_main and sum(len(s.text) for s in page.sections) < 300:
        page = _run(html, main_only=False)
    return page
