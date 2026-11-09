"""Split extracted documents into overlapping, metadata-rich chunks."""

from __future__ import annotations

import uuid
from typing import Any

from ircopilot.models import DocChunk


def _split(text: str, max_chars: int, overlap: int) -> list[str]:
    paragraphs = [p.strip() for p in text.split("\n\n") if p.strip()]
    chunks: list[str] = []
    buf = ""
    for para in paragraphs:
        while len(para) > max_chars:  # hard-split oversized paragraphs
            if buf:
                chunks.append(buf)
                buf = ""
            chunks.append(para[:max_chars])
            para = para[max_chars - overlap :]
        if buf and len(buf) + len(para) + 2 > max_chars:
            chunks.append(buf)
            tail = buf[-overlap:] if overlap else ""
            buf = f"{tail}\n\n{para}" if tail else para
        else:
            buf = f"{buf}\n\n{para}" if buf else para
    if buf:
        chunks.append(buf)
    return chunks


def chunk_document(doc: dict[str, Any], *, max_chars: int = 1200, overlap: int = 150, min_chars: int = 80) -> list[DocChunk]:
    """`doc` is one corpus record: {url, title, source, fetched_at, content_sha256, sections:[{heading,text}]}."""
    url, title = str(doc["url"]), str(doc.get("title", ""))
    out: list[DocChunk] = []
    for section in doc.get("sections", []):
        heading = str(section.get("heading", "")) or title
        for piece in _split(str(section.get("text", "")), max_chars, overlap):
            if len(piece) < min_chars:
                continue
            idx = len(out)
            out.append(
                DocChunk(
                    id=str(uuid.uuid5(uuid.NAMESPACE_URL, f"{url}#{idx}")),
                    text=f"{title} — {heading}\n{piece}",
                    url=url,
                    title=title,
                    section=heading,
                    source=str(doc.get("source", "")),
                    chunk_index=idx,
                    fetched_at=str(doc.get("fetched_at", "")),
                    content_sha256=str(doc.get("content_sha256", "")),
                )
            )
    return out
