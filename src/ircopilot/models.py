"""Shared data types and the narrow interfaces the RAG pipeline depends on."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal, Protocol

Severity = Literal["high", "medium", "low", "info"]
SEVERITY_ORDER: dict[str, int] = {"high": 0, "medium": 1, "low": 2, "info": 3}

_MAX_FIELD = 20_000


@dataclass(frozen=True)
class DocChunk:
    id: str
    text: str
    url: str
    title: str
    section: str
    source: str
    chunk_index: int
    fetched_at: str = ""
    content_sha256: str = ""

    def to_payload(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_payload(cls, point_id: Any, payload: Any) -> DocChunk | None:
        """Build a chunk from vector-store payload, which is treated as untrusted."""
        if not isinstance(payload, dict):
            return None

        def s(key: str) -> str:
            value = payload.get(key, "")
            return str(value)[:_MAX_FIELD] if isinstance(value, (str, int, float)) else ""

        idx = payload.get("chunk_index", 0)
        url = s("url")
        if not url.startswith("https://"):
            return None
        return cls(
            id=str(point_id)[:64],
            text=s("text"),
            url=url,
            title=s("title"),
            section=s("section"),
            source=s("source"),
            chunk_index=idx if isinstance(idx, int) else 0,
            fetched_at=s("fetched_at"),
            content_sha256=s("content_sha256"),
        )


@dataclass(frozen=True)
class SearchHit:
    chunk: DocChunk
    score: float


@dataclass
class Finding:
    rule: str
    severity: Severity
    message: str
    line: int | None = None
    service: str | None = None
    evidence: str | None = None
    doc_query: str | None = None
    occurrences: int = 1

    def to_dict(self) -> dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v is not None}


@dataclass
class Answer:
    text: str
    sufficient: bool
    citations: list[SearchHit] = field(default_factory=list)
    citation_ids: list[str] = field(default_factory=list)  # "S1"... as they appear in `text`
    withheld: int = 0
    reason: str | None = None
    invalid_citations: list[str] = field(default_factory=list)


class Embedder(Protocol):
    def embed_documents(self, texts: list[str]) -> list[list[float]]: ...

    def embed_query(self, text: str) -> list[float]: ...


class ChatModel(Protocol):
    def chat(self, system: str, user: str) -> str: ...


class VectorStore(Protocol):
    def ensure_collection(self, dim: int, *, recreate: bool = False) -> None: ...

    def upsert(self, chunks: list[DocChunk], vectors: list[list[float]]) -> None: ...

    def search(self, vector: list[float], limit: int) -> list[SearchHit]: ...

    def count(self) -> int: ...
