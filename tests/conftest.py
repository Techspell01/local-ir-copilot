from __future__ import annotations

from dataclasses import dataclass, field

import pytest

from ircopilot.config import Settings
from ircopilot.models import DocChunk, SearchHit


def make_chunk(i: int, text: str, url: str | None = None) -> DocChunk:
    return DocChunk(
        id=f"00000000-0000-0000-0000-{i:012d}",
        text=text,
        url=url or f"https://docs.docker.com/page{i}/",
        title=f"Page {i}",
        section=f"Section {i}",
        source="docker",
        chunk_index=0,
    )


class FakeEmbedder:
    def __init__(self) -> None:
        self.queries: list[str] = []

    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        return [[1.0, 0.0, 0.0] for _ in texts]

    def embed_query(self, text: str) -> list[float]:
        self.queries.append(text)
        return [1.0, 0.0, 0.0]


@dataclass
class FakeStore:
    hits: list[SearchHit] = field(default_factory=list)
    upserted: int = 0

    def ensure_collection(self, dim: int, *, recreate: bool = False) -> None: ...

    def upsert(self, chunks: list[DocChunk], vectors: list[list[float]]) -> None:
        self.upserted += len(chunks)

    def search(self, vector: list[float], limit: int) -> list[SearchHit]:
        return self.hits[:limit]

    def count(self) -> int:
        return self.upserted


@dataclass
class FakeChat:
    reply: str | list[str] = ""
    calls: list[tuple[str, str]] = field(default_factory=list)

    def chat(self, system: str, user: str) -> str:
        self.calls.append((system, user))
        if isinstance(self.reply, list):
            return self.reply[min(len(self.calls), len(self.reply)) - 1]
        return self.reply


@pytest.fixture
def settings() -> Settings:
    return Settings(max_log_bytes=64 * 1024, max_compose_bytes=64 * 1024)
