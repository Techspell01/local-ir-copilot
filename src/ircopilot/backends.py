"""HTTP clients for the two local services: Ollama (chat + embeddings) and Qdrant (vector search).

Both use plain REST via httpx with proxies disabled (`trust_env=False`) and no redirects, so a
proxy environment variable cannot silently route prompts or documents off the machine.
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

from ircopilot.config import Settings
from ircopilot.models import DocChunk, SearchHit

log = logging.getLogger(__name__)


class BackendError(RuntimeError):
    """A local service is unavailable or returned an unexpected response."""


def _client(base_url: str, timeout: float, headers: dict[str, str] | None = None) -> httpx.Client:
    return httpx.Client(base_url=base_url, timeout=timeout, trust_env=False, follow_redirects=False, headers=headers)


def _json(resp: httpx.Response, what: str) -> Any:
    if resp.status_code >= 400:
        # Do not echo the response body: it may reflect prompt content.
        raise BackendError(f"{what} failed with HTTP {resp.status_code}.")
    try:
        return resp.json()
    except ValueError as exc:
        raise BackendError(f"{what} returned invalid JSON.") from exc


class OllamaClient:
    def __init__(self, settings: Settings) -> None:
        self._s = settings
        self._http = _client(settings.ollama_url, settings.timeout_s)

    def _post(self, path: str, body: dict[str, Any], what: str) -> Any:
        try:
            return _json(self._http.post(path, json=body), what)
        except httpx.HTTPError as exc:
            raise BackendError(f"{what} failed: Ollama is not reachable at {self._s.ollama_url}.") from exc

    def _embed(self, texts: list[str]) -> list[list[float]]:
        data = self._post("/api/embed", {"model": self._s.embed_model, "input": texts, "truncate": True}, "Embedding")
        vectors = data.get("embeddings") if isinstance(data, dict) else None
        if not isinstance(vectors, list) or len(vectors) != len(texts):
            raise BackendError("Embedding response had an unexpected shape.")
        return vectors

    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        out: list[list[float]] = []
        for i in range(0, len(texts), 32):
            out.extend(self._embed([self._s.embed_doc_prefix + t for t in texts[i : i + 32]]))
        return out

    def embed_query(self, text: str) -> list[float]:
        return self._embed([self._s.embed_query_prefix + text])[0]

    def chat(self, system: str, user: str) -> str:
        body = {
            "model": self._s.chat_model,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "stream": False,
            "options": {"temperature": 0, "seed": 7, "num_ctx": 8192},
        }
        data = self._post("/api/chat", body, "Chat")
        content = data.get("message", {}).get("content") if isinstance(data, dict) else None
        if not isinstance(content, str):
            raise BackendError("Chat response had an unexpected shape.")
        return content

    def list_models(self) -> list[str]:
        try:
            data = _json(self._http.get("/api/tags"), "Model listing")
        except httpx.HTTPError as exc:
            raise BackendError(f"Ollama is not reachable at {self._s.ollama_url}.") from exc
        return [m.get("name", "") for m in data.get("models", []) if isinstance(m, dict)]


class QdrantStore:
    def __init__(self, settings: Settings) -> None:
        self._s = settings
        headers = {"api-key": settings.qdrant_api_key} if settings.qdrant_api_key else None
        self._http = _client(settings.qdrant_url, 60.0, headers)
        self._base = f"/collections/{settings.collection}"

    def _req(self, method: str, path: str, what: str, body: dict[str, Any] | None = None) -> httpx.Response:
        try:
            return self._http.request(method, self._base + path, json=body)
        except httpx.HTTPError as exc:
            raise BackendError(f"{what} failed: Qdrant is not reachable at {self._s.qdrant_url}.") from exc

    def ensure_collection(self, dim: int, *, recreate: bool = False) -> None:
        if recreate:
            self._req("DELETE", "", "Collection delete")
        resp = self._req("GET", "", "Collection lookup")
        if resp.status_code == 404:
            body = {"vectors": {"size": dim, "distance": "Cosine"}}
            _json(self._req("PUT", "", "Collection create", body), "Collection create")
            return
        info = _json(resp, "Collection lookup")
        size = info.get("result", {}).get("config", {}).get("params", {}).get("vectors", {}).get("size")
        if size is not None and size != dim:
            raise BackendError(f"Collection vector size {size} != embedding size {dim}; re-run ingest with --recreate.")

    def upsert(self, chunks: list[DocChunk], vectors: list[list[float]]) -> None:
        for i in range(0, len(chunks), 64):
            points = [
                {"id": c.id, "vector": v, "payload": c.to_payload()}
                for c, v in zip(chunks[i : i + 64], vectors[i : i + 64], strict=True)
            ]
            _json(self._req("PUT", "/points?wait=true", "Upsert", {"points": points}), "Upsert")

    def search(self, vector: list[float], limit: int) -> list[SearchHit]:
        resp = self._req("POST", "/points/query", "Search", {"query": vector, "limit": limit, "with_payload": True})
        if resp.status_code == 404:
            raise BackendError("The documentation index is empty. Run `ircopilot ingest` first.")
        data = _json(resp, "Search")
        hits: list[SearchHit] = []
        for point in data.get("result", {}).get("points", []):
            chunk = DocChunk.from_payload(point.get("id"), point.get("payload"))
            score = point.get("score")
            if chunk is not None and isinstance(score, (int, float)):
                hits.append(SearchHit(chunk=chunk, score=float(score)))
        return hits

    def count(self) -> int:
        resp = self._req("POST", "/points/count", "Count", {"exact": True})
        if resp.status_code == 404:
            return 0
        return int(_json(resp, "Count").get("result", {}).get("count", 0))
