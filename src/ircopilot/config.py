"""Runtime settings. Every service URL must point at the local machine unless explicitly overridden."""

from __future__ import annotations

import ipaddress
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit


class ConfigError(ValueError):
    """Raised for invalid or unsafe configuration."""


_LOOPBACK_NAMES = {"localhost"}
_COLLECTION_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


def ensure_local_url(url: str, *, allow_nonlocal: bool = False) -> str:
    """Return `url` normalised (no trailing slash) if it targets a loopback host."""
    parts = urlsplit(url)
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        raise ConfigError(f"Unsupported service URL scheme or host: {url!r}")
    if parts.username or parts.password:
        raise ConfigError("Service URLs must not embed credentials.")
    host = parts.hostname
    is_loopback = host in _LOOPBACK_NAMES
    if not is_loopback:
        try:
            is_loopback = ipaddress.ip_address(host).is_loopback
        except ValueError:
            is_loopback = False
    if not is_loopback and not allow_nonlocal:
        raise ConfigError(
            f"Refusing non-loopback service host {host!r}. "
            "Set IRCOPILOT_ALLOW_NONLOCAL=1 only if you understand the exposure."
        )
    return url.rstrip("/")


@dataclass(frozen=True)
class Settings:
    ollama_url: str = "http://127.0.0.1:11434"
    qdrant_url: str = "http://127.0.0.1:6333"
    qdrant_api_key: str | None = None
    chat_model: str = "llama3.2:3b"
    embed_model: str = "nomic-embed-text"
    embed_query_prefix: str = "search_query: "
    embed_doc_prefix: str = "search_document: "
    collection: str = "ircopilot_docs"
    corpus_path: Path = Path("data/corpus/docs.jsonl")
    top_k: int = 5
    min_score: float = 0.68  # tuned on eval set: answerable top-1 >= 0.75, off-topic <= 0.65 (nomic-embed-text)
    max_log_bytes: int = 5 * 1024 * 1024
    max_compose_bytes: int = 1024 * 1024
    timeout_s: float = 180.0
    allow_nonlocal: bool = False


def _int(env: Mapping[str, str], key: str, default: int, lo: int, hi: int) -> int:
    raw = env.get(key)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ConfigError(f"{key} must be an integer") from exc
    if not lo <= value <= hi:
        raise ConfigError(f"{key} must be between {lo} and {hi}")
    return value


def _float(env: Mapping[str, str], key: str, default: float, lo: float, hi: float) -> float:
    raw = env.get(key)
    if raw is None:
        return default
    try:
        value = float(raw)
    except ValueError as exc:
        raise ConfigError(f"{key} must be a number") from exc
    if not lo <= value <= hi:
        raise ConfigError(f"{key} must be between {lo} and {hi}")
    return value


def load_settings(env: Mapping[str, str] | None = None) -> Settings:
    env = os.environ if env is None else env
    d = Settings()
    allow_nonlocal = env.get("IRCOPILOT_ALLOW_NONLOCAL", "") == "1"
    collection = env.get("IRCOPILOT_COLLECTION", d.collection)
    if not _COLLECTION_RE.match(collection):
        raise ConfigError("IRCOPILOT_COLLECTION may only contain letters, digits, '_' and '-'.")
    return Settings(
        ollama_url=ensure_local_url(env.get("IRCOPILOT_OLLAMA_URL", d.ollama_url), allow_nonlocal=allow_nonlocal),
        qdrant_url=ensure_local_url(env.get("IRCOPILOT_QDRANT_URL", d.qdrant_url), allow_nonlocal=allow_nonlocal),
        qdrant_api_key=env.get("IRCOPILOT_QDRANT_API_KEY") or None,
        chat_model=env.get("IRCOPILOT_CHAT_MODEL", d.chat_model),
        embed_model=env.get("IRCOPILOT_EMBED_MODEL", d.embed_model),
        embed_query_prefix=env.get("IRCOPILOT_EMBED_QUERY_PREFIX", d.embed_query_prefix),
        embed_doc_prefix=env.get("IRCOPILOT_EMBED_DOC_PREFIX", d.embed_doc_prefix),
        collection=collection,
        corpus_path=Path(env.get("IRCOPILOT_CORPUS", str(d.corpus_path))),
        top_k=_int(env, "IRCOPILOT_TOP_K", d.top_k, 1, 20),
        min_score=_float(env, "IRCOPILOT_MIN_SCORE", d.min_score, 0.0, 1.0),
        max_log_bytes=_int(env, "IRCOPILOT_MAX_LOG_BYTES", d.max_log_bytes, 1024, 50 * 1024 * 1024),
        max_compose_bytes=_int(env, "IRCOPILOT_MAX_COMPOSE_BYTES", d.max_compose_bytes, 1024, 10 * 1024 * 1024),
        timeout_s=_float(env, "IRCOPILOT_TIMEOUT", d.timeout_s, 1.0, 1800.0),
        allow_nonlocal=allow_nonlocal,
    )
