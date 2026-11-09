"""One-time, explicit download of the curated public docs. This is the only networked step."""

from __future__ import annotations

import hashlib
import json
import logging
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

import httpx

from ircopilot.docs.extract import extract_page
from ircopilot.docs.sources import ALLOWED_HOSTS, CURATED_SOURCES, LICENSES, DocSource

log = logging.getLogger(__name__)
MAX_PAGE_BYTES = 4 * 1024 * 1024


class FetchBlocked(RuntimeError):
    pass


def check_url(url: str) -> None:
    parts = urlsplit(url)
    if parts.scheme != "https" or parts.hostname not in ALLOWED_HOSTS or parts.port not in (None, 443):
        raise FetchBlocked(f"URL not on the documentation allowlist: {url}")


def _guard(request: httpx.Request) -> None:  # runs for every request, including redirects
    check_url(str(request.url))


@dataclass
class FetchReport:
    saved: int = 0
    failed: list[str] = field(default_factory=list)


def fetch_docs(out_path: Path, sources: Iterable[DocSource] = CURATED_SOURCES, client: httpx.Client | None = None) -> FetchReport:
    own = client is None
    client = client or httpx.Client(
        timeout=30.0,
        follow_redirects=True,
        max_redirects=5,
        headers={"User-Agent": "ircopilot-docs-fetcher/0.1"},
        event_hooks={"request": [_guard]},
    )
    report = FetchReport()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = out_path.with_suffix(".tmp")
    try:
        with tmp.open("w", encoding="utf-8") as out:
            for src in sources:
                try:
                    check_url(src.url)
                    record = _fetch_one(client, src)
                except (httpx.HTTPError, FetchBlocked, ValueError) as exc:
                    log.warning("skip %s: %s", src.url, type(exc).__name__)
                    report.failed.append(src.url)
                    continue
                out.write(json.dumps(record, ensure_ascii=False) + "\n")
                report.saved += 1
        tmp.replace(out_path)
    finally:
        if own:
            client.close()
        tmp.unlink(missing_ok=True)
    return report


def _fetch_one(client: httpx.Client, src: DocSource) -> dict[str, object]:
    with client.stream("GET", src.url) as resp:
        resp.raise_for_status()
        check_url(str(resp.url))
        if "text/html" not in resp.headers.get("content-type", ""):
            raise ValueError("not HTML")
        body = bytearray()
        for part in resp.iter_bytes():
            body.extend(part)
            if len(body) > MAX_PAGE_BYTES:
                raise ValueError("page too large")
        final_url = str(resp.url)
    html = body.decode(resp.encoding or "utf-8", errors="replace")
    page = extract_page(html)
    if not page.sections:
        raise ValueError("no extractable text")
    return {
        "url": final_url,
        "title": page.title or final_url,
        "source": src.source,
        "license": LICENSES.get(src.source, ""),
        "fetched_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "content_sha256": hashlib.sha256(bytes(body)).hexdigest(),
        "sections": [asdict(s) for s in page.sections],
    }
