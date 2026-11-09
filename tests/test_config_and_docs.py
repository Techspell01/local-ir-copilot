import httpx
import pytest

from ircopilot.config import ConfigError, ensure_local_url, load_settings
from ircopilot.docs.chunk import chunk_document
from ircopilot.docs.extract import extract_page
from ircopilot.docs.fetch import FetchBlocked, check_url


@pytest.mark.parametrize("url", ["http://127.0.0.1:6333", "http://localhost:11434/", "http://[::1]:6333"])
def test_loopback_urls_allowed(url: str) -> None:
    assert ensure_local_url(url) == url.rstrip("/")


@pytest.mark.parametrize("url", ["http://10.0.0.5:6333", "https://api.example.com", "http://0.0.0.0:6333", "http://u:p@localhost:1", "file:///etc/passwd"])
def test_non_local_urls_rejected(url: str) -> None:
    with pytest.raises(ConfigError):
        ensure_local_url(url)


def test_env_cannot_point_services_off_machine() -> None:
    with pytest.raises(ConfigError):
        load_settings({"IRCOPILOT_OLLAMA_URL": "http://198.51.100.7:11434"})
    with pytest.raises(ConfigError):
        load_settings({"IRCOPILOT_COLLECTION": "../x"})


@pytest.mark.parametrize("url", ["http://docs.docker.com/x", "https://evil.example/x", "https://kubernetes.io.evil.example/", "https://kubernetes.io:8443/"])
def test_fetch_allowlist(url: str) -> None:
    with pytest.raises(FetchBlocked):
        check_url(url)


def test_fetch_blocks_redirect_off_allowlist(tmp_path) -> None:  # type: ignore[no-untyped-def]
    from ircopilot.docs.fetch import _guard, fetch_docs
    from ircopilot.docs.sources import DocSource

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "docs.docker.com":
            return httpx.Response(302, headers={"location": "https://evil.example/steal"})
        return httpx.Response(200, html="<main><p>pwned</p></main>")

    client = httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=True, event_hooks={"request": [_guard]})
    report = fetch_docs(tmp_path / "c.jsonl", [DocSource("https://docs.docker.com/a/", "docker")], client=client)
    assert report.saved == 0 and report.failed


def test_extract_and_chunk_keep_metadata() -> None:
    html = """<html><head><title>Restart policies | Docker Docs</title><script>alert(1)</script></head>
    <body><nav>menu</nav><main><h1>Restart policies</h1><p>%s</p><h2>Use a restart policy</h2>
    <pre>docker run --restart always redis</pre><p>%s</p></main><footer>foot</footer></body></html>""" % ("A" * 400, "B" * 300)
    page = extract_page(html)
    assert page.title == "Restart policies"
    joined = " ".join(s.text for s in page.sections)
    assert "alert" not in joined and "menu" not in joined and "foot" not in joined
    doc = {"url": "https://docs.docker.com/r/", "title": page.title, "source": "docker", "sections": [vars(s) for s in page.sections]}
    chunks = chunk_document(doc)
    assert chunks and all(c.url == "https://docs.docker.com/r/" for c in chunks)
    assert {c.section for c in chunks} == {"Restart policies", "Use a restart policy"}
    assert len({c.id for c in chunks}) == len(chunks)
