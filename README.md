# Local Incident Response Copilot

A local-only, read-only CLI that helps diagnose Docker and Kubernetes problems. It answers questions from
public Docker/Kubernetes documentation (RAG with mandatory citations), inspects log files and Compose files
you supply, and exposes the same capabilities as narrowly scoped MCP tools.

- **Local only:** Ollama (chat + embeddings) and Qdrant run on `127.0.0.1`. No API keys, telemetry or cloud calls
  at runtime. The only networked step is the one-off `fetch-docs` download of public docs.
- **Read-only:** nothing from your files, the docs, or model output is ever executed.
- **Grounded:** answers must cite retrieved sources; otherwise the tool says the evidence is insufficient.

See [SECURITY.md](SECURITY.md) for the threat model and known limits.

## Requirements

| | Minimum | Notes |
|---|---|---|
| Python | 3.12 + [uv](https://docs.astral.sh/uv/) | dependencies are pinned in `uv.lock` |
| Docker | Docker Engine / Desktop with Compose v2 | runs Qdrant (and optionally Ollama) |
| RAM | 8 GB (16 GB recommended) | `llama3.2:3b` needs ~3 GB; Qdrant ~0.3 GB for this corpus |
| Disk | ~4 GB | models ~2.3 GB, Ollama image ~2–4 GB if containerised |
| GPU | optional | NVIDIA GPU with ≥4 GB VRAM makes answers ~5–10× faster; CPU works |

**Model downloads (one-off):**

| Model | Purpose | Size |
|---|---|---|
| `nomic-embed-text` | embeddings (768-dim) | ~275 MB |
| `llama3.2:3b` (default) | answers | ~2.0 GB |
| `qwen2.5:7b` (optional, better answers) | answers | ~4.7 GB, wants ≥8 GB VRAM or 16 GB RAM |

## Setup

```bash
uv sync                                   # install pinned deps into .venv
docker compose up -d qdrant               # Qdrant on 127.0.0.1:6333 (non-root, read-only rootfs)

# Ollama — either install natively (recommended; runs as your user, uses GPU):
#   https://ollama.com/download, then:  ollama pull nomic-embed-text && ollama pull llama3.2:3b
# ...or run it containerised on 127.0.0.1:11434:
docker compose --profile ollama up -d ollama
#   (NVIDIA GPU: docker compose -f docker-compose.yml -f docker-compose.gpu.yml --profile ollama up -d ollama)
docker compose exec ollama ollama pull nomic-embed-text
docker compose exec ollama ollama pull llama3.2:3b

uv run ircopilot fetch-docs               # one-off download of curated public docs -> data/corpus/docs.jsonl
uv run ircopilot ingest                   # chunk + embed + index into Qdrant
uv run ircopilot status                   # check models and index
```

Two Qdrant startup warnings are expected with this hardened config: "api_key is set but empty" (no key
configured, so auth is off; it is only reachable on loopback) and "Failed to create init file indicator"
(read-only root filesystem; it only affects an optional readiness marker).

After `fetch-docs`, everything runs offline. Native Ollama binds to `127.0.0.1` by default; do not set
`OLLAMA_HOST=0.0.0.0` on the host.

## Usage

```bash
uv run ircopilot ask "My pod is in CrashLoopBackOff. How do I see the previous container's logs?"
uv run ircopilot search "restart policy unless-stopped"          # retrieval only, no generation
uv run ircopilot inspect examples/app.log                        # rule-based findings, secrets redacted
uv run ircopilot inspect examples/compose.yml --explain          # + cited explanation from the local model
uv run ircopilot inspect examples/compose.yml --all              # include low/info findings
uv run ircopilot ask "..." --long                                # longer answer (default is short: Cause + up to 4 Steps)
uv run ircopilot inspect /var/log/app.log --root /var/log --json # files must be inside --root (default: cwd)
uv run ircopilot eval                                            # retrieval + answer-quality metrics
uv run ircopilot eval --retrieval-only
```

### MCP server

`ircopilot mcp --root <dir>` serves three read-only tools over **stdio** (no network listener):

| Tool | Does | Never does |
|---|---|---|
| `search_docs(query, top_k≤10)` | vector search over the indexed docs; returns excerpts + URLs | call the chat model, write anything |
| `inspect_log_file(path)` | pattern scan of a log under `--root`, redacted | return raw log content, persist anything |
| `parse_compose_file(path)` | static Compose analysis under `--root` | interpolate, execute, return env values |

Example client config (Claude Desktop / Claude Code style):

```json
{
  "mcpServers": {
    "ircopilot": {
      "command": "uv",
      "args": ["--directory", "/path/to/local-ir-copilot", "run", "ircopilot", "mcp", "--root", "/path/to/incident-files"]
    }
  }
}
```

The MCP host's own model does the reasoning; this server only supplies data, marked as untrusted.

## Configuration

Environment variables (all optional): `IRCOPILOT_OLLAMA_URL`, `IRCOPILOT_QDRANT_URL` (must be loopback unless
`IRCOPILOT_ALLOW_NONLOCAL=1`), `IRCOPILOT_QDRANT_API_KEY`, `IRCOPILOT_CHAT_MODEL`, `IRCOPILOT_EMBED_MODEL`,
`IRCOPILOT_COLLECTION`, `IRCOPILOT_TOP_K`, `IRCOPILOT_MIN_SCORE` (relevance threshold, default 0.68; retune if you change the embedding model),
`IRCOPILOT_MAX_LOG_BYTES` (5 MiB), `IRCOPILOT_MAX_COMPOSE_BYTES` (1 MiB), `IRCOPILOT_TIMEOUT`.

## Architecture

```
            fetch-docs (one-off, allowlisted HTTPS)          your log / compose file
                         │                                            │
                         ▼                                  safety/paths (root, symlinks, devices, size)
         docs/extract → docs/chunk (url, title, section,              │
                         │          source, sha256)           safety/redact + safety/text
                         ▼                                            │
 Ollama embed ◀── service.ingest ──▶ Qdrant            inspect_log / inspect_compose (rules, no exec)
   (localhost)                       (localhost)                      │
                         ▲                                            │ redacted summary
                         │                                            ▼
 CLI ask/inspect ──▶ rag.retrieve ── injection filter ──▶ rag.build_prompt (nonce-delimited untrusted data,
 MCP search_docs ──┘                                      fixed system rules) ──▶ Ollama chat (localhost)
                                                                      │
                                         rag.postprocess: citations must map to retrieved sources,
                                         else "insufficient evidence"; output sanitised + redacted
```

| Module | Responsibility |
|---|---|
| `config.py` | settings from env; rejects non-loopback service URLs |
| `safety/paths.py` | allowed-root path validation, bounded reads |
| `safety/redact.py` | secret redaction |
| `safety/injection.py` | injection heuristics, token neutralisation, nonce delimiters |
| `safety/text.py` | strip ANSI/control/bidi characters |
| `docs/` | curated sources, fetch (allowlist), HTML extraction, chunking |
| `backends.py` | Ollama + Qdrant REST clients (no proxies, no redirects) |
| `rag.py` | retrieval, prompt construction, citation validation, abstention |
| `inspect_log.py`, `inspect_compose.py` | rule-based analysers |
| `service.py` | operations shared by CLI and MCP |
| `mcp_server.py`, `cli.py`, `evaluation.py` | entry points |

## Evaluation

`eval/questions.jsonl` has 15 answerable questions (each with acceptable source-URL fragments and expected
keywords) and 4 that must be refused (off-topic, private data, prompt injection). Metrics:

- **retrieval_hit@k / retrieval_mrr:** whether an expected source appears in the top-k, and how high.
- **abstention_accuracy:** answered when answerable, abstained when not.
- **citation_precision:** share of cited sources that are expected sources.
- **keyword_recall:** share of expected keywords present in the answer (a rough proxy for completeness).
- **answers_with_invalid_citations:** answers where the model cited a source that wasn't retrieved (removed).

These are small-sample, automatic proxies, not a substitute for human review.

**Measured (2026-11-08, `llama3.2:3b` + `nomic-embed-text`, RTX 3050 4 GB, 34 pages / 1,098 chunks, temperature 0):**

| Metric | Result |
|---|---|
| retrieval hit@5 / MRR | 1.00 / 1.00 |
| answered when answerable | 1.00 (15/15) |
| abstained when unanswerable | 1.00 (4/4; all stopped by the relevance threshold before the model ran) |
| citation precision / keyword recall | 0.95 / 0.97 |
| answers with fabricated citations | 0 |
| mean latency | ~8 s per answer |

Caveats: the relevance threshold (0.68) was tuned on this same set, so these numbers are optimistic. Keyword
recall doesn't measure correctness: in manual spot checks the 3B model sometimes misreads a cited passage
(e.g. it misdescribed exit code 137 from the Docker "Exit status" section). Use `qwen2.5:7b` or larger for
better answers (`IRCOPILOT_CHAT_MODEL=qwen2.5:7b`).

If an answer has no valid `[S#]` citation, the model gets one retry with a reminder; if the retry is also
uncited, the tool reports insufficient evidence.

## Tests

```bash
uv run pytest
```

Tests use in-memory fakes for Ollama/Qdrant and cover path validation, prompt-injection handling, secret
redaction, citation enforcement, Compose parsing limits, fetch allowlisting and MCP tool restrictions.

## Licences of the corpus

Docker documentation: Apache-2.0. Kubernetes documentation: CC BY 4.0. Source URLs are stored with every chunk
and shown with every answer.
