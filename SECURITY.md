# Security notes

This tool reduces risk; it does not eliminate it. Nothing here makes it "unhackable". Read the limits below.

## Trust model

| Input | Trusted? | Handling |
|---|---|---|
| CLI arguments / MCP `--root` | yes (the operator) | validated for shape |
| Log files, Compose files | **no** | path-validated, size-limited, redacted, parsed with limits |
| Public docs and Qdrant payloads | **no** | sanitised, injection-filtered, delimited as data |
| Model output | **no** | sanitised, citation-validated, redacted, never executed |
| MCP tool arguments | **no** (they come from another model) | same validation as the CLI, plus `top_k` clamped |

## Controls

- **No execution.** No code path shells out, runs Docker/kubectl, or evaluates file content. YAML uses
  `safe_load` (no Python tags). Suggested commands in answers are displayed as text only.
- **Prompt injection.** Fixed system rules; untrusted text is wrapped in delimiters with a fresh random nonce per
  request (content cannot close the block); chat-template tokens are stripped; doc chunks and log lines matching
  injection heuristics are withheld from the model and reported; a reminder follows the data. Answers must cite
  retrieved sources or are replaced by "insufficient evidence"; fabricated citations are removed.
- **Paths.** Files must resolve inside an explicit allowed root (a filesystem root is refused). Rejects traversal,
  any symlink or junction under the root, UNC/device paths, Windows device names and alternate data streams,
  non-regular files (directories, FIFOs, devices), oversized and binary files. Type and size are re-checked on the
  open descriptor; `O_NOFOLLOW` is used where the OS supports it.
- **Parsing limits.** Logs: 5 MiB, 100k lines, 4k chars/line. Compose: 1 MiB, one document, ≤50k nodes after
  alias expansion (blocks "billion laughs" and recursive anchors), depth ≤40, ≤500 services.
- **Secrets.** Redaction runs before display and before anything reaches the model (keys, tokens, JWTs, private
  keys, URL passwords, `password=`-style pairs). Compose environment *values* are never returned. Raw logs are
  never written to disk; the only files written are the docs corpus and, if asked, eval results.
- **Network.** Service URLs must be loopback unless `IRCOPILOT_ALLOW_NONLOCAL=1`. HTTP clients ignore proxy
  environment variables and do not follow redirects. `fetch-docs` only contacts `docs.docker.com` and
  `kubernetes.io` over HTTPS, enforced on every request including redirects. The MCP server uses stdio only.
- **Containers.** Ports bound to `127.0.0.1`; no Docker socket, no privileged mode, no host networking.
  Qdrant: upstream non-root image, read-only root filesystem, all capabilities dropped, `no-new-privileges`,
  telemetry disabled, PID and memory limits. Images pinned by tag.
- **Logging.** Only counts and status go to stderr; prompts, file contents and response bodies are not logged.

## Known limitations and residual risks

- **Injection heuristics are bypassable** (paraphrase, other languages, encodings). The structural controls
  limit the impact: worst case is a misleading answer, never an action. Review suggested commands yourself.
- **Small local models follow rules imperfectly.** A cited answer can still be wrong or cite a weakly relevant
  source; citation validation proves the source was retrieved, not that it supports the claim. The relevance
  threshold is a single cosine cut-off tuned on a small eval set; unusual on-topic questions may be refused
  and close-but-off-topic ones may get through.
- **Injection heuristics have false positives too.** Against the bundled corpus they flag 0 of 1,098 chunks,
  but new documents may trip them (they are then withheld and reported, not silently used).
- **Redaction is pattern-based** and will miss unusual secret formats (and sometimes over-redact). Don't feed
  files you can't afford to show a local process.
- **TOCTOU.** Paths are checked, then opened; on Windows there is no `O_NOFOLLOW`, so a local attacker who can
  swap files inside the allowed root during the check could race it. Choose a root only you control.
- **Ollama container runs as root** (upstream image). Prefer native Ollama. The Ollama port is unauthenticated:
  any local process or user can use it, as can any local process with Qdrant unless you set an API key
  (`QDRANT_API_KEY` for compose + `IRCOPILOT_QDRANT_API_KEY` for the CLI). On shared machines, set one.
- **Model and image supply chain.** Images are pinned by tag, not digest; models are pulled by tag from the
  Ollama registry. Pin digests (`image@sha256:…`) for stricter reproducibility.
- **Ollama and Qdrant need egress only for setup** (model pulls). Compose doesn't block their outbound network;
  block it with a firewall if you need hard isolation after setup.
- The MCP `ToolAnnotations` are hints to clients; the guarantee is that the code exposes no write paths.
- Corpus poisoning: anyone who can write to the local Qdrant or `data/corpus/` can influence answers.

## Reporting

Open an issue (without secrets or exploit details) or contact the maintainer privately.
