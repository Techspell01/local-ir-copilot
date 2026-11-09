"""Command-line interface. Output is sanitised; nothing from files or model output is executed."""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import textwrap
from pathlib import Path
from typing import Any

from ircopilot import __version__, service
from ircopilot.backends import BackendError, OllamaClient, QdrantStore
from ircopilot.config import ConfigError, Settings, load_settings
from ircopilot.inspect_compose import COMPOSE_SUFFIXES, ComposeError
from ircopilot.models import Answer, Finding
from ircopilot.render import Style, render_answer, use_color, width
from ircopilot.safety.paths import PathRejected
from ircopilot.safety.text import clean_text, truncate

EXIT_OK, EXIT_INPUT, EXIT_BACKEND = 0, 2, 3


def _out(text: str = "") -> None:
    print(clean_text(text))


def _styled(text: str) -> None:
    """Print text that was sanitised before our own styling codes were added."""
    print(text)


def _print_answer(ans: Answer) -> None:
    st = Style(use_color())
    notes: list[str] = []
    if ans.sufficient:
        _styled(render_answer(clean_text(ans.text), st))
        _styled("\n" + st.bold("Sources"))
        for sid, hit in zip(ans.citation_ids, ans.citations, strict=True):
            c = hit.chunk
            title = truncate(clean_text(f"{c.title} > {c.section}" if c.section != c.title else c.title), 90)
            url = clean_text(c.url).removeprefix("https://")
            _styled(f"  {st.dim(sid):<4} {title}\n       {st.dim(url)}")
        notes.append("Commands above were not run. Check them against the sources first.")
    else:
        _styled(st.yellow(clean_text(ans.text)))
    if ans.reason:
        notes.append(ans.reason)
    if ans.invalid_citations:
        notes.append(f"Removed {len(ans.invalid_citations)} citation(s) that did not match a retrieved source.")
    if ans.withheld:
        notes.append(f"Withheld {ans.withheld} retrieved passage(s) that looked like prompt-injection attempts.")
    if notes:
        _styled("")
        for note in notes:
            _styled(st.dim(f"  - {clean_text(note)}"))


_SEV_STYLE = {"high": "yellow", "medium": "cyan", "low": "dim", "info": "dim"}


def _print_findings(findings: list[Finding]) -> None:
    st = Style(use_color())
    if not findings:
        _out("No known failure patterns found.")
        return
    for f in findings:
        where = f"line {f.line}" if f.line else (clean_text(f.service) if f.service else "")
        count = f" x{f.occurrences}" if f.occurrences > 1 else ""
        sev = getattr(st, _SEV_STYLE[f.severity])(f"{f.severity.upper():<6}")
        _styled(f"  {sev} {st.bold(clean_text(f.rule))}  {st.dim(where + count)}")
        _styled(textwrap.fill(clean_text(f.message), width=width(), initial_indent="         ", subsequent_indent="         "))
        if f.evidence:
            _styled(st.dim("         " + truncate(clean_text(f.evidence), width() - 9)))


def _ask(settings: Settings, question: str, extra: str | None = None, top_k: int | None = None, detailed: bool = False) -> Answer:
    from ircopilot.rag import answer_question

    ollama = OllamaClient(settings)
    return answer_question(
        question,
        ollama,
        QdrantStore(settings),
        ollama,
        top_k=top_k or settings.top_k,
        min_score=settings.min_score,
        extra_context=extra,
        detailed=detailed,
    )


def cmd_fetch_docs(args: argparse.Namespace, s: Settings) -> int:
    from ircopilot.docs.fetch import fetch_docs

    out = Path(args.out or s.corpus_path)
    _out("Downloading curated public Docker/Kubernetes docs (the only networked step)...")
    report = fetch_docs(out)
    _out(f"Saved {report.saved} pages to {out}.")
    for url in report.failed:
        _out(f"  failed: {url}")
    return EXIT_OK if report.saved else EXIT_BACKEND


def cmd_ingest(args: argparse.Namespace, s: Settings) -> int:
    stats = service.ingest(Path(args.corpus or s.corpus_path), OllamaClient(s), QdrantStore(s), recreate=args.recreate)
    _out(f"Indexed {stats.chunks} chunks from {stats.documents} documents (skipped {stats.skipped_records} bad records).")
    return EXIT_OK


def cmd_search(args: argparse.Namespace, s: Settings) -> int:
    result = service.search_docs(args.query, args.top_k or s.top_k, OllamaClient(s), QdrantStore(s))
    if args.json:
        _out(json.dumps(result, indent=2, ensure_ascii=False))
        return EXIT_OK
    for r in result["results"]:
        _out(f"{r['rank']}. ({r['score']:.2f}) {r['title']} / {r['section']}\n   {r['url']}")
    if result["withheld_suspected_injection"]:
        _out(f"(Withheld {result['withheld_suspected_injection']} suspicious passage(s).)")
    return EXIT_OK


def cmd_ask(args: argparse.Namespace, s: Settings) -> int:
    _print_answer(_ask(s, args.question, top_k=args.top_k, detailed=args.long))
    return EXIT_OK


def cmd_inspect(args: argparse.Namespace, s: Settings) -> int:
    root = Path(args.root)
    # A shell-typed relative path means "relative to where I am"; make it absolute (lexically) before validation.
    path = args.path if Path(args.path).is_absolute() or not args.path.strip() else os.path.abspath(args.path)
    kind = args.kind
    if kind == "auto":
        kind = "compose" if Path(path).suffix.lower() in COMPOSE_SUFFIXES else "log"
    report: Any = service.parse_compose_file(path, root, s) if kind == "compose" else service.inspect_log_file(path, root, s)
    if args.json:
        _out(json.dumps(report.to_dict(), indent=2, ensure_ascii=False))
    else:
        st = Style(use_color())
        _styled(st.bold(f"{clean_text(report.path)}") + st.dim(f"  ({kind})"))
        if kind == "log":
            if report.redactions:
                _styled(st.dim(f"  - Hid {sum(report.redactions.values())} secret(s): {', '.join(sorted(report.redactions))}"))
            if report.suspicious_lines:
                _styled(st.yellow(f"  - {len(report.suspicious_lines)} line(s) look like prompt injection; kept away from the model"))
        _styled("")
        shown = report.findings if args.all else [f for f in report.findings if f.severity in ("high", "medium")]
        _print_findings(shown)
        if hidden := len(report.findings) - len(shown):
            _styled(st.dim(f"\n  + {hidden} low/info finding(s) hidden; use --all to see them"))
    if args.explain:
        query = report.doc_query()
        if not query:
            _out("\nNothing to explain: no actionable findings.")
            return EXIT_OK
        st = Style(use_color())
        _styled("\n" + st.bold("Explanation") + st.dim("  (local model, from the docs below)"))
        question = f"Diagnose these {kind} findings and suggest troubleshooting steps: {query}"
        _print_answer(_ask(s, question, extra=report.summary_for_model(), detailed=args.long))
    return EXIT_OK


def cmd_mcp(args: argparse.Namespace, s: Settings) -> int:
    from ircopilot.mcp_server import run_stdio

    run_stdio(s, Path(args.root))
    return EXIT_OK


def cmd_status(args: argparse.Namespace, s: Settings) -> int:
    ok = True
    try:
        models = OllamaClient(s).list_models()
        for m in (s.chat_model, s.embed_model):
            present = any(x == m or x.split(":")[0] == m or x == f"{m}:latest" for x in models)
            ok &= present
            _out(f"ollama model {m}: {'present' if present else 'MISSING (ollama pull ' + m + ')'}")
    except BackendError as exc:
        ok = False
        _out(str(exc))
    try:
        _out(f"qdrant collection {s.collection}: {QdrantStore(s).count()} chunks")
    except BackendError as exc:
        ok = False
        _out(str(exc))
    return EXIT_OK if ok else EXIT_BACKEND


def cmd_eval(args: argparse.Namespace, s: Settings) -> int:
    from ircopilot.evaluation import load_cases, run_eval

    ollama = OllamaClient(s)
    result = run_eval(
        load_cases(Path(args.file)),
        ollama,
        QdrantStore(s),
        None if args.retrieval_only else ollama,
        top_k=args.top_k or s.top_k,
        min_score=s.min_score,
    )
    if args.out:
        Path(args.out).write_text(json.dumps(result, indent=2), encoding="utf-8")
    _out(json.dumps(result["summary"], indent=2))
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="ircopilot", description="Local Incident Response Copilot (local-only, read-only).")
    p.add_argument("--version", action="version", version=f"ircopilot {__version__}")
    p.add_argument("-v", "--verbose", action="store_true", help="log progress (never content) to stderr")
    sub = p.add_subparsers(dest="command", required=True)

    f = sub.add_parser("fetch-docs", help="download the curated public docs corpus (network, run once)")
    f.add_argument("--out", help="corpus JSONL path (default data/corpus/docs.jsonl)")
    f.set_defaults(func=cmd_fetch_docs)

    i = sub.add_parser("ingest", help="chunk, embed and index the local corpus into Qdrant")
    i.add_argument("--corpus", help="corpus JSONL path")
    i.add_argument("--recreate", action="store_true", help="drop and rebuild the collection")
    i.set_defaults(func=cmd_ingest)

    se = sub.add_parser("search", help="retrieve matching doc passages (no model generation)")
    se.add_argument("query")
    se.add_argument("--top-k", type=int)
    se.add_argument("--json", action="store_true")
    se.set_defaults(func=cmd_search)

    a = sub.add_parser("ask", help="ask a question; answers cite retrieved docs or abstain")
    a.add_argument("question")
    a.add_argument("--top-k", type=int)
    a.add_argument("--long", action="store_true", help="longer, more detailed answer")
    a.set_defaults(func=cmd_ask)

    n = sub.add_parser("inspect", help="inspect a log or Compose file you supply (read-only)")
    n.add_argument("path")
    n.add_argument("--root", default=".", help="directory the file must be inside (default: current directory)")
    n.add_argument("--kind", choices=("auto", "log", "compose"), default="auto")
    n.add_argument("--explain", action="store_true", help="ask the local model to explain findings with citations")
    n.add_argument("--json", action="store_true")
    n.add_argument("--all", action="store_true", help="also show low/info findings")
    n.add_argument("--long", action="store_true", help="longer, more detailed explanation")
    n.set_defaults(func=cmd_inspect)

    m = sub.add_parser("mcp", help="run the read-only MCP server on stdio")
    m.add_argument("--root", required=True, help="the only directory MCP file tools may read from")
    m.set_defaults(func=cmd_mcp)

    st = sub.add_parser("status", help="check local Ollama models and Qdrant index")
    st.set_defaults(func=cmd_status)

    e = sub.add_parser("eval", help="run the evaluation set")
    e.add_argument("--file", default="eval/questions.jsonl")
    e.add_argument("--retrieval-only", action="store_true", help="skip answer generation")
    e.add_argument("--top-k", type=int)
    e.add_argument("--out", help="write per-case results JSON here")
    e.set_defaults(func=cmd_eval)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=logging.INFO if args.verbose else logging.WARNING, stream=sys.stderr, format="%(levelname)s %(name)s: %(message)s")
    if args.command != "fetch-docs":
        logging.getLogger("httpx").setLevel(logging.WARNING)  # request lines are noise and may include query params
    try:
        settings = load_settings()
        return int(args.func(args, settings))
    except (ConfigError, PathRejected, ComposeError, ValueError, FileNotFoundError) as exc:
        print(f"error: {clean_text(str(exc))}", file=sys.stderr)
        return EXIT_INPUT
    except BackendError as exc:
        print(f"error: {clean_text(str(exc))}", file=sys.stderr)
        return EXIT_BACKEND
    except KeyboardInterrupt:
        return 130
