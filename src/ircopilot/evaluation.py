"""Small evaluation harness: retrieval quality (hit@k, MRR) and answer quality (citations, abstention, keywords)."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ircopilot.models import ChatModel, Embedder, VectorStore
from ircopilot.rag import answer_question, retrieve


@dataclass(frozen=True)
class EvalCase:
    id: str
    question: str
    answerable: bool
    expected_urls: tuple[str, ...]
    keywords: tuple[str, ...]


def load_cases(path: Path) -> list[EvalCase]:
    cases = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        r = json.loads(line)
        cases.append(
            EvalCase(
                id=str(r["id"]),
                question=str(r["question"]),
                answerable=bool(r.get("answerable", True)),
                expected_urls=tuple(r.get("expected_urls", [])),
                keywords=tuple(r.get("keywords", [])),
            )
        )
    return cases


def _rank(urls: list[str], expected: tuple[str, ...]) -> int | None:
    for i, url in enumerate(urls, start=1):
        if any(e in url for e in expected):
            return i
    return None


def run_eval(
    cases: list[EvalCase],
    embedder: Embedder,
    store: VectorStore,
    chat: ChatModel | None,
    *,
    top_k: int,
    min_score: float,
) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    for case in cases:
        row: dict[str, Any] = {"id": case.id, "answerable": case.answerable}
        if case.answerable:
            hits = retrieve(case.question, embedder, store, top_k).hits
            rank = _rank([h.chunk.url for h in hits], case.expected_urls)
            row.update(rank=rank, top_score=round(hits[0].score, 3) if hits else None)
        if chat is not None:
            t0 = time.perf_counter()
            ans = answer_question(case.question, embedder, store, chat, top_k=top_k, min_score=min_score)
            row["latency_s"] = round(time.perf_counter() - t0, 2)
            row["abstained"] = not ans.sufficient
            row["abstention_correct"] = ans.sufficient == case.answerable
            row["invalid_citations"] = len(ans.invalid_citations)
            if ans.reason:
                row["abstain_reason"] = ans.reason
            if ans.sufficient:
                cited = [h.chunk.url for h in ans.citations]
                row["citation_precision"] = (
                    round(sum(any(e in u for e in case.expected_urls) for u in cited) / len(cited), 3) if case.expected_urls else None
                )
                lower = ans.text.lower()
                row["keyword_recall"] = round(sum(k.lower() in lower for k in case.keywords) / len(case.keywords), 3) if case.keywords else None
        rows.append(row)
    return {"summary": summarize(rows, top_k), "cases": rows}


def _mean(values: list[float]) -> float | None:
    return round(sum(values) / len(values), 3) if values else None


def summarize(rows: list[dict[str, Any]], top_k: int) -> dict[str, Any]:
    ans_rows = [r for r in rows if r["answerable"]]
    summary: dict[str, Any] = {
        "cases": len(rows),
        f"retrieval_hit@{top_k}": _mean([1.0 if r.get("rank") else 0.0 for r in ans_rows]),
        "retrieval_mrr": _mean([1.0 / r["rank"] if r.get("rank") else 0.0 for r in ans_rows]),
    }
    gen = [r for r in rows if "abstained" in r]
    if gen:
        answered = [r for r in gen if not r["abstained"]]
        summary.update(
            abstention_accuracy=_mean([1.0 if r["abstention_correct"] else 0.0 for r in gen]),
            answered_when_answerable=_mean([0.0 if r["abstained"] else 1.0 for r in gen if r["answerable"]]),
            abstained_when_unanswerable=_mean([1.0 if r["abstained"] else 0.0 for r in gen if not r["answerable"]]),
            citation_precision=_mean([r["citation_precision"] for r in answered if r.get("citation_precision") is not None]),
            keyword_recall=_mean([r["keyword_recall"] for r in answered if r.get("keyword_recall") is not None]),
            answers_with_invalid_citations=sum(1 for r in gen if r["invalid_citations"]),
            mean_latency_s=_mean([r["latency_s"] for r in gen]),
        )
    return summary
