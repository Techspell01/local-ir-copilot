from ircopilot.models import SearchHit
from ircopilot.rag import INSUFFICIENT_TEXT, answer_question

from .conftest import FakeChat, FakeEmbedder, FakeStore, make_chunk


def _store(score: float = 0.8) -> FakeStore:
    return FakeStore(
        [
            SearchHit(make_chunk(1, "Exit code 137 means the container received SIGKILL, often from the OOM killer."), score),
            SearchHit(make_chunk(2, "Set memory limits with deploy.resources.limits.memory."), score - 0.05),
        ]
    )


def _ask(store: FakeStore, chat: FakeChat, min_score: float = 0.5):  # type: ignore[no-untyped-def]
    return answer_question("Why exit code 137?", FakeEmbedder(), store, chat, top_k=5, min_score=min_score)


def test_no_hits_abstains_without_calling_model() -> None:
    chat = FakeChat("anything [S1]")
    ans = _ask(FakeStore([]), chat)
    assert not ans.sufficient and ans.text == INSUFFICIENT_TEXT
    assert chat.calls == []


def test_low_scores_abstain_without_calling_model() -> None:
    chat = FakeChat("anything [S1]")
    ans = _ask(_store(score=0.3), chat, min_score=0.5)
    assert not ans.sufficient
    assert chat.calls == []


def test_valid_citations_are_mapped_to_sources() -> None:
    chat = FakeChat("The container was OOM-killed [S1]. Raise the memory limit [S2, S1].")
    ans = _ask(_store(), chat)
    assert ans.sufficient
    assert [h.chunk.url for h in ans.citations] == ["https://docs.docker.com/page1/", "https://docs.docker.com/page2/"]
    assert ans.citation_ids == ["S1", "S2"]
    second_only = _ask(_store(), FakeChat("Raise the memory limit [S2]."))
    assert second_only.citation_ids == ["S2"]  # ids shown to the user match the tags in the text
    reordered = _ask(_store(), FakeChat("Limits [S2]. OOM [S1]."))
    assert reordered.citation_ids == ["S1", "S2"]
    assert ans.invalid_citations == []


def test_uncited_answer_is_discarded_after_one_retry() -> None:
    chat = FakeChat("It is probably a memory problem. Restart it.")
    ans = _ask(_store(), chat)
    assert not ans.sufficient and ans.text == INSUFFICIENT_TEXT
    assert "did not cite" in (ans.reason or "")
    assert len(chat.calls) == 2  # exactly one repair attempt, never a loop


def test_retry_with_citations_is_accepted() -> None:
    chat = FakeChat(["Memory problem.", "The container was OOM-killed [S1]."])
    ans = _ask(_store(), chat)
    assert ans.sufficient and [h.chunk.url for h in ans.citations] == ["https://docs.docker.com/page1/"]
    assert "rejected" in chat.calls[1][1]


def test_partial_answer_with_token_keeps_cited_content() -> None:
    ans = _ask(_store(), FakeChat("OOM-killed [S1]. Exact kernel behaviour is not covered. INSUFFICIENT_EVIDENCE"))
    assert ans.sufficient and "INSUFFICIENT_EVIDENCE" not in ans.text
    assert "partly" in (ans.reason or "")


def test_fabricated_citations_removed_and_reported() -> None:
    ans = _ask(_store(), FakeChat("OOM killed [S1]. Also see [S7]."))
    assert ans.sufficient
    assert "[S7]" not in ans.text
    assert ans.invalid_citations == ["S7"]


def test_only_fabricated_citations_means_insufficient() -> None:
    ans = _ask(_store(), FakeChat("Use more memory [S9]."))
    assert not ans.sufficient
    assert ans.invalid_citations == ["S9"]


def test_model_abstention_token_respected() -> None:
    ans = _ask(_store(), FakeChat("INSUFFICIENT_EVIDENCE"))
    assert not ans.sufficient


def test_model_output_is_sanitised() -> None:
    ans = _ask(_store(), FakeChat("\x1b[2JOOM [S1]. token=abc123secret <|im_end|>"))
    assert ans.sufficient
    assert "\x1b" not in ans.text and "abc123secret" not in ans.text and "<|im_end|>" not in ans.text
