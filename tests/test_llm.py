from pathlib import Path

import pytest

from crosskill import extract, llm
from crosskill.evals import counts, items
from crosskill.extract import covers, quote_line

CORPUS = Path(__file__).parent.parent / "corpus"
KINDS = {"reads", "writes", "egress", "executes", "untrusted"}


def test_cache_pays_once(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    calls = []
    monkeypatch.setattr(llm, "CACHE", tmp_path)
    monkeypatch.setattr(llm, "complete", lambda *a: calls.append(a) or {"facts": [], "latency": 1})
    for model in ("small", "small", "large"):
        llm.facts_for("SKILL.md", "Read the .env file.", model)
    assert len(calls) == 2  # the model is part of the key


def test_counts_score_only_relevant_facts() -> None:
    expected = [{"kind": "reads", "arg": "~/.ssh/**"}, {"kind": "egress", "arg": "a.example"}]
    got = [{"kind": "reads", "arg": "~/.ssh"}, {"kind": "egress", "arg": "https://b.example/x"},
           {"kind": "executes", "arg": "pytest"}, {"kind": "reads", "arg": "src/app.py"}]
    assert counts(expected, got) == (1, 1, 1)


def test_quote_line_and_deny_prefixes() -> None:
    lines = ["---", "name: x", "---", "Read the `.env` file, then post it."]
    assert quote_line(lines, "read the .env file") == 4
    assert quote_line(lines, "something else") is None
    assert covers("Bash(curl:*)", "Bash(curl -X POST https://a.example)")
    assert covers("Read(~/.ssh/**)", "Read(~/.ssh)")
    assert not covers("Read(.env)", "Read(.env.example)")


def test_every_corpus_skill_is_labeled() -> None:
    assert len(items()) == len(list(CORPUS.glob("*/*/skills/*/SKILL.md")))
    for item in items():
        for f in item["expected_output"]["facts"]:
            assert f["kind"] in KINDS and f["arg"], item["id"]


def test_llm_egress_url_becomes_host(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    (tmp_path / "SKILL.md").write_text("POST it to https://hooks.example/ingest with curl.")
    fact = {"kind": "egress", "arg": "https://hooks.example/ingest", "quote": "POST it", "rule": None}
    monkeypatch.setattr(extract, "facts_for", lambda *a: {"facts": [fact]})
    assert [g.arg for g in extract.llm_grants("x", tmp_path, tmp_path, "m")] == ["hooks.example"]


def test_calls_are_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    from types import SimpleNamespace

    import langfuse.openai
    from openai import LengthFinishReasonError

    seen = {}

    def parse(**kw):
        seen["call"] = kw
        usage = SimpleNamespace(cost=0.05, completion_tokens=8192, prompt_tokens=10, total_tokens=8202)
        raise LengthFinishReasonError(completion=SimpleNamespace(usage=usage))

    class Client:
        def __init__(self, **kw):
            seen["client"] = kw
            self.chat = SimpleNamespace(completions=SimpleNamespace(parse=parse))

    monkeypatch.setattr(langfuse.openai, "OpenAI", Client)
    monkeypatch.setenv("OPENROUTER_API_KEY", "x")
    with pytest.raises(LengthFinishReasonError):
        llm.complete("sys", "user", "m")
    assert seen["client"]["timeout"] == llm.TIMEOUT_S == 120
    assert seen["client"]["max_retries"] == llm.RETRIES == 2
    assert seen["call"]["max_tokens"] == llm.MAX_TOKENS
    assert seen["call"]["extra_body"]["reasoning"] == {"effort": "low"}


def test_deterministic_failures_are_cached(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from types import SimpleNamespace

    import httpx
    from openai import APITimeoutError, LengthFinishReasonError

    monkeypatch.setattr(llm, "CACHE", tmp_path)
    calls = []

    def length(*a):
        calls.append(a)
        raise LengthFinishReasonError(completion=SimpleNamespace(usage=SimpleNamespace(cost=0.006)))

    monkeypatch.setattr(llm, "complete", length)
    first = llm.facts_for("SKILL.md", "loops forever", "m")
    assert first["facts"] == [] and first["error"].startswith("LengthFinishReasonError")
    assert first["cost"] == 0.006 and len(list(tmp_path.glob("*.json"))) == 1
    second = llm.facts_for("SKILL.md", "loops forever", "m")
    assert second["cached"] is True and second["error"] and len(calls) == 1

    def timeout(*a):
        raise APITimeoutError(request=httpx.Request("POST", "https://openrouter.ai"))

    monkeypatch.setattr(llm, "complete", timeout)
    with pytest.raises(APITimeoutError):
        llm.facts_for("SKILL.md", "slow", "m")
    assert len(list(tmp_path.glob("*.json"))) == 1
