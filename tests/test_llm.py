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


def test_triage_report_counts() -> None:
    from crosskill import evals, triage

    one = items()[0]
    labels = evals.role_labels(one["expected_output"]["facts"])
    report = evals.triage_report(roles=lambda text: dict.fromkeys(triage.ROLES, 1.0 * (text == one["input"]["text"])))
    assert "risky-skill recall" in report
    for role, hit in labels.items():
        line = next(x for x in report.splitlines() if x.startswith(role))
        assert f"tp {int(hit)} fp {int(not hit)}" in line


def test_calls_are_bounded_and_failed_calls_charged(monkeypatch: pytest.MonkeyPatch) -> None:
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
    monkeypatch.setattr(llm, "spent_usd", 0.0)
    monkeypatch.setattr(llm, "max_call_usd", 0.0)
    with pytest.raises(LengthFinishReasonError):
        llm.complete("sys", "user", "m")
    assert llm.spent_usd == 0.05
    assert seen["client"]["timeout"] == llm.TIMEOUT_S == 120
    assert seen["call"]["max_tokens"] == llm.MAX_TOKENS
    assert seen["call"]["extra_body"]["reasoning"] == {"max_tokens": llm.REASONING_TOKENS}
    assert llm.REASONING_TOKENS < llm.MAX_TOKENS


def test_spend_gate_blocks_uncached_calls(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    calls, asked = [], []
    monkeypatch.setattr(llm, "CACHE", tmp_path)
    monkeypatch.setattr(llm, "complete", lambda *a: calls.append(a) or {"facts": [], "cost": 0.02})
    monkeypatch.setattr(llm, "max_call_usd", 0.0)
    monkeypatch.setattr(llm, "spent_usd", 0.0)
    monkeypatch.setattr(llm, "allow", lambda n: asked.append(n) or len(asked) < 2)
    llm.facts_for("SKILL.md", "one", "m")
    with pytest.raises(llm.OverBudget):
        llm.facts_for("SKILL.md", "two", "m")
    llm.facts_for("SKILL.md", "one", "m")  # cached: no gate, no call
    assert len(calls) == 1 and asked == [0, 0] and llm.in_flight == 0


def test_deterministic_failures_are_cached(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from types import SimpleNamespace

    import httpx
    from openai import APITimeoutError, LengthFinishReasonError

    monkeypatch.setattr(llm, "CACHE", tmp_path)
    monkeypatch.setattr(llm, "spent_usd", 0.0)
    monkeypatch.setattr(llm, "max_call_usd", 0.0)
    calls = []

    def length(*a):  # as complete() does: charge the failed call, then raise
        calls.append(a)
        llm.charge(0.006)
        raise LengthFinishReasonError(completion=SimpleNamespace(usage=SimpleNamespace(cost=0.006)))

    monkeypatch.setattr(llm, "complete", length)
    first = llm.facts_for("SKILL.md", "loops forever", "m")
    assert first["facts"] == [] and first["error"].startswith("LengthFinishReasonError")
    assert llm.spent_usd == pytest.approx(0.006) and len(list(tmp_path.glob("*.json"))) == 1
    second = llm.facts_for("SKILL.md", "loops forever", "m")
    assert second["cached"] is True and second["error"] and len(calls) == 1
    assert llm.spent_usd == pytest.approx(0.006)

    def timeout(*a):
        raise APITimeoutError(request=httpx.Request("POST", "https://openrouter.ai"))

    monkeypatch.setattr(llm, "complete", timeout)
    with pytest.raises(APITimeoutError):
        llm.facts_for("SKILL.md", "slow", "m")
    assert len(list(tmp_path.glob("*.json"))) == 1 and llm.in_flight == 0
