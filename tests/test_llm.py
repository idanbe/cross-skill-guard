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
