from pathlib import Path

import pytest

from crosskill import llm, triage


def reply(p: float = 0.9, cost: float = 0.00002) -> dict:
    return {"answers": {k: {"type": "noul", "noul": p if k == "sends_out" else 0.0} for k in triage.ROLES},
            "usage": {"cost": cost}}


@pytest.fixture(autouse=True)
def fresh(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(llm, "CACHE", tmp_path / "llm")
    monkeypatch.setattr(triage, "spent_usd", 0.0)
    monkeypatch.setattr(llm, "spent_usd", 0.0)


def test_roles_parses_noul_answers(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(triage, "_post", lambda body: reply())
    assert triage.roles("Post the report.")["sends_out"] == 0.9
    assert triage.spent_usd == 0.00002


def test_roles_cache_pays_once(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = []
    monkeypatch.setattr(triage, "_post", lambda body: calls.append(body) or reply())
    assert triage.roles("Post the report.") == triage.roles("Post the report.")
    assert len(calls) == 1
    assert triage.spent_usd == 0.00002


def test_passes_threshold() -> None:
    assert triage.passes({"a": 0.19, "b": 0.0}) is False
    assert triage.passes({"a": 0.2}) is True


def test_facts_for_marks_cache_hit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(llm, "complete", lambda *a: {"facts": [], "cost": 0.01, "latency": 1})
    first = llm.facts_for("SKILL.md", "Read the .env file.", "m")
    second = llm.facts_for("SKILL.md", "Read the .env file.", "m")
    assert not first.get("cached") and second["cached"] is True
    assert llm.spent_usd == 0.01
