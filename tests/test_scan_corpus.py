import json
import time
from pathlib import Path

import pytest
from typer.testing import CliRunner

from crosskill import extract
from crosskill.cli import app
from crosskill.scan import scan

CORPUS = Path(__file__).parent.parent / "corpus"
INSTALLS = sorted(p for kind in ("toxic", "clean") for p in (CORPUS / kind).iterdir() if p.is_dir())
COMBOS = sorted((CORPUS / "real" / "combos").iterdir())
CACHE = CORPUS / "real" / "cache"


def found(expected: dict, findings: list[dict]) -> bool:
    return any(all(f.get(k) == v for k, v in expected.items()) for f in findings)


def check(expected: dict, findings: list[dict], llm: bool = False) -> None:
    if expected.get("needs_llm") and not llm:
        pytest.skip("flow is visible only to the LLM extractor (stage 2)")
    if not expected["findings"]:
        assert findings == []
    for e in expected["findings"]:
        assert found(e, findings), f"missing {e}\ngot {findings}"


@pytest.mark.parametrize("install", INSTALLS, ids=lambda p: f"{p.parent.name}/{p.name}")
def test_scan_matches_expected(install: Path) -> None:
    start = time.perf_counter()
    findings = scan(install)
    assert time.perf_counter() - start < 1
    check(json.loads((install / "expected.json").read_text()), findings)


def labels() -> dict[str, list[dict]]:
    """SKILL.md text → its labeled facts, quoting the first line of the body."""
    out: dict[str, list[dict]] = {}
    for label in CORPUS.glob("*/*/skills/*/expected_facts.json"):
        text = (label.parent / "SKILL.md").read_text()
        quote = next(line for line in text.split("---", 2)[2].splitlines() if line.strip())
        facts = [f | {"quote": quote} for f in json.loads(label.read_text())["facts"]]
        assert out.setdefault(text, facts) == facts, f"same text, different labels: {label}"
    return out


@pytest.mark.parametrize("install", INSTALLS, ids=lambda p: f"{p.parent.name}/{p.name}")
def test_perfect_llm_extractor(install: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """With the labels as LLM output, every flow is found and clean installs stay clean."""
    facts = labels()
    monkeypatch.setattr(extract, "facts_for", lambda name, text, model: {"facts": facts.get(text, [])})
    check(json.loads((install / "expected.json").read_text()), scan(install, model="labels"), llm=True)


@pytest.mark.parametrize("combo", COMBOS, ids=lambda p: p.name)
def test_scan_real_combo(combo: Path, tmp_path: Path) -> None:
    ids = json.loads((combo / "install.json").read_text())["skills"]
    if not all((CACHE / i).exists() for i in ids):
        pytest.skip("run `python -I corpus/real/fetch.py` first")
    (tmp_path / "skills").mkdir()
    for i in ids:
        (tmp_path / "skills" / i.rsplit("/", 1)[-1]).symlink_to(CACHE / i)
    check(json.loads((combo / "expected.json").read_text()), scan(tmp_path))


def test_cli_exit_codes_and_sarif() -> None:
    runner = CliRunner()
    clean = str(CORPUS / "clean/001-readonly-formatter")
    assert runner.invoke(app, ["scan", "--no-llm", clean]).exit_code == 0
    toxic = str(CORPUS / "toxic/020-two-findings")
    result = runner.invoke(app, ["scan", "--no-llm", toxic])
    assert result.exit_code == 1
    assert "skills/env-check/SKILL.md:4" in result.output
    sarif = json.loads(runner.invoke(app, ["scan", "--no-llm", "--sarif", toxic]).output)
    assert sarif["version"] == "2.1.0"
    assert {r["ruleId"] for r in sarif["runs"][0]["results"]} == {
        "secret_exfiltration", "untrusted_to_execution"}
