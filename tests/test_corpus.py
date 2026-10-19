import json
from pathlib import Path

import pytest

CORPUS = Path(__file__).parent.parent / "corpus"
INSTALLS = sorted(p for kind in ("toxic", "clean") for p in (CORPUS / kind).iterdir() if p.is_dir())
RULE_FIELDS = {
    "secret_exfiltration": {"resource", "sink"},
    "untrusted_to_execution": {"source", "sink"},
    "lethal_trifecta": {"private_data", "untrusted_input", "egress"},
}
PINS = {
    "skills.sh": {"repo", "commit", "path"},
    "clawhub": {"owner", "slug", "version", "sha256"},
}


def test_corpus_size() -> None:
    assert len(list((CORPUS / "toxic").iterdir())) >= 20
    assert len(list((CORPUS / "clean").iterdir())) >= 50


@pytest.mark.parametrize("install", INSTALLS, ids=lambda p: f"{p.parent.name}/{p.name}")
def test_install_is_well_formed(install: Path) -> None:
    expected = json.loads((install / "expected.json").read_text())
    findings = expected["findings"]
    assert isinstance(expected.get("needs_llm", False), bool)
    assert isinstance(expected.get("based_on", ""), str)
    if install.parent.name == "toxic":
        assert findings, "toxic install must expect at least one finding"
        for f in findings:
            assert f["path"]
            assert RULE_FIELDS[f["rule"]] <= f.keys()
    else:
        assert findings == []
    for name in ("settings.json", ".mcp.json"):
        if (install / name).exists():
            json.loads((install / name).read_text())
    skills = list((install / "skills").glob("*"))
    assert skills
    for skill in skills:
        assert (skill / "SKILL.md").exists()


def test_real_manifest() -> None:
    entries = json.loads((CORPUS / "real" / "MANIFEST.json").read_text())["skills"]
    assert len(entries) >= 100
    assert len({e["id"] for e in entries}) == len(entries)
    for e in entries:
        assert e["license"] and e["url"]
        assert PINS[e["source"]] <= e.keys()


@pytest.mark.parametrize("combo", sorted((CORPUS / "real" / "combos").iterdir()), ids=lambda p: p.name)
def test_real_combo(combo: Path) -> None:
    ids = {e["id"] for e in json.loads((CORPUS / "real" / "MANIFEST.json").read_text())["skills"]}
    assert set(json.loads((combo / "install.json").read_text())["skills"]) <= ids
    for f in json.loads((combo / "expected.json").read_text())["findings"]:
        assert RULE_FIELDS[f["rule"]] <= f.keys()
