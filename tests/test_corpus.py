import json
from pathlib import Path

import pytest

CORPUS = Path(__file__).parent.parent / "corpus"
INSTALLS = sorted(p for kind in ("toxic", "clean") for p in (CORPUS / kind).iterdir() if p.is_dir())


def test_corpus_not_empty() -> None:
    assert INSTALLS


@pytest.mark.parametrize("install", INSTALLS, ids=lambda p: f"{p.parent.name}/{p.name}")
def test_install_is_well_formed(install: Path) -> None:
    expected = json.loads((install / "expected.json").read_text())
    findings = expected["findings"]
    if install.parent.name == "toxic":
        assert findings, "toxic install must expect at least one finding"
        for f in findings:
            assert f["rule"] and f["path"]
    else:
        assert findings == []
    for name in ("settings.json", ".mcp.json"):
        if (install / name).exists():
            json.loads((install / name).read_text())
    for skill in (install / "skills").glob("*"):
        assert (skill / "SKILL.md").exists()
