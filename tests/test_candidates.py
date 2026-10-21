import json
import math
import shutil
from pathlib import Path

import pytest

from crosskill import candidates
from crosskill.sources import Skill

CORPUS = Path(__file__).parent.parent / "corpus"
POPULAR = json.loads(candidates.POPULAR.read_text())["mcpServers"]


def skill(name: str, installs: int = 100, version: str = "1.0.0") -> Skill:
    return Skill("acme", name, version, installs, 0, f"https://clawhub.ai/acme/skills/{name}")


def install(tmp_path: Path, srcs: dict[str, Path], with_mcp: bool = False) -> Path:
    """srcs: Skill.dirname -> corpus skill dir (copied, so it acts as a downloaded skill)."""
    dirs = {}
    for dirname, src in srcs.items():
        dirs[dirname] = tmp_path / "dl" / dirname
        shutil.copytree(src, dirs[dirname], ignore=shutil.ignore_patterns("expected_facts.json"))
    root = tmp_path / "install"
    root.mkdir()
    candidates.build_install(root, dirs)
    return root


T4 = CORPUS / "toxic/004-aws-creds-to-curl/skills"


def test_check_keeps_only_new_skill_findings(tmp_path):
    root = install(tmp_path, {"acme--cost-report": T4 / "cost-report", "acme--uploader": T4 / "uploader"})
    got = candidates.check(root, "acme--uploader", None)
    assert any(f["rule"] == "secret_exfiltration" and f["path"] == ["cost-report", "uploader"]
               and f["resource"] == "~/.aws/credentials" for f in got)
    found = candidates.check(root, "acme--cost-report", None)
    assert found and {f["rule"] for f in found} == {"secret_exfiltration"}
    assert all(any(c["file"].startswith("skills/acme--cost-report/") for c in f["chain"]) for f in found)
    # popular-MCP-only flows (github, slack, ...) are never reported for a new skill
    assert not any(c["file"] == ".mcp.json" for f in found for c in f["chain"][:1])
    clean = CORPUS / "clean/001-readonly-formatter/skills"
    root2 = install(tmp_path / "b", {"acme--fmt": next(clean.iterdir()), "acme--cost-report": T4 / "cost-report"})
    assert candidates.check(root2, "acme--fmt", None) == []


def test_single_skill_finding_is_a_candidate(tmp_path):
    src = CORPUS / "toxic/010-netrc-single-skill/skills/sync-tool"
    root = install(tmp_path, {"acme--sync-tool": src})
    [f] = [f for f in candidates.check(root, "acme--sync-tool", None) if f["path"] == ["sync-tool"]]
    comps = candidates.components(f, {"acme--sync-tool": skill("sync-tool")}, POPULAR)
    assert [c["id"] for c in comps] == ["clawhub/acme/sync-tool"]
    assert comps[0]["match"] == {"kind": "skill", "name": "sync-tool"}


def combo(tmp_path):
    d = tmp_path / "src" / "client-notes"
    d.mkdir(parents=True)
    (d / "SKILL.md").write_text(
        "---\nname: client-notes\ndescription: Summarize client files\n"
        "allowed-tools: Read(~/clients/**)\n---\n\nSummarize the client files.\n")
    root = install(tmp_path, {"acme--client-notes": d})
    return root, candidates.check(root, "acme--client-notes", None)


def pick(found):
    """The trifecta made of the skill and the popular fetch server only."""
    sk = {"acme--client-notes": skill("client-notes")}
    for f in found:
        comps = candidates.components(f, sk, POPULAR)
        if f["rule"] == "lethal_trifecta" and {c["id"] for c in comps} == {
                "clawhub/acme/client-notes", "mcp/fetch"}:
            return f, comps
    raise AssertionError([f["path"] for f in found])


def test_combination_with_popular_mcp(tmp_path):
    _root, found = combo(tmp_path)
    _f, comps = pick(found)
    assert len(comps) == 2
    fetch = next(c for c in comps if c["id"] == "mcp/fetch")
    assert fetch["match"] == {"kind": "mcp", "package": "mcp-server-fetch", "host": None}
    assert fetch["installs"] == POPULAR["fetch"]["x-crosskill"]["installs"]


def test_key_ignores_versions():
    f = {"rule": "secret_exfiltration", "path": ["b", "a"]}
    a = [{"id": "clawhub/x/b", "version": "1"}, {"id": "clawhub/x/a", "version": "1"}]
    b = [{"id": "clawhub/x/a", "version": "2"}, {"id": "clawhub/x/b", "version": "9"}]
    assert candidates.key(f, a) == candidates.key(f, b) == "secret_exfiltration:clawhub/x/a,clawhub/x/b"


def chain(*extractors):
    return [{"file": "f", "line": 1, "component": "c", "fact": "x", "quote": "q", "extractor": e}
            for e in extractors]


def test_score_values():
    f = {"rule": "secret_exfiltration", "chain": chain("static", "static")}
    comps = [{"installs": 99}, {"installs": 5000}]
    s, b = candidates.score(f, comps)
    assert s == pytest.approx(3 * 2.0 * 1.0)
    assert b == {"severity": 3, "reach": pytest.approx(2.0), "confidence": 1.0}
    s2, _ = candidates.score({**f, "chain": chain("static", "llm")}, comps)
    assert s2 == pytest.approx(6 * 0.8)
    _s3, b3 = candidates.score({**f, "chain": chain("static", "static", "static")}, comps)
    assert b3["confidence"] == pytest.approx(0.9)
    s4, _ = candidates.score(f, [{"installs": 0}])
    assert s4 < candidates.MIN_SCORE
    assert candidates.score({"rule": "lethal_trifecta", "chain": chain("static")}, [{"installs": 9}])[0] \
        == pytest.approx(2 * math.log10(10))


def test_render_wording(tmp_path):
    _root, found = combo(tmp_path)
    f, comps = pick(found)
    s, b = candidates.score(f, comps)
    adv = candidates.advisory(f, comps, s, b, "CK-draft", "https://github.com/o/r/issues/1", "2026-10-21")
    assert adv["key"] == candidates.key(f, comps) and adv["id"] == "CK-draft" and adv["title"]
    page = candidates.render(adv)
    assert "may be safe on its own" in page and "client-notes" in page and "fetch" in page
    assert "https://clawhub.ai/acme/skills/client-notes SKILL.md:" in page
    assert "pipeline/popular-mcp.json:" in page
    assert json.loads(json.dumps(adv)) == adv

    src = CORPUS / "toxic/010-netrc-single-skill/skills/sync-tool"
    root = install(tmp_path / "s", {"acme--sync-tool": src})
    [f1] = [f for f in candidates.check(root, "acme--sync-tool", None) if f["path"] == ["sync-tool"]]
    c1 = candidates.components(f1, {"acme--sync-tool": skill("sync-tool")}, POPULAR)
    a1 = candidates.advisory(f1, c1, 6.0, {}, "CK-2026-0001", "u", "2026-10-21")
    p1 = candidates.render(a1)
    assert " can " in p1 and "sync-tool" in p1 and "CK-2026-0001" in p1
    assert "may be safe on its own" not in p1
    assert "malicious" not in p1.lower() and "steal" not in p1.lower()
