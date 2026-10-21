import json
from pathlib import Path

from typer.testing import CliRunner

from crosskill import known
from crosskill.cli import app

runner = CliRunner()
SK = {"kind": "skill", "name": "a"}
MCP = {"kind": "mcp", "package": "pkg-x", "host": None}
HOST = {"kind": "mcp", "package": None, "host": "h.example"}


def adv(*matches) -> dict:
    return {"id": "CK-2026-0001", "title": "t", "components": [
        {"id": "x", "url": "u", "match": m} for m in matches]}


def test_match_requires_all_components() -> None:
    a = adv(SK, MCP)
    assert known.matches([a], {("skill", "a"), ("mcp", "pkg-x")}) == [a]
    assert known.matches([a], {("skill", "a")}) == []
    assert known.matches([adv()], {("skill", "a")}) == []


def test_mcp_matches_package_or_host() -> None:
    assert known.matches([adv(MCP)], {("mcp", "pkg-x")})
    assert known.matches([adv(HOST)], {("mcp", "h.example")})
    assert not known.matches([adv(HOST)], {("mcp", "other")})


def test_local_keys(tmp_path: Path) -> None:
    (tmp_path / ".mcp.json").write_text(json.dumps({"mcpServers": {
        "a": {"command": "npx", "args": ["-y", "pkg-x@1.2"]},
        "b": {"url": "https://h.example/mcp"}}}))
    g = [type("G", (), {"comp": "sk", "file": "skills/sk/SKILL.md"})(),
         type("G", (), {"comp": "srv", "file": ".mcp.json"})()]
    assert known.local_keys(tmp_path, g) == {("skill", "sk"), ("mcp", "pkg-x"), ("mcp", "h.example")}


def test_load_failure_is_empty(tmp_path: Path) -> None:
    cache = tmp_path / "feed.json"
    assert known.load("http://127.0.0.1:9/none", cache) == []
    bad = tmp_path / "bad.json"
    bad.write_text("not json")
    assert known.load(bad.as_uri(), cache) == []
    good = tmp_path / "good.json"
    good.write_text('[{"id": "CK-1"}]')
    assert known.load(good.as_uri(), cache) == [{"id": "CK-1"}]
    assert known.load("http://127.0.0.1:9/none", cache) == [{"id": "CK-1"}]  # stale cache
    good.write_text('{"not": "a list"}')
    assert known.load(good.as_uri(), tmp_path / "c2.json") == []


def test_scan_offline_unchanged(tmp_path: Path, monkeypatch) -> None:
    args = ["scan", "--no-llm", "corpus/toxic/020-two-findings"]
    base = runner.invoke(app, args)
    monkeypatch.setenv("CROSSKILL_OFFLINE", "0")
    monkeypatch.setattr(known, "FEED_URL", "http://127.0.0.1:9/none")
    monkeypatch.setattr(known, "CACHE_FILE", tmp_path / "feed.json")
    broken = runner.invoke(app, args)
    assert (broken.output, broken.exit_code) == (base.output, base.exit_code)
    assert base.exit_code == 1


def test_scan_prints_possible_match(tmp_path: Path, monkeypatch) -> None:
    a = adv({"kind": "skill", "name": "x"})
    a["title"] = "Bad combo"
    feed = tmp_path / "f.json"
    monkeypatch.setattr(known, "load", lambda *a_, **k: [a])
    monkeypatch.setenv("CROSSKILL_OFFLINE", "0")
    # any skill name: use whatever the install has
    g = known.local_keys
    monkeypatch.setattr(known, "local_keys", lambda r, gr: g(r, gr) | {("skill", "x")})
    out = runner.invoke(app, ["scan", "--no-llm", "--offline", "corpus/toxic/020-two-findings"])
    assert "possible match" not in out.output
    out = runner.invoke(app, ["scan", "--no-llm", "corpus/toxic/020-two-findings"])
    assert "possible match: CK-2026-0001 Bad combo u" in out.output
    assert out.exit_code == 1 and not feed.exists()


def test_malformed_advisories_never_break_scan(monkeypatch) -> None:
    args = ["scan", "--no-llm", "corpus/toxic/020-two-findings"]
    base = runner.invoke(app, args)
    mk = lambda **kw: {"components": [{"match": {"kind": "skill", "name": "x"}, **kw}], **kw}
    feed = [{"id": "CK-1", "components": [{"match": {"kind": "skill", "name": "x"}}]},
            {"title": "t", "components": [{"match": {"kind": "skill", "name": "x"}, "url": "u"}]},
            {"id": "CK-3", "components": [{}]}, {"id": "CK-4", "components": ["bad"]}, mk()]
    monkeypatch.setattr(known, "load", lambda *a, **k: feed)
    monkeypatch.setenv("CROSSKILL_OFFLINE", "0")
    g = known.local_keys
    monkeypatch.setattr(known, "local_keys", lambda r, gr: g(r, gr) | {("skill", "x")})
    out = runner.invoke(app, args)
    assert out.exit_code == base.exit_code == 1
    assert out.output.startswith(base.output.rstrip("\n"))
    assert out.exception is None or isinstance(out.exception, SystemExit)
