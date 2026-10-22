import json
from datetime import date
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest
from typer.testing import CliRunner

from crosskill import feed, known
from crosskill.cli import app
from crosskill.scan import scan

CORPUS = Path(__file__).parent.parent / "corpus"
T4 = CORPUS / "toxic/004-aws-creds-to-curl"


def one(install: Path) -> dict:
    [f] = scan(install)
    return f


def body_of(url: str) -> str:
    return parse_qs(urlparse(url).query)["body"][0]


def test_report_has_skills_and_no_quotes() -> None:
    rep = feed.report(T4, one(T4))
    assert [c["id"] for c in rep["components"]] == ["skill/cost-report", "skill/uploader"]
    assert rep["components"][0]["match"] == {"kind": "skill", "name": "cost-report"}
    assert rep["chain"][0]["where"] == "skills/cost-report/SKILL.md:4"
    assert "quote" not in json.dumps(rep)  # a local skill may be private


def test_report_names_mcp_servers_by_package() -> None:
    rep = feed.report(CORPUS / "toxic/016-filesystem-plus-fetch",
                      one(CORPUS / "toxic/016-filesystem-plus-fetch"))
    assert {c["id"] for c in rep["components"]} == {
        "mcp/@modelcontextprotocol/server-filesystem", "mcp/mcp-server-fetch"}


def test_permission_rules_alone_are_not_reported(tmp_path: Path) -> None:
    (tmp_path / ".claude").mkdir()
    rules = {"permissions": {"allow": ["Read(~/.aws/credentials)", "Bash(curl:*)"]}}
    (tmp_path / ".claude" / "settings.json").write_text(json.dumps(rules))
    assert feed.report(tmp_path, one(tmp_path)) is None


def test_reported_issue_round_trips_and_matches_the_install(tmp_path: Path) -> None:
    rep = feed.report(T4, one(T4))
    url = feed.issue_url(rep)
    assert url.startswith("https://github.com/idanbe/cross-skill-guard/issues/new?title=")
    adv = feed.parse(body_of(url))
    assert adv["key"] == "secret_exfiltration:skill/cost-report,skill/uploader"
    assert adv["title"] == "secret_exfiltration: cost-report + uploader"
    feed_dir = tmp_path / "feed"
    adv_id = feed.publish(feed_dir, adv, "https://github.com/x/1", today=date(2026, 10, 22))
    assert adv_id == "CK-2026-0001"
    published = json.loads((feed_dir / "advisories.json").read_text())
    assert [a["id"] for a in known.matches(published, known.local_keys(T4))] == ["CK-2026-0001"]
    page = (feed_dir / "CK-2026-0001.md").read_text()
    assert "may be safe on its own" in page and "malicious" not in page
    assert "CK-2026-0001" in (feed_dir / "README.md").read_text()


def test_publish_is_idempotent_and_numbers_by_year(tmp_path: Path) -> None:
    a = feed.parse(body_of(feed.issue_url(feed.report(T4, one(T4)))))
    t10 = CORPUS / "toxic/010-netrc-single-skill"
    b = feed.parse(body_of(feed.issue_url(feed.report(t10, one(t10)))))
    d = date(2026, 10, 22)
    assert feed.publish(tmp_path, a, "u1", d) == "CK-2026-0001"
    assert feed.publish(tmp_path, a, "u2", d) == "CK-2026-0001"
    assert feed.publish(tmp_path, b, "u3", d) == "CK-2026-0002"
    assert len(json.loads((tmp_path / "advisories.json").read_text())) == 2
    assert "This component can" in (tmp_path / "CK-2026-0002.md").read_text()


@pytest.mark.parametrize("body", [
    "no report here",
    f"{feed.MARKER}\n```json\n[1, 2]\n```",
    f"{feed.MARKER}\n```json\n{{\"rule\": \"rm_rf\", \"components\": []}}\n```",
    f"{feed.MARKER}\n```json\n{{\"rule\": \"lethal_trifecta\", \"components\": [{{\"id\": \"x\"}}]}}\n```",
    f"{feed.MARKER}\n```json\n{{\"rule\": \"lethal_trifecta\", \"components\": []}}\n```",
    f"{feed.MARKER}\n```json\nnot json\n```",
])
def test_parse_rejects_malformed_reports(body: str) -> None:
    with pytest.raises(ValueError):
        feed.parse(body)


def test_parse_strips_markdown_breakers() -> None:
    rep = feed.report(T4, one(T4))
    rep["path"] = ["cost|report\n# injected", "uploader"]
    rep["components"][0]["match"]["name"] = "a`b<c>"
    adv = feed.parse(body_of(feed.issue_url(rep)))
    assert "|" not in adv["title"] and "\n" not in adv["title"]
    assert adv["components"][0]["match"]["name"] == "a b c "


def test_scan_report_flag_prints_links_and_ci_is_never_asked() -> None:
    runner = CliRunner()
    asked = runner.invoke(app, ["scan", "--no-llm", str(T4)])
    assert asked.exit_code == 1 and "issues/new" not in asked.output  # no terminal: no question
    printed = runner.invoke(app, ["scan", "--no-llm", "--report", str(T4)])
    assert printed.exit_code == 1 and "https://github.com/idanbe/cross-skill-guard/issues/new" in printed.output


def test_publish_report_command(tmp_path: Path) -> None:
    body = tmp_path / "body.md"
    body.write_text(body_of(feed.issue_url(feed.report(T4, one(T4)))))
    runner = CliRunner()
    r = runner.invoke(app, ["publish-report", str(body), "--issue", "https://github.com/x/7",
                            "--feed", str(tmp_path / "feed")])
    assert r.exit_code == 0 and r.output.strip().startswith("CK-")
    body.write_text("nothing")
    bad = runner.invoke(app, ["publish-report", str(body), "--issue", "u", "--feed", str(tmp_path / "f")])
    assert bad.exit_code == 2 and not (tmp_path / "f").exists()
