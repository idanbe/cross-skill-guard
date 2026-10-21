import json
import shutil
import time
from datetime import date
from pathlib import Path

import pytest

pytest.importorskip("langgraph")
pytest.importorskip("langgraph.checkpoint.sqlite")

from crosskill import candidates, daily, llm, triage
from crosskill.github import MemoryGitHub
from crosskill.sources import Skill

CORPUS = Path(__file__).parent.parent / "corpus"
T4 = CORPUS / "toxic/004-aws-creds-to-curl/skills"
CLEAN = CORPUS / "clean/001-readonly-formatter/skills"
T0 = int(time.time() * 1000) - 3_600_000  # an hour ago, inside the first run's 24 h window
YEAR = date.today().year


def skill(name: str, t: int, version: str = "1.0.0") -> Skill:
    return Skill("acme", name, version, 5000, t, f"https://clawhub.ai/acme/skills/{name}")


class Source:
    """Fake ClawHub: listings from lists, downloads copied from corpus dirs."""

    def __init__(self, new: list[Skill], popular: list[Skill], dirs: dict[str, Path]):
        self.new, self.popular_skills, self.dirs, self.downloads = new, popular, dirs, []

    def updated_since(self, after_ms, limit, **_):
        return sorted((s for s in self.new if s.updated_at > after_ms), key=lambda s: s.updated_at)[:limit]

    def popular(self, n=200, **_):
        return self.popular_skills[:n]

    def download(self, sk: Skill, dest: Path, **_) -> Path:
        self.downloads.append(sk.slug)
        out = dest / sk.dirname
        shutil.copytree(self.dirs[sk.slug], out, ignore=shutil.ignore_patterns("expected_facts.json"))
        return out


@pytest.fixture(autouse=True)
def offline(monkeypatch, tmp_path):
    """No network: empty popular MCP set, LLM and Jev stubs that cost money per uncached call."""
    mcp = tmp_path / "popular-mcp.json"
    mcp.write_text(json.dumps({"mcpServers": {}}))
    monkeypatch.setattr(candidates, "POPULAR", mcp)
    monkeypatch.setattr(llm, "CACHE", tmp_path / "unused-cache")
    monkeypatch.setattr(llm, "spent_usd", 0.0)
    monkeypatch.setattr(triage, "spent_usd", 0.0)
    calls = {"llm": 0, "jev": 0}

    def complete(system, user, model, prompt=None):
        calls["llm"] += 1
        return {"facts": [], "cost": 0.01, "latency": 0}

    def post(body):
        calls["jev"] += 1
        return {"answers": {k: {"type": "noul", "noul": 0.0} for k in triage.ROLES},
                "usage": {"cost": 0.0001}}

    monkeypatch.setattr(llm, "complete", complete)
    monkeypatch.setattr(triage, "_post", post)
    return calls


def go(tmp_path, gh, src, **kw):
    return daily.run(tmp_path / "state", tmp_path / "feed", gh, list_new=src.updated_since,
                     list_popular=src.popular, fetch=src.download, **kw)


def ledger(tmp_path) -> dict:
    return json.loads((tmp_path / "state" / "ledger.json").read_text())


def t4_source() -> Source:
    return Source([skill("uploader", T0 + 2)], [skill("cost-report", T0 + 1)],
                  {"uploader": T4 / "uploader", "cost-report": T4 / "cost-report"})


def test_candidate_waits_for_label(tmp_path):
    gh = MemoryGitHub()
    go(tmp_path, gh, t4_source())
    assert gh.known_labels == {"approve", "reject", "crosskill-candidate"}
    [(n, issue)] = gh.issues.items()
    assert issue["title"] == "[candidate] secret_exfiltration: cost-report + uploader"
    assert issue["labels"] == {"crosskill-candidate"}
    assert "Add the `approve` label to publish" in issue["body"] and "CK-draft" in issue["body"]
    assert not (tmp_path / "feed" / "advisories.json").exists()
    [(key, entry)] = ledger(tmp_path).items()
    assert key == "secret_exfiltration:clawhub/acme/cost-report,clawhub/acme/uploader"
    assert entry == {"status": "pending", "issue": n, "advisory": None}


def test_approve_publishes_on_next_run(tmp_path):
    gh, src = MemoryGitHub(), t4_source()
    go(tmp_path, gh, src)
    gh.set_labels(1, {"crosskill-candidate", "approve"})
    summary = go(tmp_path, gh, src)  # a new run opens a new SqliteSaver on the same file
    assert "published 1" in summary
    page = tmp_path / "feed" / f"CK-{YEAR}-0001.md"
    assert page.exists() and "cost-report" in page.read_text()
    advs = json.loads((tmp_path / "feed" / "advisories.json").read_text())
    assert [a["id"] for a in advs] == [f"CK-{YEAR}-0001"] and advs[0]["issue"] == "memory://issues/1"
    assert f"CK-{YEAR}-0001" in (tmp_path / "feed" / "README.md").read_text()
    [entry] = ledger(tmp_path).values()
    assert entry == {"status": "approved", "issue": 1, "advisory": f"CK-{YEAR}-0001"}
    assert gh.issues[1]["state"] == "closed"


def test_reject_closes_and_never_returns(tmp_path):
    gh, src = MemoryGitHub(), t4_source()
    go(tmp_path, gh, src)
    gh.set_labels(1, {"crosskill-candidate", "reject"})
    go(tmp_path, gh, src)
    assert gh.issues[1]["state"] == "closed" and gh.issues[1]["comments"]
    assert not (tmp_path / "feed" / "advisories.json").exists()
    [entry] = ledger(tmp_path).values()
    assert entry["status"] == "rejected"
    src.new.append(skill("uploader", T0 + 3, version="1.1.0"))  # an update, same combination
    go(tmp_path, gh, src)
    assert "uploader" in src.downloads[-1] and len(gh.issues) == 1


@pytest.mark.parametrize("labels", [{"approve", "reject"}, set()])
def test_both_or_no_label_keeps_waiting(tmp_path, labels):
    gh, src = MemoryGitHub(), t4_source()
    go(tmp_path, gh, src)
    gh.set_labels(1, labels | {"crosskill-candidate"})
    go(tmp_path, gh, src)
    assert gh.issues[1]["state"] == "open"
    assert [e["status"] for e in ledger(tmp_path).values()] == ["pending"]
    assert not (tmp_path / "feed" / "advisories.json").exists()
    gh.set_labels(1, {"approve"})
    go(tmp_path, gh, src)  # still resumable afterwards
    assert [e["status"] for e in ledger(tmp_path).values()] == ["approved"]


def adv(key: str = "k") -> dict:
    return {"id": "CK-draft", "key": key, "published": "2026-10-21", "title": "secret_exfiltration: a + b",
            "rule": "secret_exfiltration", "components": [], "path": ["a", "b"],
            "resource": "~/.aws/credentials", "sink": "*", "chain": [], "score": 6.0, "breakdown": {},
            "issue": "memory://issues/1"}


def test_publish_is_idempotent(tmp_path):
    feed = tmp_path / "feed"
    daily.publish(feed, adv())
    daily.publish(feed, adv())
    daily.publish(feed, adv("k2"))
    advs = json.loads((feed / "advisories.json").read_text())
    assert [a["id"] for a in advs] == ["CK-2026-0001", "CK-2026-0002"]
    assert sorted(p.name for p in feed.glob("CK-*.md")) == ["CK-2026-0001.md", "CK-2026-0002.md"]
    readme = (feed / "README.md").read_text()
    assert readme.index("CK-2026-0002") < readme.index("CK-2026-0001")  # newest first


def test_budget_stops_and_cursor_resumes(tmp_path, offline):
    src = Source([skill("cost-report", T0 + 1), skill("uploader", T0 + 2)], [],
                 {"uploader": T4 / "uploader", "cost-report": T4 / "cost-report"})
    gh = MemoryGitHub()
    go(tmp_path, gh, src, max_usd=0.01)  # one uncached LLM call costs 0.01
    cursor = tmp_path / "state" / "cursor.json"
    assert json.loads(cursor.read_text()) == {"clawhub": T0 + 1}
    assert src.downloads == ["cost-report"]
    go(tmp_path, gh, src, max_usd=0.01)
    assert json.loads(cursor.read_text()) == {"clawhub": T0 + 2}
    assert src.downloads == ["cost-report", "uploader"]


def test_jev_gate_skips_quiet_skill(tmp_path, offline):
    src = Source([skill("fmt", T0 + 1)], [], {"fmt": next(CLEAN.iterdir())})
    gh = MemoryGitHub()
    go(tmp_path, gh, src)
    assert offline == {"llm": 0, "jev": 1} and not gh.issues
    assert json.loads((tmp_path / "state" / "cursor.json").read_text()) == {"clawhub": T0 + 1}


def test_one_bad_skill_does_not_stop_the_run(tmp_path):
    src = Source([skill("broken", T0 + 1), skill("uploader", T0 + 2)], [skill("cost-report", T0)],
                 {"uploader": T4 / "uploader", "cost-report": T4 / "cost-report"})
    gh = MemoryGitHub()
    summary = go(tmp_path, gh, src)  # "broken" has no source dir: its download raises
    assert "acme/broken" in summary and len(gh.issues) == 1
    assert json.loads((tmp_path / "state" / "cursor.json").read_text()) == {"clawhub": T0 + 2}
