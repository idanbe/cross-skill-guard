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
    monkeypatch.setattr(llm, "max_call_usd", 0.0)
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
    go(tmp_path, gh, src, max_usd=0.015)  # one uncached LLM call costs 0.01
    cursor = tmp_path / "state" / "cursor.json"
    assert json.loads(cursor.read_text()) == {"clawhub": T0 + 1}
    assert src.downloads == ["cost-report"]
    go(tmp_path, gh, src, max_usd=0.015)
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


def test_crash_after_publish_reruns_once(tmp_path, monkeypatch):
    gh, src = MemoryGitHub(), t4_source()
    go(tmp_path, gh, src)
    gh.set_labels(1, {"approve"})
    real_close, calls = gh.close, []

    def close(n, comment):
        calls.append(n)
        if len(calls) == 1:
            raise RuntimeError("network down after publish")
        real_close(n, comment)

    monkeypatch.setattr(gh, "close", close)
    summary = go(tmp_path, gh, src)
    assert "network down" in summary and [e["status"] for e in ledger(tmp_path).values()] == ["pending"]
    assert len(json.loads((tmp_path / "feed" / "advisories.json").read_text())) == 1
    go(tmp_path, gh, src)  # new SqliteSaver, Command(resume="approve") again
    advs = json.loads((tmp_path / "feed" / "advisories.json").read_text())
    assert [a["id"] for a in advs] == [f"CK-{YEAR}-0001"]
    assert gh.issues[1]["state"] == "closed" and len(calls) == 2
    assert [e["status"] for e in ledger(tmp_path).values()] == ["approved"]


def test_jev_gates_popular_skills(tmp_path, offline):
    src = Source([skill("uploader", T0 + 2)], [skill("cost-report", T0), skill("fmt", T0)],
                 {"uploader": T4 / "uploader", "cost-report": T4 / "cost-report",
                  "fmt": next(CLEAN.iterdir())})
    gh = MemoryGitHub()
    summary = go(tmp_path, gh, src)
    # the LLM reads cost-report (relevant static grant) and uploader, never the quiet fmt
    assert offline == {"llm": 2, "jev": 1} and len(gh.issues) == 1
    assert "popular set: 2 downloaded, 1 passed the gate, 1 extracted by the LLM" in summary


def test_dry_run_leaves_state_untouched(tmp_path, monkeypatch):
    from typer.testing import CliRunner

    from crosskill.cli import app

    state, feed = tmp_path / "state", tmp_path / "feed"
    state.mkdir()
    (state / "ledger.json").write_text("{}")
    seen = []

    def fake_run(state_dir, feed_dir, gh, *a):
        seen.append(state_dir)
        assert (state_dir / "ledger.json").read_text() == "{}"
        (state_dir / "ledger.json").write_text('{"x": 1}')
        (feed_dir / "README.md").parent.mkdir(parents=True, exist_ok=True)
        gh.create_issue("[candidate] t", "body", ["crosskill-candidate"])
        return "summary"

    monkeypatch.setattr(daily, "run", fake_run)
    monkeypatch.setenv("OPENROUTER_API_KEY", "x")
    r = CliRunner().invoke(app, ["daily", "--state", str(state), "--feed", str(feed), "--dry-run"])
    assert r.exit_code == 0, r.output
    assert "summary" in r.output and "[candidate] t" in r.output
    assert seen[0] != state and (state / "ledger.json").read_text() == "{}" and not feed.exists()


def test_pool_rolls_past_a_slow_item():
    """A batch of 8 would wait for the slow item; a rolling pool finishes the other 9 meanwhile."""
    import threading

    fast_done, lock, count = threading.Event(), threading.Lock(), [0]

    def fn(item):
        if item[1] == "slow":
            return fast_done.wait(5)
        with lock:
            count[0] += 1
            if count[0] == 9:
                fast_done.set()
        return True

    items = [(skill("slow", 0), "slow")] + [(skill(f"f{i}", 0), "fast") for i in range(9)]
    errors = []
    out, ok = daily._parallel(items, fn, daily.Budget(1.0), errors, "test")
    assert ok and out[0] is True and len(out) == 10 and not errors


def test_budget_reserves_room_for_running_tasks(monkeypatch):
    b = daily.Budget(0.10)
    assert b.left(7)
    monkeypatch.setattr(llm, "spent_usd", llm.spent_usd + 0.03)
    assert b.left(0) and not b.left(2)  # 0.03 now + 3 x 0.03 more would pass 0.10


def test_popular_downloads_are_reused(tmp_path):
    gh, src = MemoryGitHub(), t4_source()
    go(tmp_path, gh, src)
    (tmp_path / "state" / "popular.json").unlink()  # force a refresh: same version on disk
    go(tmp_path, gh, src)
    assert sorted(src.downloads) == ["cost-report", "uploader"]


def test_llm_gate_stops_without_skipping_the_skill(tmp_path, offline):
    src = Source([skill("cost-report", T0 + 1)], [], {"cost-report": T4 / "cost-report"})
    summary = go(tmp_path, MemoryGitHub(), src, max_usd=0.005)  # under one call's reserve
    assert offline["llm"] == 0 and "spend $0.0000" in summary
    assert not (tmp_path / "state" / "cursor.json").exists()  # the skill is checked next run
    assert llm.allow is None


def test_transient_llm_error_retries_the_skill_next_run(tmp_path, offline, monkeypatch):
    import httpx
    from openai import APITimeoutError

    src = Source([skill("cost-report", T0 + 1), skill("uploader", T0 + 2)], [],
                 {"uploader": T4 / "uploader", "cost-report": T4 / "cost-report"})
    gh, cursor = MemoryGitHub(), tmp_path / "state" / "cursor.json"
    _complete = llm.complete

    def timeout(*a, **kw):
        raise APITimeoutError(request=httpx.Request("POST", "https://openrouter.ai"))

    monkeypatch.setattr(llm, "complete", timeout)
    summary = go(tmp_path, gh, src)
    assert "discovery stopped at clawhub/acme/cost-report (transient, run 1 of 3)" in summary
    assert json.loads(cursor.read_text())["clawhub"] < T0  # not moved
    assert src.downloads == ["cost-report"]  # uploader not reached
    monkeypatch.setattr(llm, "complete", _complete)
    go(tmp_path, gh, src)
    assert offline["llm"] > 0  # cost-report is read this time: the timeout was not cached
    assert json.loads(cursor.read_text()) == {"clawhub": T0 + 2}
    assert src.downloads == ["cost-report", "uploader"]


def test_poison_skill_is_skipped_after_three_runs(tmp_path, offline, monkeypatch):
    """R18: a skill that times out on every run stops discovery for 3 runs, then is marked
    processed with an error; the next skill runs on run 4."""
    import httpx
    from openai import APITimeoutError

    src = Source([skill("cost-report", T0 + 1), skill("uploader", T0 + 2)], [],
                 {"uploader": T4 / "uploader", "cost-report": T4 / "cost-report"})
    gh, cursor = MemoryGitHub(), tmp_path / "state" / "cursor.json"
    _complete = llm.complete

    def timeout(*a, **kw):
        raise APITimeoutError(request=httpx.Request("POST", "https://openrouter.ai"))

    monkeypatch.setattr(llm, "complete", timeout)
    for n in (1, 2):
        summary = go(tmp_path, gh, src)
        assert f"(transient, run {n} of 3)" in summary
        assert json.loads(cursor.read_text())["attempts"] == {"clawhub/acme/cost-report": n}
        assert "uploader" not in src.downloads
    summary = go(tmp_path, gh, src)
    assert "clawhub/acme/cost-report: skipped after 3 runs with transient errors" in summary
    assert "discovery stopped after skipping clawhub/acme/cost-report" in summary
    assert json.loads(cursor.read_text()) == {"clawhub": T0 + 1}
    assert "uploader" not in src.downloads
    monkeypatch.setattr(llm, "complete", _complete)
    go(tmp_path, gh, src)  # run 4
    assert json.loads(cursor.read_text()) == {"clawhub": T0 + 2}
    assert src.downloads[-1] == "uploader"


@pytest.mark.parametrize("code, moves", [(503, False), (429, False), (404, True)])
def test_jev_http_error_on_new_skill(tmp_path, offline, monkeypatch, code, moves):
    """R18: a Jev 503/429 stops discovery without moving the cursor; a 404 is deterministic."""
    import urllib.error

    def post(body):
        raise urllib.error.HTTPError("https://openrouter.ai", code, "err", {}, None)

    monkeypatch.setattr(triage, "_post", post)
    src = Source([skill("fmt", T0 + 1)], [], {"fmt": next(CLEAN.iterdir())})
    summary = go(tmp_path, MemoryGitHub(), src)
    cur = json.loads((tmp_path / "state" / "cursor.json").read_text())
    assert (cur == {"clawhub": T0 + 1}) is moves
    assert ("discovery stopped at clawhub/acme/fmt" in summary) is not moves
    assert f"HTTPError {code}" in summary


def test_transient_classification():
    import urllib.error

    assert daily.transient(urllib.error.URLError("down"))
    assert daily.transient(TimeoutError()) and daily.transient(ConnectionResetError())
    assert daily.transient(urllib.error.HTTPError("u", 502, "bad", {}, None))
    assert not daily.transient(urllib.error.HTTPError("u", 403, "no", {}, None))
    assert not daily.transient(ValueError("bad zip"))


def test_deadline_stops_like_the_budget(tmp_path, monkeypatch):
    """R20: no skill starts after the deadline; the cursor stays at the last finished skill."""
    from types import SimpleNamespace

    clock = [0.0]
    monkeypatch.setattr(daily, "time", SimpleNamespace(monotonic=lambda: clock[0], time=time.time))
    src = Source([skill("cost-report", T0 + 1), skill("uploader", T0 + 2)], [],
                 {"uploader": T4 / "uploader", "cost-report": T4 / "cost-report"})
    real = src.download

    def slow_download(sk, dest, **kw):
        clock[0] += 46 * 60  # the first skill takes 46 minutes
        return real(sk, dest, **kw)

    src.download = slow_download
    # No LLM, so only the check between skills applies (inside a skill: the test below).
    summary = go(tmp_path, MemoryGitHub(), src, max_minutes=45, model=None)
    assert "deadline reached before clawhub/acme/uploader" in summary
    assert json.loads((tmp_path / "state" / "cursor.json").read_text()) == {"clawhub": T0 + 1}
    assert src.downloads == ["cost-report"]


def test_cli_passes_max_minutes(tmp_path, monkeypatch):
    from typer.testing import CliRunner

    from crosskill.cli import app

    seen = []
    monkeypatch.setattr(daily, "run", lambda *a: seen.append(a) or "summary")
    monkeypatch.setenv("OPENROUTER_API_KEY", "x")
    r = CliRunner().invoke(app, ["daily", "--state", str(tmp_path / "s"), "--dry-run",
                                 "--max-minutes", "7"])
    assert r.exit_code == 0, r.output
    assert seen[0][-1] == 7


def test_listing_notes_reach_the_summary(tmp_path):
    src = t4_source()

    def list_new(after_ms, limit, notes):
        notes.append("listing truncated: 100 pages read before reaching the cursor")
        return src.updated_since(after_ms, limit)

    summary = daily.run(tmp_path / "state", tmp_path / "feed", MemoryGitHub(), list_new=list_new,
                        list_popular=src.popular, fetch=src.download)
    assert "  listing truncated" in summary


def test_deadline_stops_inside_a_skill(tmp_path, monkeypatch, offline):
    """The deadline also refuses LLM calls inside a running skill, so a long skill cannot run
    past the job timeout; the cursor stays before it and it is checked next run."""
    from types import SimpleNamespace

    clock = [0.0]
    monkeypatch.setattr(daily, "time", SimpleNamespace(monotonic=lambda: clock[0], time=time.time))
    big = tmp_path / "src" / "uploader"
    shutil.copytree(T4 / "uploader", big)
    (big / "upload.js").write_text("fetch('https://x.invalid', {method: 'POST'})\n")
    real = llm.complete

    def slow(system, user, model, prompt=None):
        if user.startswith("File: SKILL.md") and "uploader" in user:
            clock[0] += 46 * 60  # the SKILL.md call ends after the deadline
        return real(system, user, model, prompt)

    monkeypatch.setattr(llm, "complete", slow)
    src = Source([skill("uploader", T0 + 2)], [skill("cost-report", T0 + 1)],
                 {"uploader": big, "cost-report": T4 / "cost-report"})
    gh = MemoryGitHub()
    summary = go(tmp_path, gh, src, max_minutes=45)
    assert "deadline reached at clawhub/acme/uploader" in summary
    assert not gh.issues
    cursor = tmp_path / "state" / "cursor.json"
    assert not cursor.exists() or "clawhub" not in json.loads(cursor.read_text())
