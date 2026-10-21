"""Daily feed run: check new ClawHub skills against the popular set and hold each candidate in a
LangGraph thread until a maintainer labels its GitHub issue `approve` or `reject`.

State lives in one directory (a `data` branch in CI): checkpoints.sqlite, ledger.json,
cursor.json, popular.json, skills/ (downloads, data only) and cache/ (LLM and Jev answers).
"""

import json
import tempfile
import time
from dataclasses import asdict
from datetime import date, timedelta
from pathlib import Path
from typing import TypedDict

from langchain_core.runnables import RunnableConfig
from langgraph.checkpoint.sqlite import SqliteSaver
from langgraph.graph import END, START, StateGraph
from langgraph.types import Command, interrupt

from crosskill import candidates, llm, sources, triage
from crosskill.evals import relevant
from crosskill.extract import extract
from crosskill.sources import Skill

LABELS = ["approve", "reject", "crosskill-candidate"]
MAX_PER_SKILL = 3
POPULAR_MAX_AGE = timedelta(days=7)
DAY_MS = 86_400_000


class Candidate(TypedDict, total=False):
    key: str
    finding: dict
    components: list
    score: float
    breakdown: dict
    issue: int | None
    issue_url: str | None
    decision: str | None


def _draft(s: Candidate, adv_id: str, issue_url: str) -> dict:
    return candidates.advisory(s["finding"], s["components"], s["score"], s["breakdown"],
                               adv_id, issue_url, date.today().isoformat())


def open_issue(s: Candidate, config: RunnableConfig) -> dict:
    gh = config["configurable"]["gh"]
    draft = _draft(s, "CK-draft", "this issue")
    b = s["breakdown"]
    body = "\n".join([
        candidates.render(draft),
        (f"Score breakdown: severity {b['severity']}, reach {b['reach']:.2f}, "
         f"confidence {b['confidence']:.2f} (candidates under {candidates.MIN_SCORE} are dropped)."),
        "", "Add the `approve` label to publish, `reject` to drop it for good."])
    n, url = gh.create_issue(f"[candidate] {draft['title']}", body, ["crosskill-candidate"])
    return {"issue": n, "issue_url": url}


def wait(s: Candidate) -> dict:
    return {"decision": interrupt({"issue": s["issue"]})}


def publish_node(s: Candidate, config: RunnableConfig) -> dict:
    adv_id = publish(config["configurable"]["feed_dir"], _draft(s, "CK-draft", s["issue_url"]))
    config["configurable"]["gh"].close(s["issue"], f"Published as {adv_id}.")
    return {}


def close_node(s: Candidate, config: RunnableConfig) -> dict:
    config["configurable"]["gh"].close(
        s["issue"], "Rejected. crosskill will not raise this combination again.")
    return {}


def graph(checkpointer):
    g = StateGraph(Candidate)
    g.add_node("open_issue", open_issue)
    g.add_node("wait", wait)
    g.add_node("publish", publish_node)
    g.add_node("close", close_node)
    g.add_edge(START, "open_issue")
    g.add_edge("open_issue", "wait")
    g.add_conditional_edges("wait", lambda s: "publish" if s["decision"] == "approve" else "close",
                            ["publish", "close"])
    g.add_edge("publish", END)
    g.add_edge("close", END)
    return g.compile(checkpointer=checkpointer)


def publish(feed_dir: Path, adv: dict) -> str:
    """Add the advisory to the feed unless its key is there already; returns its id."""
    index = feed_dir / "advisories.json"
    advs = json.loads(index.read_text()) if index.exists() else []
    for a in advs:
        if a["key"] == adv["key"]:
            return a["id"]
    prefix = f"CK-{adv['published'][:4]}-"
    n = 1 + max((int(a["id"].removeprefix(prefix)) for a in advs if a["id"].startswith(prefix)),
                default=0)
    adv = {**adv, "id": f"{prefix}{n:04d}"}
    feed_dir.mkdir(parents=True, exist_ok=True)
    (feed_dir / f"{adv['id']}.md").write_text(candidates.render(adv))
    advs.append(adv)
    index.write_text(json.dumps(advs, indent=2) + "\n")
    rows = [f"| [{a['id']}]({a['id']}.md) | {a['published']} | {a['title']} | {a['score']} |"
            for a in reversed(advs)]
    (feed_dir / "README.md").write_text("\n".join([
        "# crosskill advisories", "", ("Toxic combinations found in new marketplace skills, newest "
                                         "first. Machine-readable list: [advisories.json](advisories.json)."), "",
        "| Advisory | Published | Combination | Score |", "| --- | --- | --- | --- |", *rows]) + "\n")
    return adv["id"]


def _load(path: Path, default):
    return json.loads(path.read_text()) if path.exists() else default


def _save(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n")


def _cfg(key: str, gh, feed_dir: Path) -> dict:
    return {"configurable": {"thread_id": key, "gh": gh, "feed_dir": feed_dir}}


def resume_waiting(state_dir: Path, gh, feed_dir: Path, errors: list[str] | None = None) -> int:
    """Resume every pending candidate whose issue carries exactly one of approve/reject."""
    errors = [] if errors is None else errors
    ledger_path = state_dir / "ledger.json"
    ledger, resumed = _load(ledger_path, {}), 0
    with SqliteSaver.from_conn_string(str(state_dir / "checkpoints.sqlite")) as cp:
        g = graph(cp)
        for key, entry in ledger.items():
            if entry["status"] != "pending":
                continue
            try:
                decision = {"approve", "reject"} & gh.labels(entry["issue"])
                if len(decision) != 1:
                    continue  # no label, or both: keep waiting for a clear decision
                [decision] = decision
                g.invoke(Command(resume=decision), _cfg(key, gh, feed_dir))
            except Exception as e:  # noqa: BLE001 - one broken thread must not block the others
                errors.append(f"resume {key}: {e!r}")
                continue
            advs = _load(feed_dir / "advisories.json", [])
            entry["status"] = "approved" if decision == "approve" else "rejected"
            entry["advisory"] = next((a["id"] for a in advs if a["key"] == key), None)
            resumed += 1
            _save(ledger_path, ledger)
    return resumed


def _spent() -> float:
    return llm.spent_usd + triage.spent_usd


class Budget:
    """Per-run cap. Keeps room for one more skill as costly as the costliest so far."""

    def __init__(self, max_usd: float):
        self.mark = _spent()
        self.limit, self.step = self.mark + max_usd, 0.0

    def left(self) -> bool:
        now = _spent()
        self.step, self.mark = max(self.step, now - self.mark), now
        return now + self.step < self.limit


def _solo(tmp: Path, dirname: str, d: Path) -> Path:
    """An install holding one skill, for per-skill extraction."""
    root = Path(tempfile.mkdtemp(dir=tmp))
    (root / "skills").mkdir()
    (root / "skills" / dirname).symlink_to(d.resolve())
    return root


def _get(sk: Skill, state_dir: Path, fetch) -> Path:
    dest = state_dir / "skills" / f"{sk.dirname}@{sk.version}"
    return dest / sk.dirname if (dest / sk.dirname).exists() else fetch(sk, dest)


def _popular_set(state_dir, model, budget, list_popular, fetch, errors, tmp):
    """Popular skills and their dirs, refreshed weekly; their LLM facts count toward the budget.

    Returns None when the budget ran out before every popular skill was extracted."""
    path = state_dir / "popular.json"
    pop = _load(path, None)
    if pop is None or date.today() - date.fromisoformat(pop["fetched"]) >= POPULAR_MAX_AGE:
        try:
            pop = {"fetched": date.today().isoformat(),
                   "skills": [asdict(s) for s in list_popular(200)]}
            _save(path, pop)
        except Exception as e:  # noqa: BLE001 - keep last week's set
            errors.append(f"popular listing: {e!r}")
            if pop is None:
                return None
    skills, dirs = {}, {}
    for d in pop["skills"]:
        sk = Skill(**d)
        if not budget.left():
            return None
        try:
            dirs[sk.dirname] = _get(sk, state_dir, fetch)
            if model:
                extract(_solo(tmp, sk.dirname, dirs[sk.dirname]), model)  # warms the LLM cache
            skills[sk.dirname] = sk
        except Exception as e:  # noqa: BLE001 - left out, so it cannot break every check
            dirs.pop(sk.dirname, None)
            errors.append(f"popular {sk.id}: {e!r}")
    return skills, dirs


def _check(sk, state_dir, pop, model, gh, feed_dir, g, ledger, fetch, tmp) -> list[str]:
    """Check one new skill; start a thread for each new candidate. Returns their keys."""
    skills, dirs = pop
    d = _get(sk, state_dir, fetch)
    if not any(relevant(x.kind, x.arg) for x in extract(_solo(tmp, sk.dirname, d))):
        skill_md = d / "SKILL.md"
        if not skill_md.exists() or not triage.passes(triage.roles(skill_md.read_text(errors="replace"))):
            return []
    root = Path(tempfile.mkdtemp(dir=tmp))
    candidates.build_install(root, {**dirs, sk.dirname: d})
    skills = {**skills, sk.dirname: sk}
    mcp = json.loads(candidates.POPULAR.read_text())["mcpServers"]
    found = []
    for f in candidates.check(root, sk.dirname, model):
        comps = candidates.components(f, skills, mcp)
        k = candidates.key(f, comps)
        if k not in ledger and k not in {c["key"] for c in found}:
            s, b = candidates.score(f, comps)
            found.append(Candidate(key=k, finding=f, components=comps, score=s, breakdown=b))
    found.sort(key=lambda c: -c["score"])
    keys = []
    for c in found:
        if c["score"] < candidates.MIN_SCORE or len(keys) >= MAX_PER_SKILL:
            ledger[c["key"]] = {"status": "dropped", "issue": None, "advisory": None}
            continue
        g.invoke(c, _cfg(c["key"], gh, feed_dir))  # runs open_issue, stops at wait
        issue = g.get_state(_cfg(c["key"], gh, feed_dir)).values["issue"]
        ledger[c["key"]] = {"status": "pending", "issue": issue, "advisory": None}
        keys.append(c["key"])
    return keys


def discover(state_dir: Path, gh, feed_dir: Path, max_usd: float, max_skills: int, model: str | None,
             errors: list[str] | None = None, list_new=sources.updated_since,
             list_popular=sources.popular, fetch=sources.download) -> list[str]:
    """Check skills updated since the cursor, oldest first, within the budget and skill cap."""
    errors = [] if errors is None else errors
    budget = Budget(max_usd)  # per run, whatever this process spent before
    cursor_path, ledger_path = state_dir / "cursor.json", state_dir / "ledger.json"
    cursor = _load(cursor_path, {"clawhub": int(time.time() * 1000) - DAY_MS})
    ledger, keys = _load(ledger_path, {}), []
    with tempfile.TemporaryDirectory() as tmp, \
            SqliteSaver.from_conn_string(str(state_dir / "checkpoints.sqlite")) as cp:
        pop = _popular_set(state_dir, model, budget, list_popular, fetch, errors, Path(tmp))
        if pop is None:
            errors.append("discovery stopped: no popular set (budget or listing)")
            return keys
        try:
            new = list_new(cursor["clawhub"], max_skills)
        except Exception as e:  # noqa: BLE001 - ends discovery, not the run
            errors.append(f"listing: {e!r}")
            return keys
        g = graph(cp)
        for i, sk in enumerate(new):
            if i >= max_skills or not budget.left():
                break
            try:
                keys += _check(sk, state_dir, pop, model, gh, feed_dir, g, ledger, fetch, Path(tmp))
            except Exception as e:  # noqa: BLE001 - the skill counts as processed
                errors.append(f"{sk.id}: {e!r}")
            _save(ledger_path, ledger)
            cursor["clawhub"] = sk.updated_at
            _save(cursor_path, cursor)
    return keys


def run(state_dir: Path, feed_dir: Path, gh, max_usd: float = 0.5, max_skills: int = 50,
        model: str | None = llm.DEFAULT_MODEL, **sources_) -> str:
    """One daily run: resume labelled candidates, then discover new ones. Returns a summary."""
    state_dir.mkdir(parents=True, exist_ok=True)
    saved_cache, start, errors = llm.CACHE, _spent(), []
    llm.CACHE = state_dir / "cache" / "crosskill" / "llm"  # Jev answers go next to it
    try:
        gh.ensure_labels(LABELS)
        before = len(_load(feed_dir / "advisories.json", []))
        resumed = resume_waiting(state_dir, gh, feed_dir, errors)
        published = len(_load(feed_dir / "advisories.json", [])) - before
        keys = discover(state_dir, gh, feed_dir, max_usd, max_skills, model, errors, **sources_)
    finally:
        llm.CACHE = saved_cache
    head = (f"resumed {resumed}, published {published}, new candidates {len(keys)}, "
            f"spend ${_spent() - start:.4f}")
    lines = [head]
    lines += [f"  candidate {k}" for k in keys] + [f"  error {e}" for e in errors]
    return "\n".join(lines)
