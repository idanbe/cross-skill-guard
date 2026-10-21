"""Daily feed run: check new ClawHub skills against the popular set and hold each candidate in a
LangGraph thread until a maintainer labels its GitHub issue `approve` or `reject`.

State lives in one directory (a `data` branch in CI): checkpoints.sqlite, ledger.json,
cursor.json, popular.json, skills/ (downloads, data only) and cache/ (LLM and Jev answers).
"""

import json
import os
import tempfile
import time
import urllib.error
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor
from concurrent.futures import wait as wait_any
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
WORKERS = 8
CALL_RESERVE_USD = llm.CALL_RESERVE_USD
MAX_ATTEMPTS = 3  # runs a skill may stop discovery with transient errors before it is skipped
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


def transient(e: BaseException) -> bool:
    """A network failure worth retrying on a later run: timeouts, connection errors, HTTP 429 or
    5xx from OpenRouter (LLM or Jev), ClawHub or GitHub. Anything else is deterministic."""
    if isinstance(e, urllib.error.HTTPError):
        return e.code == 429 or e.code >= 500
    if isinstance(e, (urllib.error.URLError, TimeoutError, ConnectionError)):
        return True
    return llm.transient(e)


def _spent() -> float:
    return llm.spent_usd + triage.spent_usd


class Budget:
    """Per-run cap and wall-clock deadline (time.monotonic()). Keeps room for each running task
    plus one more, each as costly as the costliest step seen so far."""

    def __init__(self, max_usd: float, deadline: float | None = None):
        self.mark = _spent()
        self.limit, self.step, self.deadline = self.mark + max_usd, 0.0, deadline
        self.reason = ""  # why left() last said no: "budget" or "deadline"

    def why(self) -> str:
        """What stopped the run: the deadline if it has passed, else the budget."""
        if self.deadline is not None and time.monotonic() >= self.deadline:
            return "deadline"
        return self.reason or "budget"

    def left(self, running: int = 0) -> bool:
        if self.deadline is not None and time.monotonic() >= self.deadline:
            self.reason = "deadline"
            return False
        now = _spent()
        self.step, self.mark = max(self.step, now - self.mark), now
        self.reason = "" if now + self.step * (running + 1) < self.limit else "budget"
        return not self.reason


def _solo(tmp: Path, dirname: str, d: Path) -> Path:
    """An install holding one skill, for per-skill extraction."""
    root = Path(tempfile.mkdtemp(dir=tmp))
    (root / "skills").mkdir()
    (root / "skills" / dirname).symlink_to(d.resolve())
    return root


def _get(sk: Skill, state_dir: Path, fetch) -> Path:
    dest = state_dir / "skills" / f"{sk.dirname}@{sk.version}"
    return dest / sk.dirname if (dest / sk.dirname).exists() else fetch(sk, dest)


def _parallel(items: list, fn, budget: Budget, errors: list[str], what: str) -> tuple[dict, bool]:
    """fn on each (Skill, ...) item in a rolling pool of WORKERS, checking the budget per submit.

    Returns {index: result} for the items that did not raise, and False when the budget ran out."""
    out, todo, running, ok = {}, list(enumerate(items)), {}, True
    with ThreadPoolExecutor(WORKERS) as ex:
        while todo or running:
            while ok and todo and len(running) < WORKERS:
                if not budget.left(len(running)):
                    ok = False
                    break
                i, it = todo.pop(0)
                running[ex.submit(fn, it)] = i
            if not running:
                break
            done, _ = wait_any(running, return_when=FIRST_COMPLETED)
            for fut in done:
                i = running.pop(fut)
                try:
                    out[i] = fut.result()
                except llm.OverBudget:
                    ok = False
                except Exception as e:  # noqa: BLE001 - that skill is left out, the rest go on
                    errors.append(f"{what} {items[i][0].id}: {e!r}")
    return out, ok


def _gate(d: Path, dirname: str, tmp: Path) -> bool:
    """Worth an LLM read: a relevant static grant, or a role Jev sees in SKILL.md."""
    if any(relevant(x.kind, x.arg) for x in extract(_solo(tmp, dirname, d))):
        return True
    skill_md = d / "SKILL.md"
    return skill_md.exists() and triage.passes(triage.roles(skill_md.read_text(errors="replace")))


def _popular_set(state_dir, model, budget, list_popular, fetch, errors, tmp, notes):
    """Popular skills, their dirs and the dirnames the LLM reads, refreshed weekly.

    Jev gates each skill; the gated ones are extracted in parallel within the budget (cached
    after the first run). Returns None only when there is no popular listing at all."""
    path = state_dir / "popular.json"
    pop = _load(path, None)
    if pop is None or date.today() - date.fromisoformat(pop["fetched"]) >= POPULAR_MAX_AGE:
        try:
            pop = {"fetched": date.today().isoformat(),
                   "skills": [asdict(s) for s in list_popular(200, notes=notes)]}
            _save(path, pop)
        except Exception as e:  # noqa: BLE001 - keep last week's set
            errors.append(f"popular listing: {e!r}")
            if pop is None:
                return None
    entries = []
    with ThreadPoolExecutor(WORKERS) as ex:  # downloads are free; _get skips skill@version on disk
        futs = [(sk, ex.submit(_get, sk, state_dir, fetch))
                for sk in (Skill(**d) for d in pop["skills"])]
    for sk, fut in futs:
        try:
            entries.append((sk, fut.result()))
        except Exception as e:  # noqa: BLE001 - left out, so it cannot break every check
            errors.append(f"popular {sk.id}: {e!r}")
    if not model:
        return {sk.dirname: sk for sk, _ in entries}, {sk.dirname: d for sk, d in entries}, set()
    # A warm-up cut short by the budget or the deadline still returns what is ready: skills without
    # LLM facts take part with their static facts, and the next run finishes them from the cache.
    gate, ok = _parallel(entries, lambda e: _gate(e[1], e[0].dirname, tmp), budget, errors, "triage")
    read = [entries[i] for i, passed in sorted(gate.items()) if passed]
    warm = {}
    if ok:
        warm, ok = _parallel(read, lambda e: extract(_solo(tmp, e[0].dirname, e[1]), model), budget,
                             errors, "extract")
    notes.append(f"popular set: {len(entries)} downloaded, {len(gate)} triaged, {len(read)} passed "
                 f"the gate, {len(warm)} extracted by the LLM"
                 + ("" if ok else f" before the {budget.why()} was reached"))
    llm_set = {read[i][0].dirname for i in warm}
    return {sk.dirname: sk for sk, _ in entries}, {sk.dirname: d for sk, d in entries}, llm_set


def _check(sk, state_dir, pop, model, gh, feed_dir, g, ledger, fetch, tmp) -> list[str]:
    """Check one new skill; start a thread for each new candidate. Returns their keys."""
    skills, dirs, llm_set = pop
    d = _get(sk, state_dir, fetch)
    if not _gate(d, sk.dirname, tmp):
        return []
    root = Path(tempfile.mkdtemp(dir=tmp))
    candidates.build_install(root, {**dirs, sk.dirname: d})
    skills = {**skills, sk.dirname: sk}
    mcp = json.loads(candidates.POPULAR.read_text())["mcpServers"]
    found = []
    llm_for = (llm_set | {sk.dirname}).__contains__
    for f in candidates.check(root, sk.dirname, model, llm_for):
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
             errors: list[str] | None = None, notes: list[str] | None = None,
             list_new=sources.updated_since,
             list_popular=sources.popular, fetch=sources.download,
             deadline: float | None = None) -> list[str]:
    """Check skills updated since the cursor, oldest first, within the budget, the skill cap and
    the deadline (time.monotonic()); the cursor stays at the last fully processed skill."""
    errors = [] if errors is None else errors
    notes = [] if notes is None else notes
    budget = Budget(max_usd, deadline)  # per run, whatever this process spent before
    cursor_path, ledger_path = state_dir / "cursor.json", state_dir / "ledger.json"
    cursor = _load(cursor_path, {"clawhub": int(time.time() * 1000) - DAY_MS})
    ledger, keys = _load(ledger_path, {}), []
    with tempfile.TemporaryDirectory() as tmp, \
            SqliteSaver.from_conn_string(str(state_dir / "checkpoints.sqlite")) as cp:
        pop = _popular_set(state_dir, model, budget, list_popular, fetch, errors, Path(tmp),
                           notes)
        if pop is None:
            errors.append("discovery stopped: no popular set (the listing failed)")
            return keys
        try:
            new = list_new(cursor["clawhub"], max_skills, notes=notes)
        except Exception as e:  # noqa: BLE001 - ends discovery, not the run
            errors.append(f"listing: {e!r}")
            return keys
        g = graph(cp)
        for i, sk in enumerate(new):
            if i >= max_skills:
                notes.append(f"skill cap reached: {max_skills} checked")
                break
            if not budget.left():
                notes.append(f"{budget.why()} reached before {sk.id}; it is checked next run")
                break
            stop = False
            try:
                keys += _check(sk, state_dir, pop, model, gh, feed_dir, g, ledger, fetch, Path(tmp))
            except llm.OverBudget:
                notes.append(f"{budget.why()} reached at {sk.id}; it is checked next run")
                _save(ledger_path, ledger)
                break
            except Exception as e:  # noqa: BLE001 - deterministic: the skill counts as processed
                _save(ledger_path, ledger)  # issues opened before the failure stay recorded
                if transient(e):
                    n = cursor.get("attempts", {}).get(sk.id, 0) + 1
                    if n < MAX_ATTEMPTS:  # the cursor stays: the next run checks it again
                        cursor["attempts"] = {sk.id: n}
                        _save(cursor_path, cursor)
                        errors.append(f"discovery stopped at {sk.id} "
                                      f"(transient, run {n} of {MAX_ATTEMPTS}): {e!r}")
                        break
                    errors.append(f"{sk.id}: skipped after {n} runs with transient errors: {e!r}")
                    stop = True
                else:
                    errors.append(f"{sk.id}: {e!r}")
            _save(ledger_path, ledger)
            cursor["clawhub"] = sk.updated_at
            cursor.pop("attempts", None)
            _save(cursor_path, cursor)
            if stop:  # the network is likely still failing: the next skill waits for the next run
                errors.append(f"discovery stopped after skipping {sk.id}")
                break
    return keys


def run(state_dir: Path, feed_dir: Path, gh, max_usd: float = 0.5, max_skills: int = 50,
        model: str | None = llm.DEFAULT_MODEL, max_minutes: float = 45, **sources_) -> str:
    """One daily run: resume labelled candidates, then discover new ones until the budget, the
    skill cap or `max_minutes` of wall-clock time runs out. Returns a summary."""
    deadline = time.monotonic() + max_minutes * 60
    state_dir.mkdir(parents=True, exist_ok=True)
    os.environ["LANGFUSE_TRACING_ENABLED"] = "false"  # no traces from the daily run (langfuse 4.x)
    saved_cache, start, errors, notes = llm.CACHE, _spent(), [], []
    llm.CACHE = state_dir / "cache" / "crosskill" / "llm"  # Jev answers go next to it
    limit = start + max_usd
    # Hard cap: a call starts only if it and every call in flight fit, each as costly as the
    # costliest call so far (at least CALL_RESERVE_USD), and only before the deadline, so a long
    # skill cannot run past the job timeout.
    llm.allow = lambda n: (time.monotonic() < deadline and
                           _spent() + (n + 1) * max(llm.max_call_usd, CALL_RESERVE_USD) < limit)
    try:
        gh.ensure_labels(LABELS)
        before = len(_load(feed_dir / "advisories.json", []))
        resumed = resume_waiting(state_dir, gh, feed_dir, errors)
        published = len(_load(feed_dir / "advisories.json", [])) - before
        keys = discover(state_dir, gh, feed_dir, max_usd, max_skills, model, errors, notes,
                        deadline=deadline, **sources_)
    finally:
        llm.CACHE, llm.allow = saved_cache, None
    head = (f"resumed {resumed}, published {published}, new candidates {len(keys)}, "
            f"spend ${_spent() - start:.4f}")
    lines = [head]
    lines += [f"  {n}" for n in notes] + [f"  candidate {k}" for k in keys] + [f"  error {e}" for e in errors]
    return "\n".join(lines)
