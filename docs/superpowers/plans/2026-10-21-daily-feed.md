# Daily Feed Implementation Plan

> **Superseded (2026-10-22).** The daily ClawHub scan was dropped as not economical (two local
> dry runs spent $2.70 warming up the popular set without checking a new skill). crosskill
> stays a local tool; users share findings from `crosskill scan` as issues the owner approves
> (`src/crosskill/feed.py`, `.github/workflows/publish.yml`).

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A daily GitHub Actions run that finds toxic flows created by new public skills, opens one issue per candidate, and publishes approved candidates as advisories in `feed/`, which `crosskill scan` then matches against local installs.

**Architecture:** Discovery is a plain function (ClawHub listing → static extraction → Jev triage → LLM extraction → one clingo scan of the new skill plus the popular set → score). Each candidate is its own LangGraph thread (`open_issue → wait (interrupt) → publish | close`) checkpointed in SQLite; later runs resume waiting threads with `Command(resume=...)` from the issue's labels. All state (checkpoints, ledger, cursor, caches) lives in a `state/` directory that the workflow keeps on a `data` branch.

**Tech Stack:** Python 3.12, existing crosskill (extract, scan, llm), LangGraph + langgraph-checkpoint-sqlite, OpenRouter (chat completions for flash, `/api/alpha/decisions` for Jev), GitHub REST API via `urllib`, GitHub Actions.

**Spec:** `docs/superpowers/specs/2026-10-21-daily-feed-design.md`

**Plan-level calls (not in the spec):**
- Source: ClawHub only for now. It has a JSON API (`/api/v1/skills?sort=updated|downloads&limit=&cursor=`, items with `ownerHandle`, `slug`, `latestVersion`, `stats.installs`, `updatedAt` in ms). skills.sh serves only HTML; add it when it has an API.
- Jev gates the **LLM** extractor only: static extraction runs on every new skill (free). A skill whose static grants are irrelevant and whose Jev roles are all below the threshold gets no LLM call.
- The triage eval reports per-role P/R and *risky-skill recall* (skills with any relevant labeled fact that pass triage), as the measurable form of "findings that survive triage".

## Global Constraints

- Python ≥ 3.12. New deps only as an optional extra: `feed = ["langgraph>=1.2,<2", "langgraph-checkpoint-sqlite>=3,<4"]`.
- Jev model `typesafe/jev-1.13`, endpoint `POST https://openrouter.ai/api/alpha/decisions`, `noul` questions, threshold **0.2** on the probability.
- Extractor model `deepseek/deepseek-v4.1-flash`, prompt v2 (unchanged `prompt.md`).
- Score = severity × reach × confidence. Severity: `secret_exfiltration` 3, `untrusted_to_execution` 3, `lethal_trifecta` 2. Reach = log10(1 + installs of the least installed component); unknown installs = 0. Confidence = 1.0 if all chain facts are static, 0.8 if any is `llm`, times 0.9 per chain entry beyond 2. Drop candidates below **1.5**. Weights in one dict in `candidates.py`.
- Daily LLM + Jev cap **$0.50** (`--max-usd`), at most **50** new skills per run (`--max-skills`). Popular set: top **200** ClawHub skills by downloads, refreshed when older than **7** days, plus `pipeline/popular-mcp.json`.
- Skill content is data: downloaded and extracted, never executed. ZIP members must stay inside the destination.
- No Langfuse in the daily run.
- Nothing is published without the `approve` label. Labels: `approve`, `reject`, `crosskill-candidate`.
- Same-combination key = rule + sorted component ids (no versions). A key in the ledger is never raised again; `reject` is final.
- Advisory ids `CK-<year>-<4-digit number>`. Files: `feed/advisories.json`, `feed/README.md`, `feed/CK-….md`.
- Wording: combinations say each skill may be safe alone and the risk is installing them together; single skills state what the skill can do and why that is risky for an agent, never intent ("can read your mail and send mail", not "steals mail").
- Feed URL for scan: `https://raw.githubusercontent.com/idanbe/cross-skill-guard/main/feed/advisories.json`, cached one day; `--offline` or `CROSSKILL_OFFLINE=1` skips it.

## Review Focus

- A ClawHub ZIP with `../` members or absolute paths: extraction must refuse those members and keep the rest inside the skill directory (test in Task 3).
- The budget runs out mid-run: the cursor must point at the last *processed* skill so the next run continues from there, never skipping one (test in Task 7).
- An issue carries both `approve` and `reject`, or neither: the thread keeps waiting, nothing is published (test in Task 7).
- A run crashes after writing an advisory and is rerun: no second advisory for the same key (test in Task 7).
- `crosskill scan` with no network, a bad feed or `--offline`: findings and exit code are unchanged and no traceback appears (test in Task 8).

---

### Task 1: Jev triage and spend tracking

**Files:**
- Create: `src/crosskill/triage.py`
- Modify: `src/crosskill/llm.py` (cache-hit flag, spend counter)
- Test: `tests/test_triage.py`

**Interfaces:**
- Produces: `triage.ROLES: dict[str, tuple[str, dict]]` (the four questions from `docs/superpowers/specs/jev_spike.py`: `reads_sensitive`, `sends_out`, `untrusted_input`, `runs_any_code`); `triage.roles(text: str, model: str = "typesafe/jev-1.13") -> dict[str, float]` (disk-cached under `CACHE.parent / "jev"`, key = sha256 of model + questions JSON + text); `triage.passes(roles: dict[str, float], threshold: float = 0.2) -> bool`; `triage.spent_usd: float` and `llm.spent_usd: float`, incremented only on uncached calls by `usage.cost`; `llm.facts_for(...)` result gains `"cached": True` on a cache hit.

- [ ] **Step 1: Write failing tests**: `test_roles_parses_noul_answers` (monkeypatch the HTTP call to return `{"answers": {"sends_out": {"type": "noul", "noul": 0.9}, …}, "usage": {"cost": 0.00002}}`; assert `roles(...)["sends_out"] == 0.9` and `triage.spent_usd == 0.00002`), `test_roles_cache_pays_once` (two calls, one HTTP request, spend unchanged by the second), `test_passes_threshold` (`passes({"a": 0.19, "b": 0.0}) is False`, `passes({"a": 0.2}) is True`), `test_facts_for_marks_cache_hit` (second `facts_for` call returns `cached=True`, `llm.spent_usd` counts only the first).
- [ ] **Step 2: Run** `pytest -q tests/test_triage.py`. Expected: FAIL (module missing).
- [ ] **Step 3: Implement** `triage.py` with `urllib.request` (Bearer `OPENROUTER_API_KEY`, `state = {"file": "SKILL.md", "text": text}`), and the two small `llm.py` changes.
- [ ] **Step 4: Run** `pytest -q tests/test_triage.py tests/test_llm.py`. Expected: PASS.
- [ ] **Step 5: Commit** `feat: Jev role triage with cache and spend tracking`.

### Task 2: Triage eval

**Files:**
- Modify: `src/crosskill/evals.py`, `src/crosskill/cli.py` (`crosskill eval --triage [--threshold 0.2]`)
- Test: `tests/test_llm.py`

**Interfaces:**
- Consumes: `triage.roles`, `triage.passes`, `evals.items`, `evals.norm`, `evals.relevant`.
- Produces: `evals.role_labels(facts: list[dict]) -> dict[str, bool]` (as in the spike: reads/writes relevant → `reads_sensitive`, egress → `sends_out`, untrusted → `untrusted_input`, arbitrary executes → `runs_any_code`); `evals.triage_report(threshold: float = 0.2, roles=triage.roles) -> str` printing per-role P/R, risky-skill recall, total cost and median latency. No Langfuse.

- [ ] **Step 1: Write failing test** `test_triage_report_counts` with a fake `roles` that returns 1.0 for every role on one labeled corpus skill and 0.0 elsewhere; assert the report contains `risky-skill recall` and the expected per-role counts.
- [ ] **Step 2: Run** it; FAIL.
- [ ] **Step 3: Implement** `role_labels`, `triage_report`, and the CLI flag.
- [ ] **Step 4: Run** `pytest -q tests/test_llm.py`; PASS. Then once with the network: `crosskill eval --triage` and record the numbers in `CLAUDE.md` (status line).
- [ ] **Step 5: Commit** `feat: crosskill eval --triage`.

### Task 3: ClawHub source

**Files:**
- Create: `src/crosskill/sources.py`
- Test: `tests/test_sources.py` (recorded JSON responses and a small ZIP built in the test)

**Interfaces:**
- Produces: `@dataclass Skill(owner: str, slug: str, version: str, installs: int, updated_at: int, url: str)` with `id -> "clawhub/<owner>/<slug>"` and `dirname -> "<owner>--<slug>"`; `sources.updated_since(after_ms: int, limit: int, get=http_json) -> list[Skill]` (pages `sort=updated` by `cursor` until `updatedAt <= after_ms` or `limit`; returns **oldest first**); `sources.popular(n: int = 200, get=http_json) -> list[Skill]` (`sort=downloads`); `sources.download(skill: Skill, dest: Path, get_bytes=http_bytes) -> Path` (`/api/v1/download?slug=&owner=&version=`, extracts into `dest / skill.dirname`, returns that dir). HTTP helpers send `User-Agent: crosskill-feed` and honor `Retry-After` on 429, as `corpus/real/fetch.py` does.

- [ ] **Step 1: Write failing tests**: `test_updated_since_pages_and_stops` (three pages, the second empty with a cursor as the real API does; stops at the first item at or before `after_ms`; result sorted oldest first), `test_popular_reads_installs`, `test_download_extracts_inside_dest`, `test_download_skips_traversal_members` (ZIP with `../evil` and `/abs` members: neither is written, the normal member is).
- [ ] **Step 2: Run**; FAIL.
- [ ] **Step 3: Implement.** Extract member by member, skipping any whose resolved path is outside the target dir.
- [ ] **Step 4: Run** `pytest -q tests/test_sources.py`; PASS.
- [ ] **Step 5: Commit** `feat: ClawHub listing and safe download`.

### Task 4: Popular MCP servers

**Files:**
- Create: `pipeline/popular-mcp.json` (`.mcp.json` format; each server entry has an extra `"x-crosskill": {"installs": <int>, "url": "<homepage>"}` that `mcp_caps` ignores)
- Modify: `src/crosskill/extract.py` (`mcp_caps`)
- Test: `tests/test_scan_corpus.py` or a new `tests/test_popular_mcp.py`

**Interfaces:**
- Produces: `mcp_caps` also knows `@modelcontextprotocol/server-slack` → `[("reads", "slack"), ("untrusted", "slack"), ("egress", "slack.com")]`, `@modelcontextprotocol/server-brave-search` → `[("untrusted", "web")]`, `@modelcontextprotocol/server-puppeteer` → `WEB`, `@modelcontextprotocol/server-gdrive` → `[("reads", "gdrive")]`. `is_private` treats `slack` and `gdrive` as private. The file lists those plus the six already known.

- [ ] **Step 1: Write failing test** `test_popular_mcp_grants`: extract a temp install whose `.mcp.json` is a copy of `pipeline/popular-mcp.json`; every server yields at least one grant; the slack server yields `egress slack.com`; grant lines point at the server's line in the file.
- [ ] **Step 2: Run**; FAIL.
- [ ] **Step 3: Implement** the table entries and the JSON file; add the new private resources to `docs/facts.md`.
- [ ] **Step 4: Run** `pytest -q`; all PASS (corpus results unchanged).
- [ ] **Step 5: Commit** `feat: popular MCP servers for the daily feed`.

### Task 5: Candidates: check, key, score, advisory

**Files:**
- Create: `src/crosskill/candidates.py`
- Test: `tests/test_candidates.py`

**Interfaces:**
- Consumes: `scan.scan(root, model)`, `sources.Skill`, `pipeline/popular-mcp.json`.
- Produces:
  - `candidates.build_install(root: Path, skill_dirs: dict[str, Path]) -> None`: `root/skills/<dirname>` symlinks to each skill dir, and `root/.mcp.json` = copy of `pipeline/popular-mcp.json`.
  - `candidates.check(root: Path, new: str, model: str | None) -> list[dict]`: `scan(root, model)` filtered to findings with a chain entry under `skills/<new>/` (the trifecta's untrusted component is `path[0]`, so it is covered).
  - `candidates.components(finding: dict, skills: dict[str, Skill], mcp: dict) -> list[dict]`: one entry per distinct source, from each chain `file` (`skills/<dirname>/…` → that Skill; `.mcp.json` → the server by component name). Entry: `{"id", "version", "url", "installs", "match": {"kind": "skill", "name": <component name>} | {"kind": "mcp", "package": <pkg>|None, "host": <host>|None}}`.
  - `candidates.key(finding: dict, comps: list[dict]) -> str` = `rule + ":" + ",".join(sorted(ids))`.
  - `candidates.score(finding: dict, comps: list[dict]) -> tuple[float, dict]` (breakdown with `severity`, `reach`, `confidence`), constants from Global Constraints; `candidates.MIN_SCORE = 1.5`.
  - `candidates.advisory(finding, comps, score, breakdown, adv_id: str, issue_url: str, published: str) -> dict` and `candidates.render(adv: dict) -> str` (Markdown page). Chain files under `skills/<dirname>/` render as `<component url> <path inside skill>:line`; `.mcp.json` renders as `pipeline/popular-mcp.json:line`.

- [ ] **Step 1: Write failing tests** using corpus installs copied into tmp dirs as "skills" (no network, `model=None`): `test_check_keeps_only_new_skill_findings` (toxic/004: new=`uploader`'s dir keeps the finding; a clean skill as new gets none), `test_single_skill_finding_is_a_candidate` (a one-skill flow, e.g. toxic/010, yields one component), `test_combination_with_popular_mcp` (a new skill whose only grant is `Read(~/clients/**)` plus the popular `mcp-server-fetch` → `lethal_trifecta` with two components, the skill and `mcp/fetch`; clingo covers three or more the same way), `test_key_ignores_versions`, `test_score_values` (secret_exfiltration, min installs 99, static: `3 * 2.0 * 1.0`; one llm fact: × 0.8; installs 0 → below `MIN_SCORE`), `test_render_wording` (combination page contains "may be safe on its own" and both names; single-skill page contains "can" and no "malicious"/"steal").
- [ ] **Step 2: Run**; FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `pytest -q tests/test_candidates.py`; PASS.
- [ ] **Step 5: Commit** `feat: candidate check, scoring and advisory pages`.

### Task 6: GitHub client

**Files:**
- Create: `src/crosskill/github.py`
- Test: `tests/test_github.py`

**Interfaces:**
- Produces: `class GitHub(repo: str, token: str, request=urlopen_json)` with `ensure_labels(names: list[str]) -> None`, `create_issue(title: str, body: str, labels: list[str]) -> tuple[int, str]` (number, html_url), `labels(number: int) -> set[str]`, `close(number: int, comment: str) -> None`. `GitHub.from_env()` reads `GITHUB_REPOSITORY` and `GITHUB_TOKEN`. Plus `class FakeGitHub` in the test module (in-memory issues, settable labels) used by Task 7's tests.

- [ ] **Step 1: Write failing test** `test_requests_are_well_formed` with a recording `request` fake: method, path (`/repos/<repo>/issues`, `/labels`), JSON body, `Authorization: Bearer`, and that `ensure_labels` skips existing labels.
- [ ] **Step 2: Run**; FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run**; PASS.
- [ ] **Step 5: Commit** `feat: minimal GitHub issues client`.

### Task 7: Daily run and candidate graph

**Files:**
- Create: `src/crosskill/daily.py`
- Modify: `src/crosskill/cli.py` (`crosskill daily`), `pyproject.toml` (`feed` extra)
- Test: `tests/test_daily.py` (skipped if `langgraph` is not installed; CI installs the extra)

**Interfaces:**
- Consumes: Tasks 1, 3, 5, 6.
- Produces:
  - `State` layout under `--state DIR`: `checkpoints.sqlite`, `ledger.json` (`{key: {"status": "pending"|"approved"|"rejected"|"dropped", "issue": int|None, "advisory": str|None}}`), `cursor.json` (`{"clawhub": <ms>}`), `popular.json` (`{"fetched": <iso date>, "skills": [...]}`), `skills/` (downloaded skills), `cache/` (`XDG_CACHE_HOME` for the LLM and Jev caches).
  - `daily.graph(checkpointer) -> CompiledStateGraph` over `TypedDict Candidate(key, finding, components, score, breakdown, issue, issue_url, decision)`: nodes `open_issue` → `wait` → conditional edge on `decision` → `publish` | `close` → END. `wait` calls `interrupt({"issue": n})` and stores the resumed value. `gh` and `feed_dir` come from `config["configurable"]`. Thread id = `key`.
  - `daily.publish(feed_dir: Path, adv: dict) -> None`: idempotent by key (skip if `advisories.json` already has the key), assigns the next `CK-<year>-NNNN`, writes the page, rewrites `advisories.json` and `README.md`.
  - `daily.resume_waiting(state_dir, gh, feed_dir) -> int`: for each `pending` ledger entry, `labels = gh.labels(issue)`; exactly one of `approve`/`reject` → `graph.invoke(Command(resume=...), {"configurable": {"thread_id": key, ...}})` and update the ledger; both or neither → keep waiting.
  - `daily.discover(state_dir, gh, feed_dir, max_usd, max_skills, model) -> list[str]`: refresh popular set if stale; `sources.updated_since(cursor)`; per new skill (oldest first): stop when `llm.spent_usd + triage.spent_usd >= max_usd` or `max_skills` reached; download; static grants; if no relevant static grant and `not triage.passes(...)` → model `None`, else flash; `candidates.check`; for each finding: key in ledger → skip; score < `MIN_SCORE` → ledger `dropped`; else start the thread (it stops at `wait`) and ledger `pending`. After each fully processed skill, set the cursor to its `updated_at`.
  - `daily.run(state_dir, feed_dir, gh, max_usd=0.5, max_skills=50, model=DEFAULT_MODEL) -> str` (summary: resumed, published, new candidates, spend): `gh.ensure_labels(["approve", "reject", "crosskill-candidate"])`, `resume_waiting`, then `discover`, with `SqliteSaver.from_conn_string(str(state_dir / "checkpoints.sqlite"))`. LLM extraction of the popular set counts toward the same budget (cached after the first run).
  - `open_issue` title: `[candidate] <rule>: <component names joined by " + ">`; body: `candidates.render(...)` of the draft advisory (id `CK-draft`), then the score breakdown, then "Add the `approve` label to publish, `reject` to drop it for good." Label `crosskill-candidate`.
  - At most **3** candidates per new skill (highest score first); the rest go to the ledger as `dropped`.
  - CLI: `crosskill daily --state DIR --feed feed [--max-usd 0.5] [--max-skills 50] [--dry-run]`; `--dry-run` uses an in-memory fake GitHub and prints the candidates instead of opening issues.

- [ ] **Step 1: Write failing tests** with `FakeGitHub`, a fake source (two skills built from corpus toxic/004's `cost-report` and `uploader` dirs), Jev and the LLM monkeypatched, all in tmp dirs:
  - `test_candidate_waits_for_label`: `run` opens one issue, publishes nothing, ledger `pending`.
  - `test_approve_publishes_on_next_run`: set label `approve`, new `run` (new `SqliteSaver` on the same file, i.e. a new process) → `feed/CK-<year>-0001.md` and `advisories.json` with one entry; ledger `approved`.
  - `test_reject_closes_and_never_returns`: label `reject` → issue closed, nothing published; a later run with the same combination opens no new issue.
  - `test_both_or_no_label_keeps_waiting`.
  - `test_publish_is_idempotent`: calling `publish` twice with the same key leaves one advisory.
  - `test_budget_stops_and_cursor_resumes`: `max_usd` set so the first skill exhausts it; cursor equals the first skill's `updated_at`; the next run processes the second skill.
- [ ] **Step 2: Run**; FAIL.
- [ ] **Step 3: Implement** `daily.py`, the CLI command and the `feed` extra.
- [ ] **Step 4: Run** `pip install -e ".[dev,feed]" && pytest -q`; all PASS. Then `crosskill daily --state /tmp/s --feed /tmp/f --dry-run --max-skills 5` against the real ClawHub API; it prints candidates or none, spends under $0.05.
- [ ] **Step 5: Commit** `feat: crosskill daily with a LangGraph approval graph`.

### Task 8: Published advisories in `crosskill scan`

**Files:**
- Create: `src/crosskill/known.py`
- Modify: `src/crosskill/cli.py` (`scan --offline`), `tests/conftest.py` (autouse `CROSSKILL_OFFLINE=1`)
- Test: `tests/test_known.py`

**Interfaces:**
- Produces: `known.load(url: str = FEED_URL, cache: Path = …/crosskill/feed.json, max_age_s: int = 86400) -> list[dict]` (returns `[]` on any network or JSON error); `known.local_keys(root: Path, grants: list[Grant]) -> set[tuple]` (`("skill", component name)` for skill grants, `("mcp", package)` and `("mcp", host)` from `root/.mcp.json`); `known.matches(advisories, keys) -> list[dict]` (every component's `match` is in `keys`). `scan` prints `possible match: <id> <title> <url>` lines after the findings; the exit code does not change.

- [ ] **Step 1: Write failing tests**: `test_match_requires_all_components`, `test_mcp_matches_package_or_host`, `test_load_failure_is_empty` (unreachable URL, bad JSON), `test_scan_offline_unchanged` (CLI output and exit code equal with and without a broken feed).
- [ ] **Step 2: Run**; FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `pytest -q`; PASS.
- [ ] **Step 5: Commit** `feat: scan reports published advisories`.

### Task 9: Workflow, data branch, docs

**Files:**
- Create: `.github/workflows/daily.yml`, `feed/README.md` (empty index), `feed/advisories.json` (`[]`)
- Modify: `.github/workflows/ci.yml` (install `.[dev,feed]`), `README.md`, `CLAUDE.md`

**Interfaces:**
- Consumes: `crosskill daily`.

- [ ] **Step 1: Write the workflow**: `on: schedule: cron "17 6 * * *"` and `workflow_dispatch`; `permissions: contents: write, issues: write`; `concurrency: daily-feed`; steps: checkout `main`; checkout branch `data` into `state/` (create an orphan `data` branch if it does not exist); setup Python 3.12; `pip install -e ".[feed]"`; `crosskill daily --state state --feed feed` with `OPENROUTER_API_KEY` from secrets and `XDG_CACHE_HOME=state/cache`; commit `state/` to `data` and `feed/` to `main` as `github-actions[bot]`, each only if changed.
- [ ] **Step 2: Validate** with `python -c "import yaml; yaml.safe_load(open('.github/workflows/daily.yml'))"` and `pytest -q`; PASS.
- [ ] **Step 3: Docs**: README section "Daily feed" (what it is, `feed/`, approval with labels, the scan's "possible match" lines, ClawHub-only for now); `CLAUDE.md` architecture lines for `triage.py`, `sources.py`, `candidates.py`, `github.py`, `daily.py`, `known.py` and the `state/` layout; tick stage 5 items in the plan file.
- [ ] **Step 4: Commit** `feat: daily feed workflow and docs`. After merge, the owner adds the `OPENROUTER_API_KEY` repository secret and runs the workflow once by hand (`workflow_dispatch`).
