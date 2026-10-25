# Z3 Permission Audit Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `crosskill audit-permissions` finds commands that pass an install's Bash allow rules yet run an arbitrary/network program, returns each as a verified counterexample, and can feed them into a scan.

**Architecture:** A new `audit.py` reuses `settings_grants` to read the allow/deny Bash rules, models them as Z3 string constraints, enumerates the documented bypass forms (absolute path, `sh -c`, `git -c`, env runners) over a small set of dangerous programs, verifies each candidate with bashlex, and returns ordinary `Grant`s (extractor `z3`, `arbitrary=True`). `scan --audit` merges those grants so a bypass completes a toxic path through the existing clingo pipeline.

**Tech Stack:** Python 3.12, z3-solver (new), bashlex (existing), clingo, typer.

**Spec:** `docs/superpowers/specs/2026-10-25-z3-permission-audit-design.md`

## Global Constraints

- Python 3.12. Add `z3-solver` to `dependencies` in `pyproject.toml`.
- Do **not** extend the global `ARBITRARY` / `NETWORK` sets in `extract.py` — verification resolves the effective program locally instead.
- Reuse `RULE`, `bash_caps`, `settings_grants`, `Grant` from `extract.py`. Never route a command string through `covers` (it matches rule-pattern vs rule-pattern only).
- A bypass `Grant`: `comp=<rule text>`, `kind="executes"` or `"egress"`, `arg=<effective program>`, `arbitrary=True`, `extractor="z3"`, `rule=<rule text>`, `file="settings.json"` (relative), `line=<rule's line>`. `arbitrary=True` is mandatory or `untrusted_to_execution` never fires.
- Text output; exit 1 when a bypass is found, 0 otherwise (match `scan`).
- Every reported counterexample must pass bashlex verification — no exceptions.

## Review Focus

- **No `settings.json`, or one with no `permissions.allow`** → `audit()` returns `[]`, command exits 0, prints "no bypasses found". (Task 2)
- **A tight rule set** (deny `curl`/`wget`/`bash`/`sh`, allow only pinned scripts like `Bash(pytest:*)`) → no bypass reported (`unsat`). (Task 3)
- **Malformed / unparseable candidate command** from the model → `verify` returns `None`, candidate dropped, never reported. (Task 1)
- **A deny rule that catches the bypass form** (e.g. allow `Bash(git:*)` but deny `Bash(git -c *)`) → that form is not reported. (Task 3)
- **A trailing-`*` allow rule that also matches the bare prefix** (`Bash(git:*)` matches `git` alone) must not crash the model or yield a false bypass with an empty effective program. (Task 3)

---

### Task 1: `verify` — resolve the effective dangerous program

**Files:**
- Create: `src/crosskill/audit.py`
- Test: `tests/test_audit.py`

**Interfaces:**
- Consumes: `ARBITRARY`, `NETWORK` from `crosskill.extract`.
- Produces: `verify(command: str) -> str | None` — the effective arbitrary/network program a command runs (e.g. `"curl"`, `"sh"`), or `None` if it parses to nothing dangerous or does not parse. Resolves: inner command of `sh -c '…'`, the program in `git -c core.sshCommand=…`, the command run by an env runner (`devbox run`, `npx`, `docker exec`, `mise exec`, `direnv exec`), and a bare program by absolute path (strip dir). A runner that runs arbitrary downloaded code (`npx`) resolves to itself.

- [ ] **Step 1: Write the failing tests**

```python
import pytest
from crosskill.audit import verify

@pytest.mark.parametrize("cmd, prog", [
    ("/usr/bin/curl https://x.invalid", "curl"),
    ("sh -c 'curl https://x.invalid'", "curl"),
    ("git -c core.sshCommand='curl https://x.invalid' fetch", "curl"),
    ("devbox run bash evil.sh", "bash"),
    ("npx some-pkg", "npx"),
    ("git status", None),
    ("ls -la", None),
    ("&& ||", None),           # unparseable → None, never raises
])
def test_verify_resolves_effective_program(cmd, prog):
    assert verify(cmd) == prog
```

- [ ] **Step 2: Run to verify it fails**

Run: `pytest tests/test_audit.py::test_verify_resolves_effective_program -v`
Expected: FAIL (ImportError / `verify` undefined).

- [ ] **Step 3: Implement `verify`**

Parse with `bashlex.parse` inside a try/except (unparseable → `None`). Walk command nodes; for each, take the first word, strip a leading directory (`/usr/bin/curl` → `curl`). If it is an env runner, recurse on the inner command words; if `git` with a `-c core.sshCommand=<x>` assignment, resolve `<x>`'s first word; if `sh`/`bash`/`zsh -c <str>`, resolve the string's first word. Return the first resolved word that is in `ARBITRARY` or `NETWORK`, or the runner itself when it is `npx`-like; else `None`.

- [ ] **Step 4: Run to verify it passes**

Run: `pytest tests/test_audit.py::test_verify_resolves_effective_program -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/crosskill/audit.py tests/test_audit.py
git commit -m "feat: audit.verify resolves the effective program of a bypass form"
```

---

### Task 2: `audit` — allow/deny rules to verified-bypass grants

**Files:**
- Modify: `src/crosskill/audit.py`
- Modify: `pyproject.toml` (add `z3-solver` to `dependencies`)
- Test: `tests/test_audit.py`
- Create: `tests/fixtures/audit/weak/.claude/settings.json` (allow `["Bash(git:*)"]`, no deny)
- Create: `tests/fixtures/audit/empty/.claude/settings.json` (allow `[]`)

**Interfaces:**
- Consumes: `settings_grants`, `Grant`, `RULE`, `bash_caps` from `crosskill.extract`; `verify` (Task 1); z3.
- Produces: `audit(root: Path) -> list[Grant]` — one `Grant` per distinct verified bypass (dedupe by `(rule, effective program)`), fields per Global Constraints. `[]` when no `settings.json`, no allow rules, or no bypass. Internal `find_candidates(allow: list[str], deny: list[str]) -> list[tuple[str, str]]` returning `(rule_text, candidate_command)` pairs is left to the builder; only `audit` is tested here.

- [ ] **Step 1: Write the failing tests**

```python
from pathlib import Path
from crosskill.audit import audit

FIX = Path(__file__).parent / "fixtures/audit"

def test_weak_git_rule_yields_curl_bypass():
    grants = audit(FIX / "weak")
    progs = {(g.arg, g.kind) for g in grants}
    assert ("curl", "egress") in progs          # git -c / sh -c reaches curl
    assert all(g.arbitrary and g.extractor == "z3" for g in grants)
    assert all(g.rule == "Bash(git:*)" and g.file == ".claude/settings.json" for g in grants)

def test_no_allow_rules_is_empty():
    assert audit(FIX / "empty") == []

def test_missing_settings_is_empty(tmp_path):
    assert audit(tmp_path) == []

def test_every_reported_bypass_verifies():
    from crosskill.audit import verify
    for g in audit(FIX / "weak"):
        assert verify  # effective program came from verify, so it is in ARBITRARY|NETWORK
```

- [ ] **Step 2: Run to verify it fails**

Run: `pytest tests/test_audit.py -k "weak or empty or missing or verifies" -v`
Expected: FAIL (`audit` undefined).

- [ ] **Step 3: Implement `audit`**

Read allow rules + lines via `settings_grants` (allow grants whose `.rule` starts `"Bash("`); get deny strings from its second return value. For each allow rule, model it as a Z3 prefix/wildcard string constraint and, per bypass form × dangerous program (`ARBITRARY ∪ NETWORK`), ask Z3 for a concrete command string the allow rule approves and no deny rule catches (deny = `Contains` of the deny prefix, matching any subcommand). Run each satisfying string through `verify`; keep those that resolve to a program. Build a `Grant` using `bash_caps`'s executes/egress split on the effective program. Dedupe by `(rule, arg)`.

- [ ] **Step 4: Run to verify it passes**

Run: `pytest tests/test_audit.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/crosskill/audit.py tests/test_audit.py tests/fixtures/audit pyproject.toml
git commit -m "feat: audit maps allow rules to verified-bypass grants via z3"
```

---

### Task 3: `unsat` on a tight rule set, and deny coverage

**Files:**
- Modify: `tests/test_audit.py`
- Create: `tests/fixtures/audit/tight/.claude/settings.json` (allow `["Bash(pytest:*)"]`, deny `["Bash(curl *)","Bash(wget *)","Bash(bash *)","Bash(sh *)"]`)
- Create: `tests/fixtures/audit/deny-form/.claude/settings.json` (allow `["Bash(git:*)"]`, deny `["Bash(git -c *)"]`)

**Interfaces:**
- Consumes: `audit` (Task 2).
- Produces: nothing new.

- [ ] **Step 1: Write the failing tests**

```python
def test_tight_rule_set_has_no_bypass():
    assert audit(FIX / "tight") == []           # unsat within the model

def test_deny_on_the_form_blocks_it():
    # git -c is denied; any surviving bypass must not use that form
    assert all("git -c" not in g.arg for g in audit(FIX / "deny-form"))
```

- [ ] **Step 2: Run to verify it fails**

Run: `pytest tests/test_audit.py -k "tight or deny" -v`
Expected: FAIL if the model ignores deny or over-reports on pinned-script rules.

- [ ] **Step 3: Fix the model**

Only touch `audit`/`find_candidates` if these fail: ensure a pinned-prefix allow rule (`Bash(pytest:*)`) constrains the program token so no dangerous program satisfies it, and that a deny `Contains` constraint removes the matching form.

- [ ] **Step 4: Run to verify it passes**

Run: `pytest tests/test_audit.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add tests/test_audit.py tests/fixtures/audit
git commit -m "test: audit returns unsat on tight rules and respects deny"
```

---

### Task 4: `crosskill audit-permissions` command

**Files:**
- Modify: `src/crosskill/cli.py`
- Modify: `src/crosskill/audit.py` (add `to_text(grants: list[Grant]) -> str`)
- Test: `tests/test_audit.py`

**Interfaces:**
- Consumes: `audit`, new `to_text` (audit).
- Produces: `audit-permissions PATH` command; exit 1 when bypasses found, 0 otherwise. `to_text(grants) -> str` renders per bypass: rule text, counterexample program (`g.arg`), kind, and `file:line`; "no bypasses found" when empty.

- [ ] **Step 1: Write the failing test**

```python
from typer.testing import CliRunner
from crosskill.cli import app

def test_audit_command_exit_codes():
    r = CliRunner()
    found = r.invoke(app, ["audit-permissions", str(FIX / "weak")])
    assert found.exit_code == 1 and "curl" in found.output and "Bash(git:*)" in found.output
    clean = r.invoke(app, ["audit-permissions", str(FIX / "tight")])
    assert clean.exit_code == 0 and "no bypasses" in clean.output.lower()
```

- [ ] **Step 2: Run to verify it fails**

Run: `pytest tests/test_audit.py::test_audit_command_exit_codes -v`
Expected: FAIL (no such command).

- [ ] **Step 3: Implement the command**

Add `@app.command("audit-permissions")` taking `path: Path = Path(".")`; import `audit`, `to_text` inside the function (match the file's lazy-import style); `typer.echo(to_text(grants))`; `raise typer.Exit(1 if grants else 0)`.

- [ ] **Step 4: Run to verify it passes**

Run: `pytest tests/test_audit.py::test_audit_command_exit_codes -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/crosskill/cli.py src/crosskill/audit.py tests/test_audit.py
git commit -m "feat: crosskill audit-permissions command"
```

---

### Task 5: `scan --audit` folds bypass grants into the toxic-path search

**Files:**
- Modify: `src/crosskill/scan.py` (`scan` gains `extra_grants`)
- Modify: `src/crosskill/cli.py` (`scan` gains `--audit`)
- Create: `tests/fixtures/audit/trifecta/` — a weak `settings.json` (`Bash(git:*)`) **plus** a skill with untrusted input, so a bypass `egress` completes `lethal_trifecta`/`untrusted_to_execution`
- Test: `tests/test_audit.py`

**Interfaces:**
- Consumes: `scan` (scan.py), `audit` (Task 2).
- Produces: `scan(root, model=None, extra_grants: list[Grant] | None = None)` — appends `extra_grants` to the extracted grants before grounding. `scan --audit` flag on the CLI runs `audit(path)` and passes the result as `extra_grants`.

- [ ] **Step 1: Write the failing tests**

```python
from crosskill.scan import scan
from crosskill.audit import audit

def test_scan_without_audit_misses_the_bypass():
    assert scan(FIX / "trifecta") == []          # static alone sees no flow

def test_scan_with_audit_grants_completes_a_path():
    findings = scan(FIX / "trifecta", extra_grants=audit(FIX / "trifecta"))
    assert any(f["rule"] in ("untrusted_to_execution", "lethal_trifecta") for f in findings)

def test_scan_audit_flag_wires_it():
    from typer.testing import CliRunner
    from crosskill.cli import app
    r = CliRunner().invoke(app, ["scan", "--no-llm", "--audit", str(FIX / "trifecta")])
    assert r.exit_code == 1
```

- [ ] **Step 2: Run to verify it fails**

Run: `pytest tests/test_audit.py -k scan -v`
Expected: FAIL (`extra_grants` / `--audit` absent).

- [ ] **Step 3: Implement**

In `scan.py`: add `extra_grants=None` param; `grants = extract(Path(root), model) + (extra_grants or [])`. In `cli.py` `scan`: add `audit: Annotated[bool, typer.Option("--audit", ...)] = False`; when set, `from crosskill.audit import audit` and pass `extra_grants=audit(path)` to `run_scan`.

- [ ] **Step 4: Run to verify it passes**

Run: `pytest tests/test_audit.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/crosskill/scan.py src/crosskill/cli.py tests/test_audit.py tests/fixtures/audit/trifecta
git commit -m "feat: scan --audit folds permission bypasses into the toxic-path search"
```

---

### Task 6: Docs and CI

**Files:**
- Modify: `docs/facts.md` (add `z3` to the extractor list)
- Modify: `CLAUDE.md` (status line: stage 6; architecture line for `audit.py`)
- Modify: `README.md` (one line + example under commands, if it lists commands)

**Interfaces:** none.

- [ ] **Step 1: Add `z3` to the extractor enumeration in `docs/facts.md`** (the line that lists `static|llm|manual`), with a half-line on what it means (a verified allow-rule bypass).

- [ ] **Step 2: Update `CLAUDE.md`** — status to stage 6 done-in-progress, and an architecture bullet: `src/crosskill/audit.py`: Z3 models the Bash allow/deny matcher, enumerates bypass forms, verifies with bashlex, returns `z3` grants; `scan --audit` folds them in.

- [ ] **Step 3: Run the full suite + ruff**

Run: `pytest -q && ruff check .`
Expected: all pass, no issues.

- [ ] **Step 4: Commit**

```bash
git add docs/facts.md CLAUDE.md README.md
git commit -m "docs: stage 6 audit-permissions in facts, CLAUDE.md, README"
```
