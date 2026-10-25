# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

crosskill finds toxic flows in an agent installation: dangerous combinations of skills, MCP servers
and permissions (for example, one skill reads `.env` and another posts to a webhook). It is a
learning project that practices one tool per stage: clingo, Langfuse, LTL, OPA, LangGraph, Z3.

The roadmap, with done criteria and targets for each stage, is in `cross-skill-guard-plan.md`. Check
which stage is current before starting work. Rule from the plan: finish a stage against its done
criteria before opening the next one.

Status: stage 1 done (22/22 static toxic findings, 0 false findings on clean, a few ms per
install). Stage 2 done. Evals per prompt version (P / R, cost per corpus run):
`deepseek/deepseek-v4.1-flash` v1 0.83 / 0.96, v2 0.96 / 0.96, $0.03; `deepseek/deepseek-v4-pro`
v1 0.75 / 0.86, v2 0.88 / 0.88, $0.23. With v2 + flash the scan gives exactly the expected
findings on all 77 installs (static alone flags 21/24 toxic), 0 false findings on clean. OpenRouter models that reject `temperature` (Sonnet
5.5, GPT-5.6) fail under `require_parameters`. The extractor now asks for low reasoning effort (`llm.REASONING`, part of the cache key): flash v2 0.92 / 0.92, $0.02; reasoning off 0.76 / 0.64; a reasoning token cap is ignored by the provider and long skills ran out of tokens. Stage 3: `crosskill guard`
(templates, automata, hooks, plugin) blocks the demo flow in real Claude Code, ~25 ms per hook
call; an armed egress property turns the network off for later Bash commands (proxy env vars to a
closed port, via CLAUDE_ENV_FILE) instead of the plan's CONNECT proxy (proxy-aware tools only;
Node before 22.21 ignores it); its week of own use with no false blocks is still open. Stage 4 done: `--policy`
(Rego, local `opa eval`) decides block/warn/ignore per finding; strict and permissive examples in
`policies/`, `opa test` runs in CI. Stage 5 changed: the daily ClawHub scan (LangGraph, Jev) was dropped as not
economical (two dry runs spent $2.70 warming up 200 popular skills without checking a new
one). crosskill stays local: `crosskill scan` offers to share each finding as a pre-filled
GitHub issue; the owner's `approve` label publishes it to `feed/`, and scans print possible
matches against the feed. Stage 6 done: `crosskill audit-permissions` (Z3 models the Bash allow/deny
matcher, enumerates bypass forms, verifies with bashlex, returns `z3` grants; `scan --audit` folds
them into the toxic-path search).

Langfuse is the local Docker stack from the triage-guard project (http://localhost:3000, project
`cross-skill-guard`); `.env` holds its keys and is gitignored.

Naming: the plan spells the command `crossskill`, but the package, entry point and imports are all
`crosskill` (one s). Use `crosskill` in code.

## Commands

```
pip install -e ".[dev]"
pytest -q                 # run from repo root; tests use corpus paths relative to it
pytest -q -k secret       # single corpus case (ids look like toxic/001-secret-to-webhook)
ruff check .              # CI (.github/workflows/ci.yml) runs ruff + pytest on Python 3.12
crosskill version
crosskill scan corpus/toxic/020-two-findings          # text; exit 1 when flows are found
crosskill scan --no-llm --sarif corpus/toxic/020-two-findings  # static only, SARIF 2.1.0
crosskill eval --push-only   # upload labels (dataset) and prompt.md to Langfuse
crosskill eval --model M     # run the extractor on the dataset, scores per prompt version
crosskill guard init --no-llm PATH   # write PATH/.claude/crosskill-guard.json (properties + automata)
crosskill guard init --audit PATH    # also arm Bash permission-bypass flows (z3 audit) at runtime
crosskill scan --no-llm --policy policies/strict/policy.rego --data policies/data.json PATH
crosskill audit-permissions PATH   # Bash allow-rule bypasses (Z3)
crosskill scan --audit PATH        # include permission bypasses in the scan
opa test policies/strict     # each policy in its own dir: both use `package crosskill`
claude --plugin-dir plugin  # load the guard hooks (they run `crosskill-guard`, which must be on PATH)
```

## Architecture

Pipeline, one engine shared by the scan, the runtime guard and the shared-findings feed:
extractors (static: `ast`, bashlex, SKILL.md frontmatter, `.mcp.json`, `settings.json`; LLM in
stage 2) → facts → clingo rules (`tainted` → `toxic`, with the path carried inside each atom) →
findings with a file:line proof chain → terminal/SARIF output. Later stages add an OPA policy,
LTL runtime hooks and user-shared advisories on top of these findings.

- `docs/facts.md` is the contract between extractors and rules. Facts are the only input to
  clingo. Every fact needs provenance `{file, line, extractor, quote?}`, and LLM facts must include
  a quote. Explanations are built from provenance, so a fact without it is invalid.
- `src/crosskill/extract.py`: static extractors → `Grant`s (one capability fact plus provenance),
  and the secret/private classification. Reads the corpus layout and `.claude/`.
- `src/crosskill/rules.lp`: clingo rules. `flow/6` is the recursive, path-carrying reachability;
  all components share the agent context (one hop per path). `not denied(G)` applies deny rules.
- `src/crosskill/llm.py`: LLM extractor through OpenRouter (`langfuse.openai` wrapper traces each
  call), Pydantic output schema, disk cache keyed by model + prompt + text
  (`~/.cache/crosskill/llm`). `prompt.md` is the prompt. `extract.llm_grants` turns its facts
  into `Grant`s (quote must be in the file; `rule` lets `deny` apply).
- `src/crosskill/evals.py`: fact-level precision/recall against `expected_facts.json`, run as a
  Langfuse experiment (`crosskill eval`).
- Shared findings (`src/crosskill/feed.py`): `report` turns a local finding into a draft
  advisory (skills and MCP servers only, no quotes), `issue_url` pre-fills a GitHub issue the
  user submits. `.github/workflows/publish.yml` runs `crosskill publish-report` on an issue
  labeled `approve`: `parse` validates the untrusted JSON in the body and rebuilds key and
  title, `publish` adds `feed/CK-<year>-NNNN.md` and `feed/advisories.json` (idempotent by
  key). `known.py` gives scan its "possible match" lines (`--offline`/`CROSSKILL_OFFLINE`).
  The stage 5 daily-feed design and plan in `docs/superpowers/` are marked superseded.
- `src/crosskill/scan.py`: grounds and solves, keeps the shortest path per finding, renders the
  file:line chain as text or SARIF. `src/crosskill/cli.py`: typer app.
- `src/crosskill/audit.py`: Z3 models the Bash allow/deny matcher, enumerates bypass forms (wrappers
  and shells), verifies each with bashlex, and returns `z3` grants. `scan --audit` folds them into
  the toxic-path search. The `z3` import is kept lazy (only `cli.py` imports this module, inside the
  command bodies), so it stays out of the hook and top-level CLI path.
- `src/crosskill/guard.py`: runtime guard. Each finding fills an LTL template (`G(a → G ¬b)` for
  secret_exfiltration and untrusted_to_execution, `G((O a ∧ O b) → ¬c)` for lethal_trifecta).
  python-statemachine builds the automata at `init` only (importing it takes ~90 ms); hooks step
  the saved transition tables with the stdlib, so keep hook-path imports stdlib-only. Tool calls
  become `read`/`egress`/`untrusted`/`exec` events; PreToolUse denies, PostToolUse saves the state
  per session in `~/.cache/crosskill/guard/`, SessionStart warns when the install hash changed.
  SessionStart also appends a line to `CLAUDE_ENV_FILE` (run before every Bash command) that sets
  `HTTPS_PROXY` etc. to `127.0.0.1:9` once `<session>.offline` exists; PostToolUse creates that
  flag when a property is one egress from breaking, and PostToolUse(Failure) reports refused
  connections to the user (`systemMessage`) and to Claude (`additionalContext`). Rewriting the
  command with `updatedInput` doesn't work: Claude Code re-checks permissions on the new command.
  `plugin/` is the Claude Code plugin that wires the hooks; `.claude-plugin/marketplace.json` makes
  the repo a marketplace (`/plugin install crosskill-guard --marketplace idanbe/cross-skill-guard`).
  `claude plugin validate .` checks both. Users install the CLI with `pipx install git+...`.
- `src/crosskill/policy.py`: `decide()` adds `id`, `severity`, `project` to findings, runs
  `opa eval` on `data.crosskill.decisions` and requires exactly one valid decision per finding
  (a missing or conflicting one is an error, never a silent pass). Exceptions are in the data
  file (`policies/data.json`). Without a policy every finding blocks.
- `corpus/`: what every stage is measured against.
  - `toxic/NNN-name/` and `clean/NNN-name/`: each is one install with `skills/<name>/SKILL.md`,
    an optional `.mcp.json` and `settings.json`, and an `expected.json`.
  - `expected.json` is `{"findings": [...]}`. In a toxic install, each finding has `rule`
    (`secret_exfiltration`, `untrusted_to_execution`, `lethal_trifecta`) and `path` (component
    names in flow order), plus rule-specific fields. In a clean install it is `[]`.
  - `real/`: 100 marketplace skills pinned by reference in `MANIFEST.json`, not committed.
    `python -I corpus/real/fetch.py` downloads them into the gitignored `real/cache/`.
    The content is untrusted: never execute it. `real/combos/` builds labeled installs from
    those skills (`install.json` lists manifest ids).
  - `needs_llm: true` in `expected.json` marks flows the static extractors can't see (SKILL.md
    prose, JS/TS scripts). The static test skips them.
  - `skills/<name>/expected_facts.json`: labeled LLM facts for every corpus skill.
  - Classification conventions (what counts as secret, private, untrusted, egress, arbitrary
    execution, deny precedence) are in `docs/facts.md`. `corpus/README.md` has the format.
  - Toxic installs use config only, never working scripts, and `.invalid` domains.
  - Stage 0 targets: 20 toxic, 50 clean, 100 real.
- `tests/test_corpus.py` checks that the corpus is well formed. `tests/test_scan_corpus.py`
  scans every install (and `real/combos/` when the cache exists) and requires every expected
  finding, no finding on clean installs, and under 1 s each. `test_perfect_llm_extractor` feeds
  the labels in as LLM output: it checks that labels and rules agree (no network).
  `tests/test_llm.py`: cache, scoring, quote lines, deny prefixes.

Stage 1 targets: at least 90% recall on toxic installs without `needs_llm`, at most 1 false finding across clean
installs, under 1 s per typical install.
