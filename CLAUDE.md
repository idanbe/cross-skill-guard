# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

crosskill finds toxic flows in an agent installation: dangerous combinations of skills, MCP servers
and permissions (for example, one skill reads `.env` and another posts to a webhook). It is a
learning project that practices one tool per stage: clingo, Langfuse, LTL, OPA, LangGraph, Z3.

The roadmap, with done criteria and targets for each stage, is in `cross-skill-guard-plan.md`. Check
which stage is current before starting work. Rule from the plan: finish a stage against its done
criteria before opening the next one.

Status: stage 1 done. `crosskill scan` meets its targets: 22/22 static toxic findings, 0 false
findings on clean, a few ms per install. Next is stage 2: Langfuse and the LLM extractor.

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
crosskill scan --sarif corpus/toxic/020-two-findings  # SARIF 2.1.0
```

## Architecture

Pipeline, one engine shared by the scan, the runtime guard and the daily feed:
extractors (static: `ast`, bashlex, SKILL.md frontmatter, `.mcp.json`, `settings.json`; LLM in
stage 2) → facts → clingo rules (`tainted` → `toxic`, with the path carried inside each atom) →
findings with a file:line proof chain → terminal/SARIF output. Later stages add an OPA policy,
LTL runtime hooks and a LangGraph daily feed on top of these findings.

- `docs/facts.md` is the contract between extractors and rules. Facts are the only input to
  clingo. Every fact needs provenance `{file, line, extractor, quote?}`, and LLM facts must include
  a quote. Explanations are built from provenance, so a fact without it is invalid.
- `src/crosskill/extract.py`: static extractors → `Grant`s (one capability fact plus provenance),
  and the secret/private classification. Reads the corpus layout and `.claude/`.
- `src/crosskill/rules.lp`: clingo rules. `flow/6` is the recursive, path-carrying reachability;
  all components share the agent context (one hop per path). `not denied(G)` applies deny rules.
- `src/crosskill/scan.py`: grounds and solves, keeps the shortest path per finding, renders the
  file:line chain as text or SARIF. `src/crosskill/cli.py`: typer app.
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
    prose, JS/TS scripts). Tests skip them until stage 2.
  - Classification conventions (what counts as secret, private, untrusted, egress, arbitrary
    execution, deny precedence) are in `docs/facts.md`. `corpus/README.md` has the format.
  - Toxic installs use config only, never working scripts, and `.invalid` domains.
  - Stage 0 targets: 20 toxic, 50 clean, 100 real.
- `tests/test_corpus.py` checks that the corpus is well formed. `tests/test_scan_corpus.py`
  scans every install (and `real/combos/` when the cache exists) and requires every expected
  finding, no finding on clean installs, and under 1 s each.

Stage 1 targets: at least 90% recall on toxic installs without `needs_llm`, at most 1 false finding across clean
installs, under 1 s per typical install.
