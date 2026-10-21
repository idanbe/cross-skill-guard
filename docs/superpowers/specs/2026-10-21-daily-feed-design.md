# Stage 5: the daily feed (design)

## Intent

`crosskill scan` protects one installation. Stage 5 looks at the public skill ecosystem: every day
it finds new public skills that form a toxic flow together with popular skills and MCP servers,
and, after the owner approves each one, publishes a warning in this repository. Users can read the
warnings before installing a skill, and `crosskill scan` tells them when a published dangerous
combination is installed in their project.

It is also the project's LangGraph stage: a graph that stops for human approval (`interrupt`),
resumes on a later run (`Command(resume=...)`), and keeps its state between GitHub Actions runs in
a checkpointer.

## Goals

- A daily GitHub Actions run that collects new skills, finds the toxic flows they create, scores
  them, and opens one GitHub issue per candidate.
- The owner approves or rejects each candidate with a label. Approved candidates are published to
  `feed/` in this repository on the next run. Nothing is published without approval.
- `crosskill scan` reads the published feed and reports matching combinations.
- Done (from the plan): a week of daily runs, and at least one candidate that went all the way to
  publication. Nothing published without approval.

## Non-goals

- No private disclosure to skill authors, no embargo period (owner's decision: publish directly
  after approval). The plan's 14-30 day disclosure step is dropped for now.
- No separate website or GitHub Pages. The `feed/` folder on GitHub is the readable site.
- No new rule logic: the pipeline reuses the clingo rules and the skill extractors from stages
  1-2. The one extraction addition is static capabilities for the popular MCP servers (see The
  popular set).

## Anti-goals (a failure even if it works)

- Publishing something the owner did not approve, or wording a warning so it reads as an
  accusation that a skill is malicious when the risk is the combination.
- Flooding the approval queue: the same combination raised again every day, or dozens of
  near-duplicates per skill.
- Running untrusted skill content. Skills are data: extracted, never executed (as in
  `corpus/real/fetch.py`).
- Uncapped LLM spend.

## Decisions made with the owner

- Warnings are public, in this (public) repository, under `feed/`.
- No warning to authors before publishing.
- Combinations of any size are in scope (three skills that only together form a lethal trifecta
  are one finding listing all three).
- Single-skill flows are in scope too: a new skill that forms a toxic flow on its own (for
  example a mail skill that reads and sends mail) is a candidate like any combination. Its
  advisory describes what the skill can do, factually (capabilities and the file:line evidence),
  never intent: "this skill can read your mail and send mail", not "this skill steals mail".
- No Langfuse tracing in the daily run for now (the local Langfuse is not reachable from GitHub
  Actions); cost is logged in the run output. Connecting Langfuse Cloud is a later step.
- Each candidate gets a score; the score is a transparent formula, not a model.
- Jev (`typesafe/jev-1.13`, OpenRouter decisions API) is added as a cheap pre-filter for roles,
  measured like the other models.

## The pipeline

One LangGraph `StateGraph`, run once a day by a scheduled workflow (and `workflow_dispatch`):

1. **collect**: list skills published or updated since the last run, from the two sources the
   corpus already uses: skills.sh leaderboard repositories (pinned by commit and path) and
   ClawHub (pinned by version and the sha256 of its ZIP, with download counts). Respect rate
   limits (`Retry-After`), identify with a User-Agent, keep a cap on skills per run. Download into
   a scratch directory as data only.
2. **triage (Jev)**: ask Jev four yes/no questions per new SKILL.md: reads secrets or private
   data, sends data out, takes untrusted input, runs arbitrary code. A skill with no role above the
   threshold stops here. Starting threshold 0.2 (low on purpose: a dropped role is a missed
   finding); tune it from the eval below.
3. **extract**: the existing static and LLM extractors (`deepseek/deepseek-v4.1-flash`, prompt
   v2) on the skills that passed, with the existing disk cache keyed by model + prompt + text, so
   a skill is never paid for twice. The cache must survive between runs (see State).
4. **check**: one clingo run with the new skill's grants plus the **popular set**'s grants. Keep
   only findings whose path includes the new skill (yesterday's combinations are not raised
   again). For `lethal_trifecta` the untrusted-input component counts as part of the combination
   even though it sits outside `path`. Keep the shortest path per rule and key fields (as `scan`
   does), and at most a few findings per new skill.
   - Same combination (builder's call, recorded here): the key is the rule plus the sorted set of
     component ids, without versions. A ledger on the `data` branch records every key that was
     raised, approved or rejected. A key in the ledger is never raised again, whatever version
     changes; a rejected key stays silent for good. An update to a skill is collected like a new
     skill, but its combinations are filtered by the ledger. Published advisories record the
     versions that were checked and are not re-checked.
5. **score**: `score = severity × reach × confidence`.
   - severity: secret_exfiltration 3, untrusted_to_execution 3, lethal_trifecta 2.
   - reach: log10(1 + installs) of the **least** installed component in the path (all must be
     installed together). Unknown install counts count as low.
   - confidence: 1.0 when every fact on the path is static, 0.8 when any fact came from the LLM,
     lower for longer paths.
   - Weights live in one small table so they can be tuned. Below a threshold, the candidate is
     dropped; the issue shows the score and how it was computed.
6. **approve**: open one GitHub issue per candidate (rule, components with links and pinned
   versions, the file:line proof chain, score breakdown) and `interrupt`. The graph state for that
   candidate waits.
7. **resume** (on later runs): read candidate issues; an `approve` label resumes the candidate
   with `Command(resume="approve")`, `reject` with `"reject"` (closes the issue). No label: keep
   waiting.
8. **publish**: for approved candidates, write the advisory files and commit them to `main`
   directly (the `approve` label is the approval; `main` has no branch protection). The workflow
   needs `contents: write` and `issues: write`, and creates the `approve`, `reject` and
   `crosskill-candidate` labels if missing.

## The popular set

The few hundred most installed skills and MCP servers, refreshed weekly: the skills.sh
leaderboard and the ClawHub top downloads, plus a hand-kept list of popular MCP servers in a JSON
file in the repo. Their grants are extracted once and cached. A new skill is checked against the
whole set in one clingo call, which also covers combinations of three or more components.

Popular MCP servers get their grants statically (builder's call): `pipeline/popular-mcp.json`
holds one `.mcp.json`-style config per server, and `mcp_caps` in `extract.py` is extended with
those packages. Provenance is the line in that file, as for any `.mcp.json`, so proof chains stay
`file:line`. Servers that cannot be described this way are left out of the set.

## The feed

```
feed/
  README.md               index, newest first (generated)
  advisories.json         machine-readable list (generated)
  CK-2026-0001.md         one readable page per advisory
```

An advisory has: `id` (`CK-<year>-<number>`), `published`, `rule`, `components` (each with
source, id, pinned version or commit, url), `path`, the rule fields, the proof chain
(file:line, fact, quote), `score` and its breakdown, and the issue link. For a combination, the
page states that each skill may be safe on its own and that the risk is installing them
together. For a single skill, it states what the skill is able to do and why that set of
capabilities is risky for an agent, without claiming intent.

`crosskill scan` (no LLM needed) downloads `advisories.json` from the repository's raw URL, caches
it for a day, and reports each advisory whose components are all installed in the scanned
project. `--offline` skips it. Matching (builder's call): a local install has no source, so a
skill matches by its component name as the extractors see it (frontmatter `name`, else directory
name), an MCP server by its package name in `args` or its URL host, and any version matches. The
report therefore says "possible match" and links the advisory; each advisory stores these local
match keys next to its source ids.

## State between runs

GitHub Actions runners are wiped after each run, so state lives on a separate `data` branch:

- the LangGraph SQLite checkpointer database,
- the "last collected" cursor per source,
- the LLM and Jev response caches.

The workflow checks out `data` at the start and commits it back at the end. The workflow has
`concurrency` set so two runs never write `data` at once.

## Cost and limits

- GitHub Actions and the repository are free (public repository).
- LLM: about $0.001 per new skill with flash, much less with Jev triage first. Daily cap in code
  (for example $0.50), tracked per run; the run stops extracting when it is reached and continues
  the next day.
- Secrets: `OPENROUTER_API_KEY` as a repository secret.

## Evaluating Jev

Jev is called on OpenRouter's decisions endpoint, `POST https://openrouter.ai/api/alpha/decisions`
([reference](https://openrouter.ai/docs/api/api-reference/alphadecisions/submit-a-decisions-request)),
not on chat completions. A request has `model`, `state` (the SKILL.md text) and `questions`; each
role is a `noul` question with `instructions` and `true`/`false` criteria, and the answer is a
probability (`{"type": "noul", "noul": 0.96}`); the threshold applies to that probability.
`usage.cost` gives the cost for the daily cap. Cache key: model + questions + text. The spike
script is kept as `docs/superpowers/specs/jev_spike.py`.

Add the roles triage to `crosskill eval`: per role, precision and recall of Jev against the roles
derived from the corpus `expected_facts.json` (as in the spike), and the recall of whole findings
after triage (scan the corpus with triage on: how many expected findings survive). A first spike
at threshold 0.5 gave, on 92 skills: reads 0.68 / 0.93, sends 1.00 / 1.00, untrusted 0.89 / 0.85,
runs code 0.40 / 0.80 (P / R), $0.0022, 0.5 s median. The labels skip frontmatter facts, so
precision is understated.

## Left to the builder

- LangGraph version, node boundaries, and how candidates map to threads in the checkpointer.
- The exact advisory Markdown layout and the issue template.
- How skills.sh and ClawHub are listed incrementally (their APIs and what "new since" means for
  each), within their terms and rate limits.
- Thresholds and weights (start with the values above; record changes).
- Test strategy (the graph should be testable offline with recorded source responses and a fake
  GitHub client).
