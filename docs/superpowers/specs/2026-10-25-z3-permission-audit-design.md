# Stage 6: Z3 permission audit (design)

*As of 2026-10-25 · Idan*

## Intent

A `Bash` allow rule in `settings.json`, such as `Bash(git:*)`, auto-approves a whole family of
commands so the agent never stops to ask. The user trusts the rule to mean "only git". But the
Claude Code permission matcher is explicit that a Bash rule "isn't a security boundary around the
program": the same dangerous program, reached through a form the rule can't constrain, slips past.

`crosskill audit-permissions` audits one install's `settings.json` and answers a sharper question
than tests can: *is there a command that the allow rules approve, the deny rules miss, and that
still runs an arbitrary or network program?* If there is, it returns the command as a concrete
counterexample. If there is not — within the model — it says so, which is a guarantee ordinary
tests never give.

This is the Z3 stage: the matcher's rules become string constraints, and the solver searches the
whole space of command strings at once instead of the handful a test author thought of.

## How the real matcher behaves (the facts the model rests on)

From the Claude Code permissions documentation (fetched 2026-10-25):

- A `Bash(prefix:*)` / `Bash(prefix *)` allow rule matches the whole command text, `*` standing
  for any run of characters. A trailing `* ` with a space also matches the bare prefix.
- **Compound commands are split** on `&&`, `||`, `;`, `|`, `|&`, `&`, and newlines. Each
  subcommand must match some allow rule on its own. So plain chaining (`allowed && evil`) no
  longer bypasses allow rules — the model must not claim it does.
- **A fixed wrapper set is stripped before matching**: `timeout`, `time`, `nice`, `nohup`,
  `stdbuf`, `command`, `builtin`, `noglob`, and bare `xargs` (no flags). An allow rule therefore
  also approves `timeout 30 <cmd>`.
- **A leading assignment of a known-safe env var is stripped** for allow rules (e.g.
  `NODE_ENV=test npm test`). An assignment of any *other* variable stops an allow-rule match.
- A deny/ask rule matches if **any** subcommand matches, including inside a subshell or
  command substitution, and matches past any leading assignment.
- The documented residual gaps — the same program by **absolute path** (`/usr/bin/curl …`),
  inside **`sh -c '…'`**, through **`git -c …`** / **`git -C …`**, or through a **non-stripped
  environment runner** (`devbox run`, `npx`, `docker exec`, `mise exec`, `direnv exec`) — are
  exactly the forms a prefix rule fails to constrain.

The bypass class this stage targets is **alternate invocation forms of a dangerous program**, not
operator chaining (which the matcher now handles).

## Goals

- `crosskill audit-permissions PATH` reads `PATH`'s `settings.json`, models its `allow`/`deny`
  Bash rules, and reports each distinct way an arbitrary/network program can be run while every
  subcommand is still auto-approved.
- Every counterexample is a real, runnable command string, verified with bashlex to actually
  invoke a program in the project's `ARBITRARY`/`NETWORK` sets before it is reported.
- `unsat` (no counterexample) is reported plainly, with a one-line statement that it holds only
  within the documented model.
- A verified bypass can join the clingo toxic-path search, so a permission bypass can complete a
  flow like any other grant. It does so through the ordinary grant pipeline (see Decisions), not a
  new fact type.
- Text output by default; exit 1 when a bypass is found, 0 otherwise (matches `scan`).

## Non-goals

- Not a full reimplementation of the Claude Code matcher. The model covers the handful of rule
  shapes that yield arbitrary-execution bypasses; find `-exec`, the read-only command list,
  redirections, Windows UNC paths and the rest are out of scope and marked so.
- Not a runtime enforcement change. This audits the static config; the stage 3 guard still does
  runtime blocking.
- Not a general shell-injection scanner. It only asks whether *the allow rules* fail to constrain
  a dangerous program.
- No change to how permissions are extracted for the scan today; this is an added command.

## Anti-goals (what would make it a failure even if it runs)

- **False counterexamples.** A reported command that Claude Code would actually prompt on, or that
  doesn't really run anything dangerous, destroys trust. Hence bashlex verification is mandatory,
  not optional.
- **A model that silently drifts from the real matcher.** If `unsat` is claimed on a rule set that
  the real matcher would let through, the guarantee is worse than nothing. The model's assumptions
  are written down next to the code and the known residual gaps are encoded as positive test
  cases, so a matcher change that we failed to model shows up as a test that should find a bypass
  and doesn't.

## Constraints

- Python 3.12, add `z3-solver` to `dependencies` in `pyproject.toml`. bashlex is already a dep.
- New module `src/crosskill/audit.py`; wire a `crosskill audit-permissions` command in `cli.py`.
- Keep it fast (seconds, like the rest). The string problem is small (a bounded alphabet of
  program tokens and separators), so cap command length and the candidate-program set.
- Reuse `ARBITRARY`, `NETWORK`, and the rule *parsing* (`RULE`, `bash_caps`) from `extract.py`
  rather than re-deriving them. `covers` is **not** reused for matching — see Decisions.

## Decisions already made (the "how")

- **Solver:** Z3 via `z3-solver`, using its string theory (`PrefixOf`, `Contains`, `str.in_re`).
  The plan names Z3; this is the point of the stage.
- **Model shape — enumerate forms, let Z3 fill the gaps.** Rather than model free-form shell
  syntax (intractable and fragile), the tool enumerates the documented bypass *forms* (absolute
  path, `sh -c`, `git -c`, env runner, wrapper-wrapped) applied to each dangerous program, and
  uses Z3 to decide, per form, whether a string exists that (a) every allow rule approves and (b)
  no deny rule catches. This keeps the solver's job to the string-matching semantics, which is
  what Z3 is good at, and keeps the model honest about *which* forms it claims to cover.

  *Rationale over a from-scratch grammar model:* the residual bypasses are a short, documented
  list of invocation forms, not an open-ended grammar. Modeling the list directly is smaller,
  readable, and maps one-to-one onto the doc, so a reader can check the model against the source.
  `ponytail:` the day the matcher grows a new documented gap, add one form; don't grow a grammar.

- **Matching is built fresh, not via `covers`.** `covers(deny, rule)` (extract.py:94) matches a
  rule *pattern* against another rule *pattern*; it cannot match a free-form command string and
  implements none of compound-split / wrapper-strip / safe-env-strip / deny-matches-any-subcommand.
  Those semantics are encoded in Z3. `RULE`/`bash_caps` are reused only to parse rule text. A
  builder must not route a command string through `covers` — doing so silently under-models deny
  and produces false `unsat`, the anti-goal above.

- **Verification resolves the *effective* program, not the top-level token.** Each candidate is
  parsed with bashlex; the tool then resolves what the form actually runs — the inner command of
  `sh -c '…'`, the program set by `git -c core.sshCommand=…` / behind `git -C`, and the command an
  environment runner (`devbox run`, `npx`, `docker exec`, `mise exec`, `direnv exec`) executes —
  and checks *that* against `ARBITRARY`/`NETWORK` (after stripping path and known wrappers). The
  global `ARBITRARY`/`NETWORK` sets are **not** extended: doing so would change scan classification
  and every corpus `expected.json`. This keeps the required `git -c … curl` case verifiable while
  leaving the scan's own classification untouched. A runner that by its nature executes arbitrary
  downloaded code (`npx <pkg>`) counts as arbitrary execution even when no inner program is named.
  Unparseable or benign candidates are dropped, never reported.

- **clingo link via the ordinary grant pipeline (no new fact).** A verified bypass becomes a plain
  `Grant(comp=<rule text>, kind="executes" or "egress", arg=<effective program>, arbitrary=True,
  extractor="z3", rule=<rule text>, file="settings.json", line=<rule line>)`, following the same
  `executes`/`egress` split `bash_caps` already makes. `scan.py` `facts()` turns it into
  `grant/arbitrary/component` with no change to `rules.lp` or the fact contract. `arbitrary=True`
  is mandatory or `untrusted_to_execution` never fires. The bespoke `executes_unrestricted` fact
  the plan sketched is dropped as unnecessary — the plan text is updated to match.

- **Audit reaches a scan only through an opt-in flag.** `audit-permissions` is standalone. A new
  `crosskill scan --audit PATH` runs the audit and merges its `z3` grants into the grant list
  before grounding, so a bypass can complete a toxic path; a plain `scan` does not run the audit,
  keeping it fast and the z3 dependency off the default path. The Done-when "flows into scan"
  criterion is met by `--audit` plus a test that a bypass grant completes a path.

- **Output:** per bypass, the rule that approved it, the counterexample command, the program it
  really runs, and the `settings.json` line. SARIF deferred (see open items) — text first.

## What is left to the builder

- The exact Z3 encoding of each bypass form (prefix constraints, the wrapper/env-strip handling,
  the deny-matches-any-subcommand rule). The design fixes *which* forms and *that* Z3 decides
  them; the constraint encoding is the builder's.
- The candidate-program alphabet and command-length bound that keep it fast while covering the
  corpus — tune against real rule sets.
- Test corpus: a few `settings.json` fixtures — at least one weak rule set that must yield a known
  bypass form, and one tight rule set (deny the network tools, allow only pinned scripts) that
  must return `unsat`. Plus the plan's named case (`git -c` style command execution).

## Done when

- The tool finds the known bypass forms on the weak test rule sets.
- It returns `unsat` on a tight, safe rule set.
- Every reported counterexample passes bashlex verification.
- A found bypass's `executes_unrestricted` fact flows into `crosskill scan` and can complete a
  toxic path.
- `opa`/`ruff`/`pytest` green in CI; the model's assumptions and residual-gap list documented in
  `audit.py` and `docs/facts.md`.

## Open items

- SARIF output for audit findings (defer until text output proves useful).
- (resolved 2026-10-25) Audit reaches scan through opt-in `scan --audit`, not automatically.
