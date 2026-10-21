# Fact schema

Every extractor emits facts of the form `predicate(args)` plus a provenance record.
Facts are the only input to the clingo rules (stage 1).

## Predicates

| Predicate | Meaning |
|---|---|
| `reads(Component, Resource)` | The component reads the resource |
| `writes(Component, Resource)` | The component writes the resource |
| `egress(Component, Domain)` | The component can send data to the domain |
| `executes(Component, Command)` | The component runs a command or program |
| `ingests_untrusted(Component, Source)` | The component processes content an attacker could control |
| `secret(Resource)` | The resource holds credentials |
| `private(Resource)` | The resource holds private data (a secret too, if `secret` also holds) |
| `arbitrary(Command)` | Running the command lets the caller run any code |

In clingo (`src/crosskill/rules.lp`) the five capability predicates arrive as one form,
`grant(Id, Component, Kind, Arg)` with `Kind` in `reads`, `writes`, `egress`, `executes`,
`untrusted` (= `ingests_untrusted`). `Id` indexes the provenance record, so every path atom
carries the ids of the grants it used, and the proof chain is read back from them.
`denied(Id)` marks a grant that a `deny` rule removes.

## Components

`skill`, `mcp_server`, `hook`, `permission_rule`. A component is named by its skill name, MCP
server key, `hook:<Event>`, or permission rule text (for example `WebFetch`).

## Resource classes

`file` (path or glob), `env` (variable name), `domain`, `mcp_tool`, `web`, `mail`, `shell`.

## Provenance

Every fact carries `source`: `{file, line, extractor, quote?}`.
`extractor` is one of `static`, `llm`, `manual`. LLM facts must include a `quote` from the text.
Explanations in stage 1 are built from these records, so a fact without provenance is invalid.

## Classification conventions

The corpus `expected.json` files assume these rules. Change them here first, then in the corpus.

- **Secret:** `.env` and `.env.*` (but not `.env.example` or `.env.sample`), `~/.ssh/**`,
  `~/.aws/credentials`, `~/.config/gcloud`, `~/.kube/config`, `~/.netrc`, `~/.npmrc`, `~/.pgpass`,
  `~/.git-credentials`, `~/.config/gh/hosts.yml`, `~/.docker/config.json`, `~/.password-store/**`,
  and the whole environment (`env:*`, read by `Bash(printenv:*)` or `Bash(env:*)`).
  Config files with no credentials (`~/.aws/config`, `~/.ssh/config`) are not secrets, and neither
  is one named variable such as `Bash(printenv HOME)`.
- Unrestricted `Read`, `Grep`, `Glob`, `Edit` cover the project tree and never count as reading a
  secret. Only a rule that names a secret path does. This is a deliberate under-approximation:
  counting them would flag almost every install.
- **Private data:** paths outside the project (`~/work`, `~/clients/**`), databases (postgres,
  sqlite MCP), mail, private repos, Slack workspaces (`slack`), Google Drive (`gdrive`). The current project tree is not private data.
- **Untrusted input:** web content (`WebFetch`, `WebSearch`, fetch and browser MCP servers),
  mail, issues and comments (GitHub MCP), tool results from unknown remote MCP servers, and
  anything `curl` or `wget` download.
- **Egress:** `WebFetch` (to its `domain:` if one is given, otherwise `*`), fetch and browser MCP
  servers (`*`), remote MCP servers (their host), GitHub MCP (`api.github.com`), and `curl`,
  `wget` (`*`).
- **Arbitrary execution:** unrestricted `Bash`, `Bash(*)`, and prefixes that run any code: `bash`,
  `sh`, `python`, `node`, `pip install`, `sudo`. A prefix that pins a script or tool (`Bash(pytest:*)`,
  `Bash(python scripts/format.py:*)`, `Bash(npm test:*)`) is not arbitrary.
- `executes(C, any)` does not imply `reads`, `egress` or `ingests_untrusted`. Only the programs
  listed under egress do.
- A `deny` rule in `settings.json` removes the matching capability, even when a skill's
  `allowed-tools` or an `allow` rule grants it. `mcp__<server>` denies every tool of that server.
- Each finding is reported once under the most specific rule: secret → egress is
  `secret_exfiltration`, even when untrusted input is also present. `lethal_trifecta` is for
  private data that is not a secret.

## LLM facts (stage 2)

`src/crosskill/llm.py` asks a model (through OpenRouter) for facts in one file: SKILL.md or a
JS/TS script. `src/crosskill/prompt.md` is the prompt, pushed to Langfuse as `crosskill-extract`.

- The `arg` forms are the ones above, plus `mail` for a mailbox and `*` for an unnamed
  destination. Egress means data is sent, posted, uploaded or replied; fetching or searching is
  untrusted input only.
- Only what the text names. A resource the text does not name is not guessed.
- Each fact carries the permission `rule` the agent needs (`Read(.env)`, `Bash(curl:*)`,
  `mcp__mail`), so `deny` applies to LLM facts too. In a deny, `prefix:*` matches any command
  that starts with the prefix, and `dir/**` also covers `dir`.
- A fact whose `quote` is not in the file is dropped. Its line is where the quote is found.
- An LLM fact is a grant even with no `allow` rule: the skill tells the agent to do it, and the
  user is one approval away. The component is the skill, even when the text describes an MCP
  server's tools.

Labels are `skills/<name>/expected_facts.json` (`{"facts": [{kind, arg, rule}]}`) for every
corpus skill, written from the body text only (frontmatter is static). They list only facts that
can change a finding: secret or private reads and writes, egress, untrusted input, arbitrary
execution. Evals score the same subset (`src/crosskill/evals.py`).

## Open questions

- Granularity of file resources (path vs. glob vs. class).
- How to represent transitive permission grants (stage 6).
- Named env vars such as `BAIDU_API_KEY` are not secrets today: 10+ real skills read their own
  API key and send it to their own provider, which is intended. Flagging them needs a notion of
  the key's own domain.
- JS/TS scripts have no static extractor (many real skills use them); stage 2 covers them.
