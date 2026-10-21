# crosskill

Find dangerous combinations of skills, MCP servers and permissions in an agent installation, and
block them while Claude Code runs.

A single skill can look harmless on its own. One reads `.env`; another posts to a webhook.
Installed together, they form a path from your secrets to the internet. crosskill finds those
paths (toxic flows) and explains each one with file:line evidence.

Status: stages 1-2 done, stage 3 (runtime guard) in trial use, stage 4 (policy) done. See
[docs/facts.md](docs/facts.md) for the fact schema and [corpus/](corpus/) for the test installs.

## Install

Needs Python 3.12 or later.

```
pipx install git+https://github.com/idanbe/cross-skill-guard
export OPENROUTER_API_KEY=...   # for the LLM extractor; skip it and pass --no-llm to stay offline
```

For the runtime guard, also install the Claude Code plugin. Inside Claude Code:

```
/plugin install crosskill-guard --marketplace idanbe/cross-skill-guard
```

On Claude Code before 2.1.275, run `/plugin marketplace add idanbe/cross-skill-guard` and then
`/plugin install crosskill-guard@crosskill`. The plugin's hooks call the `crosskill-guard` command
that pipx installed; if it is missing, each session starts with a warning instead.

Quick start:

```
cd your-project
crosskill scan --no-llm .           # what toxic flows does this setup allow?
crosskill guard init --no-llm .     # turn them into runtime properties for the plugin
```

## Scan a project

```
crosskill scan path/to/project            # exit 1 when toxic flows are found
crosskill scan --no-llm path/to/project   # static only, nothing leaves the machine
crosskill scan --sarif path/to/project    # SARIF 2.1.0 for code scanning tools
```

It reads skills (`skills/` and `.claude/skills/`), `.mcp.json` and `.claude/settings*.json`.
Static extractors read SKILL.md frontmatter, permission rules, MCP servers and Python and shell
scripts. The LLM extractor also reads SKILL.md prose and JS/TS scripts, and every fact it returns
must quote the file. Results are cached, so the same text is never paid for twice. clingo rules
then look for three kinds of flow:

| Rule | Meaning |
|---|---|
| `secret_exfiltration` | a secret (`.env`, `~/.ssh`, `~/.aws/credentials`, ...) can reach a network sink |
| `untrusted_to_execution` | web, mail or issue content can drive arbitrary code execution |
| `lethal_trifecta` | private data, untrusted input and egress in one agent |

Example output:

```
secret_exfiltration: secret ~/.aws/credentials can reach * via cost-report → uploader
  skills/cost-report/SKILL.md:4  reads(cost-report, ~/.aws/credentials)
      allowed-tools: Read(~/.aws/credentials)
  skills/uploader/SKILL.md:4  egress(uploader, *)
      allowed-tools: Bash(curl:*)
```

## Decide what to do with each finding

A Rego policy decides, for each finding, whether it blocks, warns or is ignored, always with a
reason. It runs in the local [OPA](https://www.openpolicyagent.org) binary, with no server.

```
crosskill scan --policy policies/strict/policy.rego --data policies/data.json path/to/project
crosskill scan --policy policies/permissive/policy.rego path/to/project
```

```
[ignore] lethal_trifecta: untrusted web input, private /tmp/claude-1000/... via ...
  policy: Claude Code's own scratch directory
[block] secret_exfiltration: secret ~/** can reach * via Read(//home/u/**) → Bash(curl *)
  policy: a secret can reach any host
[warn] secret_exfiltration: secret ~/** can reach langfuse.com via ...
  policy: secret_exfiltration to a named host or of non-secret data: review it
```

| Policy | Blocks | Warns |
|---|---|---|
| `policies/strict` | every finding | nothing |
| `policies/permissive` | untrusted input → code execution, a secret → any host | the rest |

Exceptions live in a data file: each entry matches on any finding field (`rule`, `sink`,
`private_data`, ... as globs) or on a `component` in the flow's path, and its `reason` is reported
with the decision. See `policies/data.json`. The scan exits 1 only when a finding blocks, SARIF
levels follow the decision, and `crosskill guard init --policy ...` turns only blocked findings
into runtime properties. Without `--policy`, every finding blocks. Test a policy with
`opa test policies/strict`.

## Guard Claude Code at runtime

```
crosskill guard init path/to/project      # add --no-llm for a static-only scan
```

Then start Claude Code in that project with the plugin installed (see Install), or, from a clone,
with `claude --plugin-dir path/to/cross-skill-guard/plugin`.

`init` turns each finding into an LTL safety property and saves it, with its automaton, to
`.claude/crosskill-guard.json`. For example, `G(read_secret(.env) → G ¬egress(*))` means "once
`.env` has been read, nothing is sent out for the rest of the session". The plugin's hooks then
follow every tool call:

- A tool call that would break a property is denied before it runs. The reason names the rule,
  the earlier call that armed it, and the file:line evidence from the scan.
- Once a secret has been read, Bash commands in that session run with the network off: proxy
  variables point to a closed port, so scripts using curl, git, pip, npm, Python or Go HTTP
  clients can't connect. `localhost` still works. You and Claude are told why.
- A new session starts clean. If skills or settings change, the next session warns you to rerun
  `init`.

Each hook call takes about 25 ms. Nothing is installed besides the plugin, and no traffic is
decrypted.

Limits: the guard sees what Claude asks to do, not what a program does inside. Programs that
ignore proxy variables (raw sockets, `ssh`, Node `fetch` before 22.21) can still reach the network
after a secret read. For a hard network boundary, also turn on Claude Code's
[sandbox](https://code.claude.com/docs/en/sandboxing). The scan reads the project's settings, not
`~/.claude`.

## Develop

```
git clone https://github.com/idanbe/cross-skill-guard && cd cross-skill-guard
pip install -e ".[dev]"
cp .env.example .env    # OpenRouter key; Langfuse keys for tracing and evals
pytest -q                                      # corpus, scan, guard and policy tests; no network
opa test policies/strict && opa test policies/permissive
ruff check .
crosskill eval --push-only                     # upload labels and prompt to Langfuse
crosskill eval --model deepseek/deepseek-v4.1-flash   # score the LLM extractor per prompt version
```

Corpus: 24 toxic and 53 clean installs, plus 100 real marketplace skills fetched by
`corpus/real/fetch.py`. With prompt v2 and `deepseek/deepseek-v4.1-flash`, the LLM extractor
reaches 0.96 precision and 0.96 recall on the labeled facts ($0.03 per corpus run), and the scan
reports exactly the expected findings on all 77 installs.

License: MIT
