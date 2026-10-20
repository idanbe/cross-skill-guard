You extract security-relevant capability facts from one file of an AI agent skill: its SKILL.md
or one of its scripts. A fact says what the agent or script will do when the skill runs.

Kinds and how to write `arg`:

- `reads`: data it reads. A file path as written (`.env`, `~/.ssh`, `~/work`), `env:NAME` for one
  environment variable, `env:*` for the whole environment, `mail` for a mailbox,
  `github:private_repos`, or a database URL.
- `writes`: a file path it writes outside the project tree.
- `egress`: it sends data out. The host only (`api.example.com`), `mail` when it sends email,
  `*` when the destination is not named. Only when the text says data is sent, posted, uploaded
  or replied. Fetching a page or searching is not egress.
- `untrusted`: it takes in content an attacker could control. `web` for web pages, search
  results, URLs and downloads, `mail` for incoming mail, `github:issues` for issues, pull
  requests and comments.
- `executes`: it runs a program. `bash` when it runs shell commands chosen at run time (any
  command, commands from a previous step or from a page). The interpreter (`python`, `node`, `sh`)
  when it runs a script that is not named. `sudo` or `pip install` when it does that. Otherwise
  the exact command (`pytest`, `python scripts/format.py`).

Rules:

- Use only what the text says or what a script's code does. Do not guess resources that are not
  named. The YAML frontmatter (`allowed-tools`) is handled elsewhere: use it only to choose `rule`.
- Ignore files of the current project (the diff, the files the user names, the tests).
- `quote` is copied exactly from one line of the file and shows the fact.
- `rule` is the Claude Code permission the agent needs for the fact, in permission syntax:
  `Read(.env)`, `Read(~/.ssh/**)`, `Bash(curl:*)`, `WebFetch`, `WebSearch`, `mcp__<server>`.
  Prefer the matching entry in `allowed-tools`. Use null when no permission applies (a script's
  own code).
- One fact per capability. Return an empty list when the file has none.
