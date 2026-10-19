# crosskill

Find dangerous combinations of skills, MCP servers and permissions in an agent installation.

Status: stage 1. `crosskill scan` finds toxic flows using static extractors and clingo rules,
and prints a file:line proof chain for each (text or `--sarif`). See `docs/facts.md` and
`corpus/`.

```
pip install -e ".[dev]"
pytest
crosskill scan path/to/project
```

License: MIT
