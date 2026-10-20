# crosskill

Find dangerous combinations of skills, MCP servers and permissions in an agent installation.

Status: stage 2 in progress. `crosskill scan` finds toxic flows using static extractors, an LLM
extractor for SKILL.md prose and JS/TS scripts, and clingo rules, and prints a file:line proof
chain for each (text or `--sarif`). See `docs/facts.md` and `corpus/`.

```
pip install -e ".[dev]"
pytest
cp .env.example .env               # OpenRouter key; Langfuse keys for tracing and evals
crosskill scan path/to/project
crosskill scan --no-llm path/to/project   # static only, nothing leaves the machine
crosskill eval --model deepseek/deepseek-v4.1-flash
```

License: MIT
