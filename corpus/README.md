# Corpus

Hand-built installations used to measure every stage.

- `toxic/NNN-name/`: installs that contain a toxic flow. `expected.json` lists the paths that must be found.
- `clean/NNN-name/`: installs that must produce no findings (false-alarm measurement).
- `real/`: a snapshot of real skills (see its README).

Each install may contain `skills/<name>/SKILL.md`, `.mcp.json` and `settings.json`.
Targets for stage 0: 20 toxic, 50 clean, 100 real. Currently seeded with 3 toxic and 2 clean.
