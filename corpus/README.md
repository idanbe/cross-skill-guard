# Corpus

Hand-built installations used to measure every stage.

- `toxic/NNN-name/`: installs that contain a toxic flow. `expected.json` lists the paths that must be found.
- `clean/NNN-name/`: installs that must produce no findings (false-alarm measurement). Many are
  near misses: one leg of a flow is missing, or a `deny` rule removes it.
- `real/`: a snapshot of real skills (see its README).

Each install has `skills/<name>/SKILL.md` and may add `.mcp.json`, `settings.json` and
`skills/<name>/scripts/`. Classification follows the conventions in `docs/facts.md`.

## expected.json

```json
{"needs_llm": false, "findings": [{"rule": "secret_exfiltration", "path": ["a", "b"], ...}]}
```

- `needs_llm`: `true` when stage 1's static extractors cannot see the flow: it is only in
  SKILL.md prose, or only in JS/TS scripts. Stage 1 measures recall on the installs where it is
  `false` or missing. Stage 2 adds the rest.
- `based_on` (optional): the published pattern the install models, for example a pattern id
  from the arXiv study of 31k marketplace skills.
- `path`: component names in flow order. A skill or MCP server is named by its name. A
  `settings.json` rule is named by its text, for example `"WebFetch"`. A `lethal_trifecta`
  path is `[untrusted input, private data, egress]`.
- Rule fields: `secret_exfiltration` has `resource` and `sink`, `untrusted_to_execution` has
  `source` and `sink`, `lethal_trifecta` has `private_data`, `untrusted_input` and `egress`.
  A sink of `"*"` means any domain.

Toxic installs give their capabilities through config only (`allowed-tools`, `.mcp.json`,
`settings.json`) and never through working scripts. Malicious domains use the reserved
`.invalid` TLD. Scripts appear only in clean installs.

`real/combos/NNN-name/`: installs built from real skills. `install.json` lists manifest ids,
`expected.json` has the same format plus `evidence` (file:line in the fetched skill). Tests that
scan them need `real/cache/`.

## expected_facts.json

Next to every SKILL.md: the facts the LLM extractor should find in its body, in the form
described in `docs/facts.md` (LLM facts). `crosskill eval --push-only` uploads them to Langfuse
as the `crosskill-facts` dataset.

Now: 24 toxic (3 need the LLM, 4 modeled on published patterns), 53 clean, 100 real, 2 real
combos.
