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
| `secret(Resource)` | The resource holds credentials or private data |

## Components

`skill`, `mcp_server`, `hook`, `permission_rule`. Each has a stable id, for example `skill:env-reader`.

## Resource classes

`file` (path or glob), `env` (variable name), `domain`, `mcp_tool`, `web`, `mail`, `shell`.

## Provenance

Every fact carries `source`: `{file, line, extractor, quote?}`.
`extractor` is one of `static`, `llm`, `manual`. LLM facts must include a `quote` from the text.
Explanations in stage 1 are built from these records, so a fact without provenance is invalid.

## Open questions

- Granularity of file resources (path vs. glob vs. class).
- How to represent transitive permission grants (stage 6).
