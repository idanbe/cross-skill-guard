"""Run the clingo rules over extracted facts and build findings with a proof chain."""

import json
from pathlib import Path

import clingo

from crosskill import __version__
from crosskill.extract import Grant, extract, is_private, is_secret

RULES = (Path(__file__).parent / "rules.lp").read_text()
FIELDS = {
    "secret_exfiltration": ("resource", "sink"),
    "untrusted_to_execution": ("source", "sink"),
    "lethal_trifecta": ("private_data", "untrusted_input", "egress"),
}


def q(s: str) -> str:
    return str(clingo.String(s))


def facts(grants: list[Grant]) -> str:
    out = {f"component({q(g.comp)})." for g in grants}
    for i, g in enumerate(grants):
        out.add(f"grant({i},{q(g.comp)},{g.kind},{q(g.arg)}).")
        if g.denied:
            out.add(f"denied({i}).")
        if g.arbitrary:
            out.add(f"arbitrary({q(g.arg)}).")
        if g.kind == "reads":
            out |= {f"secret({q(g.arg)})."} if is_secret(g.arg) else set()
            out |= {f"private({q(g.arg)})."} if is_private(g.arg) else set()
    return "\n".join(sorted(out))


def path_ids(p: clingo.Symbol) -> list[int]:
    ids = []
    while p.name == "p":
        ids.append(p.arguments[0].number)
        p = p.arguments[1]
    return ids[::-1]


def dedupe(xs: list[str]) -> list[str]:
    return [x for i, x in enumerate(xs) if i == 0 or x != xs[i - 1]]


def finding(atom: clingo.Symbol, grants: list[Grant]) -> tuple[list[int], dict]:
    args = atom.arguments
    if atom.name == "lethal_trifecta":
        ids = [args[3].number] + path_ids(args[4])
        path = [grants[i].comp for i in (ids[0], ids[1], ids[-1])]
    else:
        ids = path_ids(args[-1])
        path = dedupe([grants[i].comp for i in ids])
    fields = dict(zip(FIELDS[atom.name], (a.string for a in args), strict=False))
    chain = [{"file": grants[i].file, "line": grants[i].line, "component": grants[i].comp,
              "fact": f"{grants[i].kind}({grants[i].comp}, {grants[i].arg})",
              "quote": grants[i].quote} for i in ids]
    return ids, {"rule": atom.name, "path": path, **fields, "chain": chain}


def scan(root: Path) -> list[dict]:
    grants = extract(Path(root))
    ctl = clingo.Control(["--warn=none"])
    ctl.add("base", [], RULES + facts(grants))
    ctl.ground([("base", [])])
    atoms: list[clingo.Symbol] = []
    ctl.solve(on_model=lambda m: atoms.extend(m.symbols(shown=True)))
    # One finding per rule and key fields, explained by its shortest path.
    best: dict[tuple, tuple] = {}
    for atom in atoms:
        ids, f = finding(atom, grants)
        key = (f["rule"], *(f[k] for k in FIELDS[f["rule"]]))
        rank = (len(ids), f["path"])
        if key not in best or rank < best[key][0]:
            best[key] = (rank, f)
    return [f for _, (_, f) in sorted(best.items())]


def summary(f: dict) -> str:
    via = " → ".join(f["path"])
    if f["rule"] == "secret_exfiltration":
        return f"secret {f['resource']} can reach {f['sink']} via {via}"
    if f["rule"] == "untrusted_to_execution":
        return f"untrusted {f['source']} input can drive {f['sink']} via {via}"
    return (f"untrusted {f['untrusted_input']} input, private {f['private_data']} "
            f"and egress to {f['egress']} via {via}")


def to_text(findings: list[dict]) -> str:
    if not findings:
        return "no toxic flows found"
    out = [f"{len(findings)} toxic flow(s)"]
    for f in findings:
        out += ["", f"{f['rule']}: {summary(f)}"]
        out += [f"  {c['file']}:{c['line']}  {c['fact']}\n      {c['quote']}" for c in f["chain"]]
    return "\n".join(out)


def to_sarif(findings: list[dict]) -> str:
    def loc(c: dict) -> dict:
        return {"physicalLocation": {"artifactLocation": {"uri": c["file"]},
                                     "region": {"startLine": c["line"]}}}

    results = [{
        "ruleId": f["rule"], "level": "error", "message": {"text": summary(f)},
        "locations": [loc(f["chain"][0])],
        "relatedLocations": [loc(c) | {"id": i, "message": {"text": c["fact"]}}
                             for i, c in enumerate(f["chain"])],
    } for f in findings]
    driver = {"name": "crosskill", "version": __version__,
              "rules": [{"id": r} for r in FIELDS]}
    return json.dumps({"version": "2.1.0",
                       "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
                       "runs": [{"tool": {"driver": driver}, "results": results}]}, indent=1)
