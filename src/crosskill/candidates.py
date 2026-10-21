"""Candidate advisories: check a new skill, identify and score findings, render advisory pages."""

import math
import re
import shutil
from pathlib import Path
from urllib.parse import urlparse

from crosskill.scan import scan, summary
from crosskill.sources import Skill

POPULAR = Path(__file__).parent.parent.parent / "pipeline" / "popular-mcp.json"
MIN_SCORE = 1.5
WEIGHTS = {
    "severity": {"secret_exfiltration": 3, "untrusted_to_execution": 3, "lethal_trifecta": 2},
    "llm_confidence": 0.8,
    "long_chain": 0.9,  # per chain entry beyond 2
}


def build_install(root: Path, skill_dirs: dict[str, Path]) -> None:
    (root / "skills").mkdir(parents=True, exist_ok=True)
    for dirname, d in skill_dirs.items():
        (root / "skills" / dirname).symlink_to(Path(d).resolve())
    shutil.copy(POPULAR, root / ".mcp.json")


def check(root: Path, new: str, model: str | None) -> list[dict]:
    prefix = f"skills/{new}/"
    return [f for f in scan(root, model) if any(c["file"].startswith(prefix) for c in f["chain"])]


def _mcp_match(server: dict) -> dict:
    host = urlparse(server["url"]).hostname if "url" in server else None
    args = [a for a in server.get("args", []) if not a.startswith("-")]
    pkg = re.sub(r"(?<=.)@[^/]*$", "", args[0]) if args and "url" not in server else None
    return {"kind": "mcp", "package": pkg, "host": host}


def _mcp_version(server: dict) -> str:
    args = [a for a in server.get("args", []) if not a.startswith("-")]
    m = re.search(r"(?<=.)@([^/]*)$", args[0]) if args else None
    return m.group(1) if m else "latest"


def components(finding: dict, skills: dict[str, Skill], mcp: dict) -> list[dict]:
    out, seen = [], set()
    for c in finding["chain"]:
        f = c["file"]
        if f.startswith("skills/"):
            sk = skills[f.split("/")[1]]
            cid = sk.id
            entry = {"id": cid, "version": sk.version, "url": sk.url, "installs": sk.installs,
                     "match": {"kind": "skill", "name": c["component"]}}
        elif f == ".mcp.json":
            server = mcp[c["component"]]
            cid = f"mcp/{c['component']}"
            meta = server.get("x-crosskill", {})
            entry = {"id": cid, "version": _mcp_version(server), "url": meta.get("url", ""),
                     "installs": int(meta.get("installs", 0)), "match": _mcp_match(server)}
        else:
            continue
        if cid not in seen:
            seen.add(cid)
            out.append(entry)
    return out


def key(finding: dict, comps: list[dict]) -> str:
    return finding["rule"] + ":" + ",".join(sorted(c["id"] for c in comps))


def score(finding: dict, comps: list[dict]) -> tuple[float, dict]:
    severity = WEIGHTS["severity"][finding["rule"]]
    reach = math.log10(1 + min((c["installs"] for c in comps), default=0))
    chain = finding["chain"]
    confidence = WEIGHTS["llm_confidence"] if any(c["extractor"] == "llm" for c in chain) else 1.0
    confidence *= WEIGHTS["long_chain"] ** max(0, len(chain) - 2)
    return severity * reach * confidence, {"severity": severity, "reach": reach, "confidence": confidence}


def _where(c: dict, comps: list[dict]) -> str:
    f = c["file"]
    if f == ".mcp.json":
        return f"pipeline/popular-mcp.json:{c['line']}"
    dirname, inner = f.split("/", 2)[1:]
    for comp in comps:
        if comp["id"].startswith("clawhub/") and comp["id"].split("/", 1)[1].replace("/", "--") == dirname:
            return f"{comp['url']} {inner}:{c['line']}"
    return f"{f}:{c['line']}"


def advisory(finding: dict, comps: list[dict], score: float, breakdown: dict,
             adv_id: str, issue_url: str, published: str) -> dict:
    names = list(dict.fromkeys(finding["path"]))
    fields = {k: v for k, v in finding.items() if k not in ("rule", "path", "chain")}
    return {
        "id": adv_id, "key": key(finding, comps), "published": published,
        "title": f"{finding['rule']}: {' + '.join(names)}",
        "rule": finding["rule"], "components": comps, "path": finding["path"], **fields,
        "chain": [{"where": _where(c, comps), "fact": c["fact"], "quote": c["quote"],
                   "extractor": c["extractor"]} for c in finding["chain"]],
        "score": round(score, 2), "breakdown": breakdown, "issue": issue_url,
    }


EXPLAIN = {
    "secret_exfiltration": "read a credential or secret and send it to an outside destination",
    "untrusted_to_execution": "act on content from an untrusted source and run commands with it",
    "lethal_trifecta": "read private data, take in untrusted input and send data out, all in one agent",
}


def render(adv: dict) -> str:
    comps = adv["components"]
    head = (f"Published {adv['published']}. Rule `{adv['rule']}`. Score {adv['score']}. "
            f"Review issue: {adv['issue']}")
    lines = [f"# {adv['id']}: {adv['title']}", "", head, "", "## Components", ""]
    lines += [f"- [{c['id']}]({c['url']}), version {c['version']}" for c in comps]
    lines += ["", "## What this means", ""]
    flow = summary({k: v for k, v in adv.items() if k != "chain"})
    if len(comps) > 1:
        lines += ["Each of these components may be safe on its own. The risk is installing them "
                  + f"together: {flow}.", ""]
        lines.append("Nothing here says any component was written to cause harm. The combination "
                     "gives an agent a path it would not have with either one alone.")
    else:
        lines += [f"This skill can {EXPLAIN[adv['rule']]}: {flow}.", ""]
        lines.append("That set of capabilities is risky for an agent, because one session can use "
                     "all of them in sequence without the user seeing a step in between. This "
                     "page describes what the skill is able to do, not why it was written.")
    lines += ["", "## Proof chain", ""]
    for c in adv["chain"]:
        lines += [f"- `{c['where']}`: `{c['fact']}`" + (" (read by an LLM)" if c["extractor"] == "llm" else ""),
                  f"  > {c['quote']}"]
    b = adv["breakdown"]
    if b:
        calc = f"severity {b['severity']} x reach {b['reach']:.2f} x confidence {b['confidence']:.2f}"
        lines += ["", "## Score", "", f"{calc} = {adv['score']}"]
    return "\n".join(lines) + "\n"


