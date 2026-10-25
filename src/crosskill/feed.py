"""Shared advisories: a user reports a flow found by a local scan, the owner approves it.

`report` turns a local finding into a draft advisory, `issue_url` opens it as a pre-filled GitHub
issue that the user reviews and submits in the browser (no token needed). When the owner adds the
`approve` label, the publish workflow runs `publish` on the issue body: the JSON in it is
untrusted input, so `parse` validates it and rebuilds every derived field.
"""

import json
import re
from datetime import date
from pathlib import Path
from urllib.parse import quote, urlparse

from crosskill import __version__
from crosskill.scan import FIELDS, summary

REPO = "idanbe/cross-skill-guard"
MARKER = "<!-- crosskill-report -->"
MAX_URL = 7000  # GitHub rejects much longer new-issue URLs
EXPLAIN = {
    "secret_exfiltration": "read a credential or secret and send it to an outside destination",
    "untrusted_to_execution": "act on content from an untrusted source and run commands with it",
    "lethal_trifecta": "read private data, take in untrusted input and send data out, all in one agent",
}


def _mcp_match(server: dict) -> dict:
    if "url" in server:
        return {"kind": "mcp", "package": None, "host": urlparse(server["url"]).hostname}
    args = [a for a in server.get("args", []) if not a.startswith("-")]
    return {"kind": "mcp", "package": re.sub(r"(?<=.)@[^/]*$", "", args[0]) if args else None,
            "host": None}


def _components(root: Path, finding: dict) -> list[dict]:
    """The skills and MCP servers in a finding. Permission rules and hooks are local config, not
    something another user installs, so they are left out."""
    try:
        servers = json.loads((root / ".mcp.json").read_text()).get("mcpServers", {})
    except (OSError, ValueError, AttributeError):
        servers = {}
    out = {}
    for c in finding["chain"]:
        name, f = c["component"], c["file"]
        if f.startswith(("skills/", ".claude/skills/")):
            out.setdefault(name, {"id": f"skill/{name}", "match": {"kind": "skill", "name": name}})
        elif f == ".mcp.json" and name in servers:
            m = _mcp_match(servers[name])
            out.setdefault(name, {"id": f"mcp/{m['package'] or m['host'] or name}", "match": m})
    return list(out.values())


def key(rule: str, comps: list[dict]) -> str:
    return rule + ":" + ",".join(sorted(c["id"] for c in comps))


def report(root: Path, finding: dict) -> dict | None:
    """A draft advisory for one finding, or None when it has no skill or MCP server in it.
    Quotes are left out: a local skill may be private."""
    comps = _components(Path(root), finding)
    if not comps:
        return None
    return {"rule": finding["rule"], "path": finding["path"],
            **{k: finding[k] for k in FIELDS[finding["rule"]]},
            "components": comps,
            "chain": [{"where": f"{c['file']}:{c['line']}", "fact": c["fact"],
                       "extractor": c["extractor"]} for c in finding["chain"]],
            "crosskill": __version__}


def issue_url(rep: dict) -> str:
    """A new-issue link with the report filled in, for the user to review and submit."""
    names = " + ".join(dict.fromkeys(rep["path"]))
    body = "\n".join([
        "`crosskill scan` found this flow in a local install, and I chose to share it.",
        "", "**Before submitting:** check that nothing below is private (paths, names).", "",
        f"{rep['rule']}: {summary(rep)}", "", MARKER, "```json", json.dumps(rep, indent=1), "```"])
    url = (f"https://github.com/{REPO}/issues/new?title={quote(f'[report] {rep['rule']}: {names}')}"
           f"&body={quote(body)}")
    return url if len(url) <= MAX_URL else f"https://github.com/{REPO}/issues/new"


def _text(v, limit: int = 200) -> str:
    if not isinstance(v, str):
        raise TypeError(f"expected text, got {type(v).__name__}")
    return re.sub(r"[\r\n|`<>]", " ", v)[:limit]


def parse(body: str) -> dict:
    """The validated report in an issue body. Raises ValueError on anything malformed."""
    m = re.search(re.escape(MARKER) + r"\s*```json\s*(.*?)```", body, re.DOTALL)
    if not m:
        raise ValueError("no crosskill report in the issue")
    try:
        return _validate(json.loads(m.group(1)))
    except (TypeError, AttributeError, KeyError) as e:
        raise ValueError(f"malformed report: {e}") from e


def _validate(raw: dict) -> dict:
    rule = raw.get("rule")
    if rule not in FIELDS:
        raise ValueError(f"unknown rule {rule!r}")
    comps = []
    for c in raw.get("components") or []:
        mt = c.get("match") or {}
        if mt.get("kind") == "skill":
            match = {"kind": "skill", "name": _text(mt.get("name"), 100)}
        elif mt.get("kind") == "mcp":
            match = {"kind": "mcp", **{k: None if mt.get(k) is None else _text(mt[k], 100)
                                       for k in ("package", "host")}}
        else:
            raise ValueError("component without a skill or mcp match")
        comps.append({"id": _text(c.get("id"), 120), "match": match})
    if not 1 <= len(comps) <= 10:
        raise ValueError("a report needs 1 to 10 components")
    chain = [{"where": _text(c.get("where")), "fact": _text(c.get("fact")),
              "extractor": "llm" if c.get("extractor") == "llm" else "static"}
             for c in (raw.get("chain") or [])[:20]]
    path = [_text(p, 100) for p in raw.get("path") or []][:20]
    names = " + ".join(dict.fromkeys(path)) or " + ".join(c["id"] for c in comps)
    return {"key": key(rule, comps), "title": f"{rule}: {names}", "rule": rule, "path": path,
            **{k: _text(raw.get(k, "")) for k in FIELDS[rule]}, "components": comps, "chain": chain}


def render(adv: dict) -> str:
    comps = adv["components"]
    lines = [f"# {adv['id']}: {adv['title']}", "",
             f"Published {adv['published']}. Rule `{adv['rule']}`. Reported in {adv['issue']}.", "",
             "## Components", ""]
    lines += [f"- {c['match'].get('name') or c['match'].get('package') or c['match'].get('host')}"
              f" ({c['match']['kind']})" for c in comps]
    lines += ["", "## What this means", ""]
    flow = summary({k: v for k, v in adv.items() if k != "chain"})
    if len(comps) > 1:
        lines += [("Each of these components may be safe on its own. The risk is installing them "
                   f"together: {flow}."), "",
                  ("Nothing here says any component was written to cause harm. The combination "
                   "gives an agent a path it would not have with any one of them alone.")]
    else:
        lines += [f"This component can {EXPLAIN[adv['rule']]}: {flow}.", "",
                  ("That set of capabilities is risky for an agent, because one session can use "
                   "all of them in sequence without the user seeing a step in between. This page "
                   "describes what the component is able to do, not why it was written.")]
    lines += ["", (f"If you maintain one of these components and think this advisory is wrong, open an "
                   f"issue at https://github.com/{REPO}/issues and it will be reviewed.")]
    lines += ["", "## Proof chain (from the reporter's install)", ""]
    lines += [f"- `{c['where']}`: `{c['fact']}`" + (" (read by an LLM)" if c["extractor"] == "llm" else "")
              for c in adv["chain"]]
    return "\n".join(lines) + "\n"


def publish(feed_dir: Path, adv: dict, issue: str, today: date | None = None) -> str:
    """Add the advisory to the feed unless its key is there already; returns its id."""
    index = feed_dir / "advisories.json"
    advs = json.loads(index.read_text()) if index.exists() else []
    for a in advs:
        if a["key"] == adv["key"]:
            return a["id"]
    published = (today or date.today()).isoformat()
    prefix = f"CK-{published[:4]}-"
    n = 1 + max((int(a["id"].removeprefix(prefix)) for a in advs if a["id"].startswith(prefix)),
                default=0)
    adv = {**adv, "id": f"{prefix}{n:04d}", "published": published, "issue": _text(issue)}
    feed_dir.mkdir(parents=True, exist_ok=True)
    (feed_dir / f"{adv['id']}.md").write_text(render(adv))
    advs.append(adv)
    index.write_text(json.dumps(advs, indent=2) + "\n")
    rows = [f"| [{a['id']}]({a['id']}.md) | {a['published']} | {a['title']} |" for a in reversed(advs)]
    (feed_dir / "README.md").write_text("\n".join([
        "# crosskill advisories", "",
        ("Toxic flows that users found with `crosskill scan` and chose to share, newest first. "
         "Machine-readable list: [advisories.json](advisories.json)."), "",
        "| Advisory | Published | Flow |", "| --- | --- | --- |", *rows]) + "\n")
    return adv["id"]
