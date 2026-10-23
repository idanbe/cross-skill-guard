"""Runtime guard: each scan finding becomes an LTL safety property, enforced by Claude Code hooks.

`init` scans an install, fills one template per finding and translates the templates into
automata with python-statemachine. The automata are saved as transition tables, so the hooks
step them with the standard library only (importing python-statemachine alone takes ~90 ms,
and every hook call must take under 50 ms).

Hooks read the event as JSON on stdin. PreToolUse denies a call that would drive a property
into its bad state, PostToolUse advances the state, SessionStart checks the install hashes.
"""

import json
import os
import re
import shlex
import sys
from fnmatch import fnmatch
from pathlib import Path

GUARD = Path(".claude") / "crosskill-guard.json"
STATE = Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache") / "crosskill" / "guard"
# Template per rule: letters in the order a call fires them, sources before the sink, so a call
# that both reads a secret and sends it is a violation on its own.
TEMPLATES = {
    "secret_exfiltration": ("NeverAfter", "G({a} → G ¬{b})",
                            {"a": ("read_secret", "resource"), "b": ("egress", "sink")}),
    "untrusted_to_execution": ("NeverAfter", "G({a} → G ¬{b})",
                               {"a": ("untrusted", "source"), "b": ("exec", "sink")}),
    "lethal_trifecta": ("NeverAfterBoth", "G((O {a} ∧ O {b}) → ¬{c})",
                        {"a": ("read", "private_data"), "b": ("untrusted", "untrusted_input"),
                         "c": ("egress", "egress")}),
}
NETWORK = {"curl", "wget"}
# Once a property is one egress away from breaking, every later Bash command in the session starts
# with these set (through CLAUDE_ENV_FILE), so proxy-aware tools (curl, pip, npm, git, requests,
# node fetch) connect to a closed port instead of the internet. Loopback stays reachable.
DEAD = "http://127.0.0.1:9"
OFFLINE = " ".join([*(f"{k}={DEAD}" for k in ("HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "https_proxy",
                                              "http_proxy", "all_proxy")),
                    "NO_PROXY=localhost,127.0.0.1,::1", "no_proxy=localhost,127.0.0.1,::1",
                    # ponytail: Node before 22.21 ignores proxies, so its fetch still gets out
                    "NODE_USE_ENV_PROXY=1"])
# curl, git, node and requests name the closed port; urllib only says refused.
# ponytail: a refused localhost service also matches; check the port too if that misleads
REFUSED = re.compile(r"127\.0\.0\.1(?::|\s+port\s+|', port=)9\b|Errno 111\] Connection refused")
LOOPBACK = {"localhost", "127.0.0.1", "::1", "[::1]"}  # traffic that never leaves the machine


def automata() -> dict:
    """Transition tables of the template automata, built with python-statemachine."""
    from statemachine import State, StateMachine

    class NeverAfter(StateMachine):
        """G(a → G ¬b): once a has happened, b never may."""
        ok = State(initial=True)
        armed = State()
        bad = State(final=True)
        a = ok.to(armed) | armed.to.itself()
        b = ok.to.itself() | armed.to(bad)

    class NeverAfterBoth(StateMachine):
        """G((O a ∧ O b) → ¬c): once both a and b have happened, c never may."""
        ok = State(initial=True)
        seen_a = State()
        seen_b = State()
        armed = State()
        bad = State(final=True)
        a = ok.to(seen_a) | seen_a.to.itself() | seen_b.to(armed) | armed.to.itself()
        b = ok.to(seen_b) | seen_b.to.itself() | seen_a.to(armed) | armed.to.itself()
        c = ok.to.itself() | seen_a.to.itself() | seen_b.to.itself() | armed.to(bad)

    tables = {}
    for m in (NeverAfter, NeverAfterBoth):
        delta: dict = {s.id: {} for s in m.states}
        for s in m.states:
            for t in s.transitions:
                delta[s.id].update({str(e): t.target.id for e in t.events})
        tables[m.__name__] = {"start": next(s.id for s in m.states if s.initial),
                              "bad": [s.id for s in m.states if s.final], "delta": delta}
    return tables


def inputs(root: Path) -> str:
    """Hash of the files the scan reads, so SessionStart can tell when the install changed."""
    import hashlib

    h = hashlib.sha256()
    for base in (root, root / ".claude"):
        files = [*base.glob("skills/*/**/*"), base / "settings.json", base / "settings.local.json"]
        for f in sorted(f for f in files if f.is_file()):
            h.update(str(f.relative_to(root)).encode() + b"\0" + f.read_bytes())
    if (root / ".mcp.json").exists():
        h.update((root / ".mcp.json").read_bytes())
    return h.hexdigest()


def properties(findings: list[dict]) -> list[dict]:
    props = []
    for f in findings:
        template, ltl, letters = TEMPLATES[f["rule"]]
        bound = {k: [kind, f[field]] for k, (kind, field) in letters.items()}
        props.append({
            "rule": f["rule"], "template": template, "path": f["path"],
            "ltl": ltl.format(**{k: f"{kind}({arg})" for k, (kind, arg) in bound.items()}),
            "letters": bound,
            "chain": [f"{c['file']}:{c['line']} {c['fact']}" for c in f["chain"]],
        })
    return props


def init(root: Path, model: str | None = None, policy: Path | None = None,
         data: Path | None = None) -> dict:
    """Scan the install and write its guard file. Returns what was written.

    With a policy, only the findings it blocks become properties."""
    from crosskill.extract import SECRET_FILES, extract
    from crosskill.policy import decide
    from crosskill.scan import scan

    mcp: dict[str, list] = {}
    for g in extract(root):
        if g.rule == f"mcp__{g.comp}" and not g.denied:
            mcp.setdefault(g.comp, []).append([g.kind.replace("reads", "read"), g.arg])
    guard = {"hash": inputs(root), "automata": automata(), "mcp": mcp, "secrets": SECRET_FILES,
             "properties": properties([f for f in decide(scan(root, model), policy, data, root.name)
                                       if f["action"] == "block"])}
    (root / GUARD).parent.mkdir(exist_ok=True)
    (root / GUARD).write_text(json.dumps(guard, indent=1, ensure_ascii=False))
    return guard


def rel(p: str, root: Path) -> str:
    """A path as the scan writes it: relative to the project, or under `~`."""
    p = os.path.expanduser(p.lstrip("@"))
    if not os.path.isabs(p):
        return os.path.normpath(p)
    for base, prefix in ((str(root), ""), (os.path.expanduser("~"), "~/")):
        if p == base or p.startswith(base.rstrip("/") + "/"):
            return prefix + os.path.relpath(p, base)
    return p


def host(url: str) -> str:
    """The host of a URL, `*` when there is none (urllib.parse is slow to import for a hook)."""
    m = re.match(r"\w+://(?:[^@/]*@)?([^:/?#]+)", url)
    return m[1].lower() if m else "*"


def bash_events(cmd: str, root: Path) -> list[tuple[str, str]]:
    events = []
    for seg in filter(None, map(str.strip, re.split(r"\|\|?|&&|;|\n", cmd))):
        try:
            words = shlex.split(seg)
        except ValueError:
            words = seg.split()
        if not words:
            continue
        events.append(("exec", " ".join(words)))
        if words[0] in NETWORK:
            url = next((w for w in words if "://" in w), "")
            events += [("untrusted", "web"), ("egress", host(url))]
        if words[0] in ("printenv", "env") and len(words) == 1:
            events.append(("read", "env:*"))
        # ponytail: any path-like word counts as read; parse per command if this over-taints
        events += [("read", rel(w, root)) for w in words[1:]
                   if not w.startswith("-") and re.match(r"[@~./]", w)]
    return events


def events(tool: str, args: dict, root: Path, mcp: dict) -> list[tuple[str, str]]:
    """What a tool call does, in the words of the properties."""
    if tool == "Read" and args.get("file_path"):
        return [("read", rel(args["file_path"], root))]
    if tool == "Grep" and args.get("path"):
        return [("read", rel(args["path"], root))]
    if tool == "WebFetch":
        return [("untrusted", "web"), ("egress", host(args.get("url", "")))]
    if tool == "WebSearch":
        return [("untrusted", "web")]
    if tool == "Bash":
        return bash_events(args.get("command", ""), root)
    if tool.startswith("mcp__"):
        return [tuple(e) for e in mcp.get(tool.split("__")[1], [])]
    return []


def with_secrets(evs: list, secrets: list[str]) -> list:
    """Add `read_secret` for reads that cover a credential file, so a rule like `Read(~/**)`
    arms only when a secret is read, not on every file under the home directory."""
    return evs + [("read_secret", a) for k, a in evs if k == "read" and any(
        fnmatch(f, a) or f.startswith(a.rstrip("/") + "/") for f in secrets)]


def in_home(evs: list, root: Path) -> list:
    """Add the `~` form of project paths: `rel` writes them relative to the project, but a
    rule like `Read(~/**)` covers them too when the project is under the home directory."""
    home, root = os.path.expanduser("~"), os.path.abspath(root)
    if not root.startswith(home.rstrip("/") + "/"):
        return evs
    base = "~/" + os.path.relpath(root, home)
    alias = [(k, os.path.normpath(f"{base}/{p}")) for k, p in evs
             if k in ("read", "read_secret") and not p.startswith(("~", "/", "env:"))]
    return evs + [e for e in alias if e[1].startswith("~/")]


def matches(event: tuple[str, str], letter: list[str]) -> bool:
    (kind, got), (want_kind, want) = event, letter
    if kind != want_kind:
        return False
    if kind == "egress":
        return got not in LOOPBACK and (want == "*" or got in ("*", want) or got.endswith("." + want))
    if kind == "exec":  # `bash` is unrestricted Bash; otherwise a command prefix such as `sh`
        return want == "bash" or got == want or got.startswith(want + " ")
    base = want.removesuffix("/**").removesuffix("/*")
    return got == want or fnmatch(got, want) or got.startswith(base.rstrip("/") + "/")


def step(guard: dict, state: dict, evs: list, what: str) -> tuple[dict, str | None]:
    """Advance every property over one call. Returns the new state and a denial reason."""
    new = {}
    for i, p in enumerate(guard["properties"]):
        table = guard["automata"][p["template"]]
        cur = state.get(str(i), {"state": table["start"], "why": []})
        s, why = cur["state"], list(cur["why"])
        for letter, bound in p["letters"].items():
            nxt = table["delta"][s].get(letter, s)
            if nxt != s and any(matches(e, bound) for e in evs):
                s = nxt
                why.append(f"{what} [{bound[0]}({bound[1]})]")
        if s in table["bad"]:
            return state, (f"crosskill guard blocked this call: {p['rule']} via "
                           f"{' → '.join(p['path'])}. Property {p['ltl']} would break. Earlier "
                           f"in this session: {'; '.join(cur['why']) or 'nothing'}. This call: "
                           f"{why[-1]}. Found by the scan at: {', '.join(p['chain'])}.")
        new[str(i)] = {"state": s, "why": why}
    return new, None


def describe(tool: str, args: dict, root: Path) -> str:
    path = args.get("file_path") and rel(args["file_path"], root)
    detail = args.get("command") or path or args.get("url") or args.get("query")
    return f"{tool} {str(detail)[:80]}" if detail else tool


def offline_reason(guard: dict, state: dict) -> str | None:
    """Why Bash runs offline: a property whose next egress, to any host, would break it."""
    for i, p in enumerate(guard["properties"]):
        table, cur = guard["automata"][p["template"]], state.get(str(i))
        sink = next((k for k, (kind, _) in p["letters"].items() if kind == "egress"), None)
        if cur and sink and table["delta"][cur["state"]].get(sink) in table["bad"]:
            return f"{'; '.join(cur['why'])} ({p['rule']} via {' → '.join(p['path'])})"
    return None


def notice(name: str, user: str, claude: str) -> dict:
    return {"systemMessage": user,
            "hookSpecificOutput": {"hookEventName": name, "additionalContext": claude}}


def hook(event: dict) -> dict | None:
    """Handle one hook event; returns the JSON to print, if any."""
    root = Path(os.environ.get("CLAUDE_PROJECT_DIR") or event.get("cwd") or ".")
    try:
        guard = json.loads((root / GUARD).read_text())
    except FileNotFoundError:
        return None  # no guard file: this project is not guarded
    name, session = event.get("hook_event_name"), event.get("session_id", "default")
    offline = STATE / f"{session}.offline"
    if name == "SessionStart":
        if os.environ.get("CLAUDE_ENV_FILE"):  # Claude Code runs this file before each Bash command
            with open(os.environ["CLAUDE_ENV_FILE"], "a") as f:
                f.write(f"if [ -e {shlex.quote(str(offline))} ]; then export {OFFLINE}; fi\n")
        if inputs(root) != guard["hash"]:
            return {"systemMessage": "crosskill guard: skills, MCP servers or settings changed "
                                     "since `crosskill guard init`; rerun it to update the properties"}
        return None
    state_file = STATE / f"{session}.json"
    try:
        state = json.loads(state_file.read_text())
    except FileNotFoundError:
        state = {}
    tool, args = event.get("tool_name", ""), event.get("tool_input") or {}
    evs = in_home(with_secrets(events(tool, args, root, guard["mcp"]), guard["secrets"]), root)
    new, reason = step(guard, state, evs, describe(tool, args, root))
    if name == "PreToolUse":
        return reason and {"hookSpecificOutput": {"hookEventName": "PreToolUse",
                                                  "permissionDecision": "deny",
                                                  "permissionDecisionReason": reason}}
    if name == "PostToolUse" and not reason:
        # ponytail: last writer wins when parallel calls race; lock the file if that loses taint
        state_file.parent.mkdir(parents=True, exist_ok=True)
        state_file.write_text(json.dumps(new))
        why = offline_reason(guard, new)
        if why and not offline.exists():
            offline.touch()
            return notice(name, f"crosskill guard: internet is now off for Bash commands in this "
                                f"session. Reason: {why}.",
                          f"crosskill guard turned off network access for Bash commands in this "
                          f"session (localhost still works) because: {why}. Network errors from "
                          f"now on come from the guard, not from the code; do not work around it.")
    output = json.dumps(event.get("tool_response") or event.get("error") or "")
    if tool == "Bash" and offline.exists() and REFUSED.search(output):
        why = offline_reason(guard, state if name == "PostToolUseFailure" else new)
        return notice(name, f"crosskill guard blocked network access from `{args.get('command')}`: "
                            f"{why}.",
                      f"This command's network access was blocked by crosskill guard: {why}.")
    return None


def main() -> None:
    out = hook(json.load(sys.stdin))
    if out:
        print(json.dumps(out))


if __name__ == "__main__":
    main()
