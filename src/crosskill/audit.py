"""Permission audit: find the program a Bash command really runs behind wrappers and shells."""

import itertools
import os
import re
from collections.abc import Callable, Iterator
from pathlib import Path

import bashlex
import z3
from bashlex.errors import ParsingError

from crosskill.extract import ARBITRARY, NETWORK, RULE, Grant, bash_caps, settings_grants

DOWNLOADERS = {"npx"}  # runs arbitrary downloaded code, so it is the finding itself
SHELLS = {"sh", "bash", "zsh"}
# Runner -> subcommands that run a command. Options (and mise TOOL@VER args) are skipped, then
# POSITIONAL words (docker container, direnv dir) before the command itself.
RUNNERS = {"devbox": {"run"}, "mise": {"exec", "x"}, "docker": {"exec"}, "direnv": {"exec"}}
POSITIONAL = {"docker": 1, "direnv": 1}


def verify(command: str) -> str | None:
    """The arbitrary or network program that the command runs, or None."""
    try:
        nodes = bashlex.parse(command)
    except (ParsingError, AttributeError, TypeError):  # bashlex raises these on bad input
        return None
    for words in _commands(nodes):
        hit = _resolve(words)
        if hit:
            return hit
    return None


def _commands(nodes: list) -> Iterator[list[str]]:
    for node in nodes:
        if node.kind == "command":
            yield [part.word for part in node.parts if part.kind == "word"]
        yield from _commands(getattr(node, "parts", []) + getattr(node, "list", []))


def _resolve(words: list[str]) -> str | None:
    if not words:
        return None
    prog = os.path.basename(words[0])
    if prog in DOWNLOADERS:
        return prog
    inner = None
    if prog in SHELLS and words[1:2] == ["-c"] and len(words) > 2:
        inner = verify(words[2])
    elif prog == "git":
        for flag, value in itertools.pairwise(words):
            if flag == "-c" and value.startswith("core.sshCommand="):
                inner = verify(value.split("=", 1)[1])
                break
    elif prog in RUNNERS:
        inner = _resolve(_runner_command(prog, words[1:]))
    if inner:
        return inner
    for name in (" ".join([prog, *words[1:2]]), prog):  # "pip install" is one entry
        if name in ARBITRARY | NETWORK:
            return name
    return None


def _runner_command(prog: str, args: list[str]) -> list[str]:
    """The words a runner runs after its subcommand, or [] when the subcommand does not run one."""
    if not args or args[0] not in RUNNERS[prog]:
        return []
    rest = args[1:]
    i = 0
    while i < len(rest) and (rest[i].startswith("-") or (prog == "mise" and "@" in rest[i])):
        i += 1
    return rest[i + POSITIONAL.get(prog, 0):]


# Bypass forms: one command string per dangerous program. Each runs `p` behind something the
# allow rule may approve; `only` limits a form to the allow rules that can approve it.
BYPASS_FORMS: list[tuple[str, Callable[[str], str], str | None]] = [
    ("absolute path", lambda p: f"/usr/bin/{p} x.invalid", None),
    ("sh -c", lambda p: f"sh -c '{p} x.invalid'", None),
    ("git -c core.sshCommand", lambda p: f"git -c core.sshCommand='{p} x.invalid' fetch", "git"),
    ("devbox run", lambda p: f"devbox run {p} x.invalid", None),
    ("mise exec", lambda p: f"mise exec -- {p} x.invalid", None),
    ("docker exec", lambda p: f"docker exec c {p} x.invalid", None),
    ("direnv exec", lambda p: f"direnv exec . {p} x.invalid", None),
    ("npx", lambda p: f"npx {p}", None),
]


def _allow_regex(arg: str) -> z3.ReRef:
    """The commands a Bash allow rule approves: `x:*` is `x` or `x ` + anything, `*` is a glob."""
    anything = z3.Full(z3.ReSort(z3.StringSort()))
    tail = arg.endswith(":*")
    pieces = []
    for i, part in enumerate((arg[:-2] if tail else arg).split("*")):
        pieces += [anything] if i else []
        pieces.append(z3.Re(z3.StringVal(part)))
    glob = pieces[0] if len(pieces) == 1 else z3.Concat(*pieces)
    return z3.Union(glob, z3.Concat(glob, z3.Re(z3.StringVal(" ")), anything)) if tail else glob


def _bash_arg(rule: str) -> str | None:
    m = RULE.match(rule.strip())
    return m[2] if m and m[1] == "Bash" else None


def _approved(candidate: str, allow_arg: str, deny: list[str]) -> bool:
    """Z3: the command is in the allow rule's language and no deny rule matches any part of it."""
    cmd = z3.String("cmd")
    solver = z3.Solver()
    solver.add(cmd == z3.StringVal(candidate), z3.InRe(cmd, _allow_regex(allow_arg)))
    anything = z3.Full(z3.ReSort(z3.StringSort()))
    for rule in deny:  # a deny rule catches a command that contains a match of its glob anywhere
        m = RULE.match(rule.strip())
        if m and m[1] == "Bash":
            hit = anything if m[2] in (None, "") else z3.Concat(anything, _allow_regex(m[2]), anything)
            solver.add(z3.Not(z3.InRe(cmd, hit)))
    return solver.check() == z3.sat


def find_candidates(allow: list[str], deny: list[str]) -> list[tuple[str, str]]:
    """(allow rule, command) pairs: the rule approves the command, no deny rule catches it."""
    out = []
    for rule in allow:
        arg = _bash_arg(rule)
        if arg in (None, "*"):  # `Bash` alone already allows everything: no bypass to find
            continue
        head = arg.removesuffix(":*").split(" ")[0]
        for _, make, only in BYPASS_FORMS:
            if only not in (None, head):
                continue
            for prog in sorted(ARBITRARY | NETWORK):
                if _approved(cmd := make(prog), arg, deny):
                    out.append((rule, cmd))
    return out


def audit(root: Path) -> list[Grant]:
    """Grants for the distinct verified bypasses of the install's Bash allow rules."""
    rules: dict[str, Grant] = {}
    deny: list[str] = []
    for base in (root, root / ".claude"):
        for name in ("settings.json", "settings.local.json"):
            if (base / name).exists():
                grants, denies = settings_grants(base / name, root)
                deny += denies
                for g in grants:
                    if g.rule and g.rule.startswith("Bash("):
                        rules.setdefault(g.rule, g)
    found: dict[tuple[str, str], list[Grant]] = {}
    for rule, cmd in find_candidates(list(rules), deny):
        prog = verify(cmd)
        own = (_bash_arg(rule) or "").removesuffix(":*").split(" ")[0]
        if prog is None or prog == own or (rule, prog) in found:
            continue
        src = rules[rule]
        quote = f"{src.quote}  [bypass: {prog}]"
        found[(rule, prog)] = [
            Grant(rule, c[0], c[1], src.file, src.line, quote, rule, True, extractor="z3")
            for c in bash_caps(prog)]
    return [g for grants in found.values() for g in grants]


def to_text(grants: list[Grant]) -> str:
    """One line per distinct bypass: the rule, the program it reaches, the kind and file:line."""
    if not grants:
        return ("no bypasses found (within the modeled invocation forms: absolute path, sh -c, "
                "git -c, devbox/mise/docker/direnv exec, npx; not a proof the rules are safe)")
    lines: list[str] = []
    seen: set[tuple] = set()
    for g in grants:
        prog = re.search(r"\[bypass: ([^\]]+)\]$", g.quote)[1]  # audit() always appends this
        key = (g.comp, prog, g.kind, g.file, g.line)
        if key not in seen:
            seen.add(key)
            lines.append(f"{g.comp} reaches {prog}  [{g.kind}]  {g.file}:{g.line}")
    return "\n".join([f"{len(lines)} permission bypass(es)", "", *lines])
