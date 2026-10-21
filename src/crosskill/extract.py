"""Static extractors: turn an install into grants, capability facts with provenance.

Classification follows the conventions in docs/facts.md.
"""

import ast
import json
import re
from dataclasses import dataclass
from fnmatch import fnmatch
from pathlib import Path
from urllib.parse import urlparse

import bashlex
import yaml

from crosskill.llm import facts_for

ARBITRARY = {"bash", "sh", "zsh", "python", "python3", "node", "sudo", "pip install"}
NETWORK = {"curl", "wget"}
# A resource is secret when it covers one of these concrete credential files.
SECRET_FILES = [
    ".env", ".env.local", ".env.production", "~/.ssh/id_rsa", "~/.ssh/id_ed25519",
    "~/.aws/credentials", "~/.config/gcloud/credentials.db", "~/.kube/config", "~/.netrc",
    "~/.npmrc", "~/.pgpass", "~/.git-credentials", "~/.config/gh/hosts.yml",
    "~/.docker/config.json", "~/.password-store/x.gpg", "env:*",
]
WEB = [("untrusted", "web"), ("egress", "*")]
RULE = re.compile(r"^([\w-]+)(?:\((.*)\))?$")
LLM_SUFFIXES = {".js", ".mjs", ".cjs", ".ts"}
LLM_MAX_CHARS = 60_000


@dataclass
class Grant:
    comp: str
    kind: str  # reads | writes | egress | executes | untrusted
    arg: str
    file: str
    line: int
    quote: str
    rule: str | None = None  # permission rule text that a deny rule can match
    arbitrary: bool = False
    denied: bool = False
    extractor: str = "static"


def is_secret(r: str) -> bool:
    return any(fnmatch(f, r) or f.startswith(r.rstrip("/") + "/") for f in SECRET_FILES)


def is_private(r: str) -> bool:
    return r.startswith(("~", "/", "postgresql://", "postgres://", "mysql://", "sqlite:")) or r in {
        "mail", "github:private_repos"}


def bash_caps(arg: str | None) -> list[tuple]:
    if arg in (None, "*"):
        return [("executes", "bash", True)]
    cmd = arg.removesuffix(":*").removesuffix(" *").strip()
    prog, _, rest = cmd.partition(" ")
    if prog in NETWORK:
        return WEB
    if prog in ("printenv", "env"):
        return [("reads", f"env:{rest or '*'}")]
    return [("executes", cmd, cmd in ARBITRARY and cmd != arg)]


def path_arg(p: str) -> str:
    """`//abs` is an absolute path in permission rules; one under $HOME is written with `~`."""
    p = p.removeprefix("/") if p.startswith("//") else p
    home = str(Path.home())
    return "~" + p[len(home):] if p == home or p.startswith(home + "/") else p


def rule_caps(rule: str) -> list[tuple]:
    m = RULE.match(rule.strip())
    if not m:
        return []
    tool, arg = m.groups()
    if tool == "Read" and arg:
        return [("reads", path_arg(arg))]
    if tool in ("Write", "Edit") and arg:
        return [("writes", path_arg(arg))]
    if tool == "WebFetch":
        return [("untrusted", "web"), ("egress", arg.removeprefix("domain:") if arg else "*")]
    if tool == "WebSearch":
        return [("untrusted", "web")]
    if tool == "Bash":
        return bash_caps(arg)
    return []


def covers(deny: str, rule: str) -> bool:
    d, g = RULE.match(deny.strip()), RULE.match(rule.strip())
    if not (d and g) or d[1] != g[1]:
        return False
    if d[2] is None or d[2] == g[2]:
        return True
    # `curl:*` is a prefix; `~/.ssh/**` also covers `~/.ssh` itself.
    pat = d[2].replace(":*", "*")
    return g[2] is not None and (fnmatch(g[2], pat) or fnmatch(g[2] + "/", pat))


def line_of(lines: list[str], needle: str) -> int:
    return next((i for i, s in enumerate(lines, 1) if needle in s), 1)


def grants_from(comp, caps, file, lines, line, rule=None) -> list[Grant]:
    quote = lines[line - 1].strip()[:120] if lines else ""
    return [Grant(comp, c[0], c[1], file, line, quote, rule, *c[2:]) for c in caps]


def sh_caps(src: str) -> list[tuple[int, tuple]]:
    out = []

    class Visitor(bashlex.ast.nodevisitor):
        def visitcommand(self, node, parts):
            words = [p.word for p in parts if p.kind == "word"]
            if words:
                caps = WEB if words[0] in NETWORK else [("executes", words[0])]
                out.extend((src.count("\n", 0, node.pos[0]) + 1, c) for c in caps)

    for tree in bashlex.parse(src):
        Visitor().visit(tree)
    return out


def dotted(node: ast.expr) -> str:
    if isinstance(node, ast.Attribute):
        return f"{dotted(node.value)}.{node.attr}"
    return node.id if isinstance(node, ast.Name) else ""


def py_caps(src: str) -> list[tuple[int, tuple]]:
    out = []
    for node in ast.walk(ast.parse(src)):
        if not isinstance(node, ast.Call):
            continue
        name, args = dotted(node.func), node.args
        a0 = args[0] if args else None
        const = a0.value if isinstance(a0, ast.Constant) and isinstance(a0.value, str) else None
        if name.startswith("subprocess.") or name == "os.system":
            first = a0.elts[0] if isinstance(a0, ast.List) and a0.elts else None
            prog = const.split()[0] if const else getattr(first, "value", None)
            if isinstance(prog, str):
                out.append((node.lineno, ("executes", prog)))
        elif name == "open" and const:
            mode = getattr(args[1], "value", "r") if len(args) > 1 else "r"
            out.append((node.lineno, ("writes" if set("wa") & set(str(mode)) else "reads", const)))
        elif name in ("os.getenv", "os.environ.get") and const:
            out.append((node.lineno, ("reads", f"env:{const}")))
        elif name.split(".")[0] in ("requests", "httpx") or name.endswith("urlopen"):
            host = urlparse(const).hostname if const else None
            out += [(node.lineno, ("untrusted", "web")), (node.lineno, ("egress", host or "*"))]
    return out


def parse_or_empty(parse, src: str) -> list[tuple[int, tuple]]:
    try:
        return parse(src)
    except (SyntaxError, ValueError, NotImplementedError, bashlex.errors.ParsingError):
        return []  # ponytail: an unparsable script yields no facts; report it once stage 2 traces


def script_grants(comp: str, skill_dir: Path, root: Path) -> list[Grant]:
    grants = []
    for f in sorted(skill_dir.rglob("*")):
        parse = {".py": py_caps, ".sh": sh_caps}.get(f.suffix)
        if not parse or not f.is_file():
            continue
        src = f.read_text(errors="replace")
        lines, rel = src.splitlines(), str(f.relative_to(root))
        for line, cap in parse_or_empty(parse, src):
            grants += grants_from(comp, [cap], rel, lines, line)
    return grants


def quote_line(lines: list[str], quote: str) -> int | None:
    """Line of the file that holds the quote, ignoring case and punctuation."""
    q = re.sub(r"\W+", "", (quote.strip().splitlines() or [""])[0].lower())[:60]
    return next((i for i, s in enumerate(lines, 1) if q and q in re.sub(r"\W+", "", s.lower())), None)


def llm_grants(comp: str, skill_dir: Path, root: Path, model: str) -> list[Grant]:
    files = [skill_dir / "SKILL.md", *sorted(f for f in skill_dir.rglob("*") if f.suffix in LLM_SUFFIXES)]
    grants = []
    for f in files:
        text = f.read_text(errors="replace")
        if len(text) > LLM_MAX_CHARS:
            continue  # ponytail: big bundles are skipped; split into chunks if real skills need it
        lines, rel = text.splitlines(), str(f.relative_to(root))
        for fact in facts_for(str(f.relative_to(skill_dir)), text, model)["facts"]:
            line = quote_line(lines, fact["quote"])
            if line is None:
                continue  # a quote that is not in the file is not evidence
            arg = fact["arg"]
            if fact["kind"] == "egress" and "://" in arg:
                arg = urlparse(arg).hostname or arg  # egress facts name a domain; models may give a URL
            arbitrary = fact["kind"] == "executes" and arg in ARBITRARY
            grants.append(Grant(comp, fact["kind"], arg, rel, line, lines[line - 1].strip()[:120],
                                fact["rule"], arbitrary, extractor="llm"))
    return grants


def frontmatter(text: str) -> dict:
    if not text.startswith("---"):
        return {}
    try:
        fm = yaml.safe_load(text.split("---", 2)[1])
    except yaml.YAMLError:
        return {}
    return fm if isinstance(fm, dict) else {}


def skill_grants(skill_md: Path, root: Path, model: str | None = None) -> list[Grant]:
    text = skill_md.read_text(errors="replace")
    fm, lines = frontmatter(text), text.splitlines()
    comp = str(fm.get("name") or skill_md.parent.name)
    tools = fm.get("allowed-tools") or []
    entries = tools if isinstance(tools, list) else re.findall(r"[^,\s(][^,(]*(?:\([^)]*\))?", tools)
    rel, line = str(skill_md.relative_to(root)), line_of(lines, "allowed-tools")
    grants = []
    for e in map(str.strip, map(str, entries)):
        grants += grants_from(comp, rule_caps(e), rel, lines, line, rule=e)
    grants += script_grants(comp, skill_md.parent, root)
    return grants + (llm_grants(comp, skill_md.parent, root, model) if model else [])


def mcp_caps(server: dict) -> list[tuple]:
    if "url" in server:
        return [("egress", urlparse(server["url"]).hostname or "*")]
    args = [a for a in server.get("args", []) if not a.startswith("-y")]
    pkgs = [re.sub(r"(?<=.)@[^/]*$", "", a) for a in args]
    for pkg in pkgs:
        rest = args[pkgs.index(pkg) + 1:]
        if pkg == "@modelcontextprotocol/server-filesystem":
            return [(k, p) for p in rest for k in ("reads", "writes")]
        if pkg in ("mcp-server-fetch", "@playwright/mcp"):
            return WEB
        if pkg == "@modelcontextprotocol/server-github":
            return [("untrusted", "github:issues"), ("reads", "github:private_repos"),
                    ("egress", "api.github.com")]
        if pkg == "@modelcontextprotocol/server-postgres" and rest:
            return [("reads", rest[0])]
        if pkg == "mcp-server-sqlite" and "--db-path" in rest:
            return [("reads", "sqlite:" + rest[rest.index("--db-path") + 1])]
    return []  # ponytail: unknown local servers give no facts; the stage 2 LLM can read their docs


def mcp_grants(path: Path, root: Path) -> list[Grant]:
    text = path.read_text()
    lines, rel, grants = text.splitlines(), str(path.relative_to(root)), []
    for name, server in json.loads(text).get("mcpServers", {}).items():
        caps = mcp_caps(server)
        if "url" in server:
            caps.append(("untrusted", f"mcp:{name}"))
        grants += grants_from(name, caps, rel, lines, line_of(lines, f'"{name}"'), f"mcp__{name}")
    return grants


def settings_grants(path: Path, root: Path) -> tuple[list[Grant], list[str]]:
    text = path.read_text()
    data, lines, rel, grants = json.loads(text), text.splitlines(), str(path.relative_to(root)), []
    perms = data.get("permissions", {})
    for rule in perms.get("allow", []):
        grants += grants_from(rule, rule_caps(rule), rel, lines, line_of(lines, json.dumps(rule)), rule)
    for event, entries in data.get("hooks", {}).items():
        for hook in (h for e in entries for h in e.get("hooks", [])):
            cmd = hook.get("command", "")
            caps = [c for _, c in parse_or_empty(sh_caps, cmd)]
            grants += grants_from(f"hook:{event}", caps, rel, lines, line_of(lines, json.dumps(cmd)))
    return grants, perms.get("deny", [])


def extract(root: Path, model: str | None = None) -> list[Grant]:
    """All grants in an install. Reads the corpus layout and the `.claude/` layout.

    With a model, the LLM extractor adds facts from SKILL.md prose and JS/TS scripts.
    """
    grants, denies = [], []
    for base in (root, root / ".claude"):
        for skill_md in sorted(base.glob("skills/*/SKILL.md")):
            grants += skill_grants(skill_md, root, model)
        for name in ("settings.json", "settings.local.json"):
            if (base / name).exists():
                g, d = settings_grants(base / name, root)
                grants, denies = grants + g, denies + d
    if (root / ".mcp.json").exists():
        grants += mcp_grants(root / ".mcp.json", root)
    for g in grants:
        g.denied = g.rule is not None and any(covers(d, g.rule) for d in denies)
    return grants
