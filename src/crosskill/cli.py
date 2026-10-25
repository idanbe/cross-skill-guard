import os
import sys
import webbrowser
from pathlib import Path
from typing import Annotated

import typer

from crosskill import __version__
from crosskill.llm import DEFAULT_MODEL
from crosskill.policy import decide
from crosskill.scan import scan as run_scan
from crosskill.scan import to_sarif, to_text

app = typer.Typer(help="Find dangerous combinations of skills, MCP servers and permissions.")
Model = Annotated[str, typer.Option(help="OpenRouter model for the LLM extractor")]
Policy = Annotated[Path | None, typer.Option(help="Rego policy that decides block, warn or ignore")]
Data = Annotated[Path | None, typer.Option(help="JSON data for the policy, such as exceptions")]


def load_env(path: Path = Path(".env")) -> None:
    """Load KEY=value lines from .env without overriding the environment."""
    if path.exists():
        for line in path.read_text().splitlines():
            key, sep, value = line.partition("=")
            if sep and not key.lstrip().startswith("#"):
                os.environ.setdefault(key.strip(), value.strip())


guard_app = typer.Typer(help="Runtime guard: Claude Code hooks that block toxic flows (plugin/).")
app.add_typer(guard_app, name="guard")


def need_key(no_llm: bool) -> None:
    if not no_llm and not os.environ.get("OPENROUTER_API_KEY"):
        typer.echo("OPENROUTER_API_KEY is not set; pass --no-llm for a static-only scan", err=True)
        raise typer.Exit(code=2)


@app.callback()
def main() -> None:
    """crosskill command line interface."""
    load_env()


@app.command()
def version() -> None:
    """Print the version."""
    typer.echo(__version__)


ADVISORY_URL = "https://github.com/idanbe/cross-skill-guard/blob/main/feed/{}.md"


def possible_matches(path: Path) -> list[str]:
    from crosskill import known

    try:
        advisories = known.load(known.FEED_URL)
        found = known.matches(advisories, known.local_keys(path)) if advisories else []
        return [(f"possible match: {a.get('id', '?')} {a.get('title', '')} "
                 + (ADVISORY_URL.format(a["id"]) if a.get("id") else "")).rstrip() for a in found]
    except Exception:  # noqa: BLE001 - advisories are best effort
        return []


def share(path: Path, findings: list[dict], ask: bool) -> None:
    """Offer to share findings as GitHub issues. Asking needs a terminal; CI never sees it."""
    from crosskill import feed

    reports: dict[str, dict] = {}  # findings that differ only in private data share one advisory
    for f in findings:
        if r := feed.report(path, f):
            reports.setdefault(feed.key(r["rule"], r["components"]), r)
    if not reports or (ask and not (sys.stdin.isatty() and sys.stdout.isatty())):
        return
    q = (f"\nShare {len(reports)} finding(s) with the crosskill feed? Each opens as a GitHub issue "
         "you review before submitting")
    if ask and not typer.confirm(q, default=False):
        return
    for r in reports.values():
        url = feed.issue_url(r)
        typer.echo(url)
        if ask:
            webbrowser.open(url)


@app.command()
def scan(
    path: Annotated[Path, typer.Argument(help="Installation directory to scan")] = Path("."),
    sarif: Annotated[bool, typer.Option("--sarif", help="Print SARIF 2.1.0 instead of text")] = False,
    no_llm: Annotated[bool, typer.Option("--no-llm", help="Static extractors only")] = False,
    model: Model = DEFAULT_MODEL,
    policy: Policy = None,
    data: Data = None,
    offline: Annotated[bool, typer.Option("--offline", help="Skip the published-advisories lookup")] = False,
    report: Annotated[bool, typer.Option(
        "--report", help="Print a link to share each finding as a GitHub issue, without asking")] = False,
) -> None:
    """Scan an installation for toxic flows. Exits 1 when any finding blocks.

    In a terminal, it then asks whether to share the findings: each one opens as a pre-filled
    GitHub issue you review and submit yourself."""
    need_key(no_llm)
    findings = run_scan(path, None if no_llm else model)
    if policy:
        findings = decide(findings, policy, data, path.resolve().name)
    typer.echo(to_sarif(findings) if sarif else to_text(findings))
    if not sarif and not offline and os.environ.get("CROSSKILL_OFFLINE") != "1":
        for line in possible_matches(path):
            typer.echo(line)
    if not sarif:
        share(path, findings, ask=not report)
    raise typer.Exit(code=1 if any(f.get("action", "block") == "block" for f in findings) else 0)


@app.command("audit-permissions")
def audit_permissions(
    path: Annotated[Path, typer.Argument(help="Installation directory to audit")] = Path("."),
) -> None:
    """Find Bash allow rules that let a dangerous program run behind a wrapper. Exits 1 when any do."""
    from crosskill.audit import audit, to_text

    if not path.is_dir():  # a typo must not read as "no bypasses": this is a security gate
        typer.echo(f"not a directory: {path}", err=True)
        raise typer.Exit(code=2)
    grants = audit(path)
    typer.echo(to_text(grants))
    raise typer.Exit(code=1 if grants else 0)


@app.command("eval")
def eval_(
    model: Model = DEFAULT_MODEL,
    push_only: Annotated[bool, typer.Option("--push-only", help="Only upload dataset and prompt")] = False,
) -> None:
    """Score the LLM extractor on the corpus labels in Langfuse."""
    from crosskill.evals import run

    typer.echo(run(model, push_only))


@guard_app.command("init")
def guard_init(
    path: Annotated[Path, typer.Argument(help="Project to guard")] = Path("."),
    no_llm: Annotated[bool, typer.Option("--no-llm", help="Static extractors only")] = False,
    model: Model = DEFAULT_MODEL,
    policy: Policy = None,
    data: Data = None,
) -> None:
    """Scan the project and write .claude/crosskill-guard.json, the properties the hooks enforce.

    With a policy, only the findings it blocks become properties."""
    from crosskill.guard import GUARD, init

    need_key(no_llm)
    guard = init(path, None if no_llm else model, policy, data)
    typer.echo(f"{len(guard['properties'])} properties written to {path / GUARD}")
    for p in guard["properties"]:
        typer.echo(f"  {p['ltl']}  ({p['rule']} via {' → '.join(p['path'])})")


@app.command("publish-report", hidden=True)
def publish_report(
    body: Annotated[Path, typer.Argument(help="File with the issue body")],
    issue: Annotated[str, typer.Option(help="URL of the approved issue")],
    feed_dir: Annotated[Path, typer.Option("--feed", help="Feed directory")] = Path("feed"),
) -> None:
    """Publish an approved report issue to the feed (run by the publish workflow); prints its id."""
    from crosskill import feed

    try:
        adv = feed.parse(body.read_text())
    except ValueError as e:
        typer.echo(f"not a valid crosskill report: {e}", err=True)
        raise typer.Exit(code=2) from e
    typer.echo(feed.publish(feed_dir, adv, issue))
