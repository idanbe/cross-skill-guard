import os
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


@app.command()
def scan(
    path: Annotated[Path, typer.Argument(help="Installation directory to scan")] = Path("."),
    sarif: Annotated[bool, typer.Option("--sarif", help="Print SARIF 2.1.0 instead of text")] = False,
    no_llm: Annotated[bool, typer.Option("--no-llm", help="Static extractors only")] = False,
    model: Model = DEFAULT_MODEL,
    policy: Policy = None,
    data: Data = None,
) -> None:
    """Scan an installation for toxic flows. Exits 1 when any finding blocks."""
    need_key(no_llm)
    findings = run_scan(path, None if no_llm else model)
    if policy:
        findings = decide(findings, policy, data, path.resolve().name)
    typer.echo(to_sarif(findings) if sarif else to_text(findings))
    raise typer.Exit(code=1 if any(f.get("action", "block") == "block" for f in findings) else 0)


@app.command("eval")
def eval_(
    model: Model = DEFAULT_MODEL,
    push_only: Annotated[bool, typer.Option("--push-only", help="Only upload dataset and prompt")] = False,
    triage: Annotated[bool, typer.Option("--triage", help="Score Jev role triage instead (no Langfuse)")] = False,
    threshold: Annotated[float, typer.Option(help="Triage gate threshold")] = 0.2,
) -> None:
    """Score the LLM extractor on the corpus labels in Langfuse."""
    from crosskill.evals import run, triage_report

    if triage:
        typer.echo(triage_report(threshold))
        return

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


@app.command("daily")
def daily_(
    state: Annotated[Path, typer.Option(help="State directory: checkpoints, ledger, cursor, caches")],
    feed: Annotated[Path, typer.Option(help="Feed directory the advisories are written to")] = Path("feed"),
    max_usd: Annotated[float, typer.Option(help="LLM and Jev spend cap for this run")] = 0.5,
    max_skills: Annotated[int, typer.Option(help="Most new skills checked this run")] = 50,
    dry_run: Annotated[bool, typer.Option(
        "--dry-run", help="In-memory GitHub: print candidates instead of opening issues. "
        "The ledger still records them, so use a scratch --state")] = False,
    model: Model = DEFAULT_MODEL,
) -> None:
    """Check new ClawHub skills and hold each candidate for an approve/reject label."""
    from crosskill.daily import run
    from crosskill.github import GitHub, MemoryGitHub

    need_key(False)
    gh = MemoryGitHub() if dry_run else GitHub.from_env()
    typer.echo(run(state, feed, gh, max_usd, max_skills, model))
    if dry_run:
        for issue in gh.issues.values():
            typer.echo(f"\n=== {issue['title']}\n\n{issue['body']}")
