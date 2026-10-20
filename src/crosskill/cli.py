import os
from pathlib import Path
from typing import Annotated

import typer

from crosskill import __version__
from crosskill.llm import DEFAULT_MODEL
from crosskill.scan import scan as run_scan
from crosskill.scan import to_sarif, to_text

app = typer.Typer(help="Find dangerous combinations of skills, MCP servers and permissions.")
Model = Annotated[str, typer.Option(help="OpenRouter model for the LLM extractor")]


def load_env(path: Path = Path(".env")) -> None:
    """Load KEY=value lines from .env without overriding the environment."""
    if path.exists():
        for line in path.read_text().splitlines():
            key, sep, value = line.partition("=")
            if sep and not key.lstrip().startswith("#"):
                os.environ.setdefault(key.strip(), value.strip())


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
) -> None:
    """Scan an installation for toxic flows. Exits 1 when any are found."""
    if not no_llm and not os.environ.get("OPENROUTER_API_KEY"):
        typer.echo("OPENROUTER_API_KEY is not set; pass --no-llm for a static-only scan", err=True)
        raise typer.Exit(code=2)
    findings = run_scan(path, None if no_llm else model)
    typer.echo(to_sarif(findings) if sarif else to_text(findings))
    raise typer.Exit(code=1 if findings else 0)


@app.command("eval")
def eval_(
    model: Model = DEFAULT_MODEL,
    push_only: Annotated[bool, typer.Option("--push-only", help="Only upload dataset and prompt")] = False,
) -> None:
    """Score the LLM extractor on the corpus labels in Langfuse."""
    from crosskill.evals import run

    typer.echo(run(model, push_only))
