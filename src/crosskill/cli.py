from pathlib import Path
from typing import Annotated

import typer

from crosskill import __version__
from crosskill.scan import scan as run_scan
from crosskill.scan import to_sarif, to_text

app = typer.Typer(help="Find dangerous combinations of skills, MCP servers and permissions.")


@app.callback()
def main() -> None:
    """crosskill command line interface."""


@app.command()
def version() -> None:
    """Print the version."""
    typer.echo(__version__)


@app.command()
def scan(
    path: Annotated[Path, typer.Argument(help="Installation directory to scan")] = Path("."),
    sarif: Annotated[bool, typer.Option("--sarif", help="Print SARIF 2.1.0 instead of text")] = False,
) -> None:
    """Scan an installation for toxic flows. Exits 1 when any are found."""
    findings = run_scan(path)
    typer.echo(to_sarif(findings) if sarif else to_text(findings))
    raise typer.Exit(code=1 if findings else 0)
