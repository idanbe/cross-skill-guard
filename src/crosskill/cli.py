import typer

from crosskill import __version__

app = typer.Typer(help="Find dangerous combinations of skills, MCP servers and permissions.")


@app.callback()
def main() -> None:
    """crosskill command line interface."""


@app.command()
def version() -> None:
    """Print the version."""
    typer.echo(__version__)


@app.command()
def scan(path: str = typer.Argument(".", help="Installation directory to scan")) -> None:
    """Scan an installation for toxic flows (not implemented until stage 1)."""
    typer.echo("scan is not implemented yet (stage 1)", err=True)
    raise typer.Exit(code=2)
