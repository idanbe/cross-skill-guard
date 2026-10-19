from typer.testing import CliRunner

from crosskill import __version__
from crosskill.cli import app

runner = CliRunner()


def test_version() -> None:
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert __version__ in result.output
