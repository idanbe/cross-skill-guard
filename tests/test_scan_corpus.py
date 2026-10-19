import pytest
from typer.testing import CliRunner

from crosskill.cli import app


@pytest.mark.xfail(reason="scan is implemented in stage 1", strict=True)
def test_scan_matches_expected_on_corpus() -> None:
    result = CliRunner().invoke(app, ["scan", "corpus/toxic/001-secret-to-webhook"])
    assert result.exit_code == 0
