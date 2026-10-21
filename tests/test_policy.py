import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest
from typer.testing import CliRunner

from crosskill import guard
from crosskill.cli import app
from crosskill.policy import decide
from crosskill.scan import scan

ROOT = Path(__file__).parent.parent
POLICIES = ROOT / "policies"
STRICT, PERMISSIVE = POLICIES / "strict" / "policy.rego", POLICIES / "permissive" / "policy.rego"
TRIFECTA = ROOT / "corpus" / "toxic" / "019-github-mcp-alone"
TWO = ROOT / "corpus" / "toxic" / "020-two-findings"

if not shutil.which("opa"):
    if os.environ.get("CI"):
        raise RuntimeError("CI must install opa")
    pytest.skip("opa is not installed", allow_module_level=True)


@pytest.mark.parametrize("policy", ["strict", "permissive"])
def test_opa_test_passes(policy: str) -> None:
    r = subprocess.run(["opa", "test", str(POLICIES / policy)], capture_output=True, text=True,
                       check=False)
    assert r.returncode == 0, r.stdout + r.stderr


def test_same_scan_different_decisions() -> None:
    runner = CliRunner()
    strict = runner.invoke(app, ["scan", "--no-llm", "--policy", str(STRICT), str(TRIFECTA)])
    assert strict.exit_code == 1 and "[block] lethal_trifecta" in strict.output
    permissive = runner.invoke(app, ["scan", "--no-llm", "--policy", str(PERMISSIVE), str(TRIFECTA)])
    assert permissive.exit_code == 0 and "[warn] lethal_trifecta" in permissive.output
    sarif = runner.invoke(app, ["scan", "--no-llm", "--sarif", "--policy", str(PERMISSIVE), str(TWO)])
    assert {r["level"] for r in json.loads(sarif.output)["runs"][0]["results"]} == {"error"}


def test_exception_ignores_and_guard_skips_it(tmp_path: Path) -> None:
    data = tmp_path / "data.json"
    data.write_text(json.dumps({"exceptions": [{"component": "env-check", "reason": "reviewed"}]}))
    decisions = {f["rule"]: (f["action"], f["reason"]) for f in decide(scan(TWO), STRICT, data)}
    blocks = "strict policy blocks every untrusted_to_execution"
    assert decisions == {"secret_exfiltration": ("ignore", "reviewed"),
                         "untrusted_to_execution": ("block", blocks)}
    root = tmp_path / "install"
    shutil.copytree(TWO, root)
    assert [p["rule"] for p in guard.init(root, policy=STRICT, data=data)["properties"]] == [
        "untrusted_to_execution"]


def test_policy_that_skips_a_finding_fails(tmp_path: Path) -> None:
    bad = tmp_path / "bad.rego"
    bad.write_text("package crosskill\n\ndecisions contains {\"id\": 0, \"action\": \"warn\", "
                   "\"reason\": \"x\"} if true\n")
    with pytest.raises(RuntimeError, match="no decision"):
        decide(scan(TWO), bad)
