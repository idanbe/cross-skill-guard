"""The daily workflow's state checkout, run against local git repos (no network)."""

import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

WORKFLOW = Path(__file__).parent.parent / ".github/workflows/daily.yml"

pytestmark = pytest.mark.skipif(not shutil.which("git"), reason="needs git")


def step(step_id: str) -> str:
    steps = yaml.safe_load(WORKFLOW.read_text())["jobs"]["daily"]["steps"]
    return next(s["run"] for s in steps if s.get("id") == step_id)


def git(*args, cwd: Path) -> None:
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True)


@pytest.fixture
def work(tmp_path: Path) -> Path:
    remote, work = tmp_path / "remote.git", tmp_path / "work"
    git("init", "--bare", "-b", "main", str(remote), cwd=tmp_path)
    git("init", "-b", "main", str(work), cwd=tmp_path)
    git("-c", "user.name=t", "-c", "user.email=t@t", "commit", "--allow-empty", "-m", "init",
        cwd=work)
    git("remote", "add", "origin", str(remote), cwd=work)
    git("push", "origin", "main", cwd=work)
    return work


def run_step(work: Path) -> subprocess.CompletedProcess:
    # GitHub runs `run:` blocks with bash -e
    return subprocess.run(["bash", "-e", "-c", step("state")], cwd=work, capture_output=True,
                          text=True, check=False)


def test_missing_data_branch_starts_empty_state(work: Path) -> None:
    r = run_step(work)
    assert r.returncode == 0, r.stderr
    assert (work / "state" / ".gitignore").read_text() == "skills/\n"


def test_ls_remote_failure_fails_the_job(work: Path) -> None:
    git("remote", "set-url", "origin", str(work.parent / "unreachable.git"), cwd=work)
    r = run_step(work)
    assert r.returncode == 1 and "git ls-remote failed" in r.stdout
    assert not (work / "state").exists()


def test_commit_steps_need_the_state_checkout() -> None:
    steps = yaml.safe_load(WORKFLOW.read_text())["jobs"]["daily"]["steps"]
    commits = [s for s in steps if s.get("name", "").startswith("Commit")]
    assert len(commits) == 2 and all("steps.state.outcome == 'success'" in s["if"] for s in commits)
