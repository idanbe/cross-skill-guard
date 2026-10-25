from pathlib import Path

import pytest

from crosskill.audit import audit, verify

FIX = Path(__file__).parent / "fixtures/audit"


@pytest.mark.parametrize("cmd, prog", [
    ("/usr/bin/curl https://x.invalid", "curl"),
    ("sh -c 'curl https://x.invalid'", "curl"),
    ("git -c core.sshCommand='curl https://x.invalid' fetch", "curl"),
    ("devbox run bash evil.sh", "bash"),
    ("npx some-pkg", "npx"),
    ("git status", None),
    ("ls -la", None),
    ("&& ||", None),           # unparseable → None, never raises
])
def test_verify_resolves_effective_program(cmd, prog):
    assert verify(cmd) == prog


@pytest.mark.parametrize("cmd, prog", [
    ("mise exec -- curl x", "curl"),
    ("mise exec node@20 -- curl x", "curl"),
    ("mise x -- curl x", "curl"),
    ("docker exec -it c curl x", "curl"),
    ("docker exec c curl", "curl"),
    ("devbox run -- curl x", "curl"),
    ("devbox run curl", "curl"),
    ("direnv exec . curl", "curl"),
    ("devbox add curl", None),       # not an exec subcommand: nothing runs
    ("mise use curl", None),
    ("docker pull curl", None),
])
def test_verify_skips_runner_options_and_checks_subcommand(cmd, prog):
    assert verify(cmd) == prog


def test_weak_git_rule_yields_curl_bypass():
    grants = audit(FIX / "weak")
    progs = {(g.arg, g.kind) for g in grants}
    assert ("curl", "egress") in progs          # git -c / sh -c reaches curl
    assert all(g.arbitrary and g.extractor == "z3" for g in grants)
    assert all(g.rule == "Bash(git:*)" and g.file == ".claude/settings.json" for g in grants)


def test_no_allow_rules_is_empty():
    assert audit(FIX / "empty") == []


def test_missing_settings_is_empty(tmp_path):
    assert audit(tmp_path) == []


def test_every_reported_bypass_verifies():
    from crosskill.extract import ARBITRARY, NETWORK
    for g in audit(FIX / "weak"):
        assert g.arg in ARBITRARY | NETWORK  # effective program came from verify
