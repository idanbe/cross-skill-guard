import json
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


def settings(tmp_path, allow, deny=(), name=".claude/settings.json"):
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"permissions": {"allow": allow, "deny": list(deny)}}, indent=2))
    return tmp_path


def test_weak_git_rule_yields_curl_bypass():
    grants = audit(FIX / "weak")
    shapes = {(g.arg, g.kind) for g in grants}
    assert ("*", "egress") in shapes            # git -c / sh -c reaches curl: bash_caps split
    assert ("web", "untrusted") in shapes
    assert not any(g.arg in ("curl", "wget") for g in grants)
    assert all(g.arbitrary and g.extractor == "z3" for g in grants)
    assert all(g.rule == "Bash(git:*)" and g.comp == "Bash(git:*)" for g in grants)
    assert all(g.file == ".claude/settings.json" for g in grants)
    assert {g.arg for g in grants if g.kind == "executes"} >= {"sh", "bash", "python"}


def test_curl_and_wget_do_not_collapse():
    quotes = [g.quote for g in audit(FIX / "weak") if g.kind == "egress"]
    assert any("curl" in q for q in quotes) and any("wget" in q for q in quotes)


def test_no_allow_rules_is_empty():
    assert audit(FIX / "empty") == []


def test_missing_settings_is_empty(tmp_path):
    assert audit(tmp_path) == []


def test_every_reported_bypass_verifies():
    from crosskill.audit import find_candidates
    cands = find_candidates(["Bash(git:*)"], [])
    assert cands
    for _, cmd in cands:
        assert verify(cmd) is not None, cmd


def test_wildcard_deny_removes_curl_bypass(tmp_path):
    root = settings(tmp_path, ["Bash(git:*)"], ["Bash(*curl*)"])
    grants = audit(root)
    assert grants                                   # wget, sh, ... still get through
    assert not any("curl" in g.quote for g in grants)
    assert ("sh", "executes") in {(g.arg, g.kind) for g in grants}


def test_prefix_deny_removes_program(tmp_path):
    grants = audit(settings(tmp_path, ["Bash(git:*)"], ["Bash(wget:*)"]))
    assert not any("wget" in g.quote for g in grants)
    assert any("curl" in g.quote for g in grants)


@pytest.mark.parametrize("rule", ["Bash(ls:*)", "Bash(git status)"])
def test_safe_rule_is_empty(tmp_path, rule):
    assert audit(settings(tmp_path, [rule])) == []


@pytest.mark.parametrize("where", ["settings.local.json", ".claude/settings.local.json",
                                   "settings.json"])
def test_other_settings_files_are_read(tmp_path, where):
    grants = audit(settings(tmp_path, ["Bash(git:*)"], name=where))
    assert grants and all(g.file == where for g in grants)
