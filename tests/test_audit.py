import pytest

from crosskill.audit import verify


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
