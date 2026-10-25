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
