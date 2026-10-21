"""Policy decisions on findings: a Rego policy says block, warn or ignore, with a reason.

The policy runs in the local `opa` binary (`opa eval`), with no server and no network. Input is
`{"findings": [...]}`; the policy returns `data.crosskill.decisions`, one `{id, action, reason}`
per finding. Without a policy every finding blocks, as in stages 1-3.
"""

import json
import shutil
import subprocess
from pathlib import Path

SEVERITY = {"secret_exfiltration": "high", "untrusted_to_execution": "high",
            "lethal_trifecta": "medium"}
ACTIONS = ("block", "warn", "ignore")


def decide(findings: list[dict], policy: Path | None, data: Path | None = None,
           project: str = "") -> list[dict]:
    """The findings with `id`, `severity`, `project`, `action` and `reason` added."""
    out = [f | {"id": i, "severity": SEVERITY[f["rule"]], "project": project}
           for i, f in enumerate(findings)]
    if policy is None:
        return [f | {"action": "block", "reason": "no policy: every finding blocks"} for f in out]
    opa = shutil.which("opa")
    if not opa:
        raise RuntimeError("opa is not on PATH; install it from https://www.openpolicyagent.org")
    cmd = [opa, "eval", "-f", "json", "--stdin-input", "-d", str(policy)]
    cmd += ["-d", str(data)] if data else []
    r = subprocess.run([*cmd, "data.crosskill.decisions"], input=json.dumps({"findings": out}),
                       capture_output=True, text=True, check=False)
    if r.returncode:
        raise RuntimeError(f"opa eval failed: {r.stderr.strip()}")
    result = json.loads(r.stdout).get("result") or [{"expressions": [{"value": []}]}]
    decided: dict[int, dict] = {}
    for d in result[0]["expressions"][0]["value"]:
        if d.get("action") not in ACTIONS or decided.get(d["id"], d) != d:
            raise RuntimeError(f"policy gave a bad or conflicting decision: {d}")
        decided[d["id"]] = d
    missing = [f["id"] for f in out if f["id"] not in decided]
    if missing:  # a policy that forgets a finding must not silently let it through
        raise RuntimeError(f"policy gave no decision for findings {missing}")
    return [f | {"action": decided[f["id"]]["action"], "reason": decided[f["id"]]["reason"]}
            for f in out]
