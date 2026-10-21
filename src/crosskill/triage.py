"""Cheap role triage with Jev (OpenRouter decisions endpoint): four yes/no questions per skill.

Answers are probabilities, cached on disk next to the LLM cache. `spent_usd` counts uncached calls.
"""

import hashlib
import json
import os
import urllib.request

from crosskill import llm

ROLES: dict[str, tuple[str, dict]] = {
    "reads_sensitive": ("Does this skill make the agent read secrets (credentials, .env, keys, tokens, the environment) or private data (mail, files outside the project, databases, private repos)?",
        {"true": "It reads secrets or private data", "false": "It only reads the current project or nothing sensitive"}),
    "sends_out": ("Does this skill send, post, upload or reply with data to a network destination or by email? Fetching or searching alone is not sending.",
        {"true": "It sends data out", "false": "It does not send data out"}),
    "untrusted_input": ("Does this skill take in content an attacker could control: web pages, search results, downloads, incoming mail, issues or comments?",
        {"true": "It ingests attacker-controllable content", "false": "It does not"}),
    "runs_any_code": ("Does this skill run arbitrary shell commands or code chosen at run time (any command, commands from a page or a previous step, pip install, sudo)?",
        {"true": "It runs arbitrary commands", "false": "It runs only fixed, named tools or nothing"}),
}
spent_usd = 0.0


def _post(body: dict) -> dict:
    req = urllib.request.Request(
        "https://openrouter.ai/api/alpha/decisions", json.dumps(body).encode(),
        {"Authorization": "Bearer " + os.environ["OPENROUTER_API_KEY"], "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.load(r)


def roles(text: str, model: str = "typesafe/jev-1.13") -> dict[str, float]:
    """Probability for each role question, from the cache when this model has seen the text."""
    global spent_usd
    questions = {k: {"type": "noul", "instructions": i, "criteria": c} for k, (i, c) in ROLES.items()}
    key = hashlib.sha256(f"{model}\0{json.dumps(questions, sort_keys=True)}\0{text}".encode()).hexdigest()
    path = llm.CACHE.parent / "jev" / f"{key}.json"
    if path.exists():
        return json.loads(path.read_text())
    r = _post({"model": model, "state": {"file": "SKILL.md", "text": text}, "questions": questions})
    out = {k: v["noul"] for k, v in r["answers"].items()}
    with llm.SPEND_LOCK:
        spent_usd += (r.get("usage") or {}).get("cost") or 0
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(out))
    return out


def passes(roles: dict[str, float], threshold: float = 0.2) -> bool:
    return any(p >= threshold for p in roles.values())
