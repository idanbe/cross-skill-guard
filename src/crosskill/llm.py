"""LLM extractor: capability facts from SKILL.md prose and JS/TS scripts, through OpenRouter.

Calls are traced to Langfuse by its OpenAI wrapper (when LANGFUSE_* keys are set) and cached on
disk, so the same text with the same model and prompt is never paid for twice.
"""

import hashlib
import json
import os
import threading
import time
from pathlib import Path
from typing import Literal

from pydantic import BaseModel

PROMPT = (Path(__file__).parent / "prompt.md").read_text()
DEFAULT_MODEL = "deepseek/deepseek-v4.1-flash"
CACHE = Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache") / "crosskill" / "llm"
spent_usd = 0.0  # cost of uncached calls this process
SPEND_LOCK = threading.Lock()  # the daily run extracts from worker threads
# Bounds on one call: a fact list fits easily; a runaway reasoning loop (131k tokens seen) does not.
MAX_TOKENS, TIMEOUT_S = 8192, 120
# Low reasoning effort: the provider ignores a reasoning token cap, and long skills burned all 8k
# completion tokens on reasoning with no answer. On the corpus labels: effort low P 0.92 / R 0.92,
# reasoning off P 0.76 / R 0.64 (2026-10-21). Part of the cache key.
REASONING = {"effort": "low"}
RETRIES = 2  # SDK retries on 429, 5xx and connection errors (timeouts included)
CALL_RESERVE_USD = 0.008  # one bounded flash call: 8k completion tokens plus the prompt
# Spend gate for runs with a cap (the daily run sets it): allow(calls_in_flight) -> bool, asked
# under SPEND_LOCK before each uncached call. `max_call_usd` is the costliest call seen.
allow = None
in_flight = 0
max_call_usd = 0.0


class OverBudget(RuntimeError):
    pass


def charge(cost: float | None, attempts: int = 1) -> None:
    """Count a call's cost. Unknown cost (None) counts as the costliest call so far, at least
    CALL_RESERVE_USD, once per attempt: a timed-out or unreadable call may still be billed."""
    global spent_usd, max_call_usd
    with SPEND_LOCK:
        if cost is None:
            cost = max(max_call_usd, CALL_RESERVE_USD)
        spent_usd += cost * attempts
        max_call_usd = max(max_call_usd, cost)


class Fact(BaseModel):
    kind: Literal["reads", "writes", "egress", "executes", "untrusted"]
    arg: str
    quote: str
    rule: str | None


class Facts(BaseModel):
    facts: list[Fact]


def complete(system: str, user: str, model: str, prompt=None) -> dict:
    from langfuse.openai import OpenAI  # imported here so static scans stay fast

    client = OpenAI(base_url="https://openrouter.ai/api/v1", api_key=os.environ["OPENROUTER_API_KEY"],
                    timeout=TIMEOUT_S, max_retries=RETRIES)
    start = time.perf_counter()
    try:
        r = client.chat.completions.parse(
            model=model, temperature=0, response_format=Facts, langfuse_prompt=prompt,
            max_tokens=MAX_TOKENS,
            messages=[{"role": "system", "content": system}, {"role": "user", "content": user}],
            # Route only to providers that enforce the JSON schema; ask OpenRouter for the cost.
            extra_body={"provider": {"require_parameters": True}, "usage": {"include": True},
                        "reasoning": REASONING},
        )
    except Exception as e:
        # A failed call can still be billed (e.g. LengthFinishReasonError carries the completion).
        # Without a cost, charge the reserve for every attempt the SDK may have made: its retries
        # (429, 5xx, timeouts, connection errors) are not visible from here.
        cost = getattr(getattr(getattr(e, "completion", None), "usage", None), "cost", None)
        charge(cost, 1 if cost is not None or not transient(e) else RETRIES + 1)
        raise
    parsed = r.choices[0].message.parsed
    return {"facts": [f.model_dump() for f in parsed.facts] if parsed else [],
            "cost": getattr(r.usage, "cost", None), "latency": time.perf_counter() - start}


def deterministic(e: Exception) -> bool:
    """A failure the same request would hit again: token cap reached or unparseable output."""
    from openai import ContentFilterFinishReasonError, LengthFinishReasonError
    from pydantic import ValidationError

    return isinstance(e, (LengthFinishReasonError, ContentFilterFinishReasonError, ValidationError,
                          json.JSONDecodeError))


def transient(e: Exception) -> bool:
    """A failure worth retrying later: timeout, connection error, 429 or 5xx from the API."""
    from openai import APIConnectionError, APIStatusError, RateLimitError

    if deterministic(e):
        return False
    return isinstance(e, (APIConnectionError, RateLimitError)) or (
        isinstance(e, APIStatusError) and e.status_code >= 500)


def facts_for(name: str, text: str, model: str, prompt=None) -> dict:
    """Facts for one file, from the cache when this model and prompt have seen the text."""
    system = prompt.prompt if prompt else PROMPT
    user = f"File: {name}\n\n{text}"
    mode = json.dumps(REASONING, sort_keys=True)
    key = hashlib.sha256(f"{model}\0{mode}\0{system}\0{user}".encode()).hexdigest()
    path = CACHE / f"{key}.json"
    if path.exists():
        return {**json.loads(path.read_text()), "cached": True}
    global in_flight
    with SPEND_LOCK:
        if allow is not None and not allow(in_flight):
            raise OverBudget("LLM budget reached")
        in_flight += 1
    start = time.perf_counter()
    try:
        out = complete(system, user, model, prompt)
        charge(out.get("cost"))  # no usage in the answer: charged as the reserve
    except Exception as e:
        if not deterministic(e):
            raise  # timeouts, connection errors, 429/5xx: try again on a later run
        # complete() already charged the failed call; cache it so the text is paid for once.
        usage = getattr(getattr(e, "completion", None), "usage", None)
        out = {"facts": [], "cost": getattr(usage, "cost", None),
               "latency": time.perf_counter() - start, "error": f"{type(e).__name__}: {e}"[:300]}
    finally:
        with SPEND_LOCK:
            in_flight -= 1
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(out))
    return out
