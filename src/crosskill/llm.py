"""LLM extractor: capability facts from SKILL.md prose and JS/TS scripts, through OpenRouter.

Calls are traced to Langfuse by its OpenAI wrapper (when LANGFUSE_* keys are set) and cached on
disk, so the same text with the same model and prompt is never paid for twice.
"""

import hashlib
import json
import os
import time
from pathlib import Path
from typing import Literal

from pydantic import BaseModel

PROMPT = (Path(__file__).parent / "prompt.md").read_text()
DEFAULT_MODEL = "deepseek/deepseek-v4.1-flash"
CACHE = Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache") / "crosskill" / "llm"
# Bounds on one call: a fact list fits easily; a runaway reasoning loop (131k tokens seen) does not.
MAX_TOKENS, TIMEOUT_S = 8192, 120
# Low reasoning effort: the provider ignores a reasoning token cap, and long skills burned all 8k
# completion tokens on reasoning with no answer. On the corpus labels: effort low P 0.92 / R 0.92,
# reasoning off P 0.76 / R 0.64 (2026-10-21). Part of the cache key.
REASONING = {"effort": "low"}
RETRIES = 2  # SDK retries on 429, 5xx and connection errors (timeouts included)


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
    r = client.chat.completions.parse(
        model=model, temperature=0, response_format=Facts, langfuse_prompt=prompt,
        max_tokens=MAX_TOKENS,
        messages=[{"role": "system", "content": system}, {"role": "user", "content": user}],
        # Route only to providers that enforce the JSON schema; ask OpenRouter for the cost.
        extra_body={"provider": {"require_parameters": True}, "usage": {"include": True},
                    "reasoning": REASONING},
    )
    parsed = r.choices[0].message.parsed
    return {"facts": [f.model_dump() for f in parsed.facts] if parsed else [],
            "cost": getattr(r.usage, "cost", None), "latency": time.perf_counter() - start}


def deterministic(e: Exception) -> bool:
    """A failure the same request would hit again: token cap reached or unparseable output."""
    from openai import ContentFilterFinishReasonError, LengthFinishReasonError
    from pydantic import ValidationError

    return isinstance(e, (LengthFinishReasonError, ContentFilterFinishReasonError, ValidationError,
                          json.JSONDecodeError))


def facts_for(name: str, text: str, model: str, prompt=None) -> dict:
    """Facts for one file, from the cache when this model and prompt have seen the text."""
    system = prompt.prompt if prompt else PROMPT
    user = f"File: {name}\n\n{text}"
    mode = json.dumps(REASONING, sort_keys=True)
    key = hashlib.sha256(f"{model}\0{mode}\0{system}\0{user}".encode()).hexdigest()
    path = CACHE / f"{key}.json"
    if path.exists():
        return {**json.loads(path.read_text()), "cached": True}
    start = time.perf_counter()
    try:
        out = complete(system, user, model, prompt)
    except Exception as e:
        if not deterministic(e):
            raise  # timeouts, connection errors, 429/5xx: not cached, so the next scan retries
        # Cache the failure so the same text is paid for once.
        usage = getattr(getattr(e, "completion", None), "usage", None)
        out = {"facts": [], "cost": getattr(usage, "cost", None),
               "latency": time.perf_counter() - start, "error": f"{type(e).__name__}: {e}"[:300]}
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(out))
    return out
