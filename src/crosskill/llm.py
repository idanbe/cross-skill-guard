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


class Fact(BaseModel):
    kind: Literal["reads", "writes", "egress", "executes", "untrusted"]
    arg: str
    quote: str
    rule: str | None


class Facts(BaseModel):
    facts: list[Fact]


def complete(system: str, user: str, model: str, prompt=None) -> dict:
    from langfuse.openai import OpenAI  # imported here so static scans stay fast

    client = OpenAI(base_url="https://openrouter.ai/api/v1", api_key=os.environ["OPENROUTER_API_KEY"])
    start = time.perf_counter()
    r = client.chat.completions.parse(
        model=model, temperature=0, response_format=Facts, langfuse_prompt=prompt,
        messages=[{"role": "system", "content": system}, {"role": "user", "content": user}],
        # Route only to providers that enforce the JSON schema; ask OpenRouter for the cost.
        extra_body={"provider": {"require_parameters": True}, "usage": {"include": True}},
    )
    parsed = r.choices[0].message.parsed
    return {"facts": [f.model_dump() for f in parsed.facts] if parsed else [],
            "cost": getattr(r.usage, "cost", None), "latency": time.perf_counter() - start}


def facts_for(name: str, text: str, model: str, prompt=None) -> dict:
    """Facts for one file, from the cache when this model and prompt have seen the text."""
    system = prompt.prompt if prompt else PROMPT
    user = f"File: {name}\n\n{text}"
    key = hashlib.sha256(f"{model}\0{system}\0{user}".encode()).hexdigest()
    path = CACHE / f"{key}.json"
    if path.exists():
        return {**json.loads(path.read_text()), "cached": True}
    global spent_usd
    out = complete(system, user, model, prompt)
    with SPEND_LOCK:
        spent_usd += out.get("cost") or 0
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(out))
    return out
