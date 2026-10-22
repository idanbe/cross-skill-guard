"""Fact-level evals of the LLM extractor against corpus labels, recorded in Langfuse.

Labels are `skills/<name>/expected_facts.json` next to each corpus SKILL.md. Only facts that can
change a finding are scored: secret or private reads and writes, egress, untrusted input and
arbitrary execution.
"""

import json
from pathlib import Path
from urllib.parse import urlparse

from crosskill.extract import ARBITRARY, is_private, is_secret
from crosskill.llm import PROMPT, facts_for

CORPUS = Path(__file__).parent.parent.parent / "corpus"
DATASET = "crosskill-facts"
PROMPT_NAME = "crosskill-extract"


def norm(f: dict) -> tuple[str, str]:
    arg = f["arg"].strip()
    if f["kind"] == "egress" and "://" in arg:
        arg = urlparse(arg).hostname or arg
    for suffix in ("/**", "/*", "/"):
        arg = arg.removesuffix(suffix)
    return f["kind"], arg.removeprefix("./")


def relevant(kind: str, arg: str) -> bool:
    if kind in ("reads", "writes"):
        return is_secret(arg) or is_private(arg)
    return kind != "executes" or arg in ARBITRARY


def counts(expected: list[dict], got: list[dict]) -> tuple[int, int, int]:
    """True positives, false positives, false negatives over relevant facts."""
    e, g = ({k for k in map(norm, fs) if relevant(*k)} for fs in (expected, got))
    return len(e & g), len(g - e), len(e - g)


def ratio(a: int, b: int) -> float:
    return a / b if b else 1.0


def items() -> list[dict]:
    out = []
    for label in sorted(CORPUS.glob("*/*/skills/*/expected_facts.json")):
        skill = label.parent.relative_to(CORPUS)
        out.append({"id": "crosskill-" + str(skill).replace("/", "--"),
                    "input": {"file": "SKILL.md", "text": (label.parent / "SKILL.md").read_text()},
                    "expected_output": json.loads(label.read_text()),
                    "metadata": {"skill": str(skill)}})
    return out


def push(lf):
    """Upsert the dataset and the prompt; returns the production prompt."""
    if not any(d.name == DATASET for d in lf.api.datasets.list().data):
        lf.create_dataset(name=DATASET, description="corpus SKILL.md files with labeled facts")
    for item in items():
        lf.create_dataset_item(dataset_name=DATASET, **item)
    try:
        current = lf.get_prompt(PROMPT_NAME, cache_ttl_seconds=0).prompt
    except Exception:  # noqa: BLE001 - the SDK raises its own error types for a missing prompt
        current = None
    if current != PROMPT:
        lf.create_prompt(name=PROMPT_NAME, prompt=PROMPT, labels=["production"])
    return lf.get_prompt(PROMPT_NAME, cache_ttl_seconds=0)


def run(model: str, push_only: bool = False) -> str:
    from langfuse import Evaluation, get_client

    lf = get_client()
    prompt = push(lf)
    if push_only:
        lf.flush()
        return f"pushed {len(items())} items to {DATASET}, prompt {PROMPT_NAME} v{prompt.version}"

    def task(*, item, **_):
        return facts_for(item.input["file"], item.input["text"], model, prompt)

    def per_item(*, output, expected_output, **_):
        tp, fp, fn = counts(expected_output["facts"], output["facts"])
        return [Evaluation(name="precision", value=ratio(tp, tp + fp)),
                Evaluation(name="recall", value=ratio(tp, tp + fn)),
                Evaluation(name="cost_usd", value=output.get("cost") or 0.0),
                Evaluation(name="latency_s", value=output["latency"])]

    def per_run(*, item_results, **_):
        rs = [r for r in item_results if r.output]
        tp, fp, fn = map(sum, zip(*(counts(r.item.expected_output["facts"], r.output["facts"])
                                    for r in rs), strict=True))
        p, r = ratio(tp, tp + fp), ratio(tp, tp + fn)
        return [Evaluation(name="precision", value=p), Evaluation(name="recall", value=r),
                Evaluation(name="f1", value=2 * p * r / (p + r) if p + r else 0.0),
                Evaluation(name="cost_usd", value=sum(x.output.get("cost") or 0.0 for x in rs))]

    result = lf.run_experiment(
        name="fact-extraction", run_name=f"{model} prompt-v{prompt.version}", data=lf.get_dataset(DATASET).items,
        task=task, evaluators=[per_item], run_evaluators=[per_run], max_concurrency=8,
        metadata={"model": model, "prompt_version": str(prompt.version)})
    lf.flush()
    return result.format()
