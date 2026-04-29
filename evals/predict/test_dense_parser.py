"""Smoke tests for dense_parser.py — checks each variant's worked example
parses without errors and produces the expected envelope shape."""

from __future__ import annotations

import re
from pathlib import Path

from dense_parser import parse_dense

VARIANTS_DIR = Path(__file__).parent / "variants"


def _extract_first_fenced_block(text: str) -> str:
    # The worked examples in the variant docs are inside ```...``` fences.
    m = re.search(r"```\n(predict loop=2 shape=A.*?)\n```", text, flags=re.DOTALL)
    assert m, "no worked example block found"
    return m.group(1)


def test_variant(name: str) -> None:
    text = (VARIANTS_DIR / f"{name}.md").read_text()
    sample = _extract_first_fenced_block(text)
    env, errs = parse_dense(sample)
    assert errs == [], f"{name}: parse errors: {errs}"
    pred = env["predict"]
    assert pred["shape"] == "A", f"{name}: expected shape A"
    assert pred["loop"] == 2, f"{name}: expected loop 2"
    hyps = pred["hypotheses"]
    assert len(hyps) == 1, f"{name}: expected 1 hypothesis"
    h = hyps[0]
    assert h["id"] == "h-001"
    assert h["name"] == "?registered-actor-initiated"
    assert "story" in h and "monitoring" in h["story"]
    assert len(h["predictions"]) == 1
    assert h["predictions"][0]["id"] == "p1"
    assert h["predictions"][0]["from_story_link"] == "s2"
    assert len(h["refutation_shape"]) == 1
    assert h["refutation_shape"][0]["refutes_predictions"] == ["p1"]
    assert len(h["authorization_contract"]) == 1
    assert h["authorization_contract"][0]["id"] == "ac1"
    assert pred["routing"]["selected_lead"] == "approved-monitoring-sources-lookup"
    print(f"{name}: OK")


if __name__ == "__main__":
    for v in ("DP", "DB", "DH"):
        test_variant(v)
