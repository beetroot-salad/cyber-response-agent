#!/usr/bin/env python3
"""Blinded pairwise judge over WHOLE INVESTIGATIONS, glm-flash vs current, per fixture.

Not a decision criterion — the plan's criteria are gather-level. This answers the question the
run-level table raises: when MAIN closes differently on the same alert depending only on which
model wrote its gather summaries, is the glm-flash-arm investigation the better-earned
document or the worse one? Rubric and mechanics are `invlang-clerk-986/analyze.py`'s (Opus
via `claude -p`, both orders, an order-flip counts as a tie). Verdicts cached under
results/pairwise/.

Usage: python3 pairwise.py [--fixture F2-authorized-keys] [--arms glm-flash current]
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
from collections import Counter
from pathlib import Path

_EXP = Path(__file__).resolve().parent
RUNS = _EXP / "runs"
OUT = _EXP / "results" / "pairwise"
JUDGE_MODEL = "claude-opus-5"

RUBRIC = """\
You are comparing two runs of an automated alert-triage agent on the SAME alert. You will see
each run's investigation document and its closing report, labelled X and Y. You do not know
how either was produced; judge only what is on the page.

Decide which run's CLOSING CLAIM is better earned, on these questions:
1. Is the disposition's rationale supported by evidence the run's own leads actually gathered
   (quoted results, not assertions)?
2. Were the leads discriminating — did each one test something that could have changed the
   verdict — rather than confirmatory or redundant?
3. Is the closing claim scoped to the entity the run actually investigated, and are the open
   questions it names the ones that are genuinely open?
4. Does the record carry what the prose asserts, so a reader could audit the verdict from the
   rows alone?

Reply with ONE JSON object and nothing else:
{"winner": "X" | "Y" | "tie", "margin": "clear" | "slight", "reasons": "<three sentences max>"}
"""


def _doc(run_id: str) -> str:
    d = RUNS / run_id
    inv = (d / "investigation.md").read_text(encoding="utf-8", errors="replace") if (d / "investigation.md").exists() else "(missing)"
    rep = (d / "report.md").read_text(encoding="utf-8", errors="replace") if (d / "report.md").exists() else "(no report)"
    return f"--- investigation.md ---\n{inv}\n\n--- report.md ---\n{rep}\n"


def _parse(text: str) -> dict:
    t = text.strip()
    if t.startswith("```"):
        t = t.split("\n", 1)[1].rsplit("```", 1)[0]
    m = re.search(r"\{.*\}", t, re.S)
    if m:
        try:
            return json.loads(re.sub(r",(\s*[}\]])", r"\1", m.group(0)))
        except json.JSONDecodeError:
            pass
    return {"winner": "tie", "margin": "unparsed", "reasons": t[:300]}


def judge_once(x: str, y: str) -> dict:
    cache = OUT / f"{x}__vs__{y}.json"
    if cache.is_file():
        return json.loads(cache.read_text(encoding="utf-8"))
    prompt = f"{RUBRIC}\n\n=== RUN X ===\n{_doc(x)}\n\n=== RUN Y ===\n{_doc(y)}\n"
    env = {k: v for k, v in os.environ.items() if k != "ANTHROPIC_API_KEY"}
    proc = subprocess.run(  # noqa: S603
        ["claude", "-p", "--model", JUDGE_MODEL], input=prompt, capture_output=True,
        text=True, env=env, timeout=1800, check=False,
    )
    v = _parse(proc.stdout) if proc.returncode == 0 else {"winner": "tie", "margin": "error", "reasons": proc.stderr[-300:]}
    OUT.mkdir(parents=True, exist_ok=True)
    cache.write_text(json.dumps(v, indent=1), encoding="utf-8")
    return v


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--fixture", default="F2-authorized-keys")
    ap.add_argument("--arms", nargs=2, default=["glm-flash", "current"])
    args = ap.parse_args()
    a, b = args.arms
    manifest = [json.loads(l) for l in (RUNS / "manifest.jsonl").open(encoding="utf-8") if l.strip()]
    ok = [m for m in manifest if m["fixture"] == args.fixture and not m.get("excluded") and (RUNS / m["run_id"] / "report.md").is_file()]
    ra = [m["run_id"] for m in ok if m["arm"] == a]
    rb = [m["run_id"] for m in ok if m["arm"] == b]
    tally = Counter()
    rows = []
    for x in ra:
        for y in rb:
            v1 = judge_once(x, y)            # x as X
            v2 = judge_once(y, x)            # x as Y
            w1 = {"X": a, "Y": b}.get(v1["winner"], "tie")
            w2 = {"X": b, "Y": a}.get(v2["winner"], "tie")
            winner = w1 if w1 == w2 else "tie"
            tally[winner] += 1
            rows.append({"a": x, "b": y, "order1": w1, "order2": w2, "winner": winner,
                         "r1": v1["reasons"], "r2": v2["reasons"]})
    print(f"{args.fixture}: {a} vs {b}, {len(rows)} pairs, both orders (flip = tie)")
    print(f"  {a}: {tally[a]}  {b}: {tally[b]}  tie: {tally['tie']}")
    (OUT / f"{args.fixture}__{a}__vs__{b}.jsonl").write_text(
        "".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
    for r in rows:
        print(f"  {r['a']} vs {r['b']}: {r['winner']}  | {r['r1'][:160]}")


if __name__ == "__main__":
    main()
