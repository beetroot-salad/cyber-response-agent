#!/usr/bin/env python3
"""#289 pilot analysis — fidelity (A2), replayability, cost/latency per (variant, fixture).

Metrics
  * Fidelity (primary): for each oracle dimension, an LLM judge (Sonnet) scores the
    variant's summary as exact | wrong | dropped against ground truth. A2 rate =
    (wrong + dropped) / dimensions. Extractions are cached under results/extractions/
    so re-runs don't re-bill; the validation pass is hand-calibrated by reading them.
  * Replayability (proposed): fraction of oracle dimensions backed by an analyses.jsonl
    row whose recorded output matches ground truth (deterministic, no LLM). current = 0.
  * Cost/latency: from meta.json — requests, wall, output/input tokens, completion.

Rank by per-occurrence mean with n shown as support.

Usage:
    python3 analyze.py                 # score every run under runs/
    python3 analyze.py --no-judge      # skip LLM scoring (replayability + cost only)
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

_EXP = Path(__file__).resolve().parent
RUNS = _EXP / "runs"
FIXTURES = _EXP / "fixtures"
RESULTS = _EXP / "results"
EXTRACTIONS = RESULTS / "extractions"
JUDGE_MODEL = "claude-sonnet-4-6"


# ----------------------------------------------------------------------------- judge
_JUDGE_SYS = (
    "You score a security 'gather' summary against ground truth. The summary was "
    "produced by a subagent told to report specific measurements over a log payload. "
    "For EACH dimension you are given its ground-truth value. Classify how the summary "
    "reported it:\n"
    "  exact   — the summary states this dimension and its value matches ground truth\n"
    "            (formatting/precision differences are fine if not contradictory; a "
    "value reported in different units that is numerically consistent is exact)\n"
    "  wrong   — the summary states this dimension but the value contradicts ground "
    "truth (e.g. a count that is off, an under-reported cardinality, a wrong timestamp)\n"
    "  dropped — the summary does not address this dimension at all\n"
    "Be strict about 'wrong': under-reporting a cardinality (e.g. saying 'nagios' or "
    "'1 user' when 5 distinct users exist) is wrong, not exact. Return ONLY JSON: "
    '{"<dim>": {"status":"exact|wrong|dropped","reported":"<verbatim or null>","note":"<short>"}, ...}'
)


def _judge(summary: str, dims: dict) -> dict:
    import anthropic  # lazy: only when judging
    client = anthropic.Anthropic()
    dim_lines = "\n".join(
        f"- {name}: ground_truth = {json.dumps(spec['expected'])}"
        for name, spec in dims.items()
    )
    user = (
        f"DIMENSIONS (with ground truth):\n{dim_lines}\n\n"
        f"SUMMARY TO SCORE:\n<<<\n{summary or '(empty — the run produced no summary)'}\n>>>"
    )
    resp = client.messages.create(
        model=JUDGE_MODEL, max_tokens=2000,
        system=_JUDGE_SYS, messages=[{"role": "user", "content": user}],
    )
    text = "".join(b.text for b in resp.content if b.type == "text")
    m = re.search(r"\{.*\}", text, re.DOTALL)
    return json.loads(m.group(0)) if m else {}


def _extract(run_id: str, summary: str, dims: dict, use_judge: bool) -> dict:
    EXTRACTIONS.mkdir(parents=True, exist_ok=True)
    cache = EXTRACTIONS / f"{run_id}.json"
    if cache.is_file():
        return json.loads(cache.read_text())
    if not use_judge:
        return {}
    scored = _judge(summary, dims)
    cache.write_text(json.dumps(scored, indent=2))
    return scored


# ----------------------------------------------------------------- replayability (det.)
def _norm(v) -> str:
    return re.sub(r"\s+", "", str(v)).strip().lower()


def _value_matches(output: str, expected) -> bool:
    """Does a recorded analysis output match an oracle expected value? Deterministic."""
    out = output.strip()
    try:
        parsed = json.loads(out)
    except (json.JSONDecodeError, ValueError):
        parsed = out
    if isinstance(expected, bool):
        return _norm(parsed) == _norm(expected)
    if isinstance(expected, (int, float)) and not isinstance(expected, bool):
        try:
            return abs(float(parsed) - float(expected)) < 1.0
        except (TypeError, ValueError):
            return _norm(expected) in _norm(out)
    if isinstance(expected, list):
        if isinstance(parsed, list):
            return {_norm(x) for x in parsed} == {_norm(x) for x in expected}
        return all(_norm(x) in _norm(out) for x in expected)
    # string (e.g. timestamp): match on the substantive prefix (ignore sub-second/Z noise)
    exp = str(expected)
    return _norm(exp) in _norm(out) or _norm(exp[:19]) in _norm(out)


def _replayability(run_dir: Path, dims: dict) -> tuple[int, int]:
    """(#dims backed by a matching analyses.jsonl output, #dims)."""
    log = run_dir / "analyses.jsonl"
    rows = []
    if log.is_file():
        for ln in log.read_text().splitlines():
            ln = ln.strip()
            if not ln:
                continue
            try:
                rows.append(json.loads(ln))
            except (json.JSONDecodeError, ValueError):
                pass
    backed = 0
    for spec in dims.values():
        if any(r.get("output_status") == "ok" and _value_matches(r.get("output", ""), spec["expected"])
               for r in rows):
            backed += 1
    return backed, len(dims)


# --------------------------------------------------------------------------- aggregate
def _mean(xs):
    xs = [x for x in xs if x is not None]
    return sum(xs) / len(xs) if xs else None


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--no-judge", action="store_true", help="skip LLM fidelity scoring")
    ns = p.parse_args(argv)
    RESULTS.mkdir(exist_ok=True)

    runs = sorted(d for d in RUNS.iterdir() if (d / "meta.json").is_file())
    cells: dict[tuple, list] = {}
    per_run = []
    for rd in runs:
        meta = json.loads((rd / "meta.json").read_text())
        fixture, variant = meta["fixture"], meta["variant"]
        oracle = json.loads((FIXTURES / fixture / "oracle.json").read_text())
        dims = oracle["dimensions"]
        summary = (rd / "summary.md").read_text() if (rd / "summary.md").is_file() else ""

        scored = _extract(meta["run_id"], summary, dims, use_judge=not ns.no_judge)
        statuses = [scored.get(d, {}).get("status", "dropped") for d in dims] if scored else None
        a2_rate = (sum(1 for s in statuses if s in ("wrong", "dropped")) / len(statuses)
                   if statuses else None)
        exact = sum(1 for s in statuses if s == "exact") if statuses else None

        backed, ndim = _replayability(rd, dims)
        usage = meta.get("usage", {})
        row = {
            "run_id": meta["run_id"], "fixture": fixture, "variant": variant,
            "complete": meta.get("exit_reason") == "ok",
            "a2_rate": a2_rate, "exact": exact, "ndim": ndim,
            "replay_frac": backed / ndim if ndim else None,
            "requests": meta.get("n_requests"), "wall_s": round(meta.get("wall_ms", 0) / 1000, 1),
            "out_tok": usage.get("output_tokens"), "in_tok": usage.get("input_tokens"),
            "n_analyses": meta.get("n_analyses"),
        }
        per_run.append(row)
        cells.setdefault((fixture, variant), []).append(row)

    # Per-cell aggregation (per-occurrence mean, n as support).
    agg = []
    for (fixture, variant), rows in sorted(cells.items()):
        agg.append({
            "fixture": fixture, "variant": variant, "n": len(rows),
            "complete": f"{sum(r['complete'] for r in rows)}/{len(rows)}",
            "a2_rate": _mean([r["a2_rate"] for r in rows]),
            "exact_mean": _mean([r["exact"] for r in rows]),
            "ndim": rows[0]["ndim"],
            "replay_frac": _mean([r["replay_frac"] for r in rows]),
            "requests": _mean([r["requests"] for r in rows]),
            "wall_s": _mean([r["wall_s"] for r in rows]),
            "out_tok": _mean([r["out_tok"] for r in rows]),
        })

    (RESULTS / "scores.json").write_text(json.dumps({"per_run": per_run, "per_cell": agg}, indent=2))
    _print_table(agg)
    return 0


def _fmt(v, nd=2):
    if v is None:
        return "—"
    if isinstance(v, float):
        return f"{v:.{nd}f}"
    return str(v)


def _print_table(agg: list) -> None:
    hdr = f"{'fixture':22} {'variant':9} {'n':>2} {'compl':>5} {'A2':>5} {'exact/dim':>9} {'replay':>6} {'reqs':>5} {'wall_s':>6} {'out_tok':>7}"
    print(hdr); print("-" * len(hdr))
    for c in sorted(agg, key=lambda x: (x["fixture"], x["variant"])):
        exact = f"{_fmt(c['exact_mean'],1)}/{c['ndim']}"
        print(f"{c['fixture']:22} {c['variant']:9} {c['n']:>2} {c['complete']:>5} "
              f"{_fmt(c['a2_rate']):>5} {exact:>9} {_fmt(c['replay_frac']):>6} "
              f"{_fmt(c['requests'],0):>5} {_fmt(c['wall_s'],0):>6} {_fmt(c['out_tok'],0):>7}")
    print("\nA2 = mean (wrong+dropped)/dim (lower=better). replay = frac dims backed by a "
          "matching analyses row. Rank by per-occurrence mean; n = support.")


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
