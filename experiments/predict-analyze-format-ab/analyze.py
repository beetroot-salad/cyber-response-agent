#!/usr/bin/env python3
"""Aggregate per-trial metrics and apply decision criteria.

Reads tasks-scratch/predict-analyze-format-ab/runs/{ab1-analyze,ab2-predict}/
{control,treatment}/trial-*/timing.json and produces a per-variant summary.

Per skill rule: rank by per-occurrence mean with `n` as support.
"""

from __future__ import annotations

import json
import statistics
from pathlib import Path

ROOT = Path(__file__).resolve().parent
RUNS = ROOT / "runs"


def _load_trials(ab_dir: Path, arm: str) -> list[dict]:
    out = []
    for trial in sorted((ab_dir / arm).glob("trial-*")):
        f = trial / "timing.json"
        if f.exists():
            try:
                out.append(json.loads(f.read_text()))
            except json.JSONDecodeError:
                pass
    return out


def _mean(xs: list[float]) -> float | None:
    return round(statistics.mean(xs), 1) if xs else None


def _summary(trials: list[dict]) -> dict:
    if not trials:
        return {"n": 0}
    walls = [t["wall_ms"] for t in trials if "wall_ms" in t]
    stdouts = [t.get("stdout_chars", 0) for t in trials]
    parsed = [t.get("parsed_ok", False) for t in trials]
    parse_errors = [t.get("parse_error") for t in trials if t.get("parse_error")]
    out = {
        "n": len(trials),
        "wall_ms_mean": _mean(walls),
        "wall_ms_min": min(walls) if walls else None,
        "wall_ms_max": max(walls) if walls else None,
        "stdout_chars_mean": _mean(stdouts),
        "parse_ok_rate": round(sum(parsed) / len(parsed), 2) if parsed else None,
        "parse_error_count": len(parse_errors),
        "parse_errors": parse_errors[:3],  # truncate to 3 examples
    }
    # analyze-shaped fields
    if all("grade_tiers" in t for t in trials):
        agg = {"++": 0, "+": 0, "-": 0, "--": 0}
        for t in trials:
            for k, v in t["grade_tiers"].items():
                agg[k] = agg.get(k, 0) + v
        out["grade_tiers_total"] = agg
        out["dispositions"] = [t.get("disposition") for t in trials]
        out["x_violations_total"] = sum(len(t.get("x_violations", [])) for t in trials)
    # predict-shaped fields
    if all("shape" in t for t in trials):
        out["shapes"] = [t.get("shape") for t in trials]
        out["n_hypotheses"] = [t.get("n_hypotheses") for t in trials]
    # downstream analyze (ab2 only)
    if any("downstream_analyze" in t for t in trials):
        d = [t["downstream_analyze"] for t in trials if "downstream_analyze" in t]
        if d:
            d_walls = [x["wall_ms"] for x in d]
            d_grades = {"++": 0, "+": 0, "-": 0, "--": 0}
            for x in d:
                for k, v in x.get("grade_tiers", {}).items():
                    d_grades[k] = d_grades.get(k, 0) + v
            out["downstream_analyze"] = {
                "n": len(d),
                "wall_ms_mean": _mean(d_walls),
                "grade_tiers_total": d_grades,
                "parse_ok_rate": round(
                    sum(x.get("parsed_ok", False) for x in d) / len(d), 2
                ),
                "dispositions": [x.get("disposition") for x in d],
            }
    return out


def _delta(control: dict, treatment: dict, key: str) -> dict:
    c = control.get(key)
    t = treatment.get(key)
    if c is None or t is None or c == 0:
        return {"control": c, "treatment": t, "pct": None}
    return {"control": c, "treatment": t, "pct": round((t - c) / c * 100, 1)}


def _decide_ab1(c: dict, t: dict) -> dict:
    """A/B-1 decision: dense-analyze wins iff wall ≤ -15% AND no new parser
    rejections AND grade tiers do not collapse `++`/`--` → `+`/`-`."""
    wall_pct = _delta(c, t, "wall_ms_mean")["pct"]
    decisive_c = c.get("grade_tiers_total", {}).get("++", 0) + c.get("grade_tiers_total", {}).get("--", 0)
    decisive_t = t.get("grade_tiers_total", {}).get("++", 0) + t.get("grade_tiers_total", {}).get("--", 0)
    parser_regression = (t.get("parse_error_count", 0) or 0) > (c.get("parse_error_count", 0) or 0)
    decisive_collapse = decisive_t < decisive_c * 0.5 if decisive_c else False
    won = (
        wall_pct is not None
        and wall_pct <= -15
        and not parser_regression
        and not decisive_collapse
    )
    return {
        "wall_pct": wall_pct,
        "parser_regression": parser_regression,
        "decisive_collapse": decisive_collapse,
        "won": won,
        "verdict": "proposed wins" if won else "current retained",
    }


def _decide_ab2(c: dict, t: dict) -> dict:
    """A/B-2 decision: symbolic stories win iff predict wall ≤ -15% AND
    output ≤ -20% AND parser-rejection stays 0 AND downstream analyze grades
    don't shift more than ±1 row."""
    wall_pct = _delta(c, t, "wall_ms_mean")["pct"]
    out_pct = _delta(c, t, "stdout_chars_mean")["pct"]
    treatment_rejected = (t.get("parse_error_count", 0) or 0) > 0
    downstream_shift = None
    if c.get("downstream_analyze") and t.get("downstream_analyze"):
        c_g = c["downstream_analyze"].get("grade_tiers_total", {})
        t_g = t["downstream_analyze"].get("grade_tiers_total", {})
        diff = sum(abs(t_g.get(k, 0) - c_g.get(k, 0)) for k in {"++", "+", "-", "--"})
        downstream_shift = diff
    won = (
        wall_pct is not None
        and wall_pct <= -15
        and out_pct is not None
        and out_pct <= -20
        and not treatment_rejected
        and (downstream_shift is None or downstream_shift <= 1)
    )
    return {
        "wall_pct": wall_pct,
        "stdout_pct": out_pct,
        "treatment_rejected": treatment_rejected,
        "downstream_grade_shift": downstream_shift,
        "won": won,
        "verdict": "proposed wins" if won else "current retained",
    }


def main() -> None:
    ab1 = RUNS / "ab1-analyze"
    ab2 = RUNS / "ab2-predict"

    ab1_c = _summary(_load_trials(ab1, "control"))
    ab1_t = _summary(_load_trials(ab1, "treatment"))
    ab2_c = _summary(_load_trials(ab2, "control"))
    ab2_t = _summary(_load_trials(ab2, "treatment"))

    report = {
        "ab1_analyze": {
            "control": ab1_c,
            "treatment": ab1_t,
            "decision": _decide_ab1(ab1_c, ab1_t) if ab1_c.get("n") and ab1_t.get("n") else None,
        },
        "ab2_predict": {
            "control": ab2_c,
            "treatment": ab2_t,
            "decision": _decide_ab2(ab2_c, ab2_t) if ab2_c.get("n") and ab2_t.get("n") else None,
        },
    }
    print(json.dumps(report, indent=2))

    out = ROOT / "results" / "summary.json"
    out.write_text(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
