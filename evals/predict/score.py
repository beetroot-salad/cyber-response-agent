"""Score PREDICT envelope outputs against case expected outcomes.

Reads `runs/{variant}/{case-id}/rep-{N}/envelope.yaml` + `cases/{case-id}.yaml`,
applies rubric dimensions D1-D5 + D7 + D8a (D6 + D8b are judge-based, deferred
per task scoping). Emits per-cell scores to `results/{variant}/{case-id}.json`
and a per-variant summary to `results/{variant}.json`.

Aggregates across reps for variance signal: for each (variant, case), reports
mean + per-rep array per dimension so reproducibility shows up directly.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from statistics import mean

import yaml

import os as _os
REPO_ROOT = Path(_os.environ.get("PREDICT_EVAL_REPO_ROOT", "/workspace"))
EVALS_ROOT = REPO_ROOT / "evals" / "predict"
CASES_DIR = EVALS_ROOT / "cases"
RUNS_DIR = EVALS_ROOT / "runs"
RESULTS_DIR = EVALS_ROOT / "results"

sys.path.insert(0, str(EVALS_ROOT))
from detectors import detect_all  # noqa: E402

WEIGHTS = {
    "D1_shape": 3,
    "D2_lead": 2,
    "D3_structural": 2,
    "D4_count": 1,
    "D5_forbidden": 2,
    "D7_auth_contract": 2,
    "D8a_pred_quality": 3,
}

VAGUE_VOCAB = re.compile(
    r"\b(looks suspicious|consistent with|behavior matches|indicates|"
    r"appears to|seems to|suggests|might be|likely|potentially)\b",
    re.IGNORECASE,
)


def _claim_text(entry: dict) -> str:
    return str(entry.get("claim") or entry.get("if") or "")


def d1_shape(envelope: dict, expected: dict) -> int:
    actual = envelope.get("predict", {}).get("shape")
    expected_shape = expected.get("shape")
    if actual == expected_shape:
        return 1
    alts = expected.get("acceptable_alternative_shapes", []) or []
    if actual in alts:
        return 1
    return 0


def d2_lead(envelope: dict, expected: dict) -> int:
    routing = envelope.get("predict", {}).get("routing", {}) or {}
    selected = routing.get("selected_lead")
    must = (expected.get("routing_must") or {}).get("selected_lead_oneof", []) or []
    branch_plan = envelope.get("predict", {}).get("branch_plan") or {}
    primary = branch_plan.get("primary_lead")
    bp_oneof = (expected.get("branch_plan_must") or {}).get("primary_lead_oneof", []) or []
    if selected and selected in must:
        return 1
    if primary and primary in bp_oneof:
        return 1
    if not must and not bp_oneof:
        return 1
    return 0


def d3_structural(envelope: dict, expected: dict) -> tuple[int, list[str]]:
    """Lightweight structural conformance: presence-matrix check + ID format.

    Skips the full invlang_validate.py path (which requires a synthetic prior
    investigation.md to merge against — out of scope for variant comparison).
    """
    errors: list[str] = []
    pred = envelope.get("predict", {})
    shape = pred.get("shape")
    hyps = pred.get("hypotheses") or []
    bp = pred.get("branch_plan") or {}
    routing = pred.get("routing") or {}

    if shape not in ("E", "A", "M"):
        errors.append(f"shape not in E/A/M: {shape!r}")
    if shape == "E":
        if hyps:
            errors.append("shape E must have no hypotheses")
        if not bp:
            errors.append("shape E missing branch_plan")
    elif shape == "A":
        if not hyps:
            errors.append("shape A requires ≥ 1 hypothesis")
        if bp:
            errors.append("shape A must not have branch_plan")
    elif shape == "M":
        if len(hyps) < 2:
            errors.append("shape M requires ≥ 2 hypotheses")

    if not (routing.get("selected_lead") or bp.get("primary_lead")):
        errors.append("missing selected_lead / primary_lead")

    for h in hyps:
        hid = h.get("id", "")
        if not re.match(r"^h-\d+(-\d+)?$", hid):
            errors.append(f"bad hypothesis id: {hid!r}")
        for p in (h.get("predictions") or []):
            pid = p.get("id", "")
            if not re.match(r"^p\d+$", pid):
                errors.append(f"bad prediction id: {pid!r}")
        for ap in (h.get("attribute_predictions") or []):
            apid = ap.get("id", "")
            if not re.match(r"^ap\d+$", apid):
                errors.append(f"bad attribute_prediction id: {apid!r}")

    return (1 if not errors else 0, errors)


def d4_count(envelope: dict, expected: dict) -> int:
    pred = envelope.get("predict", {})
    shape = pred.get("shape")
    hyps = pred.get("hypotheses") or []
    n = len(hyps)
    must = expected.get("hypotheses_must") or {}
    if shape == "E":
        return 1 if n == 0 else 0
    if must:
        cmin = must.get("count_min", 1)
        cmax = must.get("count_max", 99)
        return 1 if cmin <= n <= cmax else 0
    return 1


def d5_forbidden(envelope: dict, expected: dict, ctx: dict) -> tuple[int, dict[str, bool]]:
    patterns = expected.get("forbidden_patterns", []) or []
    fired = detect_all(patterns, envelope, ctx)
    return (0 if any(fired.values()) else 1, fired)


def d7_auth_contract(envelope: dict, expected: dict) -> int | None:
    """Shape-A only: returns None for non-A cases (skipped in aggregate)."""
    if expected.get("shape") != "A":
        return None
    must = expected.get("hypotheses_must") or {}
    must_have = must.get("must_include_authorization_contract", False)
    has_contract = False
    for h in envelope.get("predict", {}).get("hypotheses") or []:
        if h.get("authorization_contract"):
            has_contract = True
            break
    return 1 if has_contract == must_have else 0


def d8a_prediction_quality(envelope: dict, expected: dict) -> tuple[float, dict]:
    """D8a code-checkable subset only: falsifiable_observable + non_tautological.
    Skip lead_can_measure (requires lead-catalog frontmatter parsing).
    """
    entries = []
    for h in envelope.get("predict", {}).get("hypotheses") or []:
        entries.extend(h.get("predictions") or [])
        entries.extend(h.get("attribute_predictions") or [])
        entries.extend(h.get("refutation_shape") or [])
    bp = envelope.get("predict", {}).get("branch_plan") or {}
    entries.extend(bp.get("predictions") or [])

    if not entries:
        return (1.0, {"n": 0, "falsifiable": 1.0, "non_tautological": 1.0})

    n_falsifiable = 0
    n_non_tautological = 0
    alert_text = ""
    # crude tautology check: token overlap with alert json
    try:
        alert_path = Path(envelope.get("__alert_path", ""))
        if alert_path and alert_path.exists():
            alert_text = alert_path.read_text().lower()
    except Exception:
        alert_text = ""

    for e in entries:
        text = _claim_text(e)
        if not text:
            continue
        if not VAGUE_VOCAB.search(text):
            n_falsifiable += 1
        if not alert_text:
            n_non_tautological += 1
        else:
            tokens = re.findall(r"\w+", text.lower())
            tokens = [t for t in tokens if len(t) > 4]
            if not tokens:
                n_non_tautological += 1
            else:
                overlap = sum(1 for t in tokens if t in alert_text) / len(tokens)
                if overlap < 0.7:
                    n_non_tautological += 1

    n = len(entries)
    f = n_falsifiable / n
    nt = n_non_tautological / n
    return ((f + nt) / 2.0, {"n": n, "falsifiable": round(f, 2), "non_tautological": round(nt, 2)})


def score_cell(envelope_path: Path, case: dict, ctx: dict) -> dict:
    envelope = yaml.safe_load(envelope_path.read_text())
    expected = case.get("expected", {})

    d1 = d1_shape(envelope, expected)
    d2 = d2_lead(envelope, expected)
    d3, d3_errors = d3_structural(envelope, expected)
    d4 = d4_count(envelope, expected)
    d5, d5_fired = d5_forbidden(envelope, expected, ctx)
    d7 = d7_auth_contract(envelope, expected)
    d8a, d8a_detail = d8a_prediction_quality(envelope, expected)

    weighted = {
        "D1_shape": d1 * WEIGHTS["D1_shape"],
        "D2_lead": d2 * WEIGHTS["D2_lead"],
        "D3_structural": d3 * WEIGHTS["D3_structural"],
        "D4_count": d4 * WEIGHTS["D4_count"],
        "D5_forbidden": d5 * WEIGHTS["D5_forbidden"],
        "D8a_pred_quality": d8a * WEIGHTS["D8a_pred_quality"],
    }
    weights_used = {k: WEIGHTS[k] for k in weighted}
    if d7 is not None:
        weighted["D7_auth_contract"] = d7 * WEIGHTS["D7_auth_contract"]
        weights_used["D7_auth_contract"] = WEIGHTS["D7_auth_contract"]
    total_w = sum(weights_used.values())
    score = sum(weighted.values()) / total_w if total_w else 0.0

    return {
        "score": round(score, 3),
        "shape": envelope.get("predict", {}).get("shape"),
        "expected_shape": expected.get("shape"),
        "dims": {
            "D1_shape": d1,
            "D2_lead": d2,
            "D3_structural": d3,
            "D4_count": d4,
            "D5_forbidden": d5,
            "D7_auth_contract": d7,
            "D8a_pred_quality": round(d8a, 3),
        },
        "d3_errors": d3_errors,
        "d5_fired": d5_fired,
        "d8a_detail": d8a_detail,
    }


def _load_case(case_id: str) -> dict:
    path = CASES_DIR / f"{case_id}.yaml"
    return yaml.safe_load(path.read_text())


def _read_prior_investigation(fixture_dir: Path) -> str | None:
    p = fixture_dir / "investigation.md"
    return p.read_text() if p.exists() else None


def score_variant(variant: str, case_filter: list[str] | None = None) -> dict:
    variant_dir = RUNS_DIR / variant
    out: dict = {"variant": variant, "cases": {}, "aggregate": {}}
    if not variant_dir.exists():
        return out

    per_dim_means: dict[str, list[float]] = {}
    per_case_means: list[float] = []
    cases_run: list[str] = []

    for case_dir in sorted(variant_dir.iterdir()):
        if not case_dir.is_dir():
            continue
        case_id = case_dir.name
        if case_filter and case_id not in case_filter:
            continue
        case = _load_case(case_id)
        fixture_dir = REPO_ROOT / "evals" / "predict" / "fixtures" / case_id
        ctx = {
            "loop_n": case.get("loop_n", 1),
            "prior_investigation": _read_prior_investigation(fixture_dir),
        }

        rep_scores: list[dict] = []
        for rep_dir in sorted(case_dir.iterdir()):
            if not rep_dir.is_dir():
                continue
            env = rep_dir / "envelope.yaml"
            if not env.exists():
                rep_scores.append({"rep": rep_dir.name, "status": "no_envelope"})
                continue
            try:
                rec = score_cell(env, case, ctx)
                rec["rep"] = rep_dir.name
                rep_scores.append(rec)
            except Exception as exc:
                rep_scores.append({"rep": rep_dir.name, "status": "score_error", "error": repr(exc)})

        # per-case aggregate
        valid = [r for r in rep_scores if "score" in r]
        case_summary = {
            "reps": rep_scores,
            "rep_count": len(rep_scores),
            "valid_reps": len(valid),
        }
        if valid:
            case_summary["mean_score"] = round(mean(r["score"] for r in valid), 3)
            shapes = [r["shape"] for r in valid]
            case_summary["shape_consensus"] = max(set(shapes), key=shapes.count) if shapes else None
            case_summary["shape_agreement"] = round(
                shapes.count(case_summary["shape_consensus"]) / len(shapes), 2
            )
            for dim in WEIGHTS:
                vals = [r["dims"].get(dim) for r in valid if r["dims"].get(dim) is not None]
                if vals:
                    case_summary.setdefault("dim_means", {})[dim] = round(mean(vals), 3)
                    per_dim_means.setdefault(dim, []).append(mean(vals))
            per_case_means.append(case_summary["mean_score"])
            cases_run.append(case_id)
        out["cases"][case_id] = case_summary

    if per_case_means:
        out["aggregate"] = {
            "case_count": len(cases_run),
            "mean_score": round(mean(per_case_means), 3),
            "dim_means": {k: round(mean(v), 3) for k, v in per_dim_means.items()},
        }
    return out


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--variant", action="append", default=None,
                        help="variant to score (repeatable). Default: all under runs/")
    parser.add_argument("--case", action="append", default=None,
                        help="case_id to score (repeatable)")
    args = parser.parse_args()

    if args.variant:
        variants = args.variant
    else:
        variants = sorted(p.name for p in RUNS_DIR.iterdir() if p.is_dir())

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    summaries = {}
    for variant in variants:
        summary = score_variant(variant, args.case)
        path = RESULTS_DIR / f"{variant}.json"
        path.write_text(json.dumps(summary, indent=2))
        summaries[variant] = summary
        print(f"\n=== {variant} ===")
        agg = summary.get("aggregate") or {}
        print(f"  cases scored: {agg.get('case_count', 0)} | mean: {agg.get('mean_score', '-')}")
        if "dim_means" in agg:
            for dim, val in agg["dim_means"].items():
                print(f"    {dim}: {val}")
        for case_id, c in summary.get("cases", {}).items():
            shape_info = ""
            if c.get("shape_consensus"):
                shape_info = f" | shape={c['shape_consensus']} ({int(c.get('shape_agreement', 0)*100)}% agreement)"
            print(f"  {case_id}: mean={c.get('mean_score', '-')} | reps={c.get('valid_reps', 0)}/{c.get('rep_count', 0)}{shape_info}")

    (RESULTS_DIR / "all.json").write_text(json.dumps(summaries, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
