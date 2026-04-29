"""Post-process dense-variant runner outputs.

For each `runs/{variant}/{case}/rep-{N}/predict_output.txt` produced by
runner.py (where variant ∈ {DP, DB, DH}), parse the dense envelope and write
envelope.yaml + parse_errors.json so score.py can run unchanged. Also
optionally invoke faithfulness.py for D11 scoring.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import yaml

EVALS_ROOT = Path(__file__).parent
sys.path.insert(0, str(EVALS_ROOT))

from dense_parser import parse_dense  # noqa: E402

RUNS_DIR = EVALS_ROOT / "runs"
DENSE_VARIANTS = ("DP", "DB", "DH")


def process_output(out_dir: Path, *, run_faithfulness: bool = False) -> dict:
    txt_path = out_dir / "predict_output.txt"
    if not txt_path.exists():
        return {"status": "missing_output", "out_dir": str(out_dir)}
    text = txt_path.read_text()
    env, errs = parse_dense(text)
    (out_dir / "envelope.yaml").write_text(yaml.safe_dump(env, sort_keys=False))
    (out_dir / "parse_errors.json").write_text(json.dumps(errs, indent=2))
    rec = {
        "status": "parsed" if not errs else "parsed_with_errors",
        "out_dir": str(out_dir),
        "n_errors": len(errs),
        "shape": env.get("predict", {}).get("shape"),
    }
    if run_faithfulness and not errs:
        from faithfulness import score_faithfulness
        try:
            f = score_faithfulness(env, text)
            (out_dir / "faithfulness.json").write_text(json.dumps({
                "score": f.score, "raw_answers": f.raw_answers,
                "expected": f.expected, "correct": f.correct,
            }, indent=2))
            rec["faithfulness"] = f.score
        except Exception as exc:
            rec["faithfulness_error"] = repr(exc)
    return rec


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--variant", action="append", default=None,
                    help=f"variants to process (default: {DENSE_VARIANTS})")
    ap.add_argument("--case", action="append", default=None,
                    help="case_ids to process (default: all under runs/{variant}/)")
    ap.add_argument("--faithfulness", action="store_true",
                    help="also run Haiku faithfulness quiz on each parsed envelope")
    args = ap.parse_args()

    variants = args.variant or list(DENSE_VARIANTS)
    summary: list[dict] = []
    for variant in variants:
        vdir = RUNS_DIR / variant
        if not vdir.exists():
            print(f"[skip] {variant}: no runs dir")
            continue
        cases = args.case or [p.name for p in vdir.iterdir() if p.is_dir()]
        for case in cases:
            cdir = vdir / case
            if not cdir.exists():
                continue
            for rep_dir in sorted(cdir.glob("rep-*")):
                rec = process_output(rep_dir, run_faithfulness=args.faithfulness)
                rec["variant"] = variant
                rec["case"] = case
                rec["rep"] = rep_dir.name
                summary.append(rec)
                print(f"[{variant}/{case}/{rep_dir.name}] status={rec['status']} "
                      f"errors={rec.get('n_errors', '?')} shape={rec.get('shape')}"
                      + (f" faith={rec.get('faithfulness'):.2f}" if "faithfulness" in rec else ""))
    out = EVALS_ROOT / "results" / "dense_parse_summary.json"
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps(summary, indent=2))
    parsed = sum(1 for r in summary if r["status"] == "parsed")
    print(f"\n[summary] {parsed}/{len(summary)} parsed without errors  →  {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
