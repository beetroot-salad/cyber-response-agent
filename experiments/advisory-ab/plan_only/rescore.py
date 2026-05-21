#!/usr/bin/env python3
"""Rescore an existing results dir by re-running extract_metrics
against the original run dirs. Use after fixing a parsing bug in
replay.py — no LLM re-spend, just re-reads on-disk artifacts.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
RESULTS_DIR = HERE / "results"

sys.path.insert(0, str(HERE))
import replay  # type: ignore


def rescore_dir(dir_: Path) -> None:
    for f in sorted(dir_.glob("*.json")):
        prev = json.loads(f.read_text())
        run_dir = Path(prev["run_dir"])
        if not run_dir.is_dir():
            print(f"[rescore] skipping {f.name}: run_dir gone", file=sys.stderr)
            continue
        new = replay.extract_metrics(
            prev["arm"], prev["case_id"], run_dir,
            prev["rc"], prev["plan_turn_wall_clock_s"],
        )
        f.write_text(json.dumps(new, indent=2))
        print(f"[rescore] {f.name}: leads={len(new['leads_authored'])} "
              f"advisory={len(new['advisory_calls'])}", file=sys.stderr)


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--dir", type=Path, default=None,
                   help="Results subdir; defaults to latest under results/")
    ns = p.parse_args(argv)
    if ns.dir:
        dir_ = ns.dir
    else:
        dirs = sorted([p for p in RESULTS_DIR.iterdir() if p.is_dir()])
        if not dirs:
            sys.exit("no results dirs")
        dir_ = dirs[-1]
    print(f"[rescore] {dir_}", file=sys.stderr)
    rescore_dir(dir_)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
