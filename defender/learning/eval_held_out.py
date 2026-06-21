#!/usr/bin/env python3
"""Primary-metric harness: score defender held-out runs against ground truth.

Walks a runs directory (default ``$DEFENDER_RUNS_BASE`` or
``/tmp/defender-runs``), keeps only runs whose ``ground_truth.yaml``
declares ``held_out: true``, and reports defender disposition correctness.

Failure accounting per design doc §Metrics: a run that fails to produce a
parseable ``report.md`` (missing, frontmatter unparseable, disposition not
in the closed enum, or a runtime crash that aborted the run) counts as
**wrong** against the ground-truth class. Excluding failures would let
regressions hide behind crashes.

Usage:
  python3 defender/learning/eval_held_out.py [<runs_dir>]
"""
from __future__ import annotations

import argparse
import os
import sys
from collections import defaultdict
from pathlib import Path

import yaml

# Put the workspace root on sys.path so the `defender.*` namespace import below
# resolves whether this file is imported or run directly (see tests/conftest.py).
if (_root := str(Path(__file__).resolve().parents[2])) not in sys.path:
    sys.path.insert(0, _root)

from defender._frontmatter import parse_frontmatter_or_none

DISPOSITION_ENUM = {"benign", "inconclusive", "malicious"}


def parse_frontmatter(report_path: Path) -> dict | None:
    """Return the YAML frontmatter as a dict, or None if unparseable/missing."""
    if not report_path.is_file():
        return None
    return parse_frontmatter_or_none(report_path.read_text())


def predicted_disposition(run_dir: Path) -> str | None:
    fm = parse_frontmatter(run_dir / "report.md")
    if fm is None:
        return None
    disp = fm.get("disposition")
    if disp in DISPOSITION_ENUM:
        return disp
    return None


def held_out_runs(runs_dir: Path) -> list[Path]:
    out = []
    for child in sorted(runs_dir.iterdir()):
        if not child.is_dir():
            continue
        gt = child / "ground_truth.yaml"
        if not gt.is_file():
            continue
        doc = yaml.safe_load(gt.read_text()) or {}
        if isinstance(doc, dict) and doc.get("held_out") is True:
            out.append(child)
    return out


def report(runs_dir: Path) -> int:
    runs = held_out_runs(runs_dir)
    if not runs:
        print(f"no held-out runs found under {runs_dir}", file=sys.stderr)
        return 1

    by_class: dict[str, list[tuple[str, str | None, str]]] = defaultdict(list)
    failures: list[tuple[str, str]] = []
    for run_dir in runs:
        gt_doc = yaml.safe_load((run_dir / "ground_truth.yaml").read_text())
        true_disp = gt_doc.get("disposition")
        pred = predicted_disposition(run_dir)
        verdict = "ok" if pred == true_disp else "wrong"
        if pred is None:
            failures.append((run_dir.name, "no parseable report.md"))
        by_class[true_disp].append((run_dir.name, pred, verdict))

    total = sum(len(v) for v in by_class.values())
    correct = sum(1 for v in by_class.values() for _, _, vd in v if vd == "ok")
    print(f"# Held-out eval — {total} runs, {len(failures)} failure(s)")
    print()
    print(f"Aggregate accuracy: {correct}/{total} = {correct / total:.1%}")
    print()
    for cls in sorted(by_class):
        items = by_class[cls]
        cls_correct = sum(1 for _, _, vd in items if vd == "ok")
        print(f"## class={cls}  recall={cls_correct}/{len(items)} = "
              f"{cls_correct / len(items):.1%}")
        for name, pred, vd in items:
            tag = "OK   " if vd == "ok" else "WRONG"
            print(f"  {tag}  {name}: predicted={pred!r}")
        print()
    if failures:
        print("## Failure bucket (counted wrong, surfaced separately)")
        for name, reason in failures:
            print(f"  {name}: {reason}")
    return 0


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    default = os.environ.get("DEFENDER_RUNS_BASE", "/tmp/defender-runs")
    p.add_argument("runs_dir", nargs="?", default=default,
                   help=f"directory of run dirs (default: {default})")
    ns = p.parse_args(argv)
    runs_dir = Path(ns.runs_dir)
    if not runs_dir.is_dir():
        print(f"runs dir does not exist: {runs_dir}", file=sys.stderr)
        return 2
    return report(runs_dir)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
