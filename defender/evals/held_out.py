#!/usr/bin/env python3
"""Primary-metric harness: score defender held-out runs against ground truth.

Walks the FIXTURE set (``defender/fixtures/held-out/``), locates each fixture's run
under the runs dir (``$DEFENDER_RUNS_BASE``, or the ``runs_dir`` argument) by run-id
convention, and reports defender disposition correctness.

**Ground truth never leaves this repo's fixture dirs.** The eval owns the labels and
reads them where they live; nothing is copied into a run dir, which is inside the
agent's own readable workspace. The direction matters: this walks fixtures and looks
for runs, not runs and looks for labels. That is what lets the run dir carry no
provenance back to its fixture and no answer key.

Launch the runs this scores with (see ``index_runs``)::

    python3 defender/run.py defender/fixtures/held-out/<slug>/alert.json \\
        --run-id <slug> --no-learn

``--no-learn`` keeps a scored run out of the learning corpora; ``run_common
.enqueue_learning`` independently refuses held-out fixtures as a fail-closed net.

Failure accounting per design doc §Metrics: a run that fails to produce a
parseable ``report.md`` (missing, frontmatter unparseable, disposition not
in the closed enum, or a runtime crash that aborted the run) counts as
**wrong** against the ground-truth class. Excluding failures would let
regressions hide behind crashes.

Usage:
  python3 defender/evals/held_out.py [<runs_dir>]
"""
from __future__ import annotations

import argparse
import sys
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

import yaml

if (_root := str(Path(__file__).resolve().parents[2])) not in sys.path:
    sys.path.insert(0, _root)

from defender._yaml import safe_load
from defender._frontmatter import parse_frontmatter_or_none
from defender._io import read_text_soft
from defender._run_paths import RunPaths
from defender.learning.core.config import DISPOSITION_ENUM
from defender.run_common import HELD_OUT_FIXTURES as FIXTURES_DIR, resolve_runs_base


def _read_frontmatter(report_path: Path) -> dict | None:
    if not report_path.is_file():
        return None
    text, _reason = read_text_soft(report_path)
    if text is None:
        return None
    return parse_frontmatter_or_none(text)


def predicted_disposition(run_dir: Path) -> str | None:
    fm = _read_frontmatter(RunPaths(run_dir).report)
    if fm is None:
        return None
    disp = fm.get("disposition")
    if disp in DISPOSITION_ENUM:
        return disp
    return None


@dataclass
class HeldOutAlert:
    slug: str
    alert_path: Path
    ground_truth: dict


def load_held_out_fixtures(fixtures_dir: Path) -> list[HeldOutAlert]:
    out: list[HeldOutAlert] = []
    for child in sorted(fixtures_dir.iterdir()):
        if not child.is_dir():
            continue
        alert = RunPaths(child).alert
        gt = child / "ground_truth.yaml"
        if not gt.is_file():
            continue
        if not alert.is_file():
            print(f"warn: {child.name}: labeled held-out fixture has no {alert.name} "
                  f"— excluded from the eval set", file=sys.stderr)
            continue
        try:
            gt_doc = safe_load(gt.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError as e:
            print(f"warn: {child.name}: unparseable ground_truth.yaml ({e}) — fixture skipped",
                  file=sys.stderr)
            continue
        if not isinstance(gt_doc, dict) or gt_doc.get("held_out") is not True:
            continue
        out.append(HeldOutAlert(child.name, alert, gt_doc))
    return out


def warn_if_outside_the_net(fixtures_dir: Path) -> bool:
    if fixtures_dir.resolve() == FIXTURES_DIR.resolve():
        return False
    print(f"WARNING: scoring {fixtures_dir}, but the enqueue-time contamination net only "
          f"refuses runs from {FIXTURES_DIR} — runs of these fixtures were NOT held out "
          f"of learning unless they were launched with --no-learn", file=sys.stderr)
    return True


def _claimed_slug(name: str, slugs: list[str]) -> str | None:
    claims = [s for s in slugs
              if name == s or name.startswith(f"{s}-") or name.endswith(f"-{s}")]
    return max(claims, key=len) if claims else None


def index_runs(slugs: list[str], runs_dir: Path) -> dict[str, Path]:
    best: dict[str, tuple[float, str, Path]] = {}
    if not runs_dir.is_dir():
        return {}
    for d in runs_dir.iterdir():
        try:
            if not d.is_dir():
                continue
            slug = _claimed_slug(d.name, slugs)
            if slug is None:
                continue
            key = (d.stat().st_mtime, d.name)
        except OSError as e:
            print(f"warn: {d.name}: unreadable run dir ({e}) — skipped", file=sys.stderr)
            continue
        prior = best.get(slug)
        if prior is None or key > prior[:2]:
            best[slug] = (*key, d)
    return {slug: v[2] for slug, v in best.items()}


@dataclass
class Scored:

    by_class: dict[str, list[tuple[str, str | None, str]]]
    failures: list[tuple[str, str]]
    not_run: list[str]

    @property
    def total(self) -> int:
        return sum(len(v) for v in self.by_class.values())

    @property
    def correct(self) -> int:
        return sum(1 for v in self.by_class.values() for _, _, vd in v if vd == "ok")


def score(fixtures: list[HeldOutAlert], runs_dir: Path) -> Scored:
    by_class: dict[str, list[tuple[str, str | None, str]]] = defaultdict(list)
    failures: list[tuple[str, str]] = []
    not_run: list[str] = []
    runs = index_runs([fx.slug for fx in fixtures], runs_dir)
    for fx in fixtures:
        run_dir = runs.get(fx.slug)
        if run_dir is None:
            not_run.append(fx.slug)
            continue
        true_disp = str(fx.ground_truth.get("disposition") or "?")
        pred = predicted_disposition(run_dir)
        verdict = "ok" if pred == true_disp else "wrong"
        if pred is None:
            failures.append((fx.slug, "no parseable report.md"))
        by_class[true_disp].append((fx.slug, pred, verdict))
    return Scored(by_class, failures, not_run)


def report(runs_dir: Path, fixtures_dir: Path = FIXTURES_DIR) -> int:
    fixtures = load_held_out_fixtures(fixtures_dir)
    if not fixtures:
        print(f"no held-out fixtures found under {fixtures_dir}", file=sys.stderr)
        return 1
    warn_if_outside_the_net(fixtures_dir)

    scored = score(fixtures, runs_dir)
    print(f"# Held-out eval — {scored.total}/{len(fixtures)} fixtures scored, "
          f"{len(scored.failures)} failure(s)")
    print()
    if not scored.total:
        print(f"no runs found under {runs_dir} for any held-out fixture", file=sys.stderr)
        print("Aggregate accuracy: n/a — nothing scored")
    else:
        print(f"Aggregate accuracy: {scored.correct}/{scored.total} = "
              f"{scored.correct / scored.total:.1%}")
    print()
    for cls in sorted(scored.by_class):
        items = scored.by_class[cls]
        cls_correct = sum(1 for _, _, vd in items if vd == "ok")
        print(f"## class={cls}  recall={cls_correct}/{len(items)} = "
              f"{cls_correct / len(items):.1%}")
        for name, pred, vd in items:
            tag = "OK   " if vd == "ok" else "WRONG"
            print(f"  {tag}  {name}: predicted={pred!r}")
        print()
    if scored.failures:
        print("## Failure bucket (counted wrong, surfaced separately)")
        for name, reason in scored.failures:
            print(f"  {name}: {reason}")
        print()
    if scored.not_run:
        print("## Not run (no matching run dir — coverage gap, excluded from accuracy)")
        for slug in scored.not_run:
            print(f"  {slug}")
    return 0 if scored.total else 1


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    default = str(resolve_runs_base())
    p.add_argument("runs_dir", nargs="?", default=default,
                   help=f"directory of run dirs (default: {default})")
    p.add_argument("--fixtures-dir", type=Path, default=FIXTURES_DIR,
                   help=f"held-out fixtures dir (default: {FIXTURES_DIR})")
    ns = p.parse_args(argv)
    runs_dir = Path(ns.runs_dir)
    if not runs_dir.is_dir():
        print(f"runs dir does not exist: {runs_dir}", file=sys.stderr)
        return 2
    return report(runs_dir, ns.fixtures_dir)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
