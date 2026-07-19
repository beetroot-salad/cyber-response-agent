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

# Put the workspace root on sys.path so the `defender.*` namespace import below
# resolves whether this file is imported or run directly (see tests/conftest.py).
if (_root := str(Path(__file__).resolve().parents[2])) not in sys.path:
    sys.path.insert(0, _root)

from defender._yaml import safe_load
from defender._frontmatter import parse_frontmatter_or_none
from defender._io import read_text_soft
from defender._run_paths import RunPaths
from defender.learning.core.config import DISPOSITION_ENUM
from defender.run_common import HELD_OUT_FIXTURES as FIXTURES_DIR, resolve_runs_base


def _read_frontmatter(report_path: Path) -> dict | None:
    """Return the YAML frontmatter as a dict, or None if unreadable/unparseable/missing.

    Soft read: an unreadable or undecodable report counts as unparseable (None),
    per the "unparseable counts as wrong" accounting above — a crash would abort
    the whole eval instead of scoring the run.
    """
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
    """The labeled held-out fixtures, read from the FIXTURE dir.

    The label never leaves this directory — see the module docstring. Lives here
    (the primary metric) and is imported by ``secondary.py``, which already depends
    on this module for ``predicted_disposition``; one fixture walk, one direction.
    """
    out: list[HeldOutAlert] = []
    for child in sorted(fixtures_dir.iterdir()):
        if not child.is_dir():
            continue
        alert = RunPaths(child).alert
        gt = child / "ground_truth.yaml"
        if not gt.is_file():
            continue  # an unlabeled dir is simply not part of the held-out set
        if not alert.is_file():
            # LABELED but unrunnable. Never silent: dropping it would shrink the
            # denominator, and a shrinking denominator is how a stable-looking score
            # hides a case that has gone missing (the same reason `score` surfaces
            # un-run fixtures instead of omitting them).
            print(f"warn: {child.name}: labeled held-out fixture has no {alert.name} "
                  f"— excluded from the eval set", file=sys.stderr)
            continue
        try:
            gt_doc = safe_load(gt.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError as e:
            # One corrupt ground_truth.yaml must cost that one fixture, not the whole
            # eval (#613; the #595 walk-survival class).
            print(f"warn: {child.name}: unparseable ground_truth.yaml ({e}) — fixture skipped",
                  file=sys.stderr)
            continue
        if not isinstance(gt_doc, dict) or gt_doc.get("held_out") is not True:
            continue
        out.append(HeldOutAlert(child.name, alert, gt_doc))
    return out


def warn_if_outside_the_net(fixtures_dir: Path) -> bool:
    """Warn when ``fixtures_dir`` is not the set the contamination net actually refuses.

    ``run_common.enqueue_learning`` refuses exactly ONE directory — the constant both
    metrics default to. An operator who points a harness elsewhere (``--fixtures-dir`` /
    ``--fixtures``) gets those fixtures SCORED but never got them REFUSED, so their
    findings may already have taught the corpus they are being measured against. Shared by
    both metrics; returns whether it warned.
    """
    if fixtures_dir.resolve() == FIXTURES_DIR.resolve():
        return False
    print(f"WARNING: scoring {fixtures_dir}, but the enqueue-time contamination net only "
          f"refuses runs from {FIXTURES_DIR} — runs of these fixtures were NOT held out "
          f"of learning unless they were launched with --no-learn", file=sys.stderr)
    return True


def _claimed_slug(name: str, slugs: list[str]) -> str | None:
    """The one fixture slug a run dir named ``name`` belongs to, or None.

    A run dir claims a slug only when the slug is ANCHORED at one end of the name, at a
    `-` boundary: the whole name (``--run-id <slug>``), a prefix (``<slug>-<attempt>``), or
    a suffix (``{utc_timestamp}-<slug>``, the shape ``materialize_run_dir`` mints when no
    ``--run-id`` is passed). A slug buried in the MIDDLE does not count — that is what
    keeps the secondary harness's own run dirs (``sec-eval-gen{N}-<slug>-<attempt>`` and
    its ``-replay`` staging twin, which share this runs base by default) from being scored
    as the primary metric's answer for that fixture.

    When several slugs anchor the same name the LONGEST wins, so a fixture set holding
    both ``m05-lsass-access`` and ``m05-lsass-access-v2`` resolves each run to the fixture
    it actually came from instead of to whichever was tried first.
    """
    claims = [s for s in slugs
              if name == s or name.startswith(f"{s}-") or name.endswith(f"-{s}")]
    return max(claims, key=len) if claims else None


def index_runs(slugs: list[str], runs_dir: Path) -> dict[str, Path]:
    """Map each fixture slug to its most recent run dir, in ONE pass over ``runs_dir``.

    Runs are located by NAME, not by any artifact inside the run dir — the run dir carries
    no provenance back to its fixture, deliberately (see the module docstring). Launch
    held-out runs as::

        python3 defender/run.py defender/fixtures/held-out/<slug>/alert.json \\
            --run-id <slug> --no-learn

    Most recent by mtime, ties broken by name, so re-running a fixture scores the latest
    attempt rather than an arbitrary one. One pass rather than a scan per fixture: the
    default runs base accumulates every run ever made and is never pruned, so a per-fixture
    scan is O(fixtures x runs) of iterdir + stat for a result one sweep already has.

    Survives a runs dir mutating underneath it — a dir unlinked between the listing and its
    ``stat`` costs that one candidate, not the whole eval (the #595 walk-survival class the
    fixture walk above already honors for a corrupt label).
    """
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
    """One scoring pass: rows by true class, the failure bucket, and the coverage gap."""

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
            # Surfaced, NOT scored: an un-attempted fixture is a coverage gap, not a
            # wrong answer. Counting it wrong would invent a failure; dropping it
            # silently would let a shrinking denominator pass for a stable score.
            not_run.append(fx.slug)
            continue
        # "?" (not None): a missing disposition still needs a printable, sortable class key.
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
