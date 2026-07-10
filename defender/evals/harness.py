#!/usr/bin/env python3
"""Run defender/learning/author.py against an isolated scenario.

A scenario directory has this layout:

    scenarios/<name>/
      README.md          # human notes: hypothesis, expected outcome
      findings.jsonl     # the batch the author should consume
      runs/<run_id>/     # source-case context the curator + forward-check read
        investigation.md
        source_refs.yaml
      lessons/           # optional pre-seeded lesson .md files

The harness materializes the scenario into a fresh temp tree shaped
like the real repo, points the author at it, runs it, and copies the
post-run lessons + author logs into ``eval/results/<timestamp>-<scenario>/``.

The curator is driven IN-PROCESS through an injected ``AuthorConfig`` rooted at
the temp tree (``LoopPaths(repo_root=tmp)``) — no entry script is copied and no
subprocess is spawned. It used to copy ``run.py`` / ``verify_forward/forward.py``
into the temp tree purely so the copied entry's ``__file__``-derived ``REPO_ROOT``
landed in tmp; the forward-check is an in-process tool reading its roots off the
curator's deps now (#558), so the injected config does that job directly. Nothing
under the real defender/ is touched.

Hand-eyeball protocol: read ``results/<run>/lessons/`` against the
findings + any pre-seeded lessons; the README.md in the scenario
states what "good" looks like.
"""
from __future__ import annotations

import argparse
import contextlib
import datetime as _dt
import io
import os
import shutil
import sys
import time
from dataclasses import dataclass
from pathlib import Path

# Sibling import — this harness runs as a standalone script, so evals/ is on
# sys.path[0]. Shared with harness_lead.py.
from _harness_util import init_git

from defender import _git  # _harness_util put the repo root on sys.path


HERE = Path(__file__).resolve().parent      # .../defender/evals
RESULTS_DIR = HERE / "results"


@dataclass(frozen=True)
class AuthorRun:
    """One in-process curator drain: what the old subprocess `CompletedProcess` carried."""

    returncode: int
    stdout: str
    stderr: str


def materialize(scenario: Path, tmp: Path) -> None:
    """Build the temp working tree."""
    (tmp / "defender" / "learning" / "_pending").mkdir(parents=True)
    (tmp / "defender" / "lessons").mkdir(parents=True)

    # No entry scripts are copied: the curator runs in-process against an AuthorConfig
    # rooted here, and its forward-check reads the roots off its deps.
    learning_dir = tmp / "defender" / "learning"

    # Copy findings.jsonl.
    src_findings = scenario / "findings.jsonl"
    if not src_findings.is_file():
        sys.exit(f"scenario missing findings.jsonl: {src_findings}")
    shutil.copy(src_findings, learning_dir / "_pending" / "findings.jsonl")

    # Copy runs/.
    src_runs = scenario / "runs"
    if src_runs.is_dir():
        shutil.copytree(src_runs, learning_dir / "runs")

    # Copy pre-seeded lessons.
    src_lessons = scenario / "lessons"
    if src_lessons.is_dir():
        for path in src_lessons.glob("*.md"):
            shutil.copy(path, tmp / "defender" / "lessons" / path.name)


def run_author(tmp: Path) -> tuple[AuthorRun, float]:
    """Drain the scenario's findings with the REAL curator, in-process, against `tmp`.

    `LoopPaths(repo_root=tmp)` roots the corpus, the pending queue and the run bundles in the
    temp tree; `build_author_config` turns that into the `AuthorConfig` the curator's own
    entry point would have built for itself. The curator's stdout/stderr are captured so the
    results dir keeps carrying them."""
    from defender.learning.author.lessons import run as author
    from defender.learning.core.config import LoopPaths

    paths = LoopPaths(repo_root=tmp)
    cfg = author.build_author_config(paths)
    out, err = io.StringIO(), io.StringIO()
    t0 = time.monotonic()
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = author.run_batch(paths=paths, cfg=cfg)
    except Exception as e:  # noqa: BLE001 — an eval harness reports the fault, never re-raises
        rc = 1
        err.write(f"\n{type(e).__name__}: {e}\n")
    return AuthorRun(rc, out.getvalue(), err.getvalue()), time.monotonic() - t0


def capture_results(tmp: Path, scenario_name: str, proc: AuthorRun,
                    wall_seconds: float | None = None) -> Path:
    ts = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    out = RESULTS_DIR / f"{ts}-{scenario_name}"
    out.mkdir(parents=True)

    # Lesson files.
    lessons_out = out / "lessons"
    lessons_out.mkdir()
    for path in (tmp / "defender" / "lessons").glob("*.md"):
        shutil.copy(path, lessons_out / path.name)

    # _pending state (consumed.jsonl, held findings, etc.)
    pending_out = out / "_pending"
    pending_out.mkdir()
    for path in (tmp / "defender" / "learning" / "_pending").iterdir():
        if path.is_file():
            shutil.copy(path, pending_out / path.name)

    # Git log of the scenario commits.
    git_log = _git.git(
        ["log", "--all", "--format=%H %s%n%b%n----"], cwd=tmp, check=False
    )
    (out / "git_log.txt").write_text(git_log)

    # Author stdout/stderr.
    (out / "author.stdout").write_text(proc.stdout)
    (out / "author.stderr").write_text(proc.stderr)
    (out / "rc.txt").write_text(str(proc.returncode))

    if wall_seconds is not None:
        # The per-check verifier timing came from the deleted CLI's `_verify_timing.log`
        # append; in-process the checks are visible in each source bundle's trace instead.
        effort = os.environ.get("LEARNING_AUTHOR_EFFORT", "(default)")
        (out / "timing.txt").write_text(
            f"wall_seconds={wall_seconds:.1f}\n"
            f"effort={effort}\n"
        )

    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("scenario", help="path to scenario dir under scenarios/")
    ap.add_argument("--keep-tmp", action="store_true",
                    help="do not delete the materialized tmp tree")
    args = ap.parse_args()

    scenario = Path(args.scenario).resolve()
    if not scenario.is_dir():
        sys.exit(f"scenario not found: {scenario}")

    RESULTS_DIR.mkdir(exist_ok=True)
    tmp_root = HERE / "_tmp"
    tmp_root.mkdir(exist_ok=True)
    ts = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    tmp = tmp_root / f"{ts}-{scenario.name}"
    tmp.mkdir()

    try:
        materialize(scenario, tmp)
        init_git(tmp)
        effort = os.environ.get("LEARNING_AUTHOR_EFFORT", "(default)")
        print(f"[harness] running author against {scenario.name} effort={effort}",
              file=sys.stderr)
        proc, wall = run_author(tmp)
        out = capture_results(tmp, scenario.name, proc, wall_seconds=wall)
        print(f"[harness] rc={proc.returncode} wall={wall:.1f}s  results: {out}",
              file=sys.stderr)
        return proc.returncode
    finally:
        if not args.keep_tmp:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
