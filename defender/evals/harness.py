#!/usr/bin/env python3
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

from _harness_util import init_git

from defender import _git


HERE = Path(__file__).resolve().parent
RESULTS_DIR = HERE / "results"

MANIFEST_SEED = "eval-harness"


@dataclass(frozen=True)
class AuthorRun:

    returncode: int
    stdout: str
    stderr: str


def materialize(scenario: Path, tmp: Path) -> None:
    (tmp / "defender" / "learning" / "_pending").mkdir(parents=True)
    (tmp / "defender" / "lessons").mkdir(parents=True)

    learning_dir = tmp / "defender" / "learning"

    src_findings = scenario / "findings.jsonl"
    if not src_findings.is_file():
        sys.exit(f"scenario missing findings.jsonl: {src_findings}")
    shutil.copy(src_findings, learning_dir / "_pending" / "findings.jsonl")

    src_runs = scenario / "runs"
    if src_runs.is_dir():
        shutil.copytree(src_runs, learning_dir / "runs")

    src_lessons = scenario / "lessons"
    if src_lessons.is_dir():
        for path in src_lessons.glob("*.md"):
            shutil.copy(path, tmp / "defender" / "lessons" / path.name)


def run_author(tmp: Path) -> tuple[AuthorRun, float]:
    from defender.learning.author.lessons import run as author
    from defender.learning.core.config import LoopPaths

    paths = LoopPaths(repo_root=tmp)
    cfg = author.build_author_config(paths, manifest_seed=MANIFEST_SEED)
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

    lessons_out = out / "lessons"
    lessons_out.mkdir()
    for path in (tmp / "defender" / "lessons").glob("*.md"):
        shutil.copy(path, lessons_out / path.name)

    pending_out = out / "_pending"
    pending_out.mkdir()
    for path in (tmp / "defender" / "learning" / "_pending").iterdir():
        if path.is_file():
            shutil.copy(path, pending_out / path.name)

    git_log = _git.git(
        ["log", "--all", "--format=%H %s%n%b%n----"], cwd=tmp, check=False
    )
    (out / "git_log.txt").write_text(git_log, encoding="utf-8")

    (out / "author.stdout").write_text(proc.stdout, encoding="utf-8")
    (out / "author.stderr").write_text(proc.stderr, encoding="utf-8")
    (out / "rc.txt").write_text(str(proc.returncode), encoding="utf-8")

    if wall_seconds is not None:
        effort = os.environ.get("LEARNING_AUTHOR_EFFORT", "(default)")
        (out / "timing.txt").write_text(
            f"wall_seconds={wall_seconds:.1f}\n"
            f"effort={effort}\n", encoding="utf-8"
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
