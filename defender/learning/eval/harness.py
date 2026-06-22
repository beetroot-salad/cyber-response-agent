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

The author's ``REPO_ROOT`` is computed from the script's own file
location, so the harness symlinks the real ``author.py`` /
``verify_forward.py`` (and prompts) into the temp tree's
``defender/learning/`` and runs that copy. Nothing under the real
defender/ is touched.

Hand-eyeball protocol: read ``results/<run>/lessons/`` against the
findings + any pre-seeded lessons; the README.md in the scenario
states what "good" looks like.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import os
import shutil
import subprocess
import sys
from pathlib import Path

# Sibling import — this harness runs as a standalone script, so eval/ is on
# sys.path[0]. Shared with harness_lead.py.
from _harness_util import find_venv_py, init_git, run as _run


HERE = Path(__file__).resolve().parent
REAL_LEARNING = HERE.parent  # .../defender/learning
REAL_REPO_ROOT = REAL_LEARNING.parents[1]  # workspace root (worktree)
RESULTS_DIR = HERE / "results"

# Files the temp tree needs as symlinks into the real script set.
LEARNING_LINKS = [
    "author.py",
    "author.md",
    "verify_forward.py",
    "verify_forward.md",
]


def materialize(scenario: Path, tmp: Path) -> None:
    """Build the temp working tree."""
    (tmp / "defender" / "learning" / "_pending").mkdir(parents=True)
    (tmp / "defender" / "lessons").mkdir(parents=True)

    # Copy learning scripts + prompts. Symlinks would break author.py's
    # REPO_ROOT computation (Path(__file__).resolve() follows the symlink).
    learning_dir = tmp / "defender" / "learning"
    for name in LEARNING_LINKS:
        shutil.copy(REAL_LEARNING / name, learning_dir / name)

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


def run_author(tmp: Path) -> tuple[subprocess.CompletedProcess, float]:
    venv_py = find_venv_py(REAL_REPO_ROOT)
    env = os.environ.copy()
    env["LEARNING_VERIFIER_PYTHON"] = str(venv_py)
    env["VERIFY_TIMING_LOG"] = str(tmp / "_verify_timing.log")
    import time
    t0 = time.monotonic()
    proc = _run(
        [str(venv_py), str(tmp / "defender" / "learning" / "author.py")],
        cwd=tmp, env=env, check=False,
    )
    return proc, time.monotonic() - t0


def capture_results(tmp: Path, scenario_name: str,
                    proc: subprocess.CompletedProcess,
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
    log_proc = _run(
        ["git", "log", "--all", "--format=%H %s%n%b%n----"],
        cwd=tmp, check=False,
    )
    (out / "git_log.txt").write_text(log_proc.stdout)

    # Author stdout/stderr.
    (out / "author.stdout").write_text(proc.stdout)
    (out / "author.stderr").write_text(proc.stderr)
    (out / "rc.txt").write_text(str(proc.returncode))

    if wall_seconds is not None:
        effort = os.environ.get("LEARNING_AUTHOR_EFFORT", "(default)")
        verifier_log = tmp / "_verify_timing.log"
        verifier_text = verifier_log.read_text() if verifier_log.is_file() else ""
        verifier_total = sum(
            float(line.split()[-1])
            for line in verifier_text.splitlines() if line.strip()
        )
        (out / "timing.txt").write_text(
            f"wall_seconds={wall_seconds:.1f}\n"
            f"verifier_seconds={verifier_total:.1f}\n"
            f"curator_seconds={wall_seconds - verifier_total:.1f}\n"
            f"effort={effort}\n"
            f"verifier_calls:\n{verifier_text}"
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
