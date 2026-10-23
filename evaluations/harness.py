#!/usr/bin/env python3
from __future__ import annotations

import argparse
import contextlib
import dataclasses
import datetime as _dt
import io
import logging
import os
import shutil
import sys
import time
import uuid
from pathlib import Path
from typing import Any

from _harness_util import LocalTenant

from defender import _git
from defender._model import model

_logger = logging.getLogger(__name__)


HERE = Path(__file__).resolve().parent
RESULTS_DIR = HERE / "results"

MANIFEST_SEED = "eval-harness"
#: The branch prefix the author lane's batches take (the author drain's).
AUTHOR_BRANCH_PREFIX = "lessons/"


@model(frozen=True)
class AuthorRun:

    returncode: int
    stdout: str
    stderr: str


def _agent_source(tmp: Path) -> Path:
    return tmp / "agent-source" / "agent"


def _state_dir(tmp: Path) -> Path:
    return tmp / "learning"


def materialize(scenario: Path, tmp: Path) -> None:
    """The scenario as a tenant's agent root (`agent-source/agent/`: the two author corpora,
    seeded with the scenario's lessons) and the learning state its queue sits in
    (`learning/_pending/findings.jsonl`, the scenario's findings; `runs/` beside it)."""
    agent = _agent_source(tmp)
    for corpus in ("lessons", "lessons-questioner"):
        (agent / corpus).mkdir(parents=True)
    learning_dir = _state_dir(tmp)
    (learning_dir / "_pending").mkdir(parents=True)

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
            shutil.copy(path, agent / "lessons" / path.name)


def run_author(tmp: Path, *, invoke_agent: Any = None) -> tuple[AuthorRun, float]:
    """One lessons-author batch over a tenant draft (#1108 P4 O7): the materialized agent root
    as a local tenant's one commit, a batch started on it, the REAL author run into the batch's
    draft (`invoke_agent` replaces only the model spawn), and the batch delivered to the fake
    forge. The authored lessons and the tenant clone stay under `tmp` for `capture_results`."""
    from defender.learning.author.lessons import run as author
    from defender.learning.core.config import AUTHOR_DRAIN_LABEL, LoopPaths
    from defender.learning.core.lane_trees import open_drain_trees
    from defender.learning.core.state import LearningState, StateRefused

    tenant = LocalTenant(tmp, _agent_source(tmp))
    paths = LoopPaths(repo_root=tmp, state_dir=_state_dir(tmp))
    out, err = io.StringIO(), io.StringIO()
    t0 = time.monotonic()
    try:
        delivery = tenant.delivery(AUTHOR_BRANCH_PREFIX)
        batch = delivery.start_batch(f"evals-{uuid.uuid4().hex[:12]}",
                                     lanes=AUTHOR_DRAIN_LABEL.lanes)
        try:
            with LearningState.open(paths) as state, \
                    open_drain_trees(paths, AUTHOR_DRAIN_LABEL, batch=batch) as trees:
                cfg = author.build_author_config(
                    paths, state=state, trees=trees, manifest_seed=MANIFEST_SEED, batch=batch)
                if invoke_agent is not None:
                    cfg = dataclasses.replace(cfg, invoke_agent=invoke_agent)
                with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                    rc = author.run_batch(paths=paths, state=state, cfg=cfg, batch=batch)
            shutil.copytree(Path(batch.draft_root) / "agent" / "lessons", tmp / "authored-lessons")
            delivered = delivery.finish(batch)
            out.write(f"\ndelivery: {delivered.status}\n")
        finally:
            batch.discard()
    # `StateRefused` is named: it is not an `Exception`, and the harness reports it too.
    except (Exception, StateRefused) as e:  # noqa: BLE001 — an eval harness reports the fault, never re-raises
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
    for path in (tmp / "authored-lessons").glob("*.md"):
        shutil.copy(path, lessons_out / path.name)

    pending_out = out / "_pending"
    pending_out.mkdir()
    for path in (_state_dir(tmp) / "_pending").iterdir():
        if path.is_file():
            shutil.copy(path, pending_out / path.name)

    clone = tmp / "data"
    clones = [p.parent for p in clone.glob("*/knowledge/.git")]
    git_log = _git.git(
        ["log", "--all", "--format=%H %s%n%b%n----"], cwd=clones[0], check=False
    ) if clones else ""
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
        effort = os.environ.get("LEARNING_AUTHOR_EFFORT", "(default)")
        _logger.info(f"running author against {scenario.name} effort={effort}")
        proc, wall = run_author(tmp)
        out = capture_results(tmp, scenario.name, proc, wall_seconds=wall)
        _logger.info(f"rc={proc.returncode} wall={wall:.1f}s  results: {out}")
        return proc.returncode
    finally:
        if not args.keep_tmp:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    from defender._log import configure_from_env
    configure_from_env()
    sys.exit(main())
