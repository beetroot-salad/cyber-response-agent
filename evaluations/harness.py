#!/usr/bin/env python3
from __future__ import annotations

import argparse
import contextlib
import dataclasses
import datetime as _dt
import io
import json
import logging
import os
import shutil
import sys
import time
import uuid
from pathlib import Path
from typing import Any

from evaluations._harness_util import LocalTenant

from defender import _git
from defender._model import model
# The branch prefix the author lane's batches take (the author drain's: delivery's own).
from defender.learning.author.version_control.delivery import (
    LESSONS_BRANCH_PREFIX as AUTHOR_BRANCH_PREFIX,
)

_logger = logging.getLogger(__name__)


HERE = Path(__file__).resolve().parent
RESULTS_DIR = HERE / "results"

MANIFEST_SEED = "eval-harness"


@model(frozen=True)
class AuthorRun:

    returncode: int
    stdout: str
    stderr: str


def _agent_source(tmp: Path) -> Path:
    return tmp / "agent-source" / "agent"


def _state_dir(tmp: Path) -> Path:
    """The learning state the scenario's queue sits in: where a checkout keeps it
    (`defender/learning/`), so the scenario tree reads as before; it holds no corpus."""
    return tmp / "defender" / "learning"


def materialize(scenario: Path, tmp: Path) -> None:
    """The scenario as a tenant's agent root (`agent-source/agent/`: the two author corpora,
    seeded with the scenario's lessons) and the learning state its queue sits in
    (`defender/learning/_pending/findings.jsonl`, the scenario's findings; `runs/` beside
    it)."""
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


def _scenario_items(tmp: Path) -> list[tuple[str, str, dict[str, Any]]]:
    """The scenario's findings as a learning store claim's items (`(kind, key, payload)`, #1278
    D1), in queue order; a row with no `finding_id` is handed under a key of its own so the
    author's own rule judges it."""
    rows = [json.loads(line) for line in
            (_state_dir(tmp) / "_pending" / "findings.jsonl").read_text(encoding="utf-8").splitlines()
            if line.strip()]
    return [("finding", str(row.get("finding_id") or f"row-{i}"), row) for i, row in enumerate(rows)]


def run_author(tmp: Path, *, invoke_agent: Any = None) -> tuple[AuthorRun, float]:
    """One lessons-author batch over a tenant draft (#1108 P4 O7): the materialized agent root
    as a local tenant's one commit, a batch started on it, the REAL author run into the batch's
    draft over the scenario's findings as the claim's items (`invoke_agent` replaces only the
    model spawn), and the batch delivered to the fake forge. The authored lessons, the tenant
    clone and the items' fates (`fates.json`) stay under `tmp` for `capture_results`."""
    from defender.learning.author.lessons import run as author
    from defender.learning.core.config import AUTHOR_DRAIN_LABEL, LoopPaths
    from defender.learning.core.lane_trees import open_drain_trees

    tenant = LocalTenant(tmp, _agent_source(tmp))
    paths = LoopPaths(repo_root=tmp, state_dir=_state_dir(tmp))
    out, err = io.StringIO(), io.StringIO()
    t0 = time.monotonic()
    try:
        items = _scenario_items(tmp)
        outcomes: dict[tuple[str, str], Any] = {}
        delivery = tenant.delivery(AUTHOR_BRANCH_PREFIX)
        batch = delivery.start_batch(f"evals-{uuid.uuid4().hex[:12]}",
                                     lanes=AUTHOR_DRAIN_LABEL.lanes)
        try:
            with open_drain_trees(paths, AUTHOR_DRAIN_LABEL, batch=batch) as trees:
                cfg = author.build_author_config(
                    paths, trees=trees, manifest_seed=MANIFEST_SEED, batch=batch)
                if invoke_agent is not None:
                    cfg = dataclasses.replace(cfg, invoke_agent=invoke_agent)
                with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                    rc = author.run_batch(paths=paths, cfg=cfg, batch=batch,
                                          items=items, outcomes=outcomes)
            shutil.copytree(Path(batch.draft_root) / "agent" / "lessons", tmp / "authored-lessons")
            (tmp / "fates.json").write_text(json.dumps(  # lint-unguarded-tree-write: ok — eval scratch dir
                {f"{kind}:{key}": {"fate": fate.name, "reason": fate.reason}
                 for (kind, key), fate in outcomes.items()}, indent=2),
                encoding="utf-8")
            delivered = delivery.finish(batch)
            out.write(f"\ndelivery: {delivered.status}\n")
        finally:
            batch.discard()
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
    for path in (tmp / "authored-lessons").glob("*.md"):
        shutil.copy(path, lessons_out / path.name)

    pending_out = out / "_pending"
    pending_out.mkdir()
    for path in (_state_dir(tmp) / "_pending").iterdir():
        if path.is_file():
            shutil.copy(path, pending_out / path.name)
    if (tmp / "fates.json").is_file():
        shutil.copy(tmp / "fates.json", out / "fates.json")

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
