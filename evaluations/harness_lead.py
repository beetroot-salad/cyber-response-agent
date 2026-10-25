#!/usr/bin/env python3
from __future__ import annotations

import argparse
import contextlib
import dataclasses
import datetime as _dt
import io
import json
import logging
import shutil
import sys
import tempfile
import uuid
from pathlib import Path

from _harness_util import LocalTenant

from defender import _git
from defender.knowledge._knowledge import KnowledgePaths
from defender._io import read_text_utf8

_logger = logging.getLogger(__name__)


HERE = Path(__file__).resolve().parent
REAL_DEFENDER = HERE.parent / "defender"
REAL_LEARNING = REAL_DEFENDER / "learning"
REAL_REPO_ROOT = REAL_DEFENDER.parent
RESULTS_DIR = HERE / "results_lead"
#: The agent root an eval tenant starts from unless `--agent` names another (a lab tenant's
#: `agent/`): the tenant template's (#1108 P4 O1: the catalog is a tenant's, never the
#: product's).
TEMPLATE_AGENT = REAL_REPO_ROOT / "knowledge" / "tenant-template" / "agent"
#: The branch prefix the lead lane's batches take (the lead-author drain's).
LEAD_BRANCH_PREFIX = "lead-author/"


def _agent_source(tmp: Path) -> Path:
    return tmp / "agent-source" / "agent"


def materialize(scenario: Path, tmp: Path, *, agent: Path = TEMPLATE_AGENT) -> Path:
    """The scenario's tree: the learning code relocated under `tmp/defender` (with the shared
    frame module it imports), the eval tenant's agent root `agent-source/agent/` (`agent`, its
    catalog overlaid with the scenario's `catalog_overlay/`), and the scenario's one run under
    `runs/`, whose folder is returned."""
    learning_dst = tmp / "defender" / "learning"
    learning_dst.mkdir(parents=True)
    _SKIP = {"__pycache__", "_pending", "_pending_leads", "runs", "frontend"}
    for path in sorted(REAL_LEARNING.rglob("*")):
        if path.suffix not in (".py", ".md"):
            continue
        rel = path.relative_to(REAL_LEARNING)
        if set(rel.parts) & _SKIP:
            continue
        dst = learning_dst / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(path, dst)

    # The copied learning tree imports this shared frame primitive directly.
    shutil.copy(REAL_DEFENDER / "_untrusted.py", tmp / "defender" / "_untrusted.py")

    source = _agent_source(tmp)
    shutil.copytree(agent, source, ignore=shutil.ignore_patterns(".tenant-id", ".git"))
    overlay = scenario / "catalog_overlay"
    if overlay.is_dir():
        shutil.copytree(overlay, KnowledgePaths(agent_root=source).catalog_dir,
                        dirs_exist_ok=True)

    src_runs = scenario / "run"
    if not src_runs.is_dir():
        sys.exit(f"scenario missing run/: {src_runs}")
    run_ids = [p for p in src_runs.iterdir() if p.is_dir()]
    if len(run_ids) != 1:
        sys.exit(f"scenario run/ must hold exactly one run dir, got {run_ids}")
    run_dst = tmp / "runs" / run_ids[0].name
    shutil.copytree(run_ids[0], run_dst)
    return run_dst


@dataclasses.dataclass(frozen=True)
class LeadRun:
    returncode: int
    stdout: str
    stderr: str
    #: The batch branch's commits past its base, oldest first (`[]`: nothing committed).
    commits: tuple[str, ...] = ()


def run_lead_author(tmp: Path, run_dir: Path) -> LeadRun:
    """One lead-author claim over a tenant draft (#1108 P4 O7): the materialized agent root as a
    local tenant's one commit, a batch started on it, the REAL lead author serving `run_dir`
    into the batch's draft, and the batch delivered to the fake forge. The draft's tree after
    the claim is kept as `tmp/after/` (the root `expect.json`'s `agent/...` paths name)."""
    from defender.learning.core.config import LEAD_AUTHOR_DRAIN_LABEL, LoopPaths
    from defender.learning.leads.lead_author import run
    from defender.run_repository import Run

    tenant = LocalTenant(tmp, _agent_source(tmp))
    paths = LoopPaths(repo_root=REAL_REPO_ROOT, state_dir=tmp / "_state")
    (tmp / "_state").mkdir(exist_ok=True)  # lint-unguarded-tree-write: ok — eval scratch dir; the handle never creates its root
    out, err = io.StringIO(), io.StringIO()
    commits: tuple[str, ...] = ()
    try:
        delivery = tenant.delivery(LEAD_BRANCH_PREFIX)
        batch = delivery.start_batch(f"evals-{uuid.uuid4().hex[:12]}",
                                     lanes=LEAD_AUTHOR_DRAIN_LABEL.lanes)
        try:
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                rc = run(Run.at(run_dir), label=LEAD_AUTHOR_DRAIN_LABEL, paths=paths,
                         batch=batch)
            shutil.copytree(Path(batch.draft_root) / "agent", tmp / "after" / "agent")
            tip = _git.git(["rev-parse", "--verify", "-q", f"refs/heads/{batch.branch}"],
                           cwd=tenant.clone, check=False)
            if tip:
                listed = _git.git(["rev-list", "--reverse", f"{batch.export.commit}..{tip}"],
                                  cwd=tenant.clone, check=False)
                commits = tuple(listed.split())
            out.write(f"\ndelivery: {delivery.finish(batch).status}\n")
        finally:
            batch.discard()
    except Exception as e:  # noqa: BLE001 — an eval harness reports the fault, never re-raises
        rc = 1
        err.write(f"\n{type(e).__name__}: {e}\n")
    return LeadRun(rc, out.getvalue(), err.getvalue(), commits)


def _catalog_path(tmp: Path, rel: str) -> Path:
    """`rel` (repo-relative, `agent/...`) in the draft's tree after the claim."""
    return tmp / "after" / rel


def _touched(tmp: Path, commits: tuple[str, ...]) -> set[str]:
    clones = [p.parent for p in (tmp / "data").glob("*/knowledge/.git")]
    if not clones or not commits:
        return set()
    shown = _git.git(["show", "--no-renames", "--name-only", "--format=", *commits],
                     cwd=clones[0], check=False)
    return {line for line in shown.splitlines() if line}


def _verdict(tmp: Path, expect: dict, proc: LeadRun) -> tuple[str, list[str]]:
    notes: list[str] = []
    if not (tmp / "after").is_dir():
        return "ERROR", [f"the claim left no draft tree to judge (rc={proc.returncode}; see stderr)"]
    for rel in expect.get("forbid_promoted", []):
        if _catalog_path(tmp, rel).exists():
            notes.append(f"UNDERFOLD: promoted narrow sibling exists: {rel}")
            return "FAIL", notes

    draft_rel = expect.get("synthesized_draft")
    draft_gone = draft_rel is not None and not _catalog_path(tmp, draft_rel).exists()
    if draft_rel is None:
        notes.append("no synthesized_draft declared; promotion-only check")
        return "PASS", notes
    if draft_gone:
        notes.append(f"draft discarded: {draft_rel}")
    else:
        notes.append(f"draft left in place (skip): {draft_rel}")

    widened = expect.get("prefer_widened")
    if widened:
        if proc.commits:
            touched = widened in _touched(tmp, proc.commits)
            notes.append(f"prefer_widened {'TOUCHED' if touched else 'untouched'}: {widened}")
        else:
            notes.append(f"prefer_widened untouched (no loop commit): {widened}")

    return ("PASS" if draft_gone else "WEAK-PASS"), notes


def capture(tmp: Path, scenario_name: str, proc: LeadRun,
            verdict: str, notes: list[str]) -> Path:
    ts = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    out = RESULTS_DIR / f"{ts}-{scenario_name}"
    out.mkdir(parents=True, exist_ok=True)
    (out / "lead_author.stdout").write_text(proc.stdout, encoding="utf-8")  # lint-run-records: ok — the lead-author role/drain/module's own name, not the `lead_author/` record dir
    (out / "lead_author.stderr").write_text(proc.stderr, encoding="utf-8")  # lint-run-records: ok — the lead-author role/drain/module's own name, not the `lead_author/` record dir
    (out / "rc.txt").write_text(str(proc.returncode), encoding="utf-8")
    clones = [p.parent for p in (tmp / "data").glob("*/knowledge/.git")]
    if clones and proc.commits:
        log = _git.git(["log", "--format=%H %s%n%b%n----", "-n", "5", proc.commits[-1]],
                       cwd=clones[0], check=False)
        show = _git.git(["show", "--stat", proc.commits[-1]], cwd=clones[0], check=False)
    else:
        log = show = "(no commit)\n"
    (out / "git_log.txt").write_text(log, encoding="utf-8")
    (out / "head_show.txt").write_text(show, encoding="utf-8")
    (out / "verdict.txt").write_text(verdict + "\n" + "\n".join(notes) + "\n", encoding="utf-8")
    after = KnowledgePaths(agent_root=tmp / "after" / "agent").catalog_dir
    if after.is_dir():
        shutil.copytree(after, out / "catalog_after", dirs_exist_ok=True)
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("scenario", help="path to a scenario dir under scenarios_lead/")
    ap.add_argument("--agent", type=Path, default=TEMPLATE_AGENT,
                    help="the agent root the eval tenant starts from (default: the tenant "
                         "template's); its catalog is what the lead author curates")
    ap.add_argument("--keep-tmp", action="store_true")
    args = ap.parse_args()

    scenario = Path(args.scenario).resolve()
    if not scenario.is_dir():
        sys.exit(f"scenario not found: {scenario}")
    expect = {}
    if (scenario / "expect.json").is_file():
        expect = json.loads(read_text_utf8(scenario / "expect.json"))

    RESULTS_DIR.mkdir(exist_ok=True)
    tmp = Path(tempfile.mkdtemp(prefix=f"leadauthor-eval-{scenario.name}-"))
    if REAL_REPO_ROOT in tmp.resolve().parents:
        shutil.rmtree(tmp, ignore_errors=True)
        sys.exit(f"refusing to run: temp tree {tmp} is inside the repo "
                 f"{REAL_REPO_ROOT} — the agent would edit real files")

    try:
        run_dir = materialize(scenario, tmp, agent=args.agent.resolve())
        _logger.info(f"running lead-author against {scenario.name}")
        proc = run_lead_author(tmp, run_dir)
        verdict, notes = _verdict(tmp, expect, proc)
        out = capture(tmp, scenario.name, proc, verdict, notes)
        _logger.info(f"rc={proc.returncode}  verdict={verdict}", extra={"notes": notes})
        _logger.info(f"results: {out}")
        return 0 if verdict in ("PASS", "WEAK-PASS") else 1
    finally:
        if not args.keep_tmp:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    from defender._log import configure_from_env
    configure_from_env()
    sys.exit(main())
