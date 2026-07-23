#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from _harness_util import find_venv_py, init_git, run as _run

from defender import _git


HERE = Path(__file__).resolve().parent
REAL_DEFENDER = HERE.parent
REAL_LEARNING = REAL_DEFENDER / "learning"
REAL_REPO_ROOT = REAL_DEFENDER.parent
RESULTS_DIR = HERE / "results_lead"


def materialize(scenario: Path, tmp: Path) -> Path:
    learning_dst = tmp / "defender" / "learning"
    learning_dst.mkdir(parents=True)
    _SKIP = {"__pycache__", "_pending", "_pending_leads", "runs", "frontend", "judge-alignment"}
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
    # Keep the relocated harness self-contained for the changed import boundary.
    shutil.copy(REAL_DEFENDER / "_untrusted.py", tmp / "defender" / "_untrusted.py")

    shutil.copytree(
        REAL_DEFENDER / "skills" / "gather" / "queries",
        tmp / "defender" / "skills" / "gather" / "queries",
    )
    for skill in sorted((REAL_DEFENDER / "skills").glob("*/SKILL.md")):
        dst = tmp / "defender" / "skills" / skill.parent.name / "SKILL.md"
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(skill, dst)

    overlay = scenario / "catalog_overlay"
    if overlay.is_dir():
        shutil.copytree(
            overlay, tmp / "defender" / "skills" / "gather" / "queries",
            dirs_exist_ok=True,
        )

    src_runs = scenario / "run"
    if not src_runs.is_dir():
        sys.exit(f"scenario missing run/: {src_runs}")
    run_ids = [p for p in src_runs.iterdir() if p.is_dir()]
    if len(run_ids) != 1:
        sys.exit(f"scenario run/ must hold exactly one run dir, got {run_ids}")
    run_dst = tmp / "runs" / run_ids[0].name
    shutil.copytree(run_ids[0], run_dst)
    return run_dst


def run_lead_author(tmp: Path, run_dir: Path) -> subprocess.CompletedProcess:
    venv_py = find_venv_py(REAL_REPO_ROOT)
    env = os.environ.copy()
    env["DEFENDER_LEARNING_STATE_DIR"] = str(tmp / "_state")
    return _run(
        [str(venv_py), str(tmp / "defender" / "learning" / "leads" / "lead_author.py"), str(run_dir)],
        cwd=tmp, env=env, check=False,
    )


def _catalog_path(tmp: Path, rel: str) -> Path:
    return tmp / rel


def _verdict(tmp: Path, expect: dict) -> tuple[str, list[str]]:
    notes: list[str] = []
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
        count = _git.git(["rev-list", "--count", "HEAD"], cwd=tmp, check=False)
        ncommits = int(count) if count.isdigit() else 0
        if ncommits >= 2:
            diff = _git.git(["diff", "--name-only", "HEAD~1", "HEAD"], cwd=tmp, check=False)
            touched = widened in diff.split()
            notes.append(f"prefer_widened {'TOUCHED' if touched else 'untouched'}: {widened}")
        else:
            notes.append(f"prefer_widened untouched (no loop commit): {widened}")

    return ("PASS" if draft_gone else "WEAK-PASS"), notes


def capture(tmp: Path, scenario_name: str, proc: subprocess.CompletedProcess,
            verdict: str, notes: list[str]) -> Path:
    ts = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    out = RESULTS_DIR / f"{ts}-{scenario_name}"
    out.mkdir(parents=True, exist_ok=True)
    (out / "lead_author.stdout").write_text(proc.stdout, encoding="utf-8")
    (out / "lead_author.stderr").write_text(proc.stderr, encoding="utf-8")
    (out / "rc.txt").write_text(str(proc.returncode), encoding="utf-8")
    log = _git.git(["log", "--format=%H %s%n%b%n----", "-n", "5"], cwd=tmp, check=False)
    (out / "git_log.txt").write_text(log, encoding="utf-8")
    show = _git.git(["show", "--stat", "HEAD"], cwd=tmp, check=False)
    (out / "head_show.txt").write_text(show, encoding="utf-8")
    (out / "verdict.txt").write_text(verdict + "\n" + "\n".join(notes) + "\n", encoding="utf-8")
    shutil.copytree(
        tmp / "defender" / "skills" / "gather" / "queries",
        out / "catalog_after", dirs_exist_ok=True,
    )
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("scenario", help="path to a scenario dir under scenarios_lead/")
    ap.add_argument("--keep-tmp", action="store_true")
    args = ap.parse_args()

    scenario = Path(args.scenario).resolve()
    if not scenario.is_dir():
        sys.exit(f"scenario not found: {scenario}")
    expect = {}
    if (scenario / "expect.json").is_file():
        expect = json.loads((scenario / "expect.json").read_text(encoding="utf-8"))

    RESULTS_DIR.mkdir(exist_ok=True)
    tmp = Path(tempfile.mkdtemp(prefix=f"leadauthor-eval-{scenario.name}-"))
    if REAL_REPO_ROOT in tmp.resolve().parents:
        shutil.rmtree(tmp, ignore_errors=True)
        sys.exit(f"refusing to run: temp tree {tmp} is inside the repo "
                 f"{REAL_REPO_ROOT} — the agent would edit real files")

    try:
        run_dir = materialize(scenario, tmp)
        init_git(tmp)
        print(f"[harness] running lead-author against {scenario.name}", file=sys.stderr)
        proc = run_lead_author(tmp, run_dir)
        verdict, notes = _verdict(tmp, expect)
        out = capture(tmp, scenario.name, proc, verdict, notes)
        print(f"[harness] rc={proc.returncode}  verdict={verdict}", file=sys.stderr)
        for n in notes:
            print(f"[harness]   - {n}", file=sys.stderr)
        print(f"[harness] results: {out}", file=sys.stderr)
        return 0 if verdict in ("PASS", "WEAK-PASS") else 1
    finally:
        if not args.keep_tmp:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
