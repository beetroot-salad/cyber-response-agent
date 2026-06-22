#!/usr/bin/env python3
"""Run defender/learning/lead_author.py against an isolated scenario.

Sibling to ``harness.py`` (which exercises the *lessons* curator,
``author.py``); this one exercises the **lead-author** — the curator that
folds executed gather queries into the query-template catalog. It exists to
test the anti-**underfolding** behaviour: when gather coins a query that is
really a *narrowing* of an existing wide/superset template, the lead-author
must discard-into-widen (or skip), never promote a narrow sibling.

A scenario directory:

    scenarios_lead/<name>/
      README.md          # hypothesis + what "good" looks like (human notes)
      expect.json        # machine verdict (see _verdict)
      run/<run_id>/
        executed_queries.jsonl                 # the QUERIES table
        gather_raw/<lead_id>.lead.json         # the LEADS table
        gather_raw/<lead_id>/<seq>.json        # by-ref payloads
      catalog_overlay/   # optional: extra/override {system}/*.md templates

The harness materializes a fresh temp repo (the real learning/ scripts +
the real query catalog + per-system SKILL.md), overlays the scenario, git
commits a baseline, runs the lead-author tick, and evaluates ``expect.json``.

The lead-author spawns ``claude -p`` (subscription — it strips
ANTHROPIC_API_KEY itself), so this is a live, non-deterministic agent run:
treat the verdict as one sample, not a unit test. Re-run for confidence.
"""
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

# Sibling import — this harness runs as a standalone script, so eval/ is on
# sys.path[0]. Shared with harness.py.
from _harness_util import find_venv_py, init_git, run as _run


HERE = Path(__file__).resolve().parent
REAL_LEARNING = HERE.parent                 # .../defender/learning
REAL_DEFENDER = REAL_LEARNING.parent        # .../defender
REAL_REPO_ROOT = REAL_DEFENDER.parent       # workspace root (worktree)
RESULTS_DIR = HERE / "results_lead"


def materialize(scenario: Path, tmp: Path) -> Path:
    """Build the temp working tree; return the scenario's run_dir inside it."""
    learning_dst = tmp / "defender" / "learning"
    learning_dst.mkdir(parents=True)
    # Copy the learning scripts + prompts (top-level files only — the agent
    # needs lead_author.{py,md} and its imported sibling modules). Copying,
    # not symlinking, so lead_author's REPO_ROOT = parents[2] lands in tmp.
    for path in sorted(REAL_LEARNING.glob("*.py")):
        shutil.copy(path, learning_dst / path.name)
    for path in sorted(REAL_LEARNING.glob("*.md")):
        shutil.copy(path, learning_dst / path.name)

    # The real query catalog (the thing under curation).
    shutil.copytree(
        REAL_DEFENDER / "skills" / "gather" / "queries",
        tmp / "defender" / "skills" / "gather" / "queries",
    )
    # Per-system SKILL.md (lift targets + reference the agent may read).
    for skill in sorted((REAL_DEFENDER / "skills").glob("*/SKILL.md")):
        dst = tmp / "defender" / "skills" / skill.parent.name / "SKILL.md"
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(skill, dst)

    # Optional catalog overlay (add/override templates for the scenario).
    overlay = scenario / "catalog_overlay"
    if overlay.is_dir():
        shutil.copytree(
            overlay, tmp / "defender" / "skills" / "gather" / "queries",
            dirs_exist_ok=True,
        )

    # The run dir (the two tables). Copy under tmp so payload refs resolve.
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
    # Keep the lead-author's mutable queue/lock state out of the repo tree so
    # the post-flight clean-tree check isn't tripped by lock files.
    env["DEFENDER_LEARNING_STATE_DIR"] = str(tmp / "_state")
    # Pin the validated model unless the caller overrode it in the environment
    # (env already carries any inherited LEAD_AUTHOR_MODEL via the copy above).
    env.setdefault("LEAD_AUTHOR_MODEL", "claude-sonnet-4-6")
    return _run(
        [str(venv_py), str(tmp / "defender" / "learning" / "lead_author.py"), str(run_dir)],
        cwd=tmp, env=env, check=False,
    )


def _catalog_path(tmp: Path, rel: str) -> Path:
    # expect.json paths are repo-relative (defender/skills/...); resolve in tmp.
    return tmp / rel


def _verdict(tmp: Path, expect: dict) -> tuple[str, list[str]]:
    """Evaluate the scenario's expectations against the post-run tree.

    Verdict levels:
      FAIL        — a forbidden narrow sibling was promoted (the underfold).
      PASS        — no forbidden promotion; the coined draft was discarded.
      WEAK-PASS   — no forbidden promotion, but the draft was left in place
                    (skip) rather than folded — acceptable, not ideal.
    """
    notes: list[str] = []
    # 1) The forbidden promotion(s) must not exist as established templates.
    for rel in expect.get("forbid_promoted", []):
        if _catalog_path(tmp, rel).exists():
            notes.append(f"UNDERFOLD: promoted narrow sibling exists: {rel}")
            return "FAIL", notes

    # 2) Was the coined draft discarded (good) or left behind (weak)?
    draft_rel = expect.get("synthesized_draft")
    draft_gone = draft_rel is not None and not _catalog_path(tmp, draft_rel).exists()
    if draft_rel is None:
        notes.append("no synthesized_draft declared; promotion-only check")
        return "PASS", notes
    if draft_gone:
        notes.append(f"draft discarded: {draft_rel}")
    else:
        notes.append(f"draft left in place (skip): {draft_rel}")

    # 3) Did the agent widen the preferred wide template? (informational.)
    widened = expect.get("prefer_widened")
    if widened:
        # Only meaningful when the agent actually committed: a no-edit/skip run
        # leaves HEAD at the baseline, so HEAD~1 doesn't exist (git errors, empty
        # stdout) and we'd mislabel it "untouched". Gate on a second commit, and
        # match the path exactly against the name-only lines (not a substring,
        # which a longer sibling path would spuriously satisfy).
        count = _run(["git", "rev-list", "--count", "HEAD"], cwd=tmp, check=False)
        ncommits = int(count.stdout.strip()) if count.stdout.strip().isdigit() else 0
        if ncommits >= 2:
            diff = _run(["git", "diff", "--name-only", "HEAD~1", "HEAD"], cwd=tmp, check=False)
            touched = widened in diff.stdout.split()
            notes.append(f"prefer_widened {'TOUCHED' if touched else 'untouched'}: {widened}")
        else:
            notes.append(f"prefer_widened untouched (no agent commit): {widened}")

    return ("PASS" if draft_gone else "WEAK-PASS"), notes


def capture(tmp: Path, scenario_name: str, proc: subprocess.CompletedProcess,
            verdict: str, notes: list[str]) -> Path:
    ts = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    out = RESULTS_DIR / f"{ts}-{scenario_name}"
    # exist_ok: re-running the same scenario inside one wall-clock second (the
    # README invites "re-run for confidence", and a skip run returns sub-second)
    # collides on the second-resolution timestamp dir — don't lose the result.
    out.mkdir(parents=True, exist_ok=True)
    (out / "lead_author.stdout").write_text(proc.stdout)
    (out / "lead_author.stderr").write_text(proc.stderr)
    (out / "rc.txt").write_text(str(proc.returncode))
    log = _run(["git", "log", "--format=%H %s%n%b%n----", "-n", "5"], cwd=tmp, check=False)
    (out / "git_log.txt").write_text(log.stdout)
    show = _run(["git", "show", "--stat", "HEAD"], cwd=tmp, check=False)
    (out / "head_show.txt").write_text(show.stdout)
    (out / "verdict.txt").write_text(verdict + "\n" + "\n".join(notes) + "\n")
    # Snapshot the post-run catalog so the disposition is inspectable.
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
        expect = json.loads((scenario / "expect.json").read_text())

    RESULTS_DIR.mkdir(exist_ok=True)
    # Materialize OUTSIDE the repo. `claude -p` resolves relative tool paths and
    # `git` against the project root it discovers by walking up from cwd — so a
    # temp tree nested inside this repo makes the agent edit/commit the REAL repo
    # instead of the sandbox. A system-temp dir (its own git repo, no enclosing
    # one) keeps the agent's writes contained.
    tmp = Path(tempfile.mkdtemp(prefix=f"leadauthor-eval-{scenario.name}-"))
    if REAL_REPO_ROOT in tmp.resolve().parents:
        shutil.rmtree(tmp, ignore_errors=True)
        sys.exit(f"refusing to run: temp tree {tmp} is inside the repo "
                 f"{REAL_REPO_ROOT} — the agent would edit real files")

    try:
        run_dir = materialize(scenario, tmp)
        init_git(tmp)
        # Sanity: the driver synthesizes the draft before spawning the agent.
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
