#!/usr/bin/env python3
"""Run one author_actor trial against the synthetic fixture.

Per-trial flow:
  1. Reset a dedicated git worktree to a fixture-baseline commit
     (a commit that contains the synthetic fixture pre-staged at
     defender/learning/_pending/ and defender/lessons-actor/).
  2. Overlay the variant prompt file (current.md or verbose.md) on top
     of defender/learning/author_actor.md.
  3. Invoke author_actor.py with LEARNING_AUTHOR_ACTOR_MODEL set.
  4. Capture: AUTHOR_RESULT, HEAD sha, lessons-actor commit diff,
     final lessons-actor state, rotated queue + consumed file, runner
     log. Snapshot into out_dir.
  5. Reset the worktree for the next trial.

The fixture-baseline commit is built one-shot via setup_baseline().

Run:
  python3 harness.py --variant current --model sonnet --trial 1 \
      --worktree /tmp/exp-actor-author/current \
      --out experiments/actor-author-discipline/runs/exp1-current/trial-1
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
EXP_DIR = Path(__file__).resolve().parent
FIXTURE_DIR = EXP_DIR / "fixtures"
VARIANTS_DIR = EXP_DIR / "variants"


def sh(cmd: list[str], cwd: Path, check: bool = True, capture: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd, cwd=cwd, check=check, text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
    )


def setup_baseline(worktree: Path, base_branch: str) -> str:
    """Ensure the worktree exists, branched off base_branch, with the
    fixture committed as a single baseline commit. Returns the baseline
    sha so trials can reset to it."""
    if not worktree.exists():
        wt_branch = f"exp-actor-author-{worktree.name}"
        sh(
            ["git", "worktree", "add", "-B", wt_branch, str(worktree), base_branch],
            cwd=REPO_ROOT,
        )

    # Wipe lessons-actor + pending, repopulate from fixture
    lessons_dst = worktree / "defender" / "lessons-actor"
    pending_dst = worktree / "defender" / "learning" / "_pending"
    if lessons_dst.exists():
        shutil.rmtree(lessons_dst)
    shutil.copytree(FIXTURE_DIR / "lessons-actor", lessons_dst)
    pending_dst.mkdir(parents=True, exist_ok=True)
    # Clear any stale queue / consumed history from prior trials
    for f in [
        "actor_observations.jsonl",
        "actor_observations.consumed.jsonl",
        "author_actor_run.jsonl",
    ]:
        p = pending_dst / f
        if p.exists():
            p.unlink()
    shutil.copy2(
        FIXTURE_DIR / "_pending" / "actor_observations.jsonl",
        pending_dst / "actor_observations.jsonl",
    )

    # Stage the synthetic source bundles inside the worktree at a
    # stable path so source_run_dir resolves. The queue rows use
    # "experiments/actor-author-discipline/fixtures/runs/{run_id}",
    # a repo-relative path that exists in the worktree because the
    # experiments/ dir is committed.
    runs_dst = (
        worktree
        / "experiments"
        / "actor-author-discipline"
        / "fixtures"
        / "runs"
    )
    runs_dst.parent.mkdir(parents=True, exist_ok=True)
    if runs_dst.exists():
        shutil.rmtree(runs_dst)
    shutil.copytree(FIXTURE_DIR / "runs", runs_dst)

    sh(["git", "add", "-A"], cwd=worktree)
    # Allow empty if nothing changed since last setup
    r = sh(
        ["git", "commit", "-m", "fixture baseline (experiment harness)"],
        cwd=worktree, check=False,
    )
    if r.returncode != 0 and "nothing to commit" not in (r.stdout or "") + (r.stderr or ""):
        raise SystemExit(f"baseline commit failed: {r.stderr}")

    return sh(["git", "rev-parse", "HEAD"], cwd=worktree).stdout.strip()


def reset_to_baseline(worktree: Path, baseline_sha: str) -> None:
    sh(["git", "reset", "--hard", baseline_sha], cwd=worktree)
    sh(["git", "clean", "-fd"], cwd=worktree)


def overlay_variant(worktree: Path, variant: str) -> None:
    src = VARIANTS_DIR / f"{variant}.md"
    dst = worktree / "defender" / "learning" / "author_actor.md"
    shutil.copy2(src, dst)
    sh(["git", "add", str(dst)], cwd=worktree)
    sh(
        ["git", "commit", "-m", f"overlay variant: {variant}"],
        cwd=worktree, check=False,
    )


def run_author(worktree: Path, model: str, log_file: Path) -> tuple[int, str, str]:
    """Run author_actor.py. Returns (returncode, stdout, stderr)."""
    env = os.environ.copy()
    env["LEARNING_AUTHOR_ACTOR_MODEL"] = model
    # Defensive: tight timeout so a hung run doesn't block the trial.
    env.setdefault("LEARNING_AUTHOR_ACTOR_TIMEOUT_SECONDS", "1500")
    venv_py = REPO_ROOT / "defender" / ".venv" / "bin" / "python3"
    if not venv_py.is_file():
        raise SystemExit(f"defender venv not found at {venv_py}")
    cmd = [str(venv_py), "defender/learning/author_actor.py"]
    with log_file.open("w") as fh:
        proc = subprocess.Popen(
            cmd, cwd=worktree, env=env,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )
        out_lines: list[str] = []
        assert proc.stdout is not None
        for line in proc.stdout:
            fh.write(line)
            fh.flush()
            out_lines.append(line)
        rc = proc.wait()
    return rc, "".join(out_lines), ""


def snapshot(worktree: Path, baseline_sha: str, out_dir: Path) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    head = sh(["git", "rev-parse", "HEAD"], cwd=worktree).stdout.strip()
    moved = head != baseline_sha
    snap: dict = {"baseline_sha": baseline_sha, "head_sha": head, "head_moved": moved}

    if moved:
        msg = sh(["git", "log", "-1", "--format=%B", head], cwd=worktree).stdout
        diff = sh(
            ["git", "show", "--stat", "--format=", head], cwd=worktree
        ).stdout
        files = sh(
            ["git", "diff", "--name-only", baseline_sha, head], cwd=worktree
        ).stdout.strip().splitlines()
        (out_dir / "commit_message.txt").write_text(msg)
        (out_dir / "commit_stat.txt").write_text(diff)
        (out_dir / "commit_files.txt").write_text("\n".join(files) + "\n")
        snap["touched_files"] = files

    # Snapshot final lessons-actor state
    lessons_dst = out_dir / "lessons-actor-final"
    if lessons_dst.exists():
        shutil.rmtree(lessons_dst)
    shutil.copytree(
        worktree / "defender" / "lessons-actor", lessons_dst,
        ignore=shutil.ignore_patterns(".*"),
    )

    # Snapshot rotated queue + consumed
    pending = worktree / "defender" / "learning" / "_pending"
    pending_dst = out_dir / "_pending-final"
    pending_dst.mkdir(exist_ok=True)
    for name in [
        "actor_observations.jsonl",
        "actor_observations.consumed.jsonl",
        "author_actor_run.jsonl",
    ]:
        src = pending / name
        if src.exists():
            shutil.copy2(src, pending_dst / name)

    return snap


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--variant", required=True, choices=["current", "verbose"])
    ap.add_argument("--model", required=True, choices=["sonnet", "haiku"])
    ap.add_argument("--trial", type=int, required=True)
    ap.add_argument("--worktree", required=True, help="dedicated worktree path")
    ap.add_argument("--base-branch", default="actor-pending-queue")
    ap.add_argument("--out", required=True, help="output dir for this trial")
    args = ap.parse_args()

    model_id = {
        "sonnet": "claude-sonnet-4-6",
        "haiku": "claude-haiku-4-5",
    }[args.model]

    worktree = Path(args.worktree).resolve()
    out_dir = Path(args.out).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    baseline_sha = setup_baseline(worktree, args.base_branch)
    reset_to_baseline(worktree, baseline_sha)
    overlay_variant(worktree, args.variant)
    overlay_sha = sh(["git", "rev-parse", "HEAD"], cwd=worktree).stdout.strip()

    log_file = out_dir / "harness_stdout.log"
    t0 = time.monotonic()
    rc, stdout, stderr = run_author(worktree, model_id, log_file)
    elapsed = time.monotonic() - t0

    snap = snapshot(worktree, overlay_sha, out_dir)
    snap.update({
        "variant": args.variant,
        "model": args.model,
        "model_id": model_id,
        "trial": args.trial,
        "rc": rc,
        "elapsed_seconds": round(elapsed, 1),
        "overlay_sha": overlay_sha,
    })
    (out_dir / "snapshot.json").write_text(json.dumps(snap, indent=2) + "\n")

    print(json.dumps(snap, indent=2))
    return rc


if __name__ == "__main__":
    sys.exit(main())
