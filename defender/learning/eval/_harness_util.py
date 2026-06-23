"""Shared scaffolding for the eval harnesses (`harness.py` + `harness_lead.py`).

Both build a tmp scenario tree, init a throwaway git repo in it, and shell out to
the author venv. The subprocess wrapper, the git baseline, and the venv probe are
collected here. `materialize` / `capture` stay per-harness — those copy genuinely
different fixtures per scenario family.

Imported sibling-style (`from _harness_util import ...`): both harnesses run as
standalone scripts (`python defender/learning/eval/harness*.py`) and never import
the `defender.*` package, so `eval/` is on `sys.path[0]`.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


def run(cmd: list[str], cwd: Path, env: dict | None = None,
        input_: str | None = None, check: bool = True) -> subprocess.CompletedProcess:
    """`subprocess.run` with capture+text. `input_` feeds stdin (the lead harness
    never uses it, so it defaults to None — a superset of both old copies)."""
    return subprocess.run(
        cmd, cwd=cwd, env=env, input=input_,
        capture_output=True, text=True, check=check,
    )


def init_git(tmp: Path) -> None:
    """git-init a throwaway repo and commit the scenario baseline, so the author's
    `git status --porcelain` sees a clean tree (the symlinks the harness lays down
    would otherwise show as untracked)."""
    run(["git", "init", "-q", "-b", "main"], cwd=tmp)
    run(["git", "config", "user.email", "eval@local"], cwd=tmp)
    run(["git", "config", "user.name", "eval"], cwd=tmp)
    run(["git", "add", "-A"], cwd=tmp)
    run(["git", "commit", "-q", "-m", "scenario baseline"], cwd=tmp)


def find_venv_py(repo_root: Path) -> Path:
    """The author venv python: `$LEARNING_VERIFIER_PYTHON`, else walk up from
    `repo_root`. A git worktree has no `.venv` of its own, so the interpreter
    lives in the main checkout's `defender/.venv`; the `workspace/` probe covers
    the canonical host layout. (Superset of the two old copies' candidate lists.)"""
    env = os.environ.get("LEARNING_VERIFIER_PYTHON")
    if env:
        return Path(env).resolve()
    candidates = [repo_root / "defender" / ".venv" / "bin" / "python3"]
    p = repo_root.parent
    for _ in range(6):
        candidates.append(p / "defender" / ".venv" / "bin" / "python3")
        candidates.append(p / "workspace" / "defender" / ".venv" / "bin" / "python3")
        if p.parent == p:
            break
        p = p.parent
    for c in candidates:
        if c.is_file():
            return c
    sys.exit(f"no defender venv found; tried {candidates}")
