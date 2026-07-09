"""Resolve the python interpreter the curators' forward-check subprocesses run under.

The four lesson curators build a ``python3 <verify_forward-script>`` bash grant; that
interpreter must have ``pyyaml`` available, which lives only in ``defender/.venv``. This
resolution discipline is shared so every curator (lessons / actor / env) inherits the same
rules regardless of which checkout — main or a throwaway batch worktree — it runs from.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path


def resolve_verifier_python(repo_root: Path) -> Path:
    """Locate a python interpreter that has pyyaml available.

    Preference order: env override → ``defender/.venv/bin/python3`` next
    to repo root → walking up the parents (so a git-worktree without its
    own venv resolves to the parent checkout's) → ``sys.executable``.

    The ``$LEARNING_VERIFIER_PYTHON`` override read here is deliberately NOT shared
    with the eval harness's ``_harness_util.find_venv_py``: that module runs
    standalone and never imports ``defender.*`` (see its docstring), and its walk is
    a documented superset. The env var has no default literal, so there is no
    duplicated-default divergence (cf. #449) to collapse.
    """
    env = os.environ.get("LEARNING_VERIFIER_PYTHON")
    if env:
        return Path(env).resolve()
    candidates = [repo_root / "defender" / ".venv" / "bin" / "python3"]
    p = repo_root.resolve().parent
    for _ in range(5):
        cand = p / "defender" / ".venv" / "bin" / "python3"
        if cand.is_file():
            candidates.append(cand)
        if p.parent == p:
            break
        p = p.parent
    for c in candidates:
        if c.is_file():
            # Do NOT resolve() — venv launchers are typically symlinks
            # that point to the system interpreter, but pyyaml lives in
            # the venv's site-packages reachable only via the venv path.
            return c
    return Path(sys.executable)
