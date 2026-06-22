"""Shared plumbing for the ``scripts/lessons/`` CLIs.

The three lesson tools (``lessons_fm.py``, ``lessons_actor_index.py``,
``lessons_env_retrieve.py``) each hand-rolled the same venv re-exec dance and
the same handful of frontmatter-coercion helpers. They are collected here once.

Deliberately **pure stdlib** — it imports nothing that the defender venv
provides (no ``yaml`` / ``defender._frontmatter``). That is what lets a caller
import it *before* :func:`reexec_into_venv` has had a chance to swap the
interpreter, on a bare system ``python3`` that has no PyYAML yet.

Each ``iter_lessons`` stays local to its module — the three have genuinely
divergent signatures (fixed root vs. ``corpus`` arg vs. a 3-tuple yielding raw
frontmatter text), so only the leaf coercions are shared.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path


def reexec_into_venv(script: str) -> None:
    """Re-exec the current process under ``defender/.venv``'s python.

    PyYAML lives only in the defender venv, but these CLIs are reachable with
    the system ``python3`` (the actor's Bash tool, a bare
    ``python3 defender/scripts/lessons/…`` run). Call this from a script's
    ``__main__`` guard, before importing any venv-only dependency.

    A no-op when the venv python is missing (e.g. CI without a bootstrapped
    venv) or already the running interpreter (e.g. the ``bin/`` shim, which
    execs the venv python directly) — so it never double-execs.
    """
    venv_py = Path(script).resolve().parents[3] / "defender" / ".venv" / "bin" / "python3"
    if venv_py.is_file() and Path(sys.executable) != venv_py:
        os.execv(str(venv_py), [str(venv_py), str(script), *sys.argv[1:]])


def as_list(v) -> list:
    """Coerce a scalar/list/None frontmatter value to a list (None → [])."""
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def as_str_set(v) -> set[str]:
    """``as_list`` then stringify into a set — for disjoint/membership tests."""
    return {str(x) for x in as_list(v)}


def csv_set(value: str | None) -> set[str]:
    """Split a ``--flag a,b,c`` CLI value into a set of trimmed, non-empty tokens."""
    if not value:
        return set()
    return {t.strip() for t in value.split(",") if t.strip()}


def rel_to_repo(path: Path, repo_root: Path) -> str:
    """``path`` relative to ``repo_root`` for display; the absolute path if outside it."""
    try:
        return str(path.relative_to(repo_root))
    except ValueError:
        return str(path)
