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

from pathlib import Path

# Re-exported so the lessons CLIs keep importing it from here unchanged; the
# single implementation now lives in the neutral `defender.scripts._venv`, shared
# with the lessons frontend. Pure stdlib, so importing it stays pre-venv-safe.
from defender.scripts._venv import reexec_into_venv

__all__ = ["reexec_into_venv", "as_list", "as_str_set", "csv_set", "rel_to_repo"]


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
