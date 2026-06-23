"""Shared plumbing for the ``scripts/lessons/`` CLIs.

The three lesson tools (``lessons_fm.py``, ``lessons_actor_index.py``,
``lessons_env_retrieve.py``) each hand-rolled the same venv re-exec dance and
the same handful of frontmatter-coercion helpers. They are collected here once.

Deliberately **pure stdlib at import time** — the module top imports nothing the
defender venv provides (no ``yaml`` / ``defender._frontmatter``). That is what
lets a caller import it *before* :func:`reexec_into_venv` has swapped the
interpreter, on a bare system ``python3`` that has no PyYAML yet. :func:`iter_lessons`
therefore imports the yaml-backed frontmatter parser *lazily*, inside the function.
"""
from __future__ import annotations

import sys
from collections.abc import Callable, Iterator
from pathlib import Path

# Re-exported so the lessons CLIs keep importing it from here unchanged; the
# single implementation now lives in the neutral `defender.scripts._venv`, shared
# with the lessons frontend. Pure stdlib, so importing it stays pre-venv-safe.
from defender.scripts._venv import reexec_into_venv

__all__ = [
    "reexec_into_venv", "iter_lessons",
    "as_list", "as_str_set", "csv_set", "rel_to_repo",
]


def iter_lessons(
    corpus_dir: Path,
    *,
    with_raw: bool = False,
    warn_label: Callable[[Path], str] | None = None,
) -> Iterator[tuple]:
    """Yield well-formed lessons under ``corpus_dir``: ``*.md`` sorted, skipping
    ``_``-prefixed files, warning-and-skipping on malformed frontmatter.

    Yields ``(path, frontmatter)`` by default, or ``(path, raw_frontmatter, fm)``
    when ``with_raw`` (the raw YAML between the fences, for frontmatter grep).
    ``warn_label`` formats the skipped path in the warning (default ``path.name``;
    the actor index passes a repo-relative label). The yaml-backed parser is
    imported lazily so this module stays importable before the venv re-exec.
    """
    from defender._frontmatter import FrontmatterError, parse_frontmatter

    label = warn_label or (lambda p: p.name)
    if not corpus_dir.is_dir():
        return
    for path in sorted(corpus_dir.glob("*.md")):
        if path.name.startswith("_"):
            continue
        text = path.read_text()
        try:
            fm, _body = parse_frontmatter(text)
        except FrontmatterError:
            print(f"warn: skipping {label(path)} (malformed frontmatter)", file=sys.stderr)
            continue
        if with_raw:
            norm = text.replace("\r\n", "\n").replace("\r", "\n")
            raw = norm[4:norm.find("\n---", 4)]  # YAML between the fences
            yield path, raw, fm
        else:
            yield path, fm


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
