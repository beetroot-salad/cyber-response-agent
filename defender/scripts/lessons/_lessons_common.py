from __future__ import annotations

from pathlib import Path

from defender._corpus import iter_lessons
from defender._io import use_utf8_stdio
from defender.scripts._venv import reexec_into_venv

__all__ = [
    "reexec_into_venv", "iter_lessons", "use_utf8_stdio",
    "as_list", "as_str_set", "csv_set", "rel_to_repo",
]


def as_list(v) -> list:
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def as_str_set(v) -> set[str]:
    return {str(x) for x in as_list(v)}


def csv_set(value: str | None) -> set[str]:
    if not value:
        return set()
    return {t.strip() for t in value.split(",") if t.strip()}


def rel_to_repo(path: Path, repo_root: Path) -> str:
    try:
        return str(path.relative_to(repo_root))
    except ValueError:
        return str(path)
