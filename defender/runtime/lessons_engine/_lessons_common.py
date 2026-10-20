from __future__ import annotations

import argparse
import os
from pathlib import Path

from defender.knowledge._corpus import as_list, iter_lessons
from defender._io import use_utf8_stdio

# No `reexec_into_venv` re-export: this module imports pydantic (via `_corpus`/`_io`), which is
# what the guard exists to avoid, so scripts take it from `defender.execution._venv`.
__all__ = [
    "iter_lessons", "use_utf8_stdio",
    "as_list", "as_str_set", "csv_set", "rel_to_repo", "resolve_corpus",
]


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


def resolve_corpus(
    raw: str | None, default: Path, ap: argparse.ArgumentParser
) -> Path:
    """`--corpus` relocates a corpus walk; it never selects a different corpus."""
    if raw is None:
        return default
    raw = raw.strip()
    if os.path.normpath(raw) == os.curdir:
        ap.error(f"--corpus needs a path to a {default.name!r} directory, not {raw!r}")
    corpus = Path(raw).resolve()
    if corpus.name != default.name:
        ap.error(
            f"--corpus must name a {default.name!r} directory (got {corpus.name!r}); this "
            f"script retrieves {default.name} only"
        )
    return corpus
