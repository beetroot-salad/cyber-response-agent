from __future__ import annotations

import argparse
import os
from pathlib import Path

from defender._corpus import iter_lessons
from defender._io import use_utf8_stdio

# No `reexec_into_venv` re-export: this module imports pydantic (via `_corpus`/`_io`), which is
# what the guard exists to avoid, so scripts take it from `defender._venv`.
__all__ = [
    "iter_lessons", "use_utf8_stdio",
    "as_list", "as_str_set", "csv_set", "rel_to_repo", "resolve_corpus",
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


def resolve_corpus(
    raw: str | None, default: Path, ap: argparse.ArgumentParser
) -> Path:
    """`--corpus` relocates a corpus walk; it never selects a different corpus.

    Shared by every script taking `--corpus`. Legitimate relocations (a forward-check worktree,
    a test fixture) change the root but not the corpus, so the rule is the leaf name.
    (`lessons_fm.cmd_show` contains a lesson path with its own `relative_to` check.)

    The check lives here, not in the permission gate, because these scripts are pinned grants
    and pinned grants are argv-blind (`docs/runtime-gates.md`); without it a role could point a
    script at a corpus `decide_read` denies it.

    The path is resolved before the name test, so a symlink or `..` cannot disguise another
    corpus. Any spelling of the CWD (`""`, `.`, `x/..` — folded by `os.path.normpath`, unlike
    `Path`) is refused rather than tested by whatever the CWD happens to be called. The operand
    is stripped once, before both tests.
    """
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
