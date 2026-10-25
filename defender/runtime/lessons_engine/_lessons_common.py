from __future__ import annotations

import argparse
import os
from pathlib import Path

from defender.knowledge._corpus import as_list, iter_lessons
from defender.knowledge._knowledge import KnowledgePaths
from defender._io import use_utf8_stdio

#: The variable naming the run's agent root (the run copy's `agent/`, `/agent` in a box): every
#: lane hands it to its lessons tools (#1108 P4, O2), and they read no other corpus.
AGENT_DIR_ENV = "DEFENDER_AGENT_DIR"

# No `reexec_into_venv` re-export: this module imports pydantic (via `_corpus`/`_io`), which is
# what the guard exists to avoid, so scripts take it from `defender.execution._venv`.
__all__ = [
    "iter_lessons", "use_utf8_stdio",
    "NoAgentRoot", "as_list", "as_str_set", "csv_set", "rel_to_repo", "resolve_corpus",
    "AGENT_DIR_ENV", "agent_knowledge",
]


class NoAgentRoot(Exception):
    """The lane named no agent root (`DEFENDER_AGENT_DIR` unset or empty)."""


def agent_knowledge(environ: os._Environ[str] | dict[str, str] | None = None) -> KnowledgePaths:
    """The knowledge of the agent root `DEFENDER_AGENT_DIR` names, or `NoAgentRoot`: a lessons
    tool reads its run's corpus and never falls back to another (#1108 P4)."""
    env = os.environ if environ is None else environ
    raw = (env.get(AGENT_DIR_ENV) or "").strip()
    if not raw:
        raise NoAgentRoot(f"{AGENT_DIR_ENV} is not set: no agent root names the lessons to read")
    return KnowledgePaths(Path(raw))


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
