#!/usr/bin/env python3
"""The project profile the spec_graph checks read.

The checks' method is repo-agnostic; where a project keeps its code, what its entrypoints
look like, and what its graph calls things live in the target repo's
`.claude/spec-flow.json`. Missing config is not an error: the defaults below apply, and
`/spec-flow:init` writes the file.
"""
from __future__ import annotations

import functools
import json
import os
import subprocess
from pathlib import Path
from typing import Any

CONFIG_REL = ".claude/spec-flow.json"

# Directory names that are never a project's own source, and are expensive to walk. Bare
# `worktrees` also catches `.claude/worktrees/`: a sibling checkout would otherwise add phantom
# drivers and graphs.
_PRUNE = {
    ".git",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    "worktrees",
    ".worktrees",
    ".mypy_cache",
    ".ruff_cache",
}


@functools.cache
def repo_root(start: Path | None = None) -> Path:
    # `start` anchors the lookup (a suite dir argument may live in another repo than cwd).
    cmd = ["git", "rev-parse", "--show-toplevel"]
    if start is not None:
        cmd[1:1] = ["-C", str(start)]
    out = subprocess.run(
        cmd, capture_output=True, text=True, encoding="utf-8", check=False
    ).stdout.strip()
    if out:
        return Path(out)
    # git could not answer (no git, no `.git`, or a `safe.directory` refusal). Walk up for
    # `.git` rather than returning `start`: anchored callers pass a specs or suite dir, and
    # joining a repo-relative `tests:` onto that would resolve the wrong suite.
    base = (start if start is not None else Path.cwd()).resolve()
    for cand in (base, *base.parents):
        if (cand / ".git").exists():
            return cand
    return base


def _walk(top: Path) -> list[Path]:
    """Every file under `top`, pruning `_PRUNE` dirs during the walk (descending is the cost)."""
    found: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(top):
        dirnames[:] = [d for d in dirnames if d not in _PRUNE]
        found.extend(Path(dirpath) / f for f in filenames)
    return found


def _section(profile: Any, key: str) -> dict[str, Any]:
    """One top-level object of the project profile, or `{}` when it is absent or not a mapping."""
    section = profile.get(key) if isinstance(profile, dict) else None
    return section if isinstance(section, dict) else {}


def load(explicit: str | None = None) -> dict[str, Any]:
    """The `specGraph` section of the project profile, with defaults filled in."""
    path = Path(explicit) if explicit else repo_root() / CONFIG_REL
    raw: dict[str, Any] = {}
    conventions: dict[str, Any] = {}
    if path.is_file():
        profile = json.loads(path.read_text(encoding="utf-8"))
        # Type-checked, not `or {}`: a non-mapping section would raise AttributeError outside
        # the checkers' try blocks. `conventions` is documented as free-form, so may be anything.
        raw = _section(profile, "specGraph")
        conventions = _section(profile, "conventions")
    return {
        # Where the committed spec_graph_*.yaml artifacts live (glob, repo-relative).
        "artifacts": raw.get("artifacts", "**/spec_graph_*.yaml"),
        # The source trees check_actors censuses for execution contexts. Unset = the whole
        # repo minus _PRUNE, which is correct but slow; a real project names its trees.
        "codeRoots": raw.get("codeRoots", []),
        # Stems that are entrypoints in this project even without a `__main__` block.
        "entrypointStems": raw.get("entrypointStems", []),
        # Entrypoint stem → the actor id the graph models it as (graphs name actors
        # semantically, files name them physically).
        "contextAliases": raw.get("contextAliases", {}),
        # Code kwarg name → graph concept name, when the two disagree.
        "conceptAliases": raw.get("conceptAliases", {}),
        # Shared roots for `spec-graph trace resource`: name → {writers, readers, grep},
        # each sink `<file>::<symbol>` (see trace.py's docstring).
        "resources": raw.get("resources", {}),
        # The default `--base` for diff-taking checkers. Read from `conventions`, where the ship
        # skill already keeps it, so there is one spelling. An unresolvable base is a hard error,
        # so repos with another default branch need this.
        "defaultBranch": conventions.get("defaultBranch") or "main",
    }


def _kept(path: Path, root: Path) -> bool:
    """Whether `path` survives pruning.

    Keyed on the path relative to the repo root: an absolute-path check would silently prune
    everything when the checkout itself sits under a matching name (`.worktrees/`, `/srv/tests/`).
    """
    parts = path.relative_to(root).parts
    return not (_PRUNE & set(parts)) and "tests" not in parts[:-1]


def artifacts(cfg: dict[str, Any]) -> list[Path]:
    """The committed spec_graph_*.yaml artifacts — the configured glob, minus prune-listed dirs.

    Pruning matters: work happens in worktrees, so an unpruned glob from the main checkout
    would pick up every sibling branch's graphs.
    """
    root = repo_root()
    return sorted(p for p in root.glob(cfg["artifacts"]) if not _PRUNE & set(p.relative_to(root).parts))


def source_files(cfg: dict[str, Any], suffix: str = ".py") -> list[Path]:
    """Every source file under the configured roots, minus tests and prune-listed dirs."""
    root = repo_root()
    roots = [root / r for r in cfg["codeRoots"]] or [root]
    files: list[Path] = []
    for p in roots:
        if p.is_file():
            files.append(p)
        elif p.is_dir():
            files.extend(f for f in _walk(p) if f.suffix == suffix)
    return [f for f in files if _kept(f, root)]
