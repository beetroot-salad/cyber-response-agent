#!/usr/bin/env python3
"""The project profile the spec_graph checks read.

The checks are the mechanical half of the write-tests gate, and the *method* they
implement is repo-agnostic: a demand's prose must not thread a concept its `binds` omits
(check_binds), and every execution context that drives the change must be modelled as an
actor (check_actors). What is NOT repo-agnostic is where a project keeps its code, what
its entrypoints look like, and what its graph calls things — so those live here, in the
target repo's `.claude/spec-flow.json`, not in the checks.

Missing config is not an error: the defaults below are the "unconfigured repo" reading,
and every field can be overridden. `/spec-flow:init` writes the file.
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

CONFIG_REL = ".claude/spec-flow.json"

# Directories that are never a project's own source, and are expensive to walk.
_PRUNE = {".git", ".venv", "venv", "node_modules", "__pycache__", ".worktrees", ".mypy_cache", ".ruff_cache"}


def repo_root() -> Path:
    out = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"], capture_output=True, text=True, check=False
    ).stdout.strip()
    return Path(out) if out else Path.cwd()


def load(explicit: str | None = None) -> dict[str, Any]:
    """The `specGraph` section of the project profile, with defaults filled in."""
    path = Path(explicit) if explicit else repo_root() / CONFIG_REL
    raw: dict[str, Any] = {}
    if path.is_file():
        raw = json.loads(path.read_text()).get("specGraph", {}) or {}
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
    }


def artifacts(cfg: dict[str, Any]) -> list[Path]:
    root = repo_root()
    return sorted(root.glob(cfg["artifacts"]))


def source_files(cfg: dict[str, Any], suffix: str = "*.py") -> list[Path]:
    """Every source file under the configured roots, minus tests and prune-listed dirs.

    Pruning is keyed on the path RELATIVE to the repo root: an absolute-path check would
    prune the entire repo whenever the checkout itself sits under a prune-listed name
    (a git worktree under `.worktrees/`, a clone under `node_modules/`).
    """
    root = repo_root()
    roots = [root / r for r in cfg["codeRoots"]] or [root]
    files: list[Path] = []
    for p in roots:
        if p.is_file():
            files.append(p)
        elif p.is_dir():
            files.extend(f for f in p.rglob(suffix) if not _PRUNE & set(f.relative_to(root).parts))
    return [f for f in files if "/tests/" not in str(f)]
