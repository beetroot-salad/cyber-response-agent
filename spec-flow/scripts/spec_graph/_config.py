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

import functools
import json
import os
import subprocess
from pathlib import Path
from typing import Any

CONFIG_REL = ".claude/spec-flow.json"

# Directory names that are never a project's own source, and are expensive to walk. `worktrees`
# is bare on purpose: it has to catch both `.worktrees/` and Claude Code's `.claude/worktrees/`,
# and a sibling checkout under either is a whole second copy of the repo — its files would enter
# the census as phantom drivers and its graphs as phantom artifacts.
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
    # `start` anchors the lookup at an explicitly-given path (a suite dir passed as an
    # argument may live in a different repo than the process cwd); default stays cwd.
    cmd = ["git", "rev-parse", "--show-toplevel"]
    if start is not None:
        cmd[1:1] = ["-C", str(start)]
    out = subprocess.run(
        cmd, capture_output=True, text=True, encoding="utf-8", check=False
    ).stdout.strip()
    if out:
        return Path(out)
    # git could not answer — no git on PATH, an exported tree with no `.git`, or a
    # `safe.directory` dubious-ownership refusal in CI. Walk up for the marker rather than
    # handing back `start` itself: every anchored caller passes a SPECS or SUITE directory, and
    # a repo-relative `tests:` joined onto that resolves the suite inside the specs dir, where
    # check_binds reports every demand as a phantom prose orphan at exit 1. The unanchored form
    # keeps its cwd fallback, which is where the gate is run from.
    base = (start if start is not None else Path.cwd()).resolve()
    for cand in (base, *base.parents):
        if (cand / ".git").exists():
            return cand
    return base


def _walk(top: Path) -> list[Path]:
    """Every file under `top`, pruning `_PRUNE` dirs from the walk itself (not after the fact —
    descending into a `.venv` or a sibling worktree is the expensive part)."""
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
        # `isinstance` on BOTH sections, not just `or {}`: the coalescing form only replaces a
        # FALSY value, so a profile that spells either section as a string or a list survives it
        # and the first `.get` below raises `AttributeError` — out of `load`, which every
        # checker main calls OUTSIDE its try, so a malformed profile arrives as a traceback
        # behind exit 1 ("looked, found something") for a gate that never loaded its config.
        # `conventions` is the newly-read one and the likelier to be prose: the init skill
        # documents everything outside `specGraph` as free-form for a skill to read.
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
        # The branch a diff-taking checker compares against when `--base` is not given. Read
        # from `conventions`, NOT `specGraph`: it is the same fact the ship skill already
        # documents there, and a second spelling would let the two disagree. Hardcoding "main"
        # was harmless while an unresolvable base silently produced an empty diff; once
        # check_actors preflights the ref (#949) it becomes a mandatory `--base` on every
        # invocation in any repo whose default branch is named something else — and this ships
        # as a plugin to repos we do not control.
        "defaultBranch": conventions.get("defaultBranch") or "main",
    }


def _kept(path: Path, root: Path) -> bool:
    """Whether `path` survives pruning.

    Every check here is keyed on the path RELATIVE to the repo root. An absolute-path check
    would misfire whenever the checkout itself sits under a matching name — prune the entire
    repo for a worktree under `.worktrees/`, or (the `tests` rule) drop every source file for
    a checkout under `/srv/tests/myrepo`. Both fail *silently*, to zero findings.
    """
    parts = path.relative_to(root).parts
    return not (_PRUNE & set(parts)) and "tests" not in parts[:-1]


def artifacts(cfg: dict[str, Any]) -> list[Path]:
    """The committed spec_graph_*.yaml artifacts — the configured glob, minus prune-listed dirs.

    The pruning is not cosmetic: the default glob is `**/spec_graph_*.yaml`, and
    write-code-from-spec *mandates* working in a worktree — so an unpruned glob run from the
    main checkout picks up every sibling branch's graphs alongside this branch's.
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
