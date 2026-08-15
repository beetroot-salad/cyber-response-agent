#!/usr/bin/env python3
"""#869 M1/M2/NF1/NF2 — the declared-systems resolver.

The authoritative "what system does this name?" answer, replacing the deleted
`pitfalls_curator._is_real_system` (`has a SKILL.md`) probe. Two sources, unioned:

* the ADAPTER glob (`defender/scripts/adapters/*_adapter.py`), read from the WORKING tree —
  the same set `runtime.verbs.ModuleVerbRegistry.systems()` reads;
* the `execution.md` MARKER, read from the COMMITTED tree, at exactly depth 1 under
  `defender/skills/`.

The union is deliberately ASYMMETRIC (NF1, the §7 human seam): an uncommitted marker
declares nothing, however it got onto disk, while an uncommitted adapter still counts. Either
source unresolvable RAISES `LeadAuthorError` — the disjunctive reading O4 forces, because a
conjunctive resolver that silently fell back to one source would retire every system the
absent source alone declared.

`adapter_declared_systems` is NF2's second resolution point: the pitfalls lane's own value,
the adapter half alone, never consulting the marker source.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

if (_root := str(Path(__file__).resolve().parents[3])) not in sys.path:
    sys.path.insert(0, _root)

from defender import _git
from defender.learning.core import config as _loop_config
from defender.learning.leads.lead_extraction import LeadAuthorError
from defender.runtime.verbs import ADAPTER_SUFFIX, _system_of

ADAPTERS_REL = "defender/scripts/adapters/"
SKILLS_REL = "defender/skills/"

_log = _loop_config.make_logger("lead-author", flush=True)


def _is_system_name(name: str) -> bool:
    """#868's shape half: refuse empty, a leading dot, and any value carrying `/`, `\\` or
    NUL — the same alphabet the dispatch seam already holds a system name to
    (`runtime.verbs._SYSTEM_RE`), asked as a pure shape question independent of membership."""
    return bool(name) and not name.startswith(".") and not any(c in name for c in "/\\\x00")


def _adapter_names(adapters_dir: Path) -> frozenset[str]:
    """The adapter half: a COLD glob over filenames, never a load (C2/G1) — an adapter whose
    import raises is still named. Explicitly tests the source rather than trusting
    `Path.glob`'s silent `[]` for an absent path, a regular file, or an unreadable directory
    (P1/P2)."""
    if not adapters_dir.is_dir():
        raise LeadAuthorError(
            f"declared_systems: {adapters_dir} is not a directory this process can read"
        )
    try:
        with os.scandir(adapters_dir) as it:
            list(it)
    except OSError as e:
        raise LeadAuthorError(
            f"declared_systems: {adapters_dir} is not readable ({e})"
        ) from e
    names: set[str] = set()
    for p in adapters_dir.glob("*" + ADAPTER_SUFFIX):
        name = _system_of(p)
        if p.is_file() and _is_system_name(name):
            names.add(name)
        else:
            _log(
                f"declared_systems: refused shape-anomalous adapter name {name!r} "
                f"from {adapters_dir}"
            )
    return frozenset(names)


def _skills_tree_exists_at_head(repo_root: Path) -> bool:
    return _git.git_ok(
        ["cat-file", "-e", f"HEAD:{SKILLS_REL.rstrip('/')}"], cwd=repo_root,
    )


def _marker_names(repo_root: Path) -> frozenset[str]:
    """The marker half: a COMMITTED-tree read (NF1), never the working tree, and never
    deeper than one directory segment (the depth rule phase F closes — a nested
    `execution.md` whose parent directory name is model-chosen must declare nothing)."""
    skills_dir = repo_root / SKILLS_REL
    if not _skills_tree_exists_at_head(repo_root):
        raise LeadAuthorError(
            f"declared_systems: {skills_dir} is not resolvable at HEAD "
            "(no commits, detached from a real repo, or the path is absent there)"
        )
    try:
        listing = _git.git(
            ["ls-tree", "-r", "--name-only", "HEAD", "--", SKILLS_REL], cwd=repo_root,
        )
    except _git.GitError as e:
        raise LeadAuthorError(
            f"declared_systems: cannot list the committed tree at {skills_dir}: {e}"
        ) from e
    names: set[str] = set()
    for rel in listing.split():
        if not rel.endswith("/execution.md") or rel.count("/") != 3:
            continue
        name = Path(rel).parent.name
        if _is_system_name(name):
            names.add(name)
        else:
            _log(
                f"declared_systems: refused shape-anomalous marker name {name!r} "
                f"from {skills_dir}"
            )
    return frozenset(names)


def declared_systems(repo_root: Path) -> frozenset[str]:
    """The UNION: the adapter glob (working tree) plus the committed `execution.md` marker,
    both rooted at `repo_root`. Either source unresolvable raises `LeadAuthorError`."""
    adapters_dir = repo_root / ADAPTERS_REL
    adapter_names = _adapter_names(adapters_dir)
    marker_names = _marker_names(repo_root)
    union = adapter_names | marker_names
    if not union:
        _log(
            f"declared_systems: no systems declared by either source "
            f"({adapters_dir} or {repo_root / SKILLS_REL})"
        )
    return union


def adapter_declared_systems(repo_root: Path) -> frozenset[str]:
    """NF2's second resolution point: the ADAPTER HALF ALONE, the value the pitfalls lane
    resolves. Never consults the marker source — an unresolvable marker is not its fault to
    raise, and emptiness is measured on the adapter half alone."""
    return _adapter_names(repo_root / ADAPTERS_REL)
