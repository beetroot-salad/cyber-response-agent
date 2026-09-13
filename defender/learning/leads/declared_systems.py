#!/usr/bin/env python3
"""The declared-systems resolver — the authoritative "is this name a system?" answer.

Two sources, unioned:

* the ADAPTER roster (`defender/scripts/adapters/*_adapter.py`), read from the WORKING tree
  through `runtime.verbs.read_roster` — the one read `ModuleVerbRegistry.systems()` is built
  from, so the two are one set by construction;
* the `execution.md` MARKER, read from the COMMITTED tree, at exactly depth 1 under
  `defender/skills/`.

The union is deliberately ASYMMETRIC: an uncommitted marker declares nothing, however it got
onto disk, while an uncommitted adapter still counts. Either source unresolvable RAISES
`LeadAuthorError`, because a resolver that silently fell back to the other source would
retire every system the absent one alone declared.

`adapter_declared_systems` is the second resolution point: the pitfalls lane's own value, the
adapter half alone, never consulting the marker source.
"""
from __future__ import annotations

import sys
from pathlib import Path

if (_root := str(Path(__file__).resolve().parents[3])) not in sys.path:
    sys.path.insert(0, _root)

from defender import _git
from defender._paths import DefenderPaths
from defender.learning.core import config as _loop_config
from defender.learning.leads.lead_extraction import LeadAuthorError
from defender.runtime.verbs import RegistryError, is_system_name, read_roster

#: Both re-exported from `DefenderPaths` rather than re-spelled: a resolver whose idea of
#: where adapters live can drift from the gate that reads its answer is the whole class of
#: defect it exists to close.
ADAPTERS_REL = DefenderPaths.adapters_rel
SKILLS_REL = DefenderPaths.skills_rel

_log = _loop_config.make_logger("lead-author", flush=True)


def _adapter_names(adapters_dir: Path) -> frozenset[str]:
    """The adapter half: a COLD read of filenames, never a load — an adapter whose import
    raises is still named.

    `runtime.verbs.read_roster` is THE read (#1035): the same call `ModuleVerbRegistry` builds
    its roster from, so this half and the runtime roster are one set by construction rather
    than by two readers agreeing. What the primitive refuses — absent, a regular file,
    unlistable, listable but not searchable, a symlink loop named like an adapter — arrives
    as `RegistryError` and leaves as this resolver's own class: `LeadAuthorError` is not an
    `OSError`, which is what keeps the drain seam's `(SubprocessError, OSError)` swallow from
    rendering a tree this process cannot read as a green tick (#869 O4, #1035 O2). The
    message keeps `not a directory this process can read` on every arm: `test_hardening_772`
    binds on it.

    The refused names are the primitive's — per derived name, sorted — so each is logged
    once, with the directory it came from, in a deterministic order."""
    try:
        roster = read_roster(adapters_dir)
    except RegistryError as e:
        raise LeadAuthorError(
            f"declared_systems: {adapters_dir} is not a directory this process can read ({e})"
        ) from e
    for name in roster.refused:
        _log(
            f"declared_systems: refused anomalous adapter name {name!r} "
            f"from {adapters_dir} — it is not a name the dispatch seam resolves"
        )
    return frozenset(roster.accepted)


def _skills_tree_exists_at_head(repo_root: Path) -> bool:
    return _git.git_ok(
        ["cat-file", "-e", f"HEAD:{SKILLS_REL.rstrip('/')}"], cwd=repo_root,
    )


def _marker_names(repo_root: Path) -> frozenset[str]:
    """The marker half: a COMMITTED-tree read, never the working tree, and never deeper than
    one directory segment — a nested `execution.md` whose parent directory name is
    model-chosen must declare nothing."""
    skills_dir = repo_root / SKILLS_REL
    if not _skills_tree_exists_at_head(repo_root):
        raise LeadAuthorError(
            f"declared_systems: {skills_dir} is not resolvable at HEAD "
            "(no commits, detached from a real repo, or the path is absent there)"
        )
    # `-z` and `--full-name` are LOAD-BEARING, not tidiness:
    #
    #   * without `-z`, `--name-only` C-QUOTES any path holding a non-ASCII byte — the entry
    #     comes back double-quoted with the byte escaped, so it no longer ends in
    #     `/execution.md` and the system is dropped — and splitting the listing on whitespace
    #     TEARS a name containing a space into two tokens that each match nothing;
    #   * without `--full-name`, output is CWD-relative, and `count("/") == 3` is a statement
    #     about a ROOT-relative path.
    #
    # Each of those silently un-declares a real system — worse than a loud refusal, because
    # the name never even reaches the `is_system_name` check below to be logged as anomalous.
    try:
        listing = _git.git(
            ["ls-tree", "-r", "-z", "--full-name", "--name-only", "HEAD", "--", SKILLS_REL],
            cwd=repo_root,
        )
    except _git.GitError as e:
        raise LeadAuthorError(
            f"declared_systems: cannot list the committed tree at {skills_dir}: {e}"
        ) from e
    names: set[str] = set()
    for rel in listing.split("\0"):
        if not rel or not rel.endswith("/execution.md") or rel.count("/") != 3:
            continue
        name = Path(rel).parent.name
        if is_system_name(name):
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
    """The ADAPTER HALF ALONE, the value the pitfalls lane resolves. Never consults the marker
    source — an unresolvable marker is not its fault to raise, and emptiness is measured on
    the adapter half alone."""
    return adapter_systems_under(repo_root / ADAPTERS_REL)


def adapter_systems_under(adapters_dir: Path) -> frozenset[str]:
    """The adapter half rooted at the ADAPTERS DIRECTORY itself, for a caller that holds the
    tree rather than the repo.

    `adapter_declared_systems` derives that directory from `repo_root`, right for the lanes
    that start from a `LoopPaths`. The permission gate does not: it is handed a `defender_dir`
    by `bind`, and reconstructing a repo root by taking `.parent` silently reads a SIBLING
    tree's adapters the moment the bound tree is not literally named `defender` — while every
    grant it compiles must anchor on the tree it was threaded.
    """
    return _adapter_names(adapters_dir)
