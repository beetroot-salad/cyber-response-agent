#!/usr/bin/env python3
"""The declared-systems resolver — the authoritative "is this name a system?" answer.

Two sources, unioned:

* the adapter roster (`defender/scripts/adapters/*_adapter.py`), read from the working tree
  through `runtime.verbs.read_roster` — the same read `ModuleVerbRegistry.systems()` uses;
* the `execution.md` marker, read from the committed tree, at exactly depth 1 under
  `defender/skills/`.

Asymmetric: an uncommitted marker declares nothing, while an uncommitted adapter counts.
Either source unresolvable raises `LeadAuthorError`; silently falling back to the other would
retire every system only the absent one declared.

`adapter_declared_systems` is the adapter half alone, used by the pitfalls lane.
"""
from __future__ import annotations

import logging
import sys
from pathlib import Path

if (_root := str(Path(__file__).resolve().parents[3])) not in sys.path:
    sys.path.insert(0, _root)

from defender import _git
from defender._paths import DefenderPaths
from defender.learning.leads._errors import LeadAuthorError
from defender.runtime.verbs import RegistryError, RosterRead, is_system_name, read_roster

#: From `DefenderPaths` rather than re-spelled, so the resolver and the gates agree on where
#: adapters live.
ADAPTERS_REL = DefenderPaths.adapters_rel
SKILLS_REL = DefenderPaths.skills_rel

_logger = logging.getLogger(__name__)


class AdaptersUnreadable(LeadAuthorError, RegistryError):
    """The adapters directory cannot be read.

    Both bases matter: `LeadAuthorError` is what the lane's callers catch; `RegistryError`
    puts it in `faults.SYSTEMIC_FAULTS`, so `run_or_dead_letter` re-raises it (CRITICAL, exit
    2) instead of charging an unreadable checkout to every queued row's `attempts` until the
    whole queue is graveyarded."""


def read_adapters(adapters_dir: Path) -> RosterRead:
    """The adapter half's one read — a cold read, never an import, so an adapter whose import
    raises is still named.

    Uses `runtime.verbs.read_roster`, the primitive every registry is built over, so this half
    and the runtime roster agree by construction. Its `RegistryError` is re-raised as
    `AdaptersUnreadable`: not an `OSError`, so the drain seam's `(SubprocessError, OSError)`
    swallow can't turn an unreadable tree into a green tick. The message must keep `not a
    directory this process can read` (`test_hardening_772` matches it).

    Refused names are logged once each, in sorted order. Returns the whole roster so a caller
    needing what each system declares doesn't read twice."""
    try:
        roster = read_roster(adapters_dir)
    except RegistryError as e:
        # Carry only the underlying `strerror`, so the CRITICAL line names the path once; a
        # cause without one (a symlink loop's `RuntimeError`) is carried whole.
        reason = getattr(e.__cause__, "strerror", None) or str(e.__cause__ or e)
        raise AdaptersUnreadable(
            f"declared_systems: {adapters_dir} is not a directory this process can read "
            f"({reason})"
        ) from e
    for name in roster.refused:
        _logger.warning(
            f"declared_systems: refused anomalous adapter name {name!r} "
            f"from {adapters_dir} — it is not a name the dispatch seam resolves"
        )
    return roster


def _adapter_names(adapters_dir: Path) -> frozenset[str]:
    """The adapter half as a set of names — `read_adapters`, indexed."""
    return frozenset(read_adapters(adapters_dir).accepted)


def _skills_tree_exists_at_head(repo_root: Path) -> bool:
    return _git.git_ok(
        ["cat-file", "-e", f"HEAD:{SKILLS_REL.rstrip('/')}"], cwd=repo_root,
    )


def _marker_names(repo_root: Path) -> frozenset[str]:
    """The marker half: a committed-tree read, exactly one directory segment deep — a nested
    `execution.md` under a model-chosen directory must declare nothing."""
    skills_dir = repo_root / SKILLS_REL
    if not _skills_tree_exists_at_head(repo_root):
        raise LeadAuthorError(
            f"declared_systems: {skills_dir} is not resolvable at HEAD "
            "(no commits, detached from a real repo, or the path is absent there)"
        )
    # `-z` and `--full-name` are required: without `-z`, non-ASCII paths come back C-quoted
    # and whitespace splitting tears names with spaces; without `--full-name` output is
    # CWD-relative, but `count("/") == 3` assumes root-relative. Either would silently
    # un-declare a real system.
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
            _logger.warning(
                f"declared_systems: refused shape-anomalous marker name {name!r} "
                f"from {skills_dir}"
            )
    return frozenset(names)


def declared_systems(repo_root: Path) -> frozenset[str]:
    """The union of the adapter glob (working tree) and the committed `execution.md` marker,
    both rooted at `repo_root`. Either source unresolvable raises `LeadAuthorError`."""
    return declared_systems_over(read_adapters(repo_root / ADAPTERS_REL), repo_root)


def declared_systems_over(roster: RosterRead, repo_root: Path) -> frozenset[str]:
    """`declared_systems` for a caller that already read the adapter half (the disposition
    census lint), so it needn't read twice."""
    union = frozenset(roster.accepted) | _marker_names(repo_root)
    if not union:
        _logger.warning(
            f"declared_systems: no systems declared by either source "
            f"({roster.root} or {repo_root / SKILLS_REL})"
        )
    return union


def adapter_declared_systems(repo_root: Path) -> frozenset[str]:
    """The adapter half alone, as the pitfalls lane resolves it. Never consults the marker
    source, so an unresolvable marker doesn't raise here."""
    return adapter_systems_under(repo_root / ADAPTERS_REL)


def adapter_systems_under(adapters_dir: Path) -> frozenset[str]:
    """The adapter half rooted at the adapters directory itself, for a caller that holds the
    tree rather than the repo (the permission gate, handed a `defender_dir` by `bind`).
    Reconstructing a repo root via `.parent` would read a sibling tree's adapters whenever the
    bound tree isn't literally named `defender`.
    """
    return _adapter_names(adapters_dir)
