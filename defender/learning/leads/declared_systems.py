#!/usr/bin/env python3
"""The declared-systems resolver — the authoritative "is this name a system?" answer."""
from __future__ import annotations

import logging
import sys
from pathlib import Path

if (_root := str(Path(__file__).resolve().parents[3])) not in sys.path:
    sys.path.insert(0, _root)

from collections.abc import Mapping

from defender._paths import DefenderPaths
from defender.learning.leads._errors import LeadAuthorError
from defender.learning.leads.path_validation import SKILLS_PREFIX
from defender.runtime.verbs import RegistryError, RosterRead, is_system_name, read_roster

#: From `DefenderPaths` rather than re-spelled, so the resolver and the gates agree on where
#: adapters live.
ADAPTERS_REL = DefenderPaths.adapters_rel

_logger = logging.getLogger(__name__)


class AdaptersUnreadable(LeadAuthorError, RegistryError):
    """The adapters directory cannot be read.

    Both bases matter: `LeadAuthorError` is what the lane's callers catch; `RegistryError`
    puts it in `faults.SYSTEMIC_FAULTS`, so `run_or_dead_letter` re-raises it (CRITICAL, exit
    2) instead of charging an unreadable checkout to every queued row's `attempts` until the
    whole queue is graveyarded."""


def read_adapters(adapters_dir: Path) -> RosterRead:
    """The adapter half's one read — a cold read, never an import, so an adapter whose import
    raises is still named."""
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


def _marker_names(agent: Mapping[str, object]) -> frozenset[str]:
    """The marker half: the tenant's committed `agent/skills/<name>/execution.md` files, read
    off a committed tree (`agent`: its repo-relative paths, as `Batch.base` gives a batch's
    base), exactly one directory segment deep — a nested `execution.md` under a model-chosen
    directory declares nothing, and the draft the model writes is never consulted (#1108 P4:
    the markers are the tenant's, never the product tree's)."""
    names: set[str] = set()
    for rel in agent:
        if not rel.startswith(SKILLS_PREFIX):
            continue
        parts = rel[len(SKILLS_PREFIX):].split("/")
        if len(parts) != 2 or parts[1] != "execution.md":
            continue
        name = parts[0]
        if is_system_name(name):
            names.add(name)
        else:
            _logger.warning(
                f"declared_systems: refused shape-anomalous marker name {name!r} "
                f"from {SKILLS_PREFIX}"
            )
    return frozenset(names)


def declared_systems(
    repo_root: Path, *, agent: Mapping[str, object] | None = None,
) -> frozenset[str]:
    """The union of the adapter glob (the product checkout at `repo_root`, working tree) and
    the tenant's committed `execution.md` markers (`agent`, a committed tree's repo-relative
    paths; none given, the adapter half alone: a product checkout carries no tenant marker
    after #1108 P4 O1). An unreadable adapter source raises `LeadAuthorError`."""
    return declared_systems_over(read_adapters(repo_root / ADAPTERS_REL), agent=agent)


def declared_systems_over(
    roster: RosterRead, *, agent: Mapping[str, object] | None = None,
) -> frozenset[str]:
    """`declared_systems` for a caller that already read the adapter half (the disposition
    census lint), so it needn't read twice."""
    union = frozenset(roster.accepted) | (_marker_names(agent) if agent is not None else frozenset())
    if not union:
        _logger.warning(
            f"declared_systems: no systems declared by either source "
            f"({roster.root} or the tenant's {SKILLS_PREFIX}<system>/execution.md)"
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
