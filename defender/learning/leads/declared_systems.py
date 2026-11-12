#!/usr/bin/env python3
"""The declared-systems resolver — the authoritative "is this name a system?" answer."""
from __future__ import annotations

import logging
import sys
from pathlib import Path

if (_root := str(Path(__file__).resolve().parents[3])) not in sys.path:
    sys.path.insert(0, _root)

from collections.abc import Mapping
from typing import TYPE_CHECKING

from defender._paths import DefenderPaths
from defender.learning.leads._errors import LeadAuthorError
from defender.learning.leads.path_validation import SKILLS_PREFIX
from defender.systems.verbs import PLATFORM_SERVED, RegistryError, RosterRead, read_roster
from defender.kit.verbs import is_system_name

#: From `DefenderPaths` rather than re-spelled, so the resolver and the gates agree on where
#: adapters live.
ADAPTERS_REL = DefenderPaths.adapters_rel

if TYPE_CHECKING:
    from defender.systems.catalog import Catalog, TenantSystems
    from defender.tenancy.models import TenantRecords

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
    for name, why in roster.refused.items():
        _logger.warning(
            f"declared_systems: refused adapter name {name!r} from {adapters_dir} — {why}"
        )
    return roster


def with_platform_systems(systems: frozenset[str]) -> frozenset[str]:
    """`systems` plus the platform-served names, which admit paths on every tree (#1390 A14)."""
    return systems.union(PLATFORM_SERVED)


def declares_no_system(systems: frozenset[str]) -> bool:
    """Whether a declared set holds nothing but the platform-served names, which every tree has
    and so say nothing about what this one declares (#1390 A14)."""
    return not systems - PLATFORM_SERVED.keys()


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


def declared_systems_over(
    roster: RosterRead, *, agent: Mapping[str, object] | None = None,
) -> frozenset[str]:
    """`declared_systems` for a caller that already read the adapter half (the disposition
    census lint), so it needn't read twice."""
    union = frozenset(roster.verbs) | (_marker_names(agent) if agent is not None else frozenset())
    if declares_no_system(union):
        _logger.warning(
            f"declared_systems: no systems declared by either source "
            f"({roster.root} or the tenant's {SKILLS_PREFIX}<system>/execution.md)"
        )
    return union


def tenant_systems_of(repo_root: Path, records: TenantRecords, *, tenant_id: object) -> TenantSystems:
    """A tenant's systems (`TenantSystems`) from its current `records` over the catalog of the
    product checkout at `repo_root`. An unreadable adapter source raises `AdaptersUnreadable`; a tenant not
    imported, `TenantRefused` naming the import (R8)."""
    from defender.systems.catalog import Catalog, TenantSystems

    return TenantSystems.of(records, Catalog(read_adapters(repo_root / ADAPTERS_REL)), tenant_id=tenant_id)


def lane_names(systems: TenantSystems | Catalog) -> frozenset[str]:
    """The names a lane handed `systems` admits: every system of the tenant (its enabled
    catalog-backed records and the platform-served ones), or, from a caller with no tenant, every
    system of the whole catalog."""
    return frozenset(systems.roster.systems)
