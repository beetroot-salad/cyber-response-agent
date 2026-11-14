"""A tenant's systems (#1366 DC7), drawn from the catalog of adapters (`system_rules.Catalog`, re-exported here with
`CatalogEntry` and `route_of`, the same objects): two types, so a surface says which it reads.

`TenantSystems` is what one tenant has: its current enabled records whose adapter the catalog carries, plus the
platform-served systems, built once from the tenant's current-records read (`TenantRecords`) and handed to every
tenant surface (O1). Its `roster` is the `RosterRead` those surfaces consume; a catalog adapter no record names is not
in it. A record whose adapter the catalog lacks (an upgrade removed it) and a disabled record are kept apart, so run
start and `tenant check` can say what became of them (R12)."""
from __future__ import annotations

import dataclasses
import types
from collections.abc import Mapping

from defender.system_rules.catalog import COMMENT_ROUTE, DECLARATIONS, Catalog, CatalogEntry, route_of
from defender.systems.verbs import PLATFORM_SERVED, RosterRead, is_platform_served
from defender.tenancy.models import SystemRecord, TenantRecords


@dataclasses.dataclass(frozen=True, eq=False)
class TenantSystems:
    """One tenant's systems (DC7, O1): its current enabled records whose adapter the catalog carries, plus the
    platform-served systems. Built once (`of`) from the tenant's current records and handed to every tenant surface;
    `roster` is the roster those surfaces read. `disabled` and `adapter_missing` keep the records that are not systems
    of the tenant's run, for the surfaces that report them (R12)."""

    catalog: Catalog
    records: TenantRecords
    roster: RosterRead
    #: Enabled records whose adapter the catalog carries: the tenant's systems besides the platform-served ones.
    enabled: Mapping[str, SystemRecord]
    #: Current records the operator disabled: not in the roster.
    disabled: Mapping[str, SystemRecord]
    #: Enabled records naming an adapter the catalog does not carry (an upgrade removed it, or a custom reference):
    #: not in the roster; run start refuses the tenant naming each.
    adapter_missing: Mapping[str, SystemRecord]

    @classmethod
    def of(cls, records: TenantRecords, catalog: Catalog, *, tenant_id: object) -> TenantSystems:
        """Tenant `tenant_id`'s systems over `catalog` from its current `records`. A tenant not imported has no
        systems to tell: `TenantRefused` naming the import (R8), here, so no caller can take its absent records for a
        tenant with none."""
        from defender.systems.run_tenant import require_imported

        require_imported(records, tenant_id)
        whole = catalog.roster
        enabled: dict[str, SystemRecord] = {}
        disabled: dict[str, SystemRecord] = {}
        missing: dict[str, SystemRecord] = {}
        for system, record in sorted(records.systems.items()):
            if is_platform_served(system):
                continue  # never a record (R3); the store refuses one
            if not record.enabled:
                disabled[system] = record
            elif record.custom_ref is not None or record.adapter_id not in catalog:
                missing[system] = record
            else:
                enabled[system] = record
        files = {s: whole.adapter_files[r.adapter_id] for s, r in enabled.items()}
        verbs = {s: whole.verbs.get(r.adapter_id, frozenset()) for s, r in enabled.items()}
        verbs.update({name: whole.verbs[name] for name in PLATFORM_SERVED if name in whole.verbs})
        roster = RosterRead(
            root=whole.root,
            adapter_files=types.MappingProxyType(files),
            verbs=types.MappingProxyType(dict(sorted(verbs.items()))),
            unparsed=types.MappingProxyType({s: whole.unparsed[r.adapter_id] for s, r in enabled.items()
                                             if r.adapter_id in whole.unparsed}),
            refused=types.MappingProxyType({}),
            no_verbs=frozenset(s for s, r in enabled.items() if r.adapter_id in whole.no_verbs),
            whole=False,
        )
        return cls(catalog=catalog, records=records, roster=roster,
                   enabled=types.MappingProxyType(enabled), disabled=types.MappingProxyType(disabled),
                   adapter_missing=types.MappingProxyType(missing))

    @property
    def imported(self) -> bool:
        """Whether the tenant's systems come from records at all (R8, R11)."""
        return self.records.imported

    @property
    def systems(self) -> tuple[str, ...]:
        """Every system of the tenant, sorted: its enabled catalog-backed records and the platform-served systems."""
        return self.roster.systems


__all__ = ["COMMENT_ROUTE", "DECLARATIONS", "Catalog", "CatalogEntry", "TenantSystems", "route_of"]
