"""The record rules (#1366 O4, #1470 D-E): what makes a tenant's system and case records usable, and the catalog of
adapters a record may name, below `systems` in the layer order so the API may load them with no run code (#1470 D-B).

- `registry`: the one read of an adapters directory (`RosterRead`, `read_roster`, `RegistryError`), the platform-served
  system names (`PLATFORM_SERVED_NAMES`) and the adapter-module loader. `systems.verbs` re-exports them.
- `catalog`: `Catalog`, every adapter of the checkout read cold, each module loaded once (a failed load kept, D8).
  `systems.catalog` re-exports it beside `TenantSystems`.
- `judgement`: `judge_records`, the one judgement the record store, `tenant check` and run start use."""
from defender.system_rules.catalog import COMMENT_ROUTE, DECLARATIONS, Catalog, CatalogEntry, route_of
from defender.system_rules.judgement import (
    RecordTenant,
    case_cover_fault,
    cover_fault,
    judge_records,
    judge_system,
    located_access,
    read_matches,
    system_faults,
    write_covers,
)
from defender.system_rules.registry import (
    ADAPTER_SUFFIX,
    PLATFORM_SERVED_NAMES,
    TACIT_KNOWLEDGE,
    GrantSystems,
    RegistryError,
    RosterRead,
    fresh_adapter_module,
    is_platform_served,
    read_roster,
)

__all__ = ["ADAPTER_SUFFIX", "COMMENT_ROUTE", "DECLARATIONS", "PLATFORM_SERVED_NAMES", "TACIT_KNOWLEDGE", "Catalog",
           "CatalogEntry", "GrantSystems", "RecordTenant", "RegistryError", "RosterRead", "case_cover_fault",
           "cover_fault", "fresh_adapter_module", "is_platform_served", "judge_records", "judge_system",
           "located_access", "read_matches", "read_roster", "route_of", "system_faults", "write_covers"]
