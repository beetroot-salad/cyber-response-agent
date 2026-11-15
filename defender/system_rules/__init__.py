"""The record rules (#1366 O4, #1470 D-E): what makes a tenant's system and case records usable, and the catalog of
adapters a record may name, below `systems` in the layer order so the API may load them with no run code (#1470 D-B).

- `registry`: the one read of an adapters directory (`RosterRead`, `read_roster`, `RegistryError`), the platform-served
  system names (`PLATFORM_SERVED_NAMES`) and the adapter-module loader. `systems.verbs` re-exports them.
- `catalog`: `Catalog`, every adapter of the checkout read cold, each module loaded once (a failed load kept, D8).
  `systems.catalog` re-exports it beside `TenantSystems`.
- `judgement`: `judge_records`, the one judgement the record store, `tenant check` and run start use."""
from typing import TYPE_CHECKING

from defender.lazy_door import lazy_door

if TYPE_CHECKING:
    from defender.system_rules.catalog import (
        COMMENT_ROUTE as COMMENT_ROUTE,
        DECLARATIONS as DECLARATIONS,
        Catalog as Catalog,
        CatalogEntry as CatalogEntry,
        route_of as route_of,
    )
    from defender.system_rules.judgement import (
        RecordTenant as RecordTenant,
        case_cover_fault as case_cover_fault,
        cover_fault as cover_fault,
        judge_records as judge_records,
        judge_system as judge_system,
        located_access as located_access,
        read_matches as read_matches,
        system_faults as system_faults,
        write_covers as write_covers,
    )
    from defender.system_rules.registry import (
        ADAPTER_SUFFIX as ADAPTER_SUFFIX,
        PLATFORM_SERVED_NAMES as PLATFORM_SERVED_NAMES,
        TACIT_KNOWLEDGE as TACIT_KNOWLEDGE,
        GrantSystems as GrantSystems,
        RegistryError as RegistryError,
        RosterRead as RosterRead,
        fresh_adapter_module as fresh_adapter_module,
        is_platform_served as is_platform_served,
        read_roster as read_roster,
    )

#: Each name this door serves, and the submodule that defines it. Lazy: `systems.tacit_registry` takes one name from
#: `registry`, and importing the catalog with it would load the transport (and its HTTP client) into the box closure.
_HOMES: dict[str, str] = {
    **dict.fromkeys(('COMMENT_ROUTE', 'DECLARATIONS', 'Catalog', 'CatalogEntry', 'route_of'), 'catalog'),
    **dict.fromkeys(('RecordTenant', 'case_cover_fault', 'cover_fault', 'judge_records', 'judge_system', 'located_access', 'read_matches', 'system_faults', 'write_covers'), 'judgement'),
    **dict.fromkeys(('ADAPTER_SUFFIX', 'PLATFORM_SERVED_NAMES', 'TACIT_KNOWLEDGE', 'GrantSystems', 'RegistryError', 'RosterRead', 'fresh_adapter_module', 'is_platform_served', 'read_roster'), 'registry'),
}

__getattr__ = lazy_door(globals(), _HOMES)

__all__ = ["ADAPTER_SUFFIX", "COMMENT_ROUTE", "DECLARATIONS", "PLATFORM_SERVED_NAMES", "TACIT_KNOWLEDGE", "Catalog",
           "CatalogEntry", "GrantSystems", "RecordTenant", "RegistryError", "RosterRead", "case_cover_fault",
           "cover_fault", "fresh_adapter_module", "is_platform_served", "judge_records", "judge_system",
           "located_access", "read_matches", "read_roster", "route_of", "system_faults", "write_covers"]
