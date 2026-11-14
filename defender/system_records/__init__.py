"""The tenant's system and case records, written (#1366, #1470): the one writer of the append-only version tables.

Reads go through `tenancy` (`TenantDirectory.current_records`); this package owns the writes: version numbering, staleness,
the per-tenant lock, the credential generation and the credential slot (#1470 P3). What makes a record usable is the
injected judgement (`RecordStore(judge=)`): its caller composes it (`system_rules.judge_records` over a catalog built
once). Every refusal is a `RecordRefused` of one type: `Stale`, `Judged`, `NoSuchTenant`, `TenantNotActive`,
`NoCurrentRecord`."""

from defender.system_records._store import (
    CaseWrite,
    CredentialSlot,
    Judge,
    Judged,
    NoCurrentRecord,
    NoSuchTenant,
    RecordRefused,
    RecordStore,
    Stale,
    SystemWrite,
    TenantNotActive,
)

__all__ = ["CaseWrite", "CredentialSlot", "Judge", "Judged", "NoCurrentRecord", "NoSuchTenant", "RecordRefused",
           "RecordStore", "Stale", "SystemWrite", "TenantNotActive"]
