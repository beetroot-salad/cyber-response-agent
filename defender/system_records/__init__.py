"""The tenant's system and case records, written (#1366): the one writer of the append-only version tables.

Reads go through `tenancy` (`TenantDirectory.current_records`); this package owns the writes: version numbering, staleness,
the per-tenant lock, the credential generation and the import. What makes a record usable is the injected judgement
(`RecordStore(judge=)`); `open_store` wires the real one, which the operator command uses."""

from defender.system_records._store import RecordRefused, RecordStore, open_store

__all__ = ["RecordRefused", "RecordStore", "open_store"]
