"""When a tenant's records are known, and the refusals of a record read or write (#1470 O8, r9).

A tenant's records are known exactly while it is `active`. `refuse_unless_active` is the one rule: the tenant rows'
current-records read (run start, jobs, the API's config reads) and the record store's writes and credential slot all
call it, so a read and a write refuse the same tenant state alike, with the same two types.

`RecordRefused` is the base of every refusal of a record read or write: these two, raised by the rule, and the record
store's own (`system_records`: `Stale`, `Judged`, `NoCurrentRecord`). It lives here, below the store, so the two tenant
refusals can be one too. Each tenant refusal is also a `TenantRefused`, the shape every tenant owner catches."""
from __future__ import annotations

from collections.abc import Sequence

from defender.records.formats import TenantRefused

#: The one state in which a tenant's records are known (#1470 O8).
RECORDS_STATE = "active"


class RecordRefused(Exception):
    """A record read, write or credential slot refused. `faults` is every reason, each a sentence naming the tenant,
    or the system and the key or part (never a file). Raised only as one of its subclasses."""

    def __init__(self, faults: Sequence[str]) -> None:
        self.faults = list(faults)
        super().__init__("; ".join(self.faults))


class NoSuchTenant(RecordRefused, TenantRefused):
    """No tenant row has this id: it has no records (the API's 404)."""

    def __init__(self, tenant: object) -> None:
        super().__init__([f"tenant {tenant} does not exist, so it has no system records"])


class TenantNotActive(RecordRefused, TenantRefused):
    """The tenant exists but is not `active` (creating, offboarding, offboarded): its records are not known, so they
    are neither read nor written (the API's 409)."""

    def __init__(self, tenant: object, state: str) -> None:
        self.state = state
        super().__init__([f"tenant {tenant} is {state}, not active: its system records are not known"])


def refuse_unless_active(tenant_id: object, state: str | None) -> None:
    """#1470 O8: `NoSuchTenant` for a tenant with no row (`state` None), `TenantNotActive` for one in any state but
    `active`. Every caller is past admission, so this is a refusal, not a transient."""
    if state is None:
        raise NoSuchTenant(tenant_id)
    if state != RECORDS_STATE:
        raise TenantNotActive(tenant_id, state)
