"""Admission of a tenant at a host entry point (#1214 Flow 4, P3): the tenant record, read through
`TenantDirectory`, decides whether a host process may work for a tenant at all; the folder rules
(`accept_tenant`) then judge the tenant's folder as before.

Every host entry point (through the host acceptance, `systems.run_tenant.host_tenant`, the one
caller of `admit_tenant` and `host_directory` outside this package) and each lead-drain claim
proceed only while the tenant is `active`, and only with its forge wiring recorded (the origin they
deliver to and publish from).
Production entry points build their directory from `DEFENDER_DATABASE_DSN`; with neither a directory
nor that variable they refuse (principles §2). Imports no database code until a directory is built
from the variable."""

from __future__ import annotations

import os
from collections.abc import Callable
from typing import TYPE_CHECKING

from defender.records.formats import TenantId, TenantRefused

if TYPE_CHECKING:
    from defender.tenancy._directory import TenantDirectory
    from defender.tenancy.models import ForgeWiring

#: The host's database address (DC-9): set for host processes only, never handed to a box.
_DSN_ENV = "DEFENDER_DATABASE_DSN"
#: The one state in which a tenant is worked for (P3).
_ACTIVE = "active"
#: The mark the lifecycle process sets on itself (r10.1 C6).
_LIFECYCLE_MARK = "DEFENDER_LIFECYCLE_PROCESS"


def database_address_variable() -> str:
    """The environment variable host processes read the database address from (DC-9): the base
    environment scrub drops it, and the launchers that need it add it back by this name."""
    return _DSN_ENV


def host_directory(
    given: TenantDirectory | None, *, check_version: Callable[[str], None],
) -> TenantDirectory:
    """The directory a host entry point admits tenants through: `given` (a test's, or a launcher's
    in-process stand-in), else one over PostgreSQL at `DEFENDER_DATABASE_DSN` once
    `check_version(dsn)` passed (#1339's light check: a database behind this code is refused,
    naming both revisions; it is `defender.migrations.check_version`, which sits above this
    package). Neither given nor configured is `TenantRefused` naming the variable."""
    if given is not None:
        return given
    dsn = os.environ.get(_DSN_ENV, "")
    if not dsn:
        raise TenantRefused(
            f"{_DSN_ENV} is not set: a host process admits a tenant only from the tenant records in "
            "PostgreSQL, and has no database to read them from")
    check_version(dsn)
    from defender.tenancy._directory import TenantDirectory
    from defender.tenancy.postgres import PostgresTenantRepository

    return TenantDirectory(lambda: PostgresTenantRepository(dsn))


def mark_lifecycle_process() -> None:
    """Mark this process as the lifecycle's (r10.1 C6): its `__main__` entry calls this first, and
    the host acceptance refuses in a marked process. Prepare holds a tenant's host lock exclusive in
    that process, so a shared hold taken there would wait on itself; the mark backs the static
    census, which cannot follow a lazy string import."""
    os.environ[_LIFECYCLE_MARK] = "1"


def in_lifecycle_process() -> bool:
    """Whether this process carries the lifecycle's mark (`mark_lifecycle_process`)."""
    return bool(os.environ.get(_LIFECYCLE_MARK))


def admit_tenant(directory: TenantDirectory, raw_id: object) -> ForgeWiring:
    """`raw_id`'s forge wiring, once the tenant record says the tenant may be worked for: it exists,
    it is `active`, and its repository is recorded. Otherwise `TenantRefused` naming the tenant (and
    its state when it has one). Reads the directory now, so a caller that admits per unit of work
    (each drain claim) sees an offboarding at once."""
    tenant_id = TenantId(raw_id)
    state, wiring = directory.admission(tenant_id)
    if state is None:
        raise TenantRefused(f"tenant {tenant_id} is not a tenant of this deployment: the tenant records "
                            "hold no such tenant")
    if state != _ACTIVE:
        raise TenantRefused(f"tenant {tenant_id} is {state}, not active: nothing is done for it")
    if wiring is None:
        raise TenantRefused(f"tenant {tenant_id} has no forge wiring recorded: its repository is not bound "
                            "to a forge")
    return wiring


def still_active(directory: TenantDirectory, tenant_id: object) -> str | None:
    """None while `tenant_id` is `active`, else why not (its state, or that it is unknown): the
    per-claim re-check a drain makes before it serves each claim (Flow 4)."""
    state = directory.state(TenantId(tenant_id))
    if state == _ACTIVE:
        return None
    return f"tenant {tenant_id} is {state or 'unknown'}, not active"
