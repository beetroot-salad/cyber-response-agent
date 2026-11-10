"""#1278: the learning store a run end files its curation request into, for tests of the investigation tail.

`reach_store(dsn, monkeypatch, tenant)` names the database where `run_common.enqueue_curation` reads it
(`DEFENDER_DATABASE_DSN`) and records `tenant` active there (once), so the store takes the tenant's requests. What is waiting is
read back with `_spec791.author_markers(paths)` / `curation_requests(paths)`."""
from __future__ import annotations

from typing import Any

DSN_ENV = "DEFENDER_DATABASE_DSN"


def reach_store(dsn: str, monkeypatch: Any, tenant: Any) -> str:
    """Point the entrypoint at `dsn` and register `tenant` (an accepted tenant) active in it; returns `dsn`."""
    from defender.tests.support.jobs._jobs1342 import register_tenant
    from defender.tests.support.shared._postgres1339 import execute

    monkeypatch.setenv(DSN_ENV, dsn)
    if not execute(dsn, "SELECT 1 FROM tenancy.tenants WHERE id = %s", (str(tenant.id),)):
        register_tenant(dsn, str(tenant.id))
    return dsn
