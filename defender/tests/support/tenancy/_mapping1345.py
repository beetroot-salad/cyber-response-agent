"""#1345 test machinery: the default alert mapping every ready-made tenant is seeded with, and the two seeders.

A tenant has no mapping until one is saved (D2) and a run or an investigation for one is refused (O4), so
every fixture that makes a tenant which later starts a run seeds today's mapping as a database row, and a
test of absence opts out by passing `alert_mapping=None` (a parameter, never a monkeypatch). NO test functions.

- `PLANTED_ALERT_MAPPING`: the one definition. Its four facts are `_tenants1106.ALERT_MAPPING_TEXT`'s; `title` and
  `description` are paths into the alerts the fixtures build (`ALERT_BYTES`, `S.generic_alert()`, the goldens), so
  the launch label still means something. `FIXTURE_ALERT_MAPPING` is the same with the committed fixture tenant's
  `event_time` (`alert_timestamp`, the shape of `ALERT_BYTES` and the goldens): the Postgres fixtures use it.
- `mapping_value(entries)`: the typed value the production seams take (`records`' mapping type). The one place
  that names that type; r5 says only "records' six-entry mapping type" (assumed `AlertMapping(paths=<mapped entries>)`).
- `add_to_twin(twin, tenant_id, mapping)` / `seed_twin(twin, tenant, entries)`: put a saved mapping into the in-memory
  twin. Here, not on the twin: the one product writer is the jobs store's replace (M1), which the twin does not stand in for.
- `ALERT_MAPPING_ROUTE` / `alert_mapping_url(tenant)`: the one spelling of the API route (r5.1); the refusal-wording
  checks (`assert_missing_wording_names_verb_and_route`) take the route's tail from it.
- `remove_postgres_mapping(dsn, tenant)`: the one raw-SQL deletion of a mapping row (r5.1 repair 13).
- `seed_postgres(dsn, tenant, entries)`: through `JobStore.put_alert_mapping(tenant_id, mapping, actor="u-1") -> created`.
"""
from __future__ import annotations
import datetime as _dt

from collections.abc import Mapping
from types import MappingProxyType
from typing import Any

#: The six entries (r5 `MAPPING_KEYS`), `None` = unmapped.
PLANTED_ALERT_MAPPING: Mapping[str, str | None] = MappingProxyType({
    "signature": "rule.id", "event_time": "timestamp", "summary": "rule.description", "case_key": "alert_id",
    "title": "rule.description", "description": "rule.id"})
FIXTURE_ALERT_MAPPING: Mapping[str, str | None] = MappingProxyType({**PLANTED_ALERT_MAPPING, "event_time": "alert_timestamp"})
#: The API route (r5.1: "tests spell it in one place"): the template as the routes table lists it, and its `{tenant_id}` filled.
ALERT_MAPPING_ROUTE = "/tenants/{tenant_id}/alert-mapping"


def alert_mapping_url(tenant_id: str) -> str:
    """The route for `tenant_id` (no host)."""
    return ALERT_MAPPING_ROUTE.format(tenant_id=tenant_id)


#: What the title and description paths derive from `_jobs1342.ALERT_BYTES`.
ALERT_BYTES_TITLE, ALERT_BYTES_DESCRIPTION = "sketch", "r-1342"


def mapping_value(entries: Mapping[str, str | None]) -> Any:
    """The typed mapping for `entries` (mapped entries only, as `records.AlertMapping.paths` holds them)."""
    from defender.records._alert_input import AlertMapping  # not in the `formats` door at base

    return AlertMapping(paths={k: v for k, v in entries.items() if v is not None})


def assert_missing_wording_names_verb_and_route(wording: str) -> None:
    """`ALERT_MAPPING_MISSING` names the command-line verb and the API route (r5 O4; route spelled in `ALERT_MAPPING_ROUTE`)."""
    assert "set-alert-mapping" in wording
    assert ALERT_MAPPING_ROUTE.split("{tenant_id}")[1] in wording, wording


async def add_to_twin(twin: Any, tenant_id: str, mapping: Any) -> None:
    """The mapping as if saved, for the in-memory tenant repository `twin`; the tenant must exist."""
    from defender.tenancy.models import AlertMappingRow

    if tenant_id not in twin._tenants:
        raise ValueError(f"no tenant {tenant_id}")
    with twin._mutex:
        twin._mappings[tenant_id] = AlertMappingRow.of(tenant_id, mapping)


def seed_twin(twin: Any, tenant: str, entries: Mapping[str, str | None] | None) -> None:
    """Give the in-memory tenant repository `twin` a mapping for `tenant`; `None` seeds nothing."""
    if entries is None:
        return
    from defender.tests.support.tenancy._active1214 import _await, run_sync

    # One shape (r5.1: async, like `add_generation`): awaited here, and by `_identity1306.World._add_tenant`.
    run_sync(_await(add_to_twin(twin, str(tenant), mapping_value(entries))))


def seed_postgres(dsn: str, tenant: str, entries: Mapping[str, str | None] | None) -> None:
    """Save `entries` as `tenant`'s mapping through the store's own replace (the tenant must exist); `None` saves nothing."""
    if entries is None:
        return
    from defender.tests.support.tenancy._active1214 import run_sync

    async def put() -> None:
        from defender.jobs import JobStore

        store = JobStore(dsn, clock=lambda: _dt.datetime(2026, 1, 1, tzinfo=_dt.UTC))
        try:
            await store.put_alert_mapping(str(tenant), mapping_value(entries), actor="u-1")
        finally:
            await store.close()

    run_sync(put())


def remove_postgres_mapping(dsn: str, tenant: str) -> None:
    """Take `tenant`'s mapping row away (a job queued before the upgrade; a tenant whose mapping is gone), the one
    deletion a test makes under the store (the product never deletes a mapping); migration and verb tests also spell the table."""
    from defender.tests.support.shared._postgres1339 import execute

    execute(dsn, "DELETE FROM tenancy.alert_mappings WHERE tenant_id = %s", (str(tenant),))
    assert execute(dsn, "SELECT count(*) FROM tenancy.alert_mappings WHERE tenant_id = %s", (str(tenant),)) == [(0,)]


def planted_mapping() -> Any:
    """`mapping_value(PLANTED_ALERT_MAPPING)`: the `mapping=` a direct `materialize_run(alert, tenant=t, mapping=...)` caller
    hands (r5: required for a non-sibling run; `settings=` is gone)."""
    return mapping_value(PLANTED_ALERT_MAPPING)
