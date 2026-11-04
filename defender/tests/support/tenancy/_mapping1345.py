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
- `seed_twin(twin, tenant, entries)`: through the in-memory twin's seeder, DESIGN-IMPLIED PRODUCTION NAME
  `InMemoryTenantRepository.add_alert_mapping(tenant_id, mapping)` (async, like `add_generation`; r5 "Where it
  lives"). It does not exist at base: tests that reach it are red until the code stage writes it.
- `seed_postgres(dsn, tenant, entries)`: through `JobStore.put_alert_mapping(tenant_id, mapping) -> created`.
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
#: What the title and description paths derive from `_jobs1342.ALERT_BYTES`.
ALERT_BYTES_TITLE, ALERT_BYTES_DESCRIPTION = "sketch", "r-1342"


def mapping_value(entries: Mapping[str, str | None]) -> Any:
    """The typed mapping for `entries` (mapped entries only, as `records.AlertMapping.paths` holds them)."""
    from defender.records._alert_input import AlertMapping  # not in the `formats` door at base

    return AlertMapping(paths={k: v for k, v in entries.items() if v is not None})


def seed_twin(twin: Any, tenant: str, entries: Mapping[str, str | None] | None) -> None:
    """Give the in-memory tenant repository `twin` a mapping for `tenant`; `None` seeds nothing."""
    if entries is None:
        return
    import inspect

    from defender.tests.support.tenancy._active1214 import _await, run_sync

    added = twin.add_alert_mapping(str(tenant), mapping_value(entries))  # design-implied seeder (r5); not at base
    if inspect.isawaitable(added):
        run_sync(_await(added))


def seed_postgres(dsn: str, tenant: str, entries: Mapping[str, str | None] | None) -> None:
    """Save `entries` as `tenant`'s mapping through the store's own replace (the tenant must exist); `None` saves nothing."""
    if entries is None:
        return
    from defender.tests.support.tenancy._active1214 import run_sync

    async def put() -> None:
        from defender.jobs import JobStore

        store = JobStore(dsn, clock=lambda: _dt.datetime(2026, 1, 1, tzinfo=_dt.UTC))
        try:
            await store.put_alert_mapping(str(tenant), mapping_value(entries))
        finally:
            await store.close()

    run_sync(put())


def planted_mapping() -> Any:
    """`mapping_value(PLANTED_ALERT_MAPPING)`: the `mapping=` a direct `materialize_run(alert, tenant=t, mapping=...)` caller
    hands (r5: required for a non-sibling run; `settings=` is gone)."""
    return mapping_value(PLANTED_ALERT_MAPPING)
