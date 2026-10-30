"""#1342 the job store over PostgreSQL: tables and their rules (O1), the trusted alert insert (O2),
create's replay rules (O3), the claim (O4), cancel (O9), delete (O10), audit after commit (O13),
the API-shaped reads (O14 store side), cross-process visibility (O15) and async methods (O12).

Entry: `defender.jobs.JobStore(dsn, clock=)` on a per-test migrated database; rows are read back on a
separate connection. Rows the store has no A-path for (an attempt 2, a terminal stage) are planted by
SQL, as B and the worker would leave them. Column names used in SQL are the sketch's (unratified)."""
from __future__ import annotations

import asyncio
import dataclasses
import datetime as dt
import inspect
import logging
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import pytest

from defender.tests.support.jobs._jobs1342 import (
    ALERT_BYTES,
    NOW,
    T1,
    T2,
    JobsAudit,
    VisibleAtEmit,
    an_alert,
    job_store,
    register_tenant,
    row,
)
from defender.tests.support.shared._pglocks1339 import until_blocked
from defender.tests.support.shared._postgres1339 import execute

pytestmark = [pytest.mark.anyio, pytest.mark.postgres]

HOUR = dt.timedelta(hours=1)
LIVE = ("queued", "running")
TERMINAL = ("completed", "unparseable", "failed", "aborted")
JOBS_AUDIT = "defender.jobs.audit"


@pytest.fixture
def dsn(migrated_database: str) -> str:
    register_tenant(migrated_database, T1)
    register_tenant(migrated_database, T2)
    return migrated_database


# --- machinery: SQL plants, locks, a clock the test moves ------------------------------------------

def _plant_alert(dsn: str, *, tenant: str = T1, ticket: str = "P-1", vendor: str = "elastic") -> str:
    alert_id = str(uuid.uuid4())
    execute(dsn, "INSERT INTO jobs.alerts (id, tenant_id, vendor, vendor_ticket_id, fired_at, changed_at, "
                 "received_at, title, description, raw) VALUES (%s, %s, %s, %s, %s, %s, %s, 't', 'd', %s)",
            (alert_id, tenant, vendor, ticket, NOW, NOW, NOW, b"{}"))
    return alert_id


def _plant_investigation(dsn: str, *, tenant: str, alert_id: str, key: str, attempt: int, stage: str,
                         created_at: dt.datetime = NOW) -> str:
    investigation_id = str(uuid.uuid4())
    execute(dsn, "INSERT INTO jobs.investigations (id, tenant_id, alert_id, request_key, attempt, "
                 "stage, created_at, cost_usd) VALUES (%s, %s, %s, %s, %s, %s, %s, 0)",
            (investigation_id, tenant, alert_id, key, attempt, stage, created_at))
    return investigation_id


def _set_stage(dsn: str, investigation_id: str, stage: str) -> None:
    execute(dsn, "UPDATE jobs.investigations SET stage = %s WHERE id = %s", (stage, investigation_id))


def _count(dsn: str, table: str, where: str = "true") -> int:
    return execute(dsn, f"SELECT count(*) FROM jobs.{table} WHERE {where}")[0][0]  # noqa: S608


@dataclasses.dataclass
class Clock:
    at: dt.datetime = NOW

    def __call__(self) -> dt.datetime:
        return self.at


@asynccontextmanager
async def store_with(dsn: str, clock: Any) -> AsyncIterator[Any]:
    from defender.jobs import JobStore

    store = JobStore(dsn, clock=clock)
    try:
        yield store
    finally:
        await store.close()


@asynccontextmanager
async def holding_alert(dsn: str, alert_id: str) -> AsyncIterator[None]:
    """`SELECT ... FOR UPDATE` on one alert row in an open transaction, committed on exit."""
    import psycopg

    async with await psycopg.AsyncConnection.connect(dsn) as conn:
        cur = await conn.execute("SELECT id FROM jobs.alerts WHERE id = %s FOR UPDATE", (alert_id,))
        assert len(await cur.fetchall()) == 1, "the alert to hold does not exist"
        try:
            yield
        finally:
            await conn.commit()


async def _absent(call: Any) -> None:
    """A read of an id this tenant lacks answers `None`, as the API's ports do; never a row or an error."""
    assert await call is None


# --- O1: the tables' own rules, observed through SQL ------------------------------------------------

@pytest.mark.parametrize("first", LIVE)
@pytest.mark.parametrize("second", LIVE)
async def test_o1_the_database_allows_one_live_investigation_per_alert(dsn, first, second):
    """A second queued/running row for one alert is refused by the database. (O1, M10)"""
    import psycopg

    alert = _plant_alert(dsn)
    _plant_investigation(dsn, tenant=T1, alert_id=alert, key="k1", attempt=1, stage=first)
    with pytest.raises(psycopg.errors.UniqueViolation):
        _plant_investigation(dsn, tenant=T1, alert_id=alert, key="k2", attempt=1, stage=second)
    assert _count(dsn, "investigations") == 1


async def test_o1_terminal_rows_never_count_as_live_and_a_finished_row_frees_the_alert(dsn):
    """Any number of terminal rows coexist with one live row; ending the live row lets another start. (O1)"""
    import psycopg

    alert = _plant_alert(dsn)
    other_alert = _plant_alert(dsn, ticket="P-2")
    for n, stage in enumerate(TERMINAL):
        _plant_investigation(dsn, tenant=T1, alert_id=alert, key=f"done-{n}", attempt=1, stage=stage)
    live = _plant_investigation(dsn, tenant=T1, alert_id=alert, key="k1", attempt=1, stage="queued")
    _plant_investigation(dsn, tenant=T1, alert_id=other_alert, key="k1", attempt=1, stage="running")

    _set_stage(dsn, live, "completed")
    again = _plant_investigation(dsn, tenant=T1, alert_id=alert, key="k2", attempt=1, stage="queued")
    assert row(dsn, again)["stage"] == "queued"
    with pytest.raises(psycopg.errors.UniqueViolation):  # an UPDATE back to live is held to it too
        _set_stage(dsn, live, "running")


async def test_o1_an_investigation_cannot_point_at_another_tenants_alert(dsn):
    """The `(tenant, alert)` foreign key refuses a cross-tenant reference; the same tenant's is accepted. (O1)"""
    import psycopg

    alert = _plant_alert(dsn, tenant=T1)
    ok = _plant_investigation(dsn, tenant=T1, alert_id=alert, key="k1", attempt=1, stage="queued")
    assert row(dsn, ok) is not None
    with pytest.raises(psycopg.errors.ForeignKeyViolation):
        _plant_investigation(dsn, tenant=T2, alert_id=alert, key="k1", attempt=1, stage="failed")
    with pytest.raises(psycopg.errors.ForeignKeyViolation):
        _plant_investigation(dsn, tenant=T1, alert_id=str(uuid.uuid4()), key="k9", attempt=1, stage="failed")


async def test_o1_an_alert_needs_its_tenant_row(dsn):
    """An alert for a tenant that has no tenant row is refused; a registered one is accepted. (O1)"""
    import psycopg

    _plant_alert(dsn, tenant=T1)
    with pytest.raises(psycopg.errors.ForeignKeyViolation):
        _plant_alert(dsn, tenant=str(uuid.uuid4()))


async def test_d_c_an_alert_for_a_tenant_with_no_row_is_an_unknown_reference_and_stores_nothing(dsn):
    """`insert_alert` for an unregistered tenant → `UnknownReference`, zero rows; a registered tenant's insert works. (D-c, O2)"""
    from defender.jobs import UnknownReference

    async with job_store(dsn) as store:
        stored = await an_alert(store, T1)  # control: the same call for a registered tenant
        with pytest.raises(UnknownReference):
            await an_alert(store, str(uuid.uuid4()), ticket="T-2")
    assert execute(dsn, "SELECT count(*) FROM jobs.alerts") == [(1,)]
    assert stored.alert_id


async def test_o1_one_attempt_number_per_alert_and_request_key(dsn):
    """`(tenant, alert, request key, attempt)` is unique, whatever the stages; the next attempt, another key, another alert are not. (O1)"""
    import psycopg

    alert = _plant_alert(dsn)
    other = _plant_alert(dsn, ticket="P-2")
    _plant_investigation(dsn, tenant=T1, alert_id=alert, key="k1", attempt=1, stage="failed")
    with pytest.raises(psycopg.errors.UniqueViolation):
        _plant_investigation(dsn, tenant=T1, alert_id=alert, key="k1", attempt=1, stage="completed")
    _plant_investigation(dsn, tenant=T1, alert_id=alert, key="k1", attempt=2, stage="failed")
    _plant_investigation(dsn, tenant=T1, alert_id=alert, key="k2", attempt=1, stage="failed")
    _plant_investigation(dsn, tenant=T1, alert_id=other, key="k1", attempt=1, stage="failed")
    assert _count(dsn, "investigations") == 4


@pytest.mark.parametrize("stage", ["queued", "running", "completed", "unparseable", "failed", "aborted"])
async def test_o1_each_of_the_six_stages_is_accepted(dsn, stage):
    """The stage CHECK's positive control: every one of the six values inserts. (O1)"""
    alert = _plant_alert(dsn)
    stored = _plant_investigation(dsn, tenant=T1, alert_id=alert, key="k1", attempt=1, stage=stage)
    assert row(dsn, stored)["stage"] == stage


@pytest.mark.parametrize("stage", ["bogus", "Queued", "RUNNING", "cancelled", "done", "", " queued"])
async def test_o1_any_other_stage_is_refused_by_the_database(dsn, stage):
    """A stage outside the six values violates the CHECK, whatever the spelling. (O1)"""
    import psycopg

    alert = _plant_alert(dsn)
    with pytest.raises(psycopg.errors.CheckViolation):
        _plant_investigation(dsn, tenant=T1, alert_id=alert, key="k1", attempt=1, stage=stage)
    assert _count(dsn, "investigations") == 0


async def test_o1_an_alert_is_unique_per_tenant_vendor_and_vendor_ticket(dsn):
    """The same `(tenant, vendor, ticket)` twice is refused; another tenant, vendor or ticket is not. (O1)"""
    import psycopg

    _plant_alert(dsn, tenant=T1, vendor="elastic", ticket="X")
    with pytest.raises(psycopg.errors.UniqueViolation):
        _plant_alert(dsn, tenant=T1, vendor="elastic", ticket="X")
    _plant_alert(dsn, tenant=T2, vendor="elastic", ticket="X")
    _plant_alert(dsn, tenant=T1, vendor="splunk", ticket="X")
    _plant_alert(dsn, tenant=T1, vendor="elastic", ticket="Y")
    assert _count(dsn, "alerts") == 4


def test_o1_the_store_loads_nothing_the_api_must_not():
    """`defender.jobs` loads without the runtime, so the API can load it. (O1, packages)"""
    from defender.tests.api.test_1080_api_loads import _loaded
    from defender.tests.tooling.layout_contracts._spec1080 import api_forbidden

    loaded = _loaded("defender.jobs")
    assert "defender.jobs" in loaded, "premise: the probe imported the store"
    assert api_forbidden(loaded) == []


# --- O12: the store is async --------------------------------------------------------------------------

@pytest.mark.parametrize("name", ["insert_alert", "get_alert", "get_investigation", "create_investigation",
                                  "cancel_investigation", "delete_investigation", "claim", "close"])
def test_o12_every_store_method_is_a_coroutine_function(name):
    """The ratified surface is awaited, never blocking. (O12)"""
    from defender.jobs import JobStore

    assert inspect.iscoroutinefunction(getattr(JobStore, name))


# --- O2: the trusted alert insert -------------------------------------------------------------------------

#: Admitted by `admit()` and unusual: nothing about the bytes may be normalised.
ADMITTED = {
    "key order, trailing zero, escape": ALERT_BYTES,
    "duplicate keys": b'{"a": 1, "a": 2, "b": {"c": 1, "c": [1, 1]}}',
    "huge numbers": b'{"n": 123456789012345678901234567890123456789, "f": 1.0e+400, "g": -0.0, "h": 1E5}',
    "NaN and Infinity tokens": b'{"x": NaN, "y": -Infinity, "z": Infinity}',
    "odd whitespace": b' \t\r\n{ "a"\t:\r\n1 ,\n"b" : [ ] }\n\n\t ',
    "CRLF lines": b'{\r\n"a": 1\r\n}\r\n',
    "no trailing newline": b'{"a":1}',
    "several trailing newlines": b'{"a":1}\n\n\n',
    "NUL escape, raw multibyte, escaped pair": '{"k": "\\u0000 é 日本 😀", "p": "\\ud83d\\ude00"}'.encode(),
    "empty object": b"{}",
    "one mebibyte string": b'{"a": "' + b"x" * (1 << 20) + b'"}',
}

#: What `admit()` refuses; the store refuses the same and keeps nothing.
REFUSED = {
    "byte-order mark": b"\xef\xbb\xbf{}",
    "UTF-16": "{}".encode("utf-16"),
    "not UTF-8": b'{"a": "\xff"}',
    "an array": b"[1, 2]",
    "a scalar": b"1",
    "null": b"null",
    "empty": b"",
    "two objects": b"{}{}",
    "trailing garbage": b"{} x",
    "unpaired surrogate escape": b'{"a": "\\ud800"}',
    "deep nesting": b'{"a":' * 500_000 + b"1" + b"}" * 500_000,
}


@pytest.mark.parametrize("name", sorted(ADMITTED))
async def test_o2_an_admitted_alert_round_trips_its_exact_bytes(dsn, name):
    """The stored and the read raw alert are the inserted bytes, byte for byte, as `bytes`. (O2, M5)"""
    raw = ADMITTED[name]
    async with job_store(dsn) as store:
        inserted = await an_alert(store, T1, raw=raw)
        read = await store.get_alert(T1, inserted.alert_id)

    assert type(read.raw) is bytes
    assert read.raw == raw
    [(stored,)] = execute(dsn, "SELECT raw FROM jobs.alerts WHERE id = %s", (inserted.alert_id,))
    assert bytes(stored) == raw
    assert execute(dsn, "SELECT length(raw) FROM jobs.alerts WHERE id = %s", (inserted.alert_id,)) == [(len(raw),)]


async def test_o2_title_and_description_are_the_callers_and_the_rest_of_the_row_is_read_back(dsn):
    """Display fields and times come from the caller, untouched; the read row carries all of them. (O2)"""
    title, description = "ünï \n 日本 'quoted' \"q\" %s", "line1\nline2 \t end"
    changed = NOW + HOUR
    async with job_store(dsn) as store:
        inserted = await store.insert_alert(
            T1, vendor="splunk", vendor_ticket_id="SPL-9", fired_at=NOW, changed_at=changed,
            received_at=NOW + 2 * HOUR, title=title, description=description, raw=ALERT_BYTES)
        read = await store.get_alert(T1, inserted.alert_id)

    assert (read.alert_id, read.vendor, read.vendor_ticket_id) == (inserted.alert_id, "splunk", "SPL-9")
    assert (read.title, read.description) == (title, description)
    assert (read.fired_at, read.changed_at, read.received_at) == (NOW, changed, NOW + 2 * HOUR)
    assert execute(dsn, "SELECT title, description FROM jobs.alerts WHERE id = %s",
                   (inserted.alert_id,)) == [(title, description)]


@pytest.mark.parametrize("name", sorted(REFUSED))
async def test_o2_what_admit_refuses_is_refused_and_nothing_is_stored(dsn, name):
    """`admit()`'s refusal reaches the caller as `AlertRefused`; the table stays empty; a good alert still goes in. (O2, scenario)"""
    from defender.records.formats import AlertRefused, admit

    with pytest.raises(AlertRefused):  # premise: the fixture is refused by admission itself
        admit(REFUSED[name])
    async with job_store(dsn) as store:
        with pytest.raises(AlertRefused):
            await an_alert(store, T1, raw=REFUSED[name])
        assert _count(dsn, "alerts") == 0
        await an_alert(store, T1)  # positive control on the same path
    assert _count(dsn, "alerts") == 1


async def test_o2_a_second_insert_of_one_vendor_ticket_is_a_conflict_and_changes_nothing(dsn):
    """A duplicate `(tenant, vendor, ticket)` raises `Conflict`; the first alert's bytes stay; another tenant may insert. (O2, M10)"""
    from defender.jobs import Conflict

    async with job_store(dsn) as store:
        first = await an_alert(store, T1, ticket="T-1", raw=b'{"first": true}')
        with pytest.raises(Conflict):
            await an_alert(store, T1, ticket="T-1", raw=b'{"second": true}')
        read = await store.get_alert(T1, first.alert_id)
        await an_alert(store, T2, ticket="T-1")  # same ticket, other tenant

    assert read.raw == b'{"first": true}'
    assert _count(dsn, "alerts") == 2


async def test_o2_an_alert_is_read_only_by_its_own_tenant(dsn):
    """Another tenant's read of an alert id never returns it; the owner's does (control). (O2, O3)"""
    async with job_store(dsn) as store:
        alert = await an_alert(store, T1)
        assert (await store.get_alert(T1, alert.alert_id)).alert_id == alert.alert_id
        await _absent(store.get_alert(T2, alert.alert_id))


# --- O3: create ----------------------------------------------------------------------------------------------

async def test_o3_a_first_request_queues_attempt_one(dsn):
    """A new request key inserts attempt 1, `queued`, `created=True`. (O3)"""
    async with job_store(dsn) as store:
        alert = await an_alert(store, T1)
        inv, created = await store.create_investigation(T1, alert.alert_id, "k1", actor="u-1")

    assert created is True
    assert (inv.request_key, inv.attempt, inv.stage, inv.alert_id) == ("k1", 1, "queued", alert.alert_id)
    stored = row(dsn, inv.investigation_id)
    assert (stored["stage"], stored["attempt"], stored["request_key"], stored["started_at"]) == (
        "queued", 1, "k1", None)
    assert (inv.cost_usd, stored["cost_usd"]) == (0, 0), "cost reads 0 (not unknown) until the end (D-n)"
    assert execute(dsn, "SELECT tenant_id, created_at FROM jobs.investigations WHERE id = %s",
                   (inv.investigation_id,)) == [(T1, NOW)]


@pytest.mark.parametrize("key", ["x" * 200, "ü-日本-😀", "has space and \"quotes\"", "0"])
async def test_o3_the_request_key_is_kept_as_given(dsn, key):
    """Keys up to the API's 200 characters, non-ASCII included, round-trip and replay. (O3)"""
    async with job_store(dsn) as store:
        alert = await an_alert(store, T1)
        inv, created = await store.create_investigation(T1, alert.alert_id, key, actor="u-1")
        again, created_again = await store.create_investigation(T1, alert.alert_id, key, actor="u-1")

    assert (created, created_again) == (True, False)
    assert inv.request_key == again.request_key == key
    assert again.investigation_id == inv.investigation_id


async def test_o3_a_replay_of_a_live_request_returns_it_and_inserts_nothing(dsn):
    """Same key while queued: the same investigation, `created=False`, one row. (O3)"""
    async with job_store(dsn) as store:
        alert = await an_alert(store, T1)
        first, _ = await store.create_investigation(T1, alert.alert_id, "k1", actor="u-1")
        again, created = await store.create_investigation(T1, alert.alert_id, "k1", actor="u-1")

    assert (created, again.investigation_id) == (False, first.investigation_id)
    assert _count(dsn, "investigations") == 1


@pytest.mark.parametrize("stage", TERMINAL)
async def test_o3_a_replay_after_the_run_ended_returns_that_investigation_not_a_new_one(dsn, stage):
    """The key is still the request's after completion or failure: its latest attempt, `created=False`. (O3, scenario)"""
    async with job_store(dsn) as store:
        alert = await an_alert(store, T1)
        first, _ = await store.create_investigation(T1, alert.alert_id, "k1", actor="u-1")
        _set_stage(dsn, first.investigation_id, stage)
        again, created = await store.create_investigation(T1, alert.alert_id, "k1", actor="u-1")

    assert created is False
    assert (again.investigation_id, again.attempt, again.stage) == (first.investigation_id, 1, stage)
    assert _count(dsn, "investigations") == 1


async def test_o3_a_replayed_request_returns_its_latest_attempt(dsn):
    """A replay answers the highest attempt under its key, `created=False`. (O3)"""
    async with job_store(dsn) as store:
        alert = await an_alert(store, T1)
        first, _ = await store.create_investigation(T1, alert.alert_id, "k1", actor="u-1")
        _set_stage(dsn, first.investigation_id, "failed")
        retry = _plant_investigation(dsn, tenant=T1, alert_id=alert.alert_id, key="k1", attempt=2,
                                     stage="queued")

        again, created = await store.create_investigation(T1, alert.alert_id, "k1", actor="u-1")

    assert created is False
    assert (again.investigation_id, again.attempt) == (retry, 2)


async def test_o3_the_latest_attempt_is_the_highest_number_not_the_newest_row(dsn):
    """Attempt 2 planted with an older `created_at` than attempt 1 is still the one returned. (O3)"""
    async with job_store(dsn) as store:
        alert = await an_alert(store, T1)
        _plant_investigation(dsn, tenant=T1, alert_id=alert.alert_id, key="k1", attempt=1, stage="failed",
                             created_at=NOW + HOUR)
        second = _plant_investigation(dsn, tenant=T1, alert_id=alert.alert_id, key="k1", attempt=2,
                                      stage="completed", created_at=NOW - HOUR)
        again, created = await store.create_investigation(T1, alert.alert_id, "k1", actor="u-1")

    assert (again.investigation_id, again.attempt, created) == (second, 2, False)


async def test_o3_a_known_key_wins_over_a_live_investigation_under_another_key(dsn):
    """Key replay is checked first: k1's ended attempt is returned though k2 is live on the alert. (O3)"""
    async with job_store(dsn) as store:
        alert = await an_alert(store, T1)
        ended = _plant_investigation(dsn, tenant=T1, alert_id=alert.alert_id, key="k1", attempt=1,
                                     stage="completed")
        live = _plant_investigation(dsn, tenant=T1, alert_id=alert.alert_id, key="k2", attempt=1,
                                    stage="queued")
        again, created = await store.create_investigation(T1, alert.alert_id, "k1", actor="u-1")

    assert (again.investigation_id, created) == (ended, False)
    assert again.investigation_id != live


async def test_o3_a_new_request_on_a_live_alert_gets_the_live_one_and_its_key_is_not_kept(dsn):
    """Collapsed onto the live investigation; after that one ends, the same key starts a new one. (O3)"""
    async with job_store(dsn) as store:
        alert = await an_alert(store, T1)
        live, _ = await store.create_investigation(T1, alert.alert_id, "k1", actor="u-1")

        collapsed, created = await store.create_investigation(T1, alert.alert_id, "k2", actor="u-2")
        assert (collapsed.investigation_id, collapsed.request_key, created) == (
            live.investigation_id, "k1", False)
        assert _count(dsn, "investigations") == 1
        assert _count(dsn, "investigations", "request_key = 'k2'") == 0

        _set_stage(dsn, live.investigation_id, "completed")
        fresh, created = await store.create_investigation(T1, alert.alert_id, "k2", actor="u-2")

    assert created is True
    assert fresh.investigation_id != live.investigation_id
    assert (fresh.request_key, fresh.attempt) == ("k2", 1)


async def test_o3_the_same_key_on_another_alert_or_tenant_is_a_different_request(dsn):
    """A key is scoped to `(tenant, alert)`: reusing it elsewhere inserts a new attempt 1. (O3)"""
    async with job_store(dsn) as store:
        a1 = await an_alert(store, T1, ticket="T-1")
        a2 = await an_alert(store, T1, ticket="T-2")
        b1 = await an_alert(store, T2, ticket="T-1")
        first, _ = await store.create_investigation(T1, a1.alert_id, "k1", actor="u-1")
        on_a2, c2 = await store.create_investigation(T1, a2.alert_id, "k1", actor="u-1")
        on_b1, c3 = await store.create_investigation(T2, b1.alert_id, "k1", actor="u-1")

    assert (c2, c3) == (True, True)
    assert len({first.investigation_id, on_a2.investigation_id, on_b1.investigation_id}) == 3


@pytest.mark.parametrize("alert_id", [str(uuid.uuid4()), "al-1", "a" * 128], ids=["uuid", "api-style id", "longest id"])
async def test_o3_an_alert_this_tenant_lacks_is_an_unknown_reference(dsn, alert_id):
    """An alert id that exists nowhere is `UnknownReference` (API-shaped ids too), and nothing is inserted. (O3)"""
    from defender.jobs import UnknownReference

    async with job_store(dsn) as store:
        with pytest.raises(UnknownReference):
            await store.create_investigation(T1, alert_id, "k1", actor="u-1")
    assert _count(dsn, "investigations") == 0


async def test_o3_another_tenants_alert_is_an_unknown_reference_and_nothing_is_inserted(dsn):
    """T2 naming T1's alert id gets `UnknownReference`; T1's own create (control) works. (O3)"""
    from defender.jobs import UnknownReference

    async with job_store(dsn) as store:
        alert = await an_alert(store, T1)
        with pytest.raises(UnknownReference):
            await store.create_investigation(T2, alert.alert_id, "k1", actor="u-1")
        assert _count(dsn, "investigations") == 0
        _, created = await store.create_investigation(T1, alert.alert_id, "k1", actor="u-1")
    assert created is True


async def test_o3_create_waits_for_the_alert_lock(dsn):
    """While another transaction holds the alert row, create blocks, then completes with one new row. (O3, serialize)"""
    async with job_store(dsn) as store:
        alert = await an_alert(store, T1)
        async with holding_alert(dsn, alert.alert_id):
            pending = asyncio.ensure_future(store.create_investigation(T1, alert.alert_id, "k1", actor="u-1"))
            await until_blocked(dsn, 1)
            assert not pending.done()
        inv, created = await asyncio.wait_for(pending, 10)
    assert (created, inv.attempt) == (True, 1)
    assert _count(dsn, "investigations") == 1


@pytest.mark.parametrize("same_key", [False, True], ids=["distinct keys", "one key"])
async def test_o3_concurrent_creates_for_one_alert_serialize_to_one_new_investigation(dsn, same_key):
    """Eight creates from eight stores: none fails, exactly one inserts, all answer one investigation. (O3, scenario)"""
    from defender.jobs import JobStore

    async with job_store(dsn) as setup:
        alert = await an_alert(setup, T1)
    stores = [JobStore(dsn, clock=Clock()) for _ in range(8)]
    try:
        outcomes = await asyncio.gather(*(
            s.create_investigation(T1, alert.alert_id, "k" if same_key else f"k{n}", actor=f"u-{n}")
            for n, s in enumerate(stores)))
    finally:
        await asyncio.gather(*(s.close() for s in stores))

    assert sorted(created for _, created in outcomes) == [False] * 7 + [True]
    assert len({inv.investigation_id for inv, _ in outcomes}) == 1
    assert _count(dsn, "investigations") == 1


# --- O4: claim -------------------------------------------------------------------------------------------------

async def test_o4_a_claim_runs_the_oldest_queued_row_first_and_stamps_started_at(dsn):
    """Rows planted newest-first are claimed oldest-first; `started_at` is the claim's clock, `running`. (O4)"""
    clock = Clock()
    alerts = [_plant_alert(dsn, ticket=f"P-{n}") for n in range(3)]
    ids = {n: _plant_investigation(dsn, tenant=T1, alert_id=a, key="k", attempt=1, stage="queued",
                                   created_at=NOW - n * HOUR)
           for n, a in reversed(list(enumerate(alerts)))}  # planted newest first; n=2 is the oldest
    claimed_at = NOW + 5 * HOUR
    clock.at = claimed_at
    async with store_with(dsn, clock) as store:
        got = [await store.claim() for _ in range(4)]

    assert [g.investigation_id for g in got[:3]] == [ids[2], ids[1], ids[0]]
    assert got[3] is None
    first = row(dsn, ids[2])
    assert (first["stage"], first["started_at"], first["finished_at"]) == ("running", claimed_at, None)
    assert got[0].stage == "running"
    assert (got[0].cost_usd, first["cost_usd"]) == (0, 0), "a claimed row reads cost 0 (D-n)"


async def test_o4_rows_created_together_are_claimed_lowest_id_first(dsn):
    """Equal `created_at`: the lower id is claimed first, whatever the insert order. (O4, D-e)"""
    low, high = "00000000-0000-4000-8000-000000000001", "ffffffff-ffff-4fff-8fff-ffffffffffff"
    alerts = [_plant_alert(dsn, ticket=f"P-{n}") for n in range(2)]
    for investigation_id, alert_id in ((high, alerts[0]), (low, alerts[1])):  # the higher id goes in first
        execute(dsn, "INSERT INTO jobs.investigations (id, tenant_id, alert_id, request_key, attempt, "
                     "stage, created_at, cost_usd) VALUES (%s, %s, %s, 'k', 1, 'queued', %s, 0)",
                (investigation_id, T1, alert_id, NOW))
    async with job_store(dsn) as store:
        got = [await store.claim() for _ in range(3)]

    assert [g.investigation_id for g in got[:2]] == [low, high]
    assert got[2] is None


async def test_o4_a_claim_skips_every_other_stage(dsn):
    """Running and terminal rows are never claimed; an empty queue answers `None`. (O4)"""
    async with store_with(dsn, Clock()) as store:
        assert await store.claim() is None  # empty
        for n, stage in enumerate(("running", *TERMINAL)):
            _plant_investigation(dsn, tenant=T1, alert_id=_plant_alert(dsn, ticket=f"P-{n}"), key="k",
                                 attempt=1, stage=stage)
        assert await store.claim() is None
        queued = _plant_investigation(dsn, tenant=T1, alert_id=_plant_alert(dsn, ticket="Q"), key="k",
                                      attempt=1, stage="queued")
        assert (await store.claim()).investigation_id == queued  # control: the queued one is found
        assert await store.claim() is None


async def test_o4_a_cancelled_row_is_never_claimed(dsn):
    """Cancel then claim: nothing to claim, the row stays `aborted`; a second queued row still is. (O4, scenario)"""
    async with job_store(dsn) as store:
        a1 = await an_alert(store, T1, ticket="T-1")
        a2 = await an_alert(store, T1, ticket="T-2")
        cancelled, _ = await store.create_investigation(T1, a1.alert_id, "k1", actor="u-1")
        await store.cancel_investigation(T1, cancelled.investigation_id, actor="u-1")
        assert await store.claim() is None
        kept, _ = await store.create_investigation(T1, a2.alert_id, "k2", actor="u-1")
        got = await store.claim()
    assert got.investigation_id == kept.investigation_id
    assert row(dsn, cancelled.investigation_id)["stage"] == "aborted"


async def test_o4_two_claims_race_one_queued_row_and_exactly_one_wins(dsn):
    """Two stores (two pools) claim at once: one gets the row, `running` with `started_at`. (O4, scenario)"""
    async with job_store(dsn) as setup:
        alert = await an_alert(setup, T1)
        inv, _ = await setup.create_investigation(T1, alert.alert_id, "k1", actor="u-1")

    async with job_store(dsn) as a, job_store(dsn) as b:
        got = await asyncio.gather(a.claim(), b.claim())

    winners = [g for g in got if g is not None]
    assert [w.investigation_id for w in winners] == [inv.investigation_id]
    stored = row(dsn, inv.investigation_id)
    assert (stored["stage"], stored["started_at"]) == ("running", NOW)


async def test_o4_three_workers_draining_six_rows_claim_each_row_once(dsn):
    """Concurrent claim loops from three stores: every queued row is claimed by exactly one. (O4)"""
    ids = {_plant_investigation(dsn, tenant=T1, alert_id=_plant_alert(dsn, ticket=f"P-{n}"), key="k",
                                attempt=1, stage="queued", created_at=NOW + n * dt.timedelta(minutes=1))
           for n in range(6)}

    async def drain(store: Any) -> list[str]:
        mine = []
        while (claimed := await store.claim()) is not None:
            mine.append(claimed.investigation_id)
            await asyncio.sleep(0)
        return mine

    async with job_store(dsn) as a, job_store(dsn) as b, job_store(dsn) as c:
        parts = await asyncio.gather(drain(a), drain(b), drain(c))

    everything = [i for part in parts for i in part]
    assert sorted(everything) == sorted(ids)
    assert execute(dsn, "SELECT count(*) FROM jobs.investigations WHERE stage = 'running'") == [(6,)]


async def test_o4_a_row_locked_elsewhere_is_skipped_not_waited_for(dsn):
    """`SKIP LOCKED`: while another transaction holds the only queued row, claim returns nothing at once. (O4)"""
    import psycopg

    async with job_store(dsn) as store:
        alert = await an_alert(store, T1)
        inv, _ = await store.create_investigation(T1, alert.alert_id, "k1", actor="u-1")
        async with await psycopg.AsyncConnection.connect(dsn) as conn:
            await conn.execute("SELECT id FROM jobs.investigations WHERE id = %s FOR UPDATE",
                               (inv.investigation_id,))
            assert await asyncio.wait_for(store.claim(), timeout=5) is None
            await conn.commit()
        claimed = await store.claim()
    assert claimed is not None
    assert claimed.investigation_id == inv.investigation_id


async def test_o4_a_claim_audits_with_the_system_actor_once_per_winner(dsn, caplog):
    """`investigation.claim`, actor `system`, one event for the one row claimed; none when nothing is claimed. (O4, O13)"""
    audit = JobsAudit(caplog)
    async with job_store(dsn) as store:
        alert = await an_alert(store, T1)
        inv, _ = await store.create_investigation(T1, alert.alert_id, "k1", actor="u-1")
        before = len(audit.events())
        await store.claim()
        await store.claim()  # nothing left
    claims = audit.events()[before:]
    assert [(e.action, e.actor, e.tenant_id, e.target) for e in claims] == [
        ("investigation.claim", "system", T1, inv.investigation_id)]


# --- O9: cancel ----------------------------------------------------------------------------------------------------

async def test_o9_cancel_aborts_queued_and_refuses_running_and_ended(dsn):
    """queued → `aborted`/`cancelled`; running → "not yet"; terminal → "already ended". (O9)"""
    from defender.jobs import Conflict

    async with job_store(dsn) as store:
        a1 = await an_alert(store, T1, ticket="T-1")
        a2 = await an_alert(store, T1, ticket="T-2")
        queued, _ = await store.create_investigation(T1, a1.alert_id, "k1", actor="u-1")
        running, _ = await store.create_investigation(T1, a2.alert_id, "k2", actor="u-1")
        _set_stage(dsn, running.investigation_id, "running")

        cancelled = await store.cancel_investigation(T1, queued.investigation_id, actor="u-1")
        with pytest.raises(Conflict, match="cannot cancel a running investigation yet"):
            await store.cancel_investigation(T1, running.investigation_id, actor="u-1")
        with pytest.raises(Conflict, match="already ended"):
            await store.cancel_investigation(T1, queued.investigation_id, actor="u-1")

    assert (cancelled.stage, cancelled.failure_reason) == ("aborted", "cancelled")
    stored = row(dsn, queued.investigation_id)
    assert (stored["stage"], stored["failure_reason"], stored["finished_at"]) == ("aborted", "cancelled", NOW)
    assert (stored["started_at"], stored["disposition"]) == (None, None)
    assert (cancelled.cost_usd, stored["cost_usd"]) == (0, 0), "a cancelled row reads cost 0 (D-n)"
    assert row(dsn, running.investigation_id)["stage"] == "running"


@pytest.mark.parametrize("stage", TERMINAL)
async def test_o9_cancel_of_an_ended_investigation_changes_nothing(dsn, stage):
    """Every terminal stage answers "already ended" and the row is as it was. (O9)"""
    from defender.jobs import Conflict

    async with job_store(dsn) as store:
        alert = await an_alert(store, T1)
        inv, _ = await store.create_investigation(T1, alert.alert_id, "k1", actor="u-1")
        _set_stage(dsn, inv.investigation_id, stage)
        before = row(dsn, inv.investigation_id)
        with pytest.raises(Conflict, match="already ended"):
            await store.cancel_investigation(T1, inv.investigation_id, actor="u-1")
    assert row(dsn, inv.investigation_id) == before


@pytest.mark.parametrize("target", [str(uuid.uuid4()), "inv-1"], ids=["uuid", "api-style id"])
async def test_o9_cancel_of_an_unknown_or_another_tenants_investigation_is_not_found(dsn, target):
    """No such id, or another tenant's, is `NotFound`; that tenant's own cancel (control) works. (O9)"""
    from defender.jobs import NotFound

    async with job_store(dsn) as store:
        alert = await an_alert(store, T1)
        inv, _ = await store.create_investigation(T1, alert.alert_id, "k1", actor="u-1")
        with pytest.raises(NotFound):
            await store.cancel_investigation(T1, target, actor="u-1")
        with pytest.raises(NotFound):
            await store.cancel_investigation(T2, inv.investigation_id, actor="u-1")
        assert row(dsn, inv.investigation_id)["stage"] == "queued"
        await store.cancel_investigation(T1, inv.investigation_id, actor="u-1")


async def test_o9_a_cancelled_alert_can_be_investigated_again(dsn):
    """Aborting frees the alert: a new key queues a new attempt 1; the old key still answers the aborted one. (O9, O1)"""
    async with job_store(dsn) as store:
        alert = await an_alert(store, T1)
        first, _ = await store.create_investigation(T1, alert.alert_id, "k1", actor="u-1")
        await store.cancel_investigation(T1, first.investigation_id, actor="u-1")
        fresh, created = await store.create_investigation(T1, alert.alert_id, "k2", actor="u-1")
        replay, replayed_created = await store.create_investigation(T1, alert.alert_id, "k1", actor="u-1")
    assert (created, fresh.attempt) == (True, 1)
    assert fresh.investigation_id != first.investigation_id
    assert (replay.investigation_id, replay.stage, replayed_created) == (first.investigation_id, "aborted", False)


async def test_o9_cancel_loses_to_a_claim_committed_while_it_waits(dsn):
    """A claim committing under cancel's feet wins: cancel says "not yet" and does not overwrite `running`. (O9, scenario)"""
    import psycopg
    from defender.jobs import Conflict

    async with job_store(dsn) as store:
        alert = await an_alert(store, T1)
        inv, _ = await store.create_investigation(T1, alert.alert_id, "k1", actor="u-1")
        async with await psycopg.AsyncConnection.connect(dsn) as conn:
            await conn.execute("UPDATE jobs.investigations SET stage = 'running', started_at = %s WHERE id = %s",
                               (NOW, inv.investigation_id))
            pending = asyncio.ensure_future(store.cancel_investigation(T1, inv.investigation_id, actor="u-1"))
            await until_blocked(dsn, 1)
            await conn.commit()
        with pytest.raises(Conflict, match="cannot cancel a running investigation yet"):
            await asyncio.wait_for(pending, 10)
    stored = row(dsn, inv.investigation_id)
    assert (stored["stage"], stored["failure_reason"]) == ("running", None)


async def test_o9_a_claim_skips_a_row_whose_cancel_is_uncommitted_and_never_claims_it_after(dsn):
    """While a cancel is in flight claim returns at once with nothing; once it commits the row is still unclaimed. (O4, O9, scenario)"""
    import psycopg

    async with job_store(dsn) as store:
        alert = await an_alert(store, T1)
        inv, _ = await store.create_investigation(T1, alert.alert_id, "k1", actor="u-1")
        async with await psycopg.AsyncConnection.connect(dsn) as conn:
            await conn.execute("UPDATE jobs.investigations SET stage = 'aborted', failure_reason = 'cancelled', "
                               "finished_at = %s WHERE id = %s", (NOW, inv.investigation_id))
            assert await asyncio.wait_for(store.claim(), 5) is None
            await conn.commit()
        assert await store.claim() is None
    assert row(dsn, inv.investigation_id)["stage"] == "aborted"


async def test_o9_cancel_and_claim_racing_for_one_row_have_exactly_one_winner(dsn):
    """Twenty rounds of cancel against claim: claim won ⇒ cancel refused "not yet", `running`; else `aborted`, claim nothing. (O9, scenario)"""
    from defender.jobs import Conflict

    outcomes = set()
    async with job_store(dsn) as setup, job_store(dsn) as a, job_store(dsn) as b:
        for n in range(20):
            alert = await an_alert(setup, T1, ticket=f"R-{n}")
            inv, _ = await setup.create_investigation(T1, alert.alert_id, f"k{n}", actor="u-1")
            cancelled, claimed = await asyncio.gather(
                a.cancel_investigation(T1, inv.investigation_id, actor="u-1"), b.claim(),
                return_exceptions=True)
            stage = row(dsn, inv.investigation_id)["stage"]
            if claimed is None:
                assert not isinstance(cancelled, BaseException), cancelled
                assert (cancelled.stage, stage) == ("aborted", "aborted")
                outcomes.add("cancel")
            else:
                assert claimed.investigation_id == inv.investigation_id
                assert isinstance(cancelled, Conflict)
                assert "running" in str(cancelled)
                assert stage == "running"
                outcomes.add("claim")
    assert outcomes <= {"cancel", "claim"}


# --- O10: delete ---------------------------------------------------------------------------------------------------

async def test_o10_delete_removes_every_attempt_and_a_replay_starts_afresh(dsn):
    """Refused while any attempt is live; then every attempt goes, and the key mints a new attempt 1. (O10)"""
    from defender.jobs import Conflict, NotFound

    async with job_store(dsn) as store:
        alert = await an_alert(store, T1)
        first, _ = await store.create_investigation(T1, alert.alert_id, "k1", actor="u-1")
        _set_stage(dsn, first.investigation_id, "failed")
        retry = _plant_investigation(dsn, tenant=T1, alert_id=alert.alert_id, key="k1", attempt=2,
                                     stage="queued")

        with pytest.raises(Conflict):
            await store.delete_investigation(T1, first.investigation_id, actor="u-1")
        assert row(dsn, first.investigation_id) is not None

        _set_stage(dsn, retry, "failed")
        await store.delete_investigation(T1, first.investigation_id, actor="u-1")
        assert _count(dsn, "investigations", "request_key = 'k1'") == 0

        with pytest.raises(NotFound):
            await store.delete_investigation(T1, first.investigation_id, actor="u-1")
        again, created = await store.create_investigation(T1, alert.alert_id, "k1", actor="u-1")

    assert created is True
    assert again.investigation_id not in {first.investigation_id, retry}
    assert again.attempt == 1


@pytest.mark.parametrize("live", LIVE)
async def test_o10_delete_while_the_investigation_is_live_is_a_conflict_and_removes_nothing(dsn, live):
    """Queued or running: `Conflict`; the row is untouched; ending it then lets delete through. (O10, scenario)"""
    from defender.jobs import Conflict

    async with job_store(dsn) as store:
        alert = await an_alert(store, T1)
        inv, _ = await store.create_investigation(T1, alert.alert_id, "k1", actor="u-1")
        _set_stage(dsn, inv.investigation_id, live)
        with pytest.raises(Conflict):
            await store.delete_investigation(T1, inv.investigation_id, actor="u-1")
        assert row(dsn, inv.investigation_id)["stage"] == live
        _set_stage(dsn, inv.investigation_id, "completed")
        await store.delete_investigation(T1, inv.investigation_id, actor="u-1")
    assert row(dsn, inv.investigation_id) is None


async def test_o10_a_live_later_attempt_blocks_deleting_through_an_earlier_one(dsn):
    """Any attempt of the key live refuses the delete, whichever attempt's id is named. (O10)"""
    from defender.jobs import Conflict

    async with job_store(dsn) as store:
        alert = await an_alert(store, T1)
        first = _plant_investigation(dsn, tenant=T1, alert_id=alert.alert_id, key="k1", attempt=1, stage="failed")
        second = _plant_investigation(dsn, tenant=T1, alert_id=alert.alert_id, key="k1", attempt=2,
                                      stage="running")
        for named in (first, second):
            with pytest.raises(Conflict):
                await store.delete_investigation(T1, named, actor="u-1")
    assert _count(dsn, "investigations") == 2


async def test_o10_delete_takes_only_its_own_key_and_leaves_the_alert(dsn):
    """Other keys on the alert, the same key on another alert, and the alert row all stay. (O10)"""
    async with job_store(dsn) as store:
        a1 = await an_alert(store, T1, ticket="T-1")
        a2 = await an_alert(store, T1, ticket="T-2")
        target = _plant_investigation(dsn, tenant=T1, alert_id=a1.alert_id, key="k1", attempt=1, stage="completed")
        second_attempt = _plant_investigation(dsn, tenant=T1, alert_id=a1.alert_id, key="k1", attempt=2,
                                              stage="failed")
        sibling_key = _plant_investigation(dsn, tenant=T1, alert_id=a1.alert_id, key="k2", attempt=1,
                                           stage="completed")
        other_alert = _plant_investigation(dsn, tenant=T1, alert_id=a2.alert_id, key="k1", attempt=1,
                                           stage="completed")
        await store.delete_investigation(T1, second_attempt, actor="u-1")  # naming attempt 2 takes attempt 1 too
        remaining = {r[0] for r in execute(dsn, "SELECT id FROM jobs.investigations")}
        alerts = _count(dsn, "alerts")
    assert target not in remaining
    assert remaining == {sibling_key, other_alert}
    assert alerts == 2


@pytest.mark.parametrize("target", [str(uuid.uuid4()), "inv-1"], ids=["uuid", "api-style id"])
async def test_o10_delete_of_an_unknown_or_another_tenants_investigation_is_not_found(dsn, target):
    """`NotFound` for no such id and for another tenant's; the row survives. (O10)"""
    from defender.jobs import NotFound

    async with job_store(dsn) as store:
        alert = await an_alert(store, T1)
        inv = _plant_investigation(dsn, tenant=T1, alert_id=alert.alert_id, key="k1", attempt=1, stage="failed")
        with pytest.raises(NotFound):
            await store.delete_investigation(T1, target, actor="u-1")
        with pytest.raises(NotFound):
            await store.delete_investigation(T2, inv, actor="u-1")
    assert row(dsn, inv) is not None


async def test_o10_delete_waits_for_the_alert_lock(dsn):
    """While another transaction holds the alert row, delete blocks, then completes. (O10, serialize with create)"""
    async with job_store(dsn) as store:
        alert = await an_alert(store, T1)
        inv = _plant_investigation(dsn, tenant=T1, alert_id=alert.alert_id, key="k1", attempt=1, stage="failed")
        async with holding_alert(dsn, alert.alert_id):
            pending = asyncio.ensure_future(store.delete_investigation(T1, inv, actor="u-1"))
            await until_blocked(dsn, 1)
            assert not pending.done()
            assert row(dsn, inv) is not None
        await asyncio.wait_for(pending, 10)
    assert row(dsn, inv) is None


async def test_o10_a_delete_and_a_create_of_one_alert_leave_a_consistent_state(dsn):
    """Concurrent delete and replay-create: no error, and the final rows agree with what create said. (O10, scenario)"""
    from defender.jobs import JobStore

    async with job_store(dsn) as setup:
        alert = await an_alert(setup, T1)
    old = _plant_investigation(dsn, tenant=T1, alert_id=alert.alert_id, key="k1", attempt=1, stage="failed")
    a, b = JobStore(dsn, clock=Clock()), JobStore(dsn, clock=Clock())
    try:
        _, (inv, created) = await asyncio.gather(
            a.delete_investigation(T1, old, actor="u-1"),
            b.create_investigation(T1, alert.alert_id, "k1", actor="u-2"))
    finally:
        await asyncio.gather(a.close(), b.close())

    rows = {r[0] for r in execute(dsn, "SELECT id FROM jobs.investigations")}
    if created:
        assert inv.investigation_id != old
        assert rows == {inv.investigation_id}
    else:
        assert inv.investigation_id == old
        assert rows == set()


# --- O13: audit after commit ---------------------------------------------------------------------------------------

async def test_o13_create_cancel_delete_are_audited_after_commit_with_the_caller(dsn, caplog):
    """Each event names the calling actor and is emitted once the row change is visible elsewhere. (O13)"""
    audit = JobsAudit(caplog)
    seen = VisibleAtEmit(dsn)
    logging.getLogger(JOBS_AUDIT).addHandler(seen)
    try:
        async with job_store(dsn) as store:
            alert = await an_alert(store, T1)
            inv, _ = await store.create_investigation(T1, alert.alert_id, "k1", actor="u-1")
            await store.cancel_investigation(T1, inv.investigation_id, actor="u-2")
            await store.delete_investigation(T1, inv.investigation_id, actor="u-3")
    finally:
        logging.getLogger(JOBS_AUDIT).removeHandler(seen)

    assert [(e.action, e.actor, e.tenant_id, e.target) for e in audit.events()] == [
        ("investigation.start", "u-1", T1, inv.investigation_id),
        ("investigation.cancel", "u-2", T1, inv.investigation_id),
        ("investigation.delete", "u-3", T1, inv.investigation_id),
    ]
    assert seen.seen == [("investigation.start", "queued"), ("investigation.cancel", "aborted"),
                         ("investigation.delete", None)]


async def test_o13_a_claim_is_audited_only_after_its_commit(dsn, caplog):
    """The claim event is emitted when `running` is already visible on another connection. (O13)"""
    audit = JobsAudit(caplog)
    seen = VisibleAtEmit(dsn)
    async with job_store(dsn) as store:
        alert = await an_alert(store, T1)
        inv, _ = await store.create_investigation(T1, alert.alert_id, "k1", actor="u-1")
        logging.getLogger(JOBS_AUDIT).addHandler(seen)
        try:
            await store.claim()
        finally:
            logging.getLogger(JOBS_AUDIT).removeHandler(seen)
    assert seen.seen == [("investigation.claim", "running")]
    assert audit.events()[-1].target == inv.investigation_id


@pytest.mark.parametrize("refusal", ["unknown alert", "cancel of a running row", "delete of a live row",
                                     "cancel of an unknown id"])
async def test_o13_a_refused_call_emits_nothing(dsn, caplog, refusal):
    """No commit, no event: each class of refusal leaves the audit log as it was. (O13)"""
    from defender.jobs import Conflict, NotFound, UnknownReference

    audit = JobsAudit(caplog)
    async with job_store(dsn) as store:
        alert = await an_alert(store, T1)
        inv, _ = await store.create_investigation(T1, alert.alert_id, "k1", actor="u-1")
        _set_stage(dsn, inv.investigation_id, "running")
        before = audit.events()
        calls = {
            "unknown alert": (UnknownReference,
                              lambda: store.create_investigation(T1, str(uuid.uuid4()), "k2", actor="u-1")),
            "cancel of a running row": (Conflict,
                                        lambda: store.cancel_investigation(T1, inv.investigation_id, actor="u-1")),
            "delete of a live row": (Conflict,
                                     lambda: store.delete_investigation(T1, inv.investigation_id, actor="u-1")),
            "cancel of an unknown id": (NotFound,
                                        lambda: store.cancel_investigation(T1, str(uuid.uuid4()), actor="u-1")),
        }
        expected, call = calls[refusal]
        with pytest.raises(expected):
            await call()
    assert audit.events() == before == [e for e in before if e.action == "investigation.start"]


async def test_o13_a_replay_emits_no_second_start(dsn, caplog):
    """A replay that inserts nothing audits nothing; the first create audited once. (O13)"""
    audit = JobsAudit(caplog)
    async with job_store(dsn) as store:
        alert = await an_alert(store, T1)
        await store.create_investigation(T1, alert.alert_id, "k1", actor="u-1")
        await store.create_investigation(T1, alert.alert_id, "k1", actor="u-2")
        await store.create_investigation(T1, alert.alert_id, "k9", actor="u-3")  # collapsed onto the live one
    assert [(e.action, e.actor) for e in audit.events()] == [("investigation.start", "u-1")]


_BOOM = """CREATE CONSTRAINT TRIGGER boom_1342 AFTER INSERT OR UPDATE OR DELETE ON jobs.investigations
           DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.boom_1342()"""


@pytest.mark.parametrize("operation", ["create", "cancel", "delete", "claim"])
async def test_o13_a_transaction_that_fails_at_commit_emits_nothing_and_stores_nothing(dsn, caplog, operation):
    """A real commit-time fault (a deferred trigger raises): the call raises, the row is as before, no event leaves. (O13)"""
    audit = JobsAudit(caplog)
    execute(dsn, "CREATE FUNCTION public.boom_1342() RETURNS trigger LANGUAGE plpgsql AS "
                 "$$ BEGIN RAISE EXCEPTION 'boom 1342'; END $$")
    async with job_store(dsn) as store:
        alert = await an_alert(store, T1)
        target = _plant_investigation(dsn, tenant=T1, alert_id=_plant_alert(dsn, ticket="Z"), key="z",
                                      attempt=1, stage="failed" if operation == "delete" else "queued")
        if operation == "create":
            do = lambda: store.create_investigation(T1, alert.alert_id, "k1", actor="u-1")  # noqa: E731
        elif operation == "cancel":
            do = lambda: store.cancel_investigation(T1, target, actor="u-1")  # noqa: E731
        elif operation == "delete":
            do = lambda: store.delete_investigation(T1, target, actor="u-1")  # noqa: E731
        else:
            do = store.claim
        before_rows = execute(dsn, "SELECT id, stage FROM jobs.investigations ORDER BY id")
        before_events = audit.events()

        execute(dsn, _BOOM)
        with pytest.raises(Exception):  # noqa: B017, PT011 — the fault's class is the driver's, not the contract's
            await do()
        assert execute(dsn, "SELECT id, stage FROM jobs.investigations ORDER BY id") == before_rows
        assert audit.events() == before_events

        execute(dsn, "DROP TRIGGER boom_1342 ON jobs.investigations")
        await do()  # control: without the fault the same call commits and emits
    assert len(audit.events()) == len(before_events) + 1


# --- D-a: an id PostgreSQL cannot hold names nothing -------------------------------------------------------------

UNSTORABLE_IDS = {"NUL": "a\x00b", "lone NUL": "\x00", "lone surrogate": "\ud800", "surrogate inside": "x\udfffy"}


@pytest.mark.parametrize("bad", sorted(UNSTORABLE_IDS))
async def test_d_a_an_id_the_database_cannot_hold_reads_as_unknown_and_never_crashes(dsn, bad):
    """Get, create, cancel, delete and finish treat a NUL or lone-surrogate id as an unknown one. (D-a)"""
    from defender.jobs import NotFound, UnknownReference

    ident = UNSTORABLE_IDS[bad]
    async with job_store(dsn) as store:
        alert = await an_alert(store, T1)
        inv, _ = await store.create_investigation(T1, alert.alert_id, "k1", actor="u-1")
        await _absent(store.get_alert(T1, ident))
        await _absent(store.get_investigation(T1, ident))
        with pytest.raises(UnknownReference):
            await store.create_investigation(T1, ident, "k2", actor="u-1")
        with pytest.raises(NotFound):
            await store.cancel_investigation(T1, ident, actor="u-1")
        with pytest.raises(NotFound):
            await store.delete_investigation(T1, ident, actor="u-1")
        assert await store.finish(T1, ident, stage="failed", failure_reason="worker_error") is None
        assert row(dsn, inv.investigation_id)["stage"] == "queued"
    assert _count(dsn, "investigations") == 1


# --- O5: the store's finish is fenced on `running` -----------------------------------------------------------------

async def test_o5_finish_ends_a_running_row_once_and_returns_it(dsn):
    """A running row finishes with its stage, disposition and cost; a second finish changes nothing. (O5, O8)"""
    async with job_store(dsn) as store:
        alert = await an_alert(store, T1)
        inv, _ = await store.create_investigation(T1, alert.alert_id, "k1", actor="u-1")
        assert (await store.claim()).investigation_id == inv.investigation_id
        done = await store.finish(T1, inv.investigation_id, stage="completed", disposition="benign", cost_usd=1.5)
        again = await store.finish(T1, inv.investigation_id, stage="failed", failure_reason="no_report")

    assert (done.stage, done.disposition, done.cost_usd) == ("completed", "benign", 1.5)
    assert again is None
    stored = row(dsn, inv.investigation_id)
    assert (stored["stage"], stored["disposition"], stored["failure_reason"], stored["finished_at"]) == (
        "completed", "benign", None, NOW)


async def test_o5_finish_of_a_queued_row_changes_nothing(dsn):
    """A row the worker never claimed is not finished: `None`, row untouched. (O5)"""
    async with job_store(dsn) as store:
        alert = await an_alert(store, T1)
        inv, _ = await store.create_investigation(T1, alert.alert_id, "k1", actor="u-1")
        before = row(dsn, inv.investigation_id)
        assert await store.finish(T1, inv.investigation_id, stage="failed", failure_reason="worker_error") is None
    assert row(dsn, inv.investigation_id) == before
    assert before["stage"] == "queued"


@pytest.mark.parametrize("moved_to", TERMINAL)
async def test_o5_finish_of_a_row_that_moved_to_a_terminal_stage_changes_nothing(dsn, moved_to):
    """A row ended elsewhere (cancel, B) keeps its stage and fields against a late finish. (O5)"""
    async with job_store(dsn) as store:
        alert = await an_alert(store, T1)
        inv, _ = await store.create_investigation(T1, alert.alert_id, "k1", actor="u-1")
        await store.claim()
        _set_stage(dsn, inv.investigation_id, moved_to)
        before = row(dsn, inv.investigation_id)
        assert await store.finish(T1, inv.investigation_id, stage="completed", disposition="benign") is None
    assert row(dsn, inv.investigation_id) == before


@pytest.mark.parametrize("stage", ["running", "queued", "nonsense"])
async def test_o5_finish_to_a_stage_that_is_not_terminal_is_refused_and_the_row_is_untouched(dsn, stage):
    """`finish` with `running`, `queued` or any other non-terminal stage raises `ValueError` and changes no field of the running row. (O5)"""
    async with job_store(dsn) as store:
        alert = await an_alert(store, T1)
        inv, _ = await store.create_investigation(T1, alert.alert_id, "k1", actor="u-1")
        await store.claim()
        before = row(dsn, inv.investigation_id)
        with pytest.raises(ValueError, match="terminal"):
            await store.finish(T1, inv.investigation_id, stage=stage, failure_reason="worker_error")
    assert row(dsn, inv.investigation_id) == before
    assert before["stage"] == "running"


async def test_o5_finish_of_another_tenants_row_changes_nothing(dsn):
    """Only the owning tenant's running row finishes. (O5)"""
    async with job_store(dsn) as store:
        alert = await an_alert(store, T1)
        inv, _ = await store.create_investigation(T1, alert.alert_id, "k1", actor="u-1")
        await store.claim()
        assert await store.finish(T2, inv.investigation_id, stage="failed", failure_reason="worker_error") is None
        assert row(dsn, inv.investigation_id)["stage"] == "running"


# --- O14 (store side): what the reads carry ----------------------------------------------------------------------------

async def test_o14_a_read_investigation_carries_the_wire_models_fields(dsn):
    """`get_investigation` answers request key, attempt, stage, times, disposition, cost, knowledge, failure detail. (O14)"""
    async with job_store(dsn) as store:
        alert = await an_alert(store, T1)
        inv, _ = await store.create_investigation(T1, alert.alert_id, "k1", actor="u-1")
        execute(dsn, "UPDATE jobs.investigations SET stage = 'failed', started_at = %s, finished_at = %s, "
                     "cost_usd = NULL, failure_reason = 'no_report', failure_message = 'exited 7' WHERE id = %s",
                (NOW, NOW + HOUR, inv.investigation_id))
        read = await store.get_investigation(T1, inv.investigation_id)

    assert (read.investigation_id, read.alert_id, read.request_key, read.attempt) == (
        inv.investigation_id, alert.alert_id, "k1", 1)
    assert (read.stage, read.started_at, read.finished_at) == ("failed", NOW, NOW + HOUR)
    assert (read.failure_reason, read.failure_message, read.disposition) == ("no_report", "exited 7", None)
    assert read.cost_usd is None  # unknown, not zero (R3)


async def test_o14_an_unknown_or_another_tenants_investigation_is_absent(dsn):
    """Reads of an id nobody has, or another tenant's, never return a row; the owner's does (control). (O14)"""
    async with job_store(dsn) as store:
        alert = await an_alert(store, T1)
        inv, _ = await store.create_investigation(T1, alert.alert_id, "k1", actor="u-1")
        assert (await store.get_investigation(T1, inv.investigation_id)).investigation_id == inv.investigation_id
        await _absent(store.get_investigation(T2, inv.investigation_id))
        await _absent(store.get_investigation(T1, "inv-1"))
        await _absent(store.get_investigation(T1, str(uuid.uuid4())))


# --- O15 (store half): another process's store sees the row, stage by stage ----------------------------------------------

async def test_o15_a_row_inserted_through_one_store_is_claimed_and_followed_through_another(dsn):
    """Store A inserts; store B claims it; A reads `running`; SQL ends it; A reads the terminal stage. (O15)"""
    async with job_store(dsn) as a, job_store(dsn) as b:
        alert = await an_alert(a, T1)
        inv, _ = await a.create_investigation(T1, alert.alert_id, "k1", actor="u-1")
        assert (await b.get_investigation(T1, inv.investigation_id)).stage == "queued"

        claimed = await b.claim()
        assert claimed.investigation_id == inv.investigation_id
        assert (await a.get_investigation(T1, inv.investigation_id)).stage == "running"
        assert await a.claim() is None  # A cannot claim what B holds

        execute(dsn, "UPDATE jobs.investigations SET stage = 'completed', disposition = 'benign', "
                     "finished_at = %s, cost_usd = 1.25 WHERE id = %s", (NOW + HOUR, inv.investigation_id))
        done = await a.get_investigation(T1, inv.investigation_id)
        assert (done.stage, done.disposition, done.cost_usd, done.finished_at) == (
            "completed", "benign", 1.25, NOW + HOUR)
        replay, created = await b.create_investigation(T1, alert.alert_id, "k1", actor="u-1")
    assert (replay.investigation_id, replay.stage, created) == (inv.investigation_id, "completed", False)
