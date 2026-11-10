"""#1342 the job store over PostgreSQL: tables and their rules (O1), the trusted alert insert (O2),
create's replay rules (O3), the claim (O4), cancel (O9), delete (O10), audit after commit (O13),
the API-shaped reads (O14 store side), cross-process visibility (O15) and async methods (O12).

Entry: `defender.jobs.JobStore(dsn, clock=)` on a per-test migrated database; rows are read back on a
separate connection. Rows the store has no A-path for (an attempt 2, a terminal stage) are planted by
SQL, as B and the worker would leave them. Column names used in SQL are the sketch's (unratified)."""
from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import datetime as dt
import inspect
import json
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
    accounting_written,
    an_alert,
    job_store,
    lapse_lease,
    lease_left,
    lower_limit,
    register_tenant,
    row,
)
from defender.tests.support.shared._pglocks1339 import blocked, until, until_blocked
from defender.tests.support.shared._postgres1339 import execute
from defender.tests.support.tenancy._mapping1345 import assert_missing_wording_names_verb_and_route, mapping_value

pytestmark = [pytest.mark.anyio, pytest.mark.postgres]

HOUR = dt.timedelta(hours=1)
LIVE = ("queued", "running")
TERMINAL = ("completed", "unparseable", "failed", "aborted")
JOBS_AUDIT = "defender.jobs.audit"


@pytest.fixture
def dsn(migrated_database: str) -> str:
    """T1 and T2 registered, each holding the default alert mapping (#1345: a tenant without one is refused an investigation)."""
    register_tenant(migrated_database, T1)
    register_tenant(migrated_database, T2)
    return migrated_database


@pytest.fixture
def unmapped_dsn(migrated_database: str) -> str:
    """T1 and T2 registered with NO alert mapping saved (#1345 D2: the absence cases opt out of the default)."""
    register_tenant(migrated_database, T1, alert_mapping=None)
    register_tenant(migrated_database, T2, alert_mapping=None)
    return migrated_database


# --- machinery: SQL plants, locks, a clock the test moves ------------------------------------------

def _plant_alert(dsn: str, *, tenant: str = T1, ticket: str = "P-1", vendor: str = "elastic", alert_id: str | None = None) -> str:
    alert_id = alert_id or str(uuid.uuid4())
    execute(dsn, "INSERT INTO jobs.alerts (id, tenant_id, vendor, vendor_ticket_id, fired_at, changed_at, "
                 "received_at, title, description, raw) VALUES (%s, %s, %s, %s, %s, %s, %s, 't', 'd', %s)",
            (alert_id, tenant, vendor, ticket, NOW, NOW, NOW, b"{}"))
    return alert_id


def _plant_investigation(dsn: str, *, tenant: str, alert_id: str, key: str, attempt: int, stage: str,
                         created_at: dt.datetime = NOW, worked: tuple[str, bool] | None = None) -> str:
    """A row in `stage`. `worked` = (`failure_reason` or "", whether its holder wrote its final figure) plants a row that was
    started, cost 1.25 and ended."""
    investigation_id = str(uuid.uuid4())
    lease = "now() + interval '30 seconds'" if stage == "running" else "NULL"  # #1343: a running row has a lease
    reason, accounted = worked or ("", False)
    execute(dsn, "INSERT INTO jobs.investigations (id, tenant_id, alert_id, request_key, attempt, stage, created_at, "
                 "started_at, finished_at, failure_reason, accounting_written_at, "
                 f"cost_usd, cost_is_lower_limit, lease_expires_at) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, false, {lease})",  # noqa: S608
            (investigation_id, tenant, alert_id, key, attempt, stage, created_at, NOW if worked else None,
             NOW if worked else None, reason or None, NOW if accounted else None,
             1.25 if worked else 0))
    return investigation_id


def _set_stage(dsn: str, investigation_id: str, stage: str) -> None:
    execute(dsn, "UPDATE jobs.investigations SET stage = %s, lease_expires_at = CASE WHEN %s = 'running' "
                 "THEN now() + interval '30 seconds' ELSE lease_expires_at END WHERE id = %s",  # #1343: running ⇒ lease
            (stage, stage, investigation_id))


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
    from defender.tests.api.test_api_loads import _loaded
    from defender.tests.tooling.layout_contracts._spec1080 import api_forbidden

    loaded = _loaded("defender.jobs")
    assert "defender.jobs" in loaded, "premise: the probe imported the store"
    assert api_forbidden(loaded) == []


# --- O12: the store is async --------------------------------------------------------------------------

@pytest.mark.parametrize("name", ["insert_alert", "get_alert", "get_investigation", "create_investigation",
                                  "cancel_investigation", "delete_investigation", "claim", "close",
                                  "put_alert_mapping", "get_alert_mapping"])
def test_o12_every_store_method_is_a_coroutine_function(name):
    """The ratified surface is awaited, never blocking; the mapping's replace and read included. (O12, #1345 O1, M1)"""
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
    "one mebibyte alert, the cap": b'{"a": "' + b"x" * ((1 << 20) - 9) + b'"}',
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


async def test_o2_the_display_is_what_the_default_mapping_derives_and_the_rest_of_the_row_is_read_back(dsn):
    """Vendor, ticket id and times come from the caller, untouched; the display is not the caller's but the one the
    seeded default mapping derives from `ALERT_BYTES` (hand-written literal). Rewritten in round 1 (repair 1):
    `insert_alert` no longer takes title/description (design O2, M3). (O2)"""
    title, description = "sketch", "r-1342"  # rule.description and rule.id of ALERT_BYTES, under the default mapping
    changed = NOW + HOUR
    async with job_store(dsn) as store:
        inserted = await store.insert_alert(
            T1, vendor="splunk", vendor_ticket_id="SPL-9", fired_at=NOW, changed_at=changed,
            received_at=NOW + 2 * HOUR, raw=ALERT_BYTES)
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


#: Text PostgreSQL cannot hold (#1379 O1).
UNSTORABLE = {"NUL": "a\x00b", "lone surrogate": "a\ud800b"}


@pytest.mark.parametrize("text", list(UNSTORABLE.values()), ids=list(UNSTORABLE))
@pytest.mark.parametrize("field", ["vendor", "vendor_ticket_id"])
async def test_1379_an_alert_field_postgresql_cannot_hold_is_refused_by_name_and_nothing_is_stored(
        dsn, field, text):
    """The store's own typed refusal, naming the field, before any query; a good alert still goes in. (#1379 O1b)
    The `title`/`description` cases are retired: the store derives them, and derived text it cannot hold becomes null
    (design M3; pinned by the 1345 M3 tests below)."""
    fields = {"vendor": "splunk", "vendor_ticket_id": "SPL-9", field: text}
    async with job_store(dsn) as store:
        with pytest.raises(ValueError, match=rf"\b{field}\b") as refused:
            await store.insert_alert(T1, fired_at=NOW, changed_at=NOW, received_at=NOW, raw=ALERT_BYTES,
                                     **fields)
        from defender.jobs import UnstorableText
        assert type(refused.value) is UnstorableText
        assert _count(dsn, "alerts") == 0
        await an_alert(store, T1)  # positive control on the same path
    assert _count(dsn, "alerts") == 1


@pytest.mark.parametrize("key", list(UNSTORABLE.values()), ids=list(UNSTORABLE))
async def test_1379_a_request_key_postgresql_cannot_hold_is_refused_by_name_and_nothing_is_inserted(dsn, key):
    """(#1379 O1b)"""
    async with job_store(dsn) as store:
        alert = await an_alert(store, T1)
        with pytest.raises(ValueError, match=r"\brequest_key\b") as refused:
            await store.create_investigation(T1, alert.alert_id, key, actor="u-1")
        from defender.jobs import UnstorableText
        assert type(refused.value) is UnstorableText
    assert _count(dsn, "investigations") == 0


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


@pytest.mark.parametrize("accounting_written", [False, True], ids=["no-figure", "figure-written"])
@pytest.mark.parametrize(("stage", "reason", "attempt"), [("aborted", "cancelled", 1), ("failed", "retry_cap", 3)],
                         ids=["cancelled", "take-over"])
async def test_1377_r6_a_replay_answers_the_whole_record_a_read_does_mark_included(
        dsn, stage, reason, attempt, accounting_written):
    """`create_investigation`'s replay of a row that ended without its holder's figure equals `get_investigation`'s record, "at least" mark too; one with its figure reads unmarked. (r6, S2)"""
    alert = _plant_alert(dsn)
    inv = _plant_investigation(dsn, tenant=T1, alert_id=alert, key="k1", attempt=attempt, stage=stage,
                               worked=(reason, accounting_written))
    async with job_store(dsn) as store:
        replayed, created = await store.create_investigation(T1, alert, "k1", actor="u-1")
        read = await store.get_investigation(T1, inv)

    assert created is False
    assert replayed == read
    assert (read.cost_usd, read.cost_is_lower_limit) == (1.25, not accounting_written)


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


@pytest.mark.parametrize("alert_id", [str(uuid.uuid4()), "a1000000-0000-4000-8000-000000000001"], ids=["uuid", "api-style id"])
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

    assert [g.record.investigation_id for g in got[:3]] == [ids[2], ids[1], ids[0]]
    assert got[3] is None
    first = row(dsn, ids[2])
    assert (first["stage"], first["started_at"], first["finished_at"]) == ("running", claimed_at, None)
    assert got[0].record.stage == "running"
    assert (got[0].record.cost_usd, first["cost_usd"]) == (0, 0), "a claimed row reads cost 0 (D-n)"


async def test_o4_rows_created_together_are_claimed_lowest_id_first(dsn):
    """Equal `created_at`: the lower id is claimed first, whatever the insert order. (O4, D-e)"""
    low, high = "00000000-0000-4000-8000-000000000001", "ffffffff-ffff-4fff-8fff-ffffffffffff"
    alerts = [_plant_alert(dsn, ticket=f"P-{n}") for n in range(2)]
    for investigation_id, alert_id in ((high, alerts[0]), (low, alerts[1])):  # the higher id goes in first
        execute(dsn, "INSERT INTO jobs.investigations (id, tenant_id, alert_id, request_key, attempt, "
                     "stage, created_at, cost_usd, cost_is_lower_limit) VALUES (%s, %s, %s, 'k', 1, 'queued', %s, 0, false)",
                (investigation_id, T1, alert_id, NOW))
    async with job_store(dsn) as store:
        got = [await store.claim() for _ in range(3)]

    assert [g.record.investigation_id for g in got[:2]] == [low, high]
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
        assert (await store.claim()).record.investigation_id == queued  # control: the queued one is found
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
    assert got.record.investigation_id == kept.investigation_id
    assert row(dsn, cancelled.investigation_id)["stage"] == "aborted"


async def test_o4_two_claims_race_one_queued_row_and_exactly_one_wins(dsn):
    """Two stores (two pools) claim at once: one gets the row, `running` with `started_at`. (O4, scenario)"""
    async with job_store(dsn) as setup:
        alert = await an_alert(setup, T1)
        inv, _ = await setup.create_investigation(T1, alert.alert_id, "k1", actor="u-1")

    async with job_store(dsn) as a, job_store(dsn) as b:
        got = await asyncio.gather(a.claim(), b.claim())

    winners = [g for g in got if g is not None]
    assert [w.record.investigation_id for w in winners] == [inv.investigation_id]
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
            mine.append(claimed.record.investigation_id)
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
    assert claimed.record.investigation_id == inv.investigation_id


@pytest.mark.parametrize("state", ["active", "creating", "offboarding", "offboarded"])
async def test_r7_1_a_claim_carries_the_state_of_the_tenants_real_row(dsn, state):
    """`claim()` returns a `defender.jobs.Claim` whose `tenant_state` is the `tenancy.tenants` state, whatever it is. (R7-1)"""
    from defender.jobs import Claim, InvestigationRecord
    from defender.tests.support.jobs._jobs1342 import move_tenant

    move_tenant(dsn, T1, state=state)
    queued = _plant_investigation(dsn, tenant=T1, alert_id=_plant_alert(dsn), key="k", attempt=1, stage="queued")
    async with job_store(dsn) as store:
        got = await store.claim()

    assert isinstance(got, Claim)
    assert isinstance(got.record, InvestigationRecord)
    assert (got.record.investigation_id, got.record.stage, got.tenant_state) == (queued, "running", state)
    assert row(dsn, queued)["stage"] == "running", "a claim for a non-active tenant still claims the row"


async def test_r7_1_each_claim_reads_its_own_tenants_state(dsn):
    """Two queued rows of two tenants in different states: each claim carries its own tenant's state. (R7-1)"""
    from defender.tests.support.jobs._jobs1342 import move_tenant

    move_tenant(dsn, T2, state="offboarding")
    one = _plant_investigation(dsn, tenant=T1, alert_id=_plant_alert(dsn), key="k", attempt=1, stage="queued",
                               created_at=NOW - HOUR)
    two = _plant_investigation(dsn, tenant=T2, alert_id=_plant_alert(dsn, tenant=T2), key="k", attempt=1,
                               stage="queued")
    async with job_store(dsn) as store:
        first, second = await store.claim(), await store.claim()

    assert [(c.record.investigation_id, c.tenant_state) for c in (first, second)] == [
        (one, "active"), (two, "offboarding")]


def test_r7_1_the_claim_is_a_frozen_dataclass_of_the_record_and_the_state_exported_by_the_door():
    """`defender.jobs.Claim` is a frozen dataclass with fields `record` and `tenant_state`, in `__all__`. (R7-1)"""
    import defender.jobs as door
    from defender.jobs import Claim

    assert dataclasses.is_dataclass(Claim)
    assert [f.name for f in dataclasses.fields(Claim)] == ["record", "tenant_state"]
    assert "Claim" in door.__all__
    with pytest.raises(dataclasses.FrozenInstanceError):
        Claim(record=None, tenant_state="active").tenant_state = "x"  # type: ignore[misc]


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

async def test_o9_cancel_aborts_queued_and_running_and_refuses_ended(dsn):
    """queued and running → `aborted`/`cancelled`; terminal → "already ended"; "not yet" is gone. (O9, B9: conflict updated)"""
    from defender.jobs import Conflict

    async with job_store(dsn) as store:
        a1 = await an_alert(store, T1, ticket="T-1")
        a2 = await an_alert(store, T1, ticket="T-2")
        queued, _ = await store.create_investigation(T1, a1.alert_id, "k1", actor="u-1")
        running, _ = await store.create_investigation(T1, a2.alert_id, "k2", actor="u-1")
        _set_stage(dsn, running.investigation_id, "running")

        cancelled = await store.cancel_investigation(T1, queued.investigation_id, actor="u-1")
        stopped = await store.cancel_investigation(T1, running.investigation_id, actor="u-1")
        for again in (queued, running):
            with pytest.raises(Conflict, match="already ended"):
                await store.cancel_investigation(T1, again.investigation_id, actor="u-1")

    assert (cancelled.stage, cancelled.failure_reason) == ("aborted", "cancelled")
    stored = row(dsn, queued.investigation_id)
    assert (stored["stage"], stored["failure_reason"], stored["finished_at"]) == ("aborted", "cancelled", NOW)
    assert (stored["started_at"], stored["disposition"]) == (None, None)
    assert (cancelled.cost_usd, stored["cost_usd"]) == (0, 0), "a cancelled row reads cost 0 (D-n)"
    assert (stopped.stage, stopped.failure_reason) == ("aborted", "cancelled")
    stored = row(dsn, running.investigation_id)
    assert (stored["stage"], stored["failure_reason"], stored["finished_at"]) == ("aborted", "cancelled", NOW)


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


@pytest.mark.parametrize("target", [str(uuid.uuid4()), "b1000000-0000-4000-8000-000000000001"], ids=["uuid", "api-style id"])
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


async def test_o9_cancel_waits_for_a_claim_committing_and_then_aborts_the_running_row(dsn):
    """A claim committing under cancel's feet is followed by the cancel, which aborts the now-running row. (O9, B9: conflict updated)"""
    import psycopg

    async with job_store(dsn) as store:
        alert = await an_alert(store, T1)
        inv, _ = await store.create_investigation(T1, alert.alert_id, "k1", actor="u-1")
        async with await psycopg.AsyncConnection.connect(dsn) as conn:
            await conn.execute("UPDATE jobs.investigations SET stage = 'running', started_at = %s, "
                               "lease_expires_at = now() + interval '30 seconds' WHERE id = %s",
                               (NOW, inv.investigation_id))
            pending = asyncio.ensure_future(store.cancel_investigation(T1, inv.investigation_id, actor="u-1"))
            await until_blocked(dsn, 1)
            await conn.commit()
        got = await asyncio.wait_for(pending, 10)
    stored = row(dsn, inv.investigation_id)
    assert (got.stage, stored["stage"], stored["failure_reason"], stored["started_at"]) == (
        "aborted", "aborted", "cancelled", NOW), "the claim's start was lost or the cancel did not follow it"


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


async def test_o9_cancel_and_claim_racing_for_one_row_always_end_it_aborted(dsn):
    """Twenty rounds of cancel against claim: whichever commits first, the row ends `aborted`/`cancelled`; a claim that won saw it `running`. (O9, B9: conflict updated)"""
    outcomes = set()
    async with job_store(dsn) as setup, job_store(dsn) as a, job_store(dsn) as b:
        for n in range(20):
            alert = await an_alert(setup, T1, ticket=f"R-{n}")
            inv, _ = await setup.create_investigation(T1, alert.alert_id, f"k{n}", actor="u-1")
            cancelled, claimed = await asyncio.gather(
                a.cancel_investigation(T1, inv.investigation_id, actor="u-1"), b.claim(), return_exceptions=True)
            assert not isinstance(cancelled, BaseException), cancelled
            assert not isinstance(claimed, BaseException), claimed
            stored = row(dsn, inv.investigation_id)
            assert (cancelled.stage, stored["stage"], stored["failure_reason"]) == ("aborted", "aborted", "cancelled")
            if claimed is None:
                assert stored["started_at"] is None
                outcomes.add("cancel first")
            else:
                assert claimed.record.investigation_id == inv.investigation_id
                assert stored["started_at"] == NOW
                outcomes.add("claim first")
    assert outcomes <= {"cancel first", "claim first"}


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


@pytest.mark.parametrize("target", [str(uuid.uuid4()), "b1000000-0000-4000-8000-000000000001"], ids=["uuid", "api-style id"])
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


class _FormattedLines(logging.Handler):
    """Collects each record as the project's real JSON formatter writes it (`defender._log.JsonFormatter`)."""

    def __init__(self) -> None:
        from defender import _log

        super().__init__(logging.DEBUG)
        self.setFormatter(_log.JsonFormatter())
        self.lines: list[dict[str, Any]] = []

    def emit(self, record: logging.LogRecord) -> None:
        import json

        self.lines.append(json.loads(self.format(record)))


async def test_d_ag_every_job_audit_event_formats_with_its_tenant_when_the_caller_bound_none(dsn, caplog):
    """start, cancel, delete, claim and finish: the line the real JSON formatter writes carries the event's `tenant_id` with no `log_context` bound. (D-ag)"""
    from defender import _log

    JobsAudit(caplog)
    lines = _FormattedLines()
    logging.getLogger(JOBS_AUDIT).addHandler(lines)
    try:
        assert not _log.current_context().get("tenant_id"), "premise: the caller binds no tenant"
        async with job_store(dsn) as store:
            a1, a2 = await an_alert(store, T1, ticket="T-1"), await an_alert(store, T2, ticket="T-2")
            gone, _ = await store.create_investigation(T1, a1.alert_id, "k1", actor="u-1")
            await store.cancel_investigation(T1, gone.investigation_id, actor="u-1")
            await store.delete_investigation(T1, gone.investigation_id, actor="u-1")
            kept, _ = await store.create_investigation(T2, a2.alert_id, "k2", actor="u-1")
            claimed = await store.claim()
            await store.finish(T2, kept.investigation_id, stage="completed", disposition="benign", cost_usd=1.0)
    finally:
        logging.getLogger(JOBS_AUDIT).removeHandler(lines)

    assert claimed is not None
    seen = [(line["action"], line["tenant_id"]) for line in lines.lines]
    assert seen == [("investigation.start", T1), ("investigation.cancel", T1), ("investigation.delete", T1),
                    ("investigation.start", T2), ("investigation.claim", T2), ("investigation.finish", T2)], seen
    assert not _log.current_context().get("tenant_id"), "announcing left a tenant bound"


def test_d_ag_an_event_announced_inside_another_tenants_scope_carries_its_own_tenant_and_leaves_the_callers_bindings(caplog):
    """`announce` called inside `log_context(run_id=R, tenant_id=OTHER)`: the formatted line carries the event's tenant (not OTHER), and afterwards the caller's `run_id` and `tenant_id` bindings are as they were. (D-ag: the tenant is bound while the event is written)"""
    from defender import _log
    from defender.jobs import audit

    JobsAudit(caplog)
    lines = _FormattedLines()
    logging.getLogger(JOBS_AUDIT).addHandler(lines)
    run = "11111111-2222-4333-8444-555555555555"
    try:
        with _log.log_context(run_id=run, tenant_id=T2):
            audit.announce("investigation.claim", actor=audit.SYSTEM, tenant_id=T1, target=run)
            after = dict(_log.current_context())
    finally:
        logging.getLogger(JOBS_AUDIT).removeHandler(lines)

    [line] = lines.lines
    assert line["action"] == "investigation.claim"
    assert line["tenant_id"] == T1, "the line carries the caller's tenant, not the event's"
    assert (after.get("run_id"), after.get("tenant_id")) == (run, T2), f"announcing changed the caller's bindings: {after}"


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


@pytest.mark.parametrize("refusal", ["unknown alert", "cancel of an ended row", "delete of a live row",
                                     "cancel of an unknown id"])
async def test_o13_a_refused_call_emits_nothing(dsn, caplog, refusal):
    """No commit, no event: each class of refusal leaves the audit log as it was. (O13)"""
    from defender.jobs import Conflict, NotFound, UnknownReference

    audit = JobsAudit(caplog)
    async with job_store(dsn) as store:
        alert = await an_alert(store, T1)
        inv, _ = await store.create_investigation(T1, alert.alert_id, "k1", actor="u-1")
        _set_stage(dsn, inv.investigation_id, "running")
        ended = _plant_investigation(dsn, tenant=T1, alert_id=_plant_alert(dsn, ticket="E"), key="e", attempt=1,
                                     stage="failed")
        before = audit.events()
        calls = {
            "unknown alert": (UnknownReference,
                              lambda: store.create_investigation(T1, str(uuid.uuid4()), "k2", actor="u-1")),
            "cancel of an ended row": (Conflict, lambda: store.cancel_investigation(T1, ended, actor="u-1")),
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


# --- #1382 P-ID (withdraws D-a): a malformed id reaching the store is a bug, refused loudly -----------------------

#: Text that is no UUID at all. (A non-canonical UUID, upper case or braced, is not here: the database's
#: `uuid` would take and canonicalise it. Ids are parsed where outside text enters, #1382; the store trusts the type.)
MALFORMED_IDS = {"NUL": "a\x00b", "lone NUL": "\x00", "lone surrogate": "\ud800", "surrogate inside": "x\udfffy",
                 "api-style": "al-1"}


@pytest.mark.parametrize("bad", sorted(MALFORMED_IDS))
async def test_p_id_text_that_is_no_uuid_fails_loudly_at_the_store_and_changes_nothing(dsn, bad):
    """The store does not parse ids: they are checked where outside text becomes one, and its signatures take the
    family types (#1382 r3.1). Text that gets past the types anyway is never answered as "unknown" (D-a withdrawn):
    get, create, cancel, delete and finish raise, and the stored row is untouched."""
    ident = MALFORMED_IDS[bad]
    calls = {
        "get_alert": lambda store: store.get_alert(T1, ident),
        "get_investigation": lambda store: store.get_investigation(T1, ident),
        "create": lambda store: store.create_investigation(T1, ident, "k2", actor="u-1"),
        "cancel": lambda store: store.cancel_investigation(T1, ident, actor="u-1"),
        "delete": lambda store: store.delete_investigation(T1, ident, actor="u-1"),
        "finish": lambda store: store.finish(T1, ident, stage="failed", failure_reason="worker_error"),
    }
    async with job_store(dsn) as store:
        alert = await an_alert(store, T1)
        inv, _ = await store.create_investigation(T1, alert.alert_id, "k1", actor="u-1")
        for call in calls.values():
            with pytest.raises(Exception):  # noqa: B017, PT011 — whatever the driver raises, so long as it is loud
                await call(store)
        assert row(dsn, inv.investigation_id)["stage"] == "queued"
    assert _count(dsn, "investigations") == 1


# --- O5: the store's finish is fenced on `running` -----------------------------------------------------------------

async def test_o5_finish_ends_a_running_row_once_and_returns_it(dsn):
    """A running row finishes with its stage, disposition and cost; a second finish changes nothing. (O5, O8)"""
    async with job_store(dsn) as store:
        alert = await an_alert(store, T1)
        inv, _ = await store.create_investigation(T1, alert.alert_id, "k1", actor="u-1")
        assert (await store.claim()).record.investigation_id == inv.investigation_id
        done = await store.finish(T1, inv.investigation_id, stage="completed", disposition="benign", cost_usd=1.5)
        again = await store.finish(T1, inv.investigation_id, stage="failed", failure_reason="no_report")

    assert (done.stage, done.disposition, done.cost_usd) == ("completed", "benign", 1.5)
    assert again is None
    stored = row(dsn, inv.investigation_id)
    assert (stored["stage"], stored["disposition"], stored["failure_reason"], stored["finished_at"]) == (
        "completed", "benign", None, NOW)
    assert accounting_written(dsn, inv.investigation_id) is not None, "A's finish carries the final accounting (B4)"


_FAILED = {"stage": "failed", "failure_reason": "worker_error"}
_COMPLETED = {"stage": "completed", "disposition": "benign"}


@pytest.mark.parametrize(("claimed", "moved_to", "tenant", "finish", "stage_before"), [
    # A row the worker never claimed is not finished.
    pytest.param(False, None, T1, _FAILED, "queued", id="a_queued_row_never_claimed"),
    # Only the owning tenant's running row finishes.
    pytest.param(True, None, T2, _FAILED, "running", id="another_tenants_row"),
    # A row ended elsewhere (cancel, B) keeps its stage and fields against a late finish.
    *[pytest.param(True, t, T1, _COMPLETED, t, id=f"a_row_moved_to_{t}") for t in TERMINAL],
])
async def test_o5_a_finish_that_does_not_apply_returns_none_and_changes_nothing(
        dsn, claimed, moved_to, tenant, finish, stage_before):
    """`None`, row untouched: for a row never claimed, another tenant's row, or one already terminal. (O5)"""
    async with job_store(dsn) as store:
        alert = await an_alert(store, T1)
        inv, _ = await store.create_investigation(T1, alert.alert_id, "k1", actor="u-1")
        if claimed:
            await store.claim()
        if moved_to:
            _set_stage(dsn, inv.investigation_id, moved_to)
        before = row(dsn, inv.investigation_id)
        assert await store.finish(tenant, inv.investigation_id, **finish) is None
    assert row(dsn, inv.investigation_id) == before
    assert before["stage"] == stage_before


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
        await _absent(store.get_investigation(T1, "b1000000-0000-4000-8000-000000000001"))
        await _absent(store.get_investigation(T1, str(uuid.uuid4())))


# --- O15 (store half): another process's store sees the row, stage by stage ----------------------------------------------

async def test_o15_a_row_inserted_through_one_store_is_claimed_and_followed_through_another(dsn):
    """Store A inserts; store B claims it; A reads `running`; SQL ends it; A reads the terminal stage. (O15)"""
    async with job_store(dsn) as a, job_store(dsn) as b:
        alert = await an_alert(a, T1)
        inv, _ = await a.create_investigation(T1, alert.alert_id, "k1", actor="u-1")
        assert (await b.get_investigation(T1, inv.investigation_id)).stage == "queued"

        claimed = await b.claim()
        assert claimed.record.investigation_id == inv.investigation_id
        assert (await a.get_investigation(T1, inv.investigation_id)).stage == "running"
        assert await a.claim() is None  # A cannot claim what B holds

        execute(dsn, "UPDATE jobs.investigations SET stage = 'completed', disposition = 'benign', "
                     "finished_at = %s, cost_usd = 1.25 WHERE id = %s", (NOW + HOUR, inv.investigation_id))
        done = await a.get_investigation(T1, inv.investigation_id)
        assert (done.stage, done.disposition, done.cost_usd, done.finished_at) == (
            "completed", "benign", 1.25, NOW + HOUR)
        replay, created = await b.create_investigation(T1, alert.alert_id, "k1", actor="u-1")
    assert (replay.investigation_id, replay.stage, created) == (inv.investigation_id, "completed", False)


async def test_o5_no_knowledge_is_sql_null_not_a_json_null(dsn):
    """A row with no knowledge, queued or finished without it, holds SQL NULL, so `knowledge IS
    NULL` finds it; never the JSON literal `null`. (finalize #1354)"""
    async with job_store(dsn) as store:
        alert = await an_alert(store, T1)
        inv, _ = await store.create_investigation(T1, alert.alert_id, "k1", actor="u-1")
        queued = execute(dsn, "SELECT knowledge IS NULL FROM jobs.investigations WHERE id = %s",
                         (inv.investigation_id,))
        await store.claim()
        await store.finish(T1, inv.investigation_id, stage="failed", failure_reason="no_report", knowledge=None)

    finished = execute(dsn, "SELECT knowledge IS NULL FROM jobs.investigations WHERE id = %s",
                       (inv.investigation_id,))
    assert (queued, finished) == ([(True,)], [(True,)])


# --- #1345: the alert mapping in the store (O1 store side, O2, M3, O4) -------------------------------------
#
# Names r5 gives (design "Where it lives"): `JobStore.put_alert_mapping(tenant_id, mapping, actor="u-1") -> created: bool` (the one
# writer, M1), `JobStore.get_alert_mapping(tenant_id) -> mapping | None`, `insert_alert` without `title`/`description`.
# `mapping` is `records`' mapping type: built by `mapping_value` (`.paths`: mapped entries only, an assumption).
# Assumed, r5 names none: the store's own re-check of an invalid mapping raises `records`' `AlertMappingFault`, and
# `records.formats.ALERT_MAPPING_MISSING` is the one refusal wording (O4, r5.1).
# #1420 (D5): a save applies to alerts stored from then on; stored alerts keep their title and description, and the
# insert takes no per-tenant lock.

#: Over `ALERT_BYTES`: `rule.description` is "sketch", `rule.id` "r-1342", `a` "é", `z` a float (not text).
TITLE_ON_RULE = {"title": "rule.description", "description": "rule.id"}
TITLE_ON_A = {"title": "a"}


async def _insert(store: Any, tenant: str, *, ticket: str, raw: bytes = ALERT_BYTES) -> Any:
    """The trusted insert as #1345 shapes it: no display fields (the store derives them)."""
    return await store.insert_alert(tenant, vendor="elastic", vendor_ticket_id=ticket, fired_at=NOW,
                                    changed_at=NOW, received_at=NOW, raw=raw)


def _display(dsn: str, alert_id: str) -> tuple[Any, Any]:
    [(title, description)] = execute(dsn, "SELECT title, description FROM jobs.alerts WHERE id = %s", (alert_id,))
    return title, description


async def test_1345_o1_a_mapping_is_absent_until_saved_then_replaced_whole_and_an_invalid_entry_writes_nothing(unmapped_dsn):
    """None until the first replace (created); a second replaces it whole (not created); an invalid
    entry is refused naming it and leaves the mapping and the alerts' display as they were. (#1345 O1, M2)"""
    dsn = unmapped_dsn
    from defender.records.formats import AlertMappingFault

    async with job_store(dsn) as store:
        assert await store.get_alert_mapping(T1) is None
        created = await store.put_alert_mapping(T1, mapping_value({"signature": "rule.id", **TITLE_ON_RULE}), actor="u-1")
        assert created is True
        created = await store.put_alert_mapping(T1, mapping_value(TITLE_ON_RULE), actor="u-1")
        assert created is False
        assert (await store.get_alert_mapping(T1)).paths == TITLE_ON_RULE, "a replace is whole: signature is gone"
        alert = await _insert(store, T1, ticket="T-1")

        with pytest.raises(AlertMappingFault) as refused:  # the store's re-check (unreachable from the API)
            await store.put_alert_mapping(T1, mapping_value({"title": "a", "case_key": "rule..id"}), actor="u-1")
        assert "case_key" in str(refused.value)
        assert (await store.get_alert_mapping(T1)).paths == TITLE_ON_RULE
    assert _display(dsn, alert.alert_id) == ("sketch", "r-1342")


async def test_1345_o2_an_alert_is_stored_with_display_derived_through_its_tenants_current_mapping(unmapped_dsn):
    """T1 has a mapping: the alert's title and description are derived at insert; T2 has none:
    both are null. Read back alike through the store and the table. (#1345 O2, M3)"""
    dsn = unmapped_dsn
    async with job_store(dsn) as store:
        await store.put_alert_mapping(T1, mapping_value(TITLE_ON_RULE), actor="u-1")
        mapped = await _insert(store, T1, ticket="T-1")
        unmapped = await _insert(store, T2, ticket="T-1")
        read_mapped = await store.get_alert(T1, mapped.alert_id)
        read_unmapped = await store.get_alert(T2, unmapped.alert_id)

    assert (mapped.title, mapped.description) == (read_mapped.title, read_mapped.description) == ("sketch", "r-1342")
    assert (unmapped.title, unmapped.description) == (read_unmapped.title, read_unmapped.description) == (None, None)
    assert _display(dsn, mapped.alert_id) == ("sketch", "r-1342")
    assert _display(dsn, unmapped.alert_id) == (None, None)


async def test_1420_a_replace_leaves_every_stored_alert_as_it_was_and_applies_to_the_next(dsn):
    """After the replace commits, T1's stored alerts keep the display their insert derived and T2's is untouched;
    T1's next alert derives through the new mapping. (#1420 I1, I2)"""
    async with job_store(dsn) as store:
        await store.put_alert_mapping(T1, mapping_value(TITLE_ON_RULE), actor="u-1")
        await store.put_alert_mapping(T2, mapping_value(TITLE_ON_RULE), actor="u-1")
        mine = [await _insert(store, T1, ticket=f"T-{n}") for n in (1, 2)]
        theirs = await _insert(store, T2, ticket="T-1")

        await store.put_alert_mapping(T1, mapping_value(TITLE_ON_A), actor="u-1")
        after = await _insert(store, T1, ticket="T-3")

    assert [_display(dsn, a.alert_id) for a in mine] == [("sketch", "r-1342"), ("sketch", "r-1342")]
    assert _display(dsn, theirs.alert_id) == ("sketch", "r-1342")
    assert _display(dsn, after.alert_id) == ("é", None)


@asynccontextmanager
async def holding_mapping(dsn: str, tenant: str) -> AsyncIterator[None]:
    """Hold a save of `tenant`'s mapping mid-transaction (#1420): the mapping row `FOR UPDATE` when it exists, else an
    uncommitted insert of one, which a first save waits on at the key. Rolled back on exit, so a held first save then
    creates. Not the tenant row: that would also hold an alert insert through its foreign key."""
    import psycopg

    async with await psycopg.AsyncConnection.connect(dsn) as conn:
        cur = await conn.execute("SELECT tenant_id FROM tenancy.alert_mappings WHERE tenant_id = %s FOR UPDATE", (tenant,))
        if not await cur.fetchall():
            await conn.execute("INSERT INTO tenancy.alert_mappings (tenant_id) VALUES (%s)", (tenant,))
        try:
            yield
        finally:
            await conn.rollback()


@pytest.mark.parametrize("saved_before", [True, False], ids=["replace", "first-save"])
async def test_1420_an_insert_completes_while_a_save_of_its_tenant_is_held(unmapped_dsn, saved_before):
    """A save of T1's mapping is held mid-transaction; an insert for T1 started then completes without waiting for it,
    with the display of either mapping. (#1420 I3)"""
    dsn = unmapped_dsn
    async with store_with(dsn, Clock()) as saving, store_with(dsn, Clock()) as inserting:
        if saved_before:
            await saving.put_alert_mapping(T1, mapping_value(TITLE_ON_RULE), actor="u-1")
        async with holding_mapping(dsn, T1):
            save = asyncio.ensure_future(saving.put_alert_mapping(T1, mapping_value(TITLE_ON_A), actor="u-1"))
            await until_blocked(dsn, 1)
            new = await asyncio.wait_for(_insert(inserting, T1, ticket="T-2"), 5)
            assert not save.done(), "control: the save was still held while the insert completed"
        await asyncio.wait_for(save, 10)

    before = ("sketch", "r-1342") if saved_before else (None, None)
    assert _display(dsn, new.alert_id) in (before, ("é", None))


async def test_1345_o4_create_for_a_tenant_without_a_mapping_is_a_conflict_naming_the_route(unmapped_dsn):
    """T2 never saved a mapping: create is `Conflict` carrying the wording `records` owns (`ALERT_MAPPING_MISSING`, r5.1:
    not `jobs`), which names the mapping and the route that sets it, and inserts nothing; T1, with one, creates (control). (#1345 O4, M2)"""
    from defender.jobs import Conflict
    from defender.records.formats import ALERT_MAPPING_MISSING

    dsn = unmapped_dsn

    async with job_store(dsn) as store:
        await store.put_alert_mapping(T1, mapping_value({}), actor="u-1")  # an empty mapping is a mapping (M2)
        theirs = await _insert(store, T2, ticket="T-1")
        mine = await _insert(store, T1, ticket="T-1")
        with pytest.raises(Conflict) as refused:
            await store.create_investigation(T2, theirs.alert_id, "k1", actor="u-1")
        assert _count(dsn, "investigations") == 0
        created = await store.create_investigation(T1, mine.alert_id, "k1", actor="u-1")
        await store.put_alert_mapping(T2, mapping_value({}), actor="u-1")  # the same tenant, once it has saved one
        after_put = await store.create_investigation(T2, theirs.alert_id, "k1", actor="u-1")

    assert (created[1], after_put[1]) == (True, True)  # `create_investigation` answers `(record, created)`
    # The one wording `records` owns, beside `MAPPING_KEYS` (design-implied name; r5.1 O4): the store's refusal is exactly it, and it names the verb
    # and the route (so the equality is not true of an empty constant).
    assert str(refused.value) == ALERT_MAPPING_MISSING
    assert_missing_wording_names_verb_and_route(ALERT_MAPPING_MISSING)


async def test_1345_o2_insert_alert_takes_no_display_fields(dsn):
    """The caller no longer supplies title or description; the store derives them. (#1345 O2)"""
    from defender.jobs import JobStore

    parameters = inspect.signature(JobStore.insert_alert).parameters
    assert {"title", "description"}.isdisjoint(parameters)
    async with job_store(dsn) as store:
        with pytest.raises(TypeError):
            await store.insert_alert(T1, vendor="elastic", vendor_ticket_id="T-1", fired_at=NOW, changed_at=NOW,
                                     received_at=NOW, raw=ALERT_BYTES, title="given", description="given")
        assert _count(dsn, "alerts") == 0
        await _insert(store, T1, ticket="T-1")  # control: without them it stores
        assert _count(dsn, "alerts") == 1


#: (raw JSON value at `t`, the title it derives): today's fact text rule (O2): a non-empty string as it is, an integer
#: (not a bool) as its decimal text; an empty string, bool, float, null, list or object is no value; text PostgreSQL
#: cannot hold (a NUL) is none.
TEXT_RULE = [
    ('"plain"', "plain"), ('"  padded "', "  padded "), ('"\\u00e9"', "é"),
    ('"\\u00fcn\\u00ef \\n \\u65e5\\u672c \'q\' \\"q\\" %s"', 'ünï \n 日本 \'q\' "q" %s'), ("42", "42"), ("-7", "-7"), ("0", "0"),
    ("123456789012345678901234567890", "123456789012345678901234567890"),
    ('""', None), ("true", None), ("false", None), ("1.5", None), ("2.0", None), ("1e3", None), ("null", None),
    ("[1]", None), ('["x"]', None), ('{"s": "x"}', None), ('{}', None), ('"x\\u0000y"', None), ('"\\u0000"', None),
]


@pytest.mark.parametrize(("literal", "expected"), TEXT_RULE)
async def test_1345_o2_the_title_is_the_value_at_its_path_only_when_it_is_usable_text(unmapped_dsn, literal, expected):
    """Stored under a mapping, the title is the text rule's result for that value and the description (an unusable
    value) is null. (#1345 O2, M3)"""
    dsn = unmapped_dsn
    raw = f'{{"t": {literal}, "d": {{"s": 1}}}}'.encode()
    mapping = mapping_value({"title": "t", "description": "d"})
    async with job_store(dsn) as store:
        await store.put_alert_mapping(T1, mapping, actor="u-1")
        alert = await _insert(store, T1, ticket="T-1", raw=raw)
        stored = _display(dsn, alert.alert_id)
    assert (alert.title, alert.description) == stored == (expected, None)


@pytest.mark.parametrize(("path", "expected"), [
    ("a", "é"),             # control: a path that is there
    ("rule.id", "r-1342"),  # nested
    ("rule.missing", None), ("missing", None), ("a.b", None),  # absent; through a scalar
    ("rule.id.x", None), ("rule.description.0", None),
])
async def test_1345_o2_a_path_absent_from_the_alert_or_through_a_non_object_derives_null(unmapped_dsn, path, expected):
    """A path walks objects only; where it cannot, the title is null. (#1345 O2)"""
    dsn = unmapped_dsn
    async with job_store(dsn) as store:
        await store.put_alert_mapping(T1, mapping_value({"title": path}), actor="u-1")
        alert = await _insert(store, T1, ticket="T-1")
    assert _display(dsn, alert.alert_id) == (expected, None)


async def test_1345_o2_an_empty_mapping_derives_null_for_every_alert_stored_under_it(unmapped_dsn):
    """Saving `{}` is a mapping (so investigations run) whose display fields are all null. (#1345 O2, M2)"""
    dsn = unmapped_dsn
    async with job_store(dsn) as store:
        await store.put_alert_mapping(T1, mapping_value(TITLE_ON_RULE), actor="u-1")
        titled = await _insert(store, T1, ticket="T-1")
        await store.put_alert_mapping(T1, mapping_value({}), actor="u-1")
        alert = await _insert(store, T1, ticket="T-2")
        assert await store.get_alert_mapping(T1) is not None, "an empty mapping is saved, not absent"
    assert _display(dsn, titled.alert_id) == ("sketch", "r-1342"), "control: the mapping before it derived a title"
    assert _display(dsn, alert.alert_id) == (None, None)


async def test_1345_o2_a_long_title_and_description_are_cut_when_stored(unmapped_dsn):
    """A display field is copied into the launch record, the run's stamp and the alert list, so it does not grow with
    the alert: the mapped text is cut to the caps when stored; a shorter one is whole. A character
    the column refuses, past the cut, is gone with the rest and does not null what was kept. (#1345 O2)"""
    from defender.records.formats import DISPLAY_CAPS

    dsn = unmapped_dsn
    long_title, long_text = "é" * (DISPLAY_CAPS["title"] + 1), "d" * (DISPLAY_CAPS["description"] + 1)
    raw = json.dumps({"t": long_title, "d": long_text, "n": "x" * DISPLAY_CAPS["title"] + "\u0000", "s": "short"}).encode()
    both = {"title": "t", "description": "d"}
    async with job_store(dsn) as store:
        await store.put_alert_mapping(T1, mapping_value(both), actor="u-1")
        alert = await _insert(store, T1, ticket="T-1", raw=raw)
        await store.put_alert_mapping(T1, mapping_value({"title": "n", "description": "s"}), actor="u-1")
        other = await _insert(store, T1, ticket="T-2", raw=raw)
    assert _display(dsn, alert.alert_id) == (long_title[:-1], long_text[:-1])
    assert _display(dsn, other.alert_id) == ("x" * DISPLAY_CAPS["title"], "short")


async def test_1345_o4_a_repeated_or_live_request_is_answered_even_without_a_mapping(unmapped_dsn):
    """The refusal guards a new row only: a repeat of a request, and a request for an alert with a live investigation,
    start nothing and answer what exists, mapping or not. A new attempt is what is refused. (#1345 O4, #1081 §4.1)"""
    from defender.jobs import Conflict
    from defender.tests.support.tenancy._mapping1345 import remove_postgres_mapping

    dsn = unmapped_dsn
    async with job_store(dsn) as store:
        await store.put_alert_mapping(T1, mapping_value({}), actor="u-1")
        alert = await _insert(store, T1, ticket="T-1")
        first, _ = await store.create_investigation(T1, alert.alert_id, "k1", actor="u-1")
        remove_postgres_mapping(dsn, T1)
        assert await store.create_investigation(T1, alert.alert_id, "k1", actor="u-1") == (first, False)
        assert await store.create_investigation(T1, alert.alert_id, "k2", actor="u-1") == (first, False)
        execute(dsn, "DELETE FROM jobs.investigations WHERE id = %s", (first.investigation_id,))
        with pytest.raises(Conflict):
            await store.create_investigation(T1, alert.alert_id, "k3", actor="u-1")


async def test_1345_o1_a_replace_is_audited_after_it_commits_and_a_refused_one_is_not(unmapped_dsn, caplog):
    """The one writer announces itself, whoever called it, first save and later ones alike; a refused replace and a
    tenant with no row announce nothing. (#1345 O1, M1)"""
    from defender.jobs import UnknownReference
    from defender.records.formats import AlertMappingFault

    dsn = unmapped_dsn
    audit = JobsAudit(caplog)
    async with job_store(dsn) as store:
        with pytest.raises(AlertMappingFault):
            await store.put_alert_mapping(T1, mapping_value({"title": "a..b"}), actor="u-1")
        with pytest.raises(UnknownReference):
            await store.put_alert_mapping(str(uuid.uuid4()), mapping_value({}), actor="u-1")
        assert [e for e in audit.events() if e.action == "alert_mapping.update"] == []
        await store.put_alert_mapping(T1, mapping_value({}), actor="u-1")
        await store.put_alert_mapping(T1, mapping_value({}), actor="u-2")
    events = [e for e in audit.events() if e.action == "alert_mapping.update"]
    assert [(e.actor, e.tenant_id, e.target) for e in events] == [("u-1", T1, T1), ("u-2", T1, T1)]


async def test_1345_o2_the_wire_alert_reads_the_stored_display_fields_nullable(unmapped_dsn):
    """The store's alert read carries null title and description for an alert stored while its tenant had no mapping
    (the wire model accepts them), still null after the first save (#1420 D6), and the derived ones for an alert
    stored after it. (#1345 O2)"""
    dsn = unmapped_dsn
    async with job_store(dsn) as store:
        alert = await _insert(store, T1, ticket="T-1")
        await store.put_alert_mapping(T1, mapping_value(TITLE_ON_RULE), actor="u-1")
        untitled = await store.get_alert(T1, alert.alert_id)
        titled = await store.get_alert(T1, (await _insert(store, T1, ticket="T-2")).alert_id)
    assert ((untitled.title, untitled.description), (titled.title, titled.description)) == ((None, None), ("sketch", "r-1342"))


# --- #1345 repairs: the first-save race ----------------------------------------------------------------------------------

async def test_1345_m3_two_first_saves_for_one_tenant_both_return_and_exactly_one_creates(unmapped_dsn):
    """Two first-save replaces race (both held at the row so neither has committed): both return, exactly one created,
    and the mapping of the one that did not (it wrote last) stands. An alert stored before either keeps its null
    display (#1420 D6). (#1345 M3, O1)"""
    dsn = unmapped_dsn
    async with store_with(dsn, Clock()) as first, store_with(dsn, Clock()) as second:
        alert = await _insert(first, T1, ticket="T-1")
        async with holding_mapping(dsn, T1):
            one = asyncio.ensure_future(first.put_alert_mapping(T1, mapping_value(TITLE_ON_RULE), actor="u-1"))
            await until_blocked(dsn, 1)
            two = asyncio.ensure_future(second.put_alert_mapping(T1, mapping_value(TITLE_ON_A), actor="u-1"))
            await until_blocked(dsn, 2)  # both wait on the held row
        results = await asyncio.wait_for(asyncio.gather(one, two, return_exceptions=True), 10)
        assert sorted(results, key=repr) == [False, True], results
        last = TITLE_ON_A if results == [True, False] else TITLE_ON_RULE
        assert (await first.get_alert_mapping(T1)).paths == last
    assert _display(dsn, alert.alert_id) == (None, None)


# --- #1343 piece B: lease, renewal, end writes, hand-back, take-over, cancel of running ------------------------------
# Unratified seams (r5 item 11 names only the first three): `JobStore(dsn, clock=, lease=)` (seconds, database clock);
# columns `lease_expires_at` / `accounting_written_at`; `take_over(held=)` (one pass of B6, every lapsed running row
# not in `held`); and, named by this contract from the writes table:
#   `renew(held, *, costs=None)`            one statement; ids it covered; `costs` = {id: figure} copied this tick
#   `write_accounting(tenant, id, *, cost_usd, knowledge)`   B4's final accounting; the record, or None if refused
#   `hand_back(tenant, id, *, cost_usd, knowledge)`          B11; the record, or None if refused

KNOWLEDGE = {"status": "current", "commit": "abc123", "stale_kind": None}


def _plant_running(dsn: str, *, alert_id: str, key: str, attempt: int, lapsed: bool, tenant: str = T1,
                   marked: bool = False) -> str:
    """A `running` row (cost 1.25) with a lease by the database clock: lapsed a minute ago, or 30 s ahead;
    optionally with the final-accounting mark already set."""
    investigation_id = str(uuid.uuid4())
    when = "now() - interval '1 minute'" if lapsed else "now() + interval '30 seconds'"
    mark = "now()" if marked else "NULL"
    execute(dsn, "INSERT INTO jobs.investigations (id, tenant_id, alert_id, request_key, attempt, stage, "
                 "created_at, started_at, cost_usd, cost_is_lower_limit, lease_expires_at, accounting_written_at) VALUES "
                 f"(%s, %s, %s, %s, %s, 'running', %s, %s, 1.25, false, {when}, {mark})",  # noqa: S608
            (investigation_id, tenant, alert_id, key, attempt, NOW, NOW))
    return investigation_id


def _snap(dsn: str, investigation_id: str) -> dict[str, Any]:
    """Every column of the row, by the database's own JSON (so a new column is compared too)."""
    return execute(dsn, "SELECT to_jsonb(x) FROM jobs.investigations x WHERE id = %s", (investigation_id,))[0][0]


def _changed(before: dict[str, Any], after: dict[str, Any]) -> set[str]:
    return {k for k in before.keys() | after.keys() if before.get(k) != after.get(k)}


async def _queued_row(dsn: str) -> str:
    """One queued row (cost 0, no mark) for T1."""
    async with job_store(dsn) as store:
        queued, _ = await store.create_investigation(T1, _plant_alert(dsn, ticket="QR"), "kqr", actor="u-1")
    return queued.investigation_id


def _retries_of(dsn: str, investigation_id: str) -> list[str]:
    return [r[0] for r in execute(
        dsn, "SELECT r.id FROM jobs.investigations r, jobs.investigations o WHERE o.id = %s AND r.tenant_id = o.tenant_id "
             "AND r.alert_id = o.alert_id AND r.request_key = o.request_key AND r.attempt > o.attempt "
             "ORDER BY r.attempt", (investigation_id,))]


def _ended_with_cost(dsn: str, stage: str, ticket: str) -> str:
    """A terminal row carrying every field a final accounting must leave alone."""
    inv = _plant_investigation(dsn, tenant=T1, alert_id=_plant_alert(dsn, ticket=ticket), key="k", attempt=1, stage=stage)
    execute(dsn, "UPDATE jobs.investigations SET started_at = %s, finished_at = %s, disposition = 'benign', "
                 "cost_usd = 1.25, failure_reason = 'no_report', failure_message = 'exited 7' WHERE id = %s",
            (NOW, NOW, inv))
    return inv


# --- B1: the lease at claim ---------------------------------------------------------------------------------------

async def test_b1_a_claim_gives_the_row_a_thirty_second_lease_by_the_database_clock(dsn):
    """The claimed row's lease ends 30 s after the database's now, not the store's injected clock. (B1, Clock)"""
    async with job_store(dsn) as store:
        alert = await an_alert(store, T1)
        inv, _ = await store.create_investigation(T1, alert.alert_id, "k1", actor="u-1")
        assert lease_left(dsn, inv.investigation_id) is None, "a queued row has no lease"
        await store.claim()
    left = lease_left(dsn, inv.investigation_id)
    assert left is not None
    assert 28 <= left <= 30, left  # NOW is days in the past: an injected-clock lease reads lapsed
    assert accounting_written(dsn, inv.investigation_id) is None


@pytest.mark.parametrize("seconds", [5.0, 90.0])
async def test_b1_the_lease_length_is_the_stores_own(dsn, seconds):
    """`JobStore(lease=n)` sets the length a claim gives; nothing else holds a copy. (B1, r5 item 11)"""
    async with job_store(dsn, lease=seconds) as store:
        alert = await an_alert(store, T1)
        inv, _ = await store.create_investigation(T1, alert.alert_id, "k1", actor="u-1")
        await store.claim()
    assert seconds - 2 <= lease_left(dsn, inv.investigation_id) <= seconds


# --- B1/B2: renewal ------------------------------------------------------------------------------------------------

async def test_b1_a_renewal_extends_the_held_running_rows_and_only_those(dsn, caplog):
    """Two held lapsed rows get a fresh lease (store-owned length) and change nothing else; a third, not held, stays lapsed; no audit. (B1, B-P3)"""
    audit = JobsAudit(caplog)
    a, b, c = (_plant_running(dsn, alert_id=_plant_alert(dsn, ticket=f"P-{n}"), key="k", attempt=1, lapsed=True)
               for n in range(3))
    before = {i: _snap(dsn, i) for i in (a, b, c)}
    async with job_store(dsn, lease=20.0) as store:
        covered = await store.renew({a, b})
    assert set(covered) == {a, b}
    assert all(18 <= lease_left(dsn, i) <= 20 for i in (a, b))
    assert lease_left(dsn, c) < 0, "a row the caller does not hold was renewed"
    assert [_changed(before[i], _snap(dsn, i)) for i in (a, b, c)] == [{"lease_expires_at"}, {"lease_expires_at"}, set()]
    assert audit.events() == []


async def test_b1_a_renewal_with_nothing_held_touches_nothing(dsn):
    """An empty held set covers nothing and renews no row. (B1)"""
    lapsed = _plant_running(dsn, alert_id=_plant_alert(dsn), key="k", attempt=1, lapsed=True)
    before = _snap(dsn, lapsed)
    async with job_store(dsn) as store:
        assert set(await store.renew(set())) == set()
        assert set(await store.renew({str(uuid.uuid4())})) == set(), "an id no row has is not covered"
    assert _snap(dsn, lapsed) == before


@pytest.mark.parametrize("stage", ["queued", *TERMINAL])
async def test_b1_a_renewal_leaves_a_row_that_is_not_running_alone(dsn, stage):
    """Renewal is conditional on `running`: a held id whose row is queued or ended is not covered or changed; a running one beside it is. (B1, B3)"""
    other = _plant_investigation(dsn, tenant=T1, alert_id=_plant_alert(dsn, ticket="O"), key="k", attempt=1, stage=stage)
    if stage != "queued":
        execute(dsn, "UPDATE jobs.investigations SET lease_expires_at = now() - interval '1 minute' WHERE id = %s", (other,))
    control = _plant_running(dsn, alert_id=_plant_alert(dsn, ticket="C"), key="k", attempt=1, lapsed=True)
    before = _snap(dsn, other)
    async with job_store(dsn) as store:
        covered = await store.renew({other, control})
    assert set(covered) == {control}
    assert _snap(dsn, other) == before


async def test_b1_a_late_renewal_of_a_row_nobody_took_over_succeeds(dsn):
    """A lapsed lease that no take-over has acted on is renewed: the row stays `running` with a fresh lease. (B1)"""
    lapsed = _plant_running(dsn, alert_id=_plant_alert(dsn), key="k", attempt=1, lapsed=True)
    async with job_store(dsn) as store:
        assert set(await store.renew({lapsed})) == {lapsed}
    assert row(dsn, lapsed)["stage"] == "running"
    assert 28 <= lease_left(dsn, lapsed) <= 30


async def test_b1_a_renewal_after_a_take_over_omits_the_row_and_leaves_it_failed(dsn):
    """Once taken over the row is no longer covered (the holder learns to end its child) and is not revived. (B1, B3, B6)"""
    lapsed = _plant_running(dsn, alert_id=_plant_alert(dsn), key="k", attempt=1, lapsed=True)
    async with job_store(dsn) as store:
        await store.take_over(held=frozenset())
        after_take_over = _snap(dsn, lapsed)
        assert set(await store.renew({lapsed})) == set()
    assert _snap(dsn, lapsed) == after_take_over
    assert after_take_over["stage"] == "failed"


@pytest.mark.parametrize("marked", [False, True], ids=["no mark: renewed", "mark set: not re-freshened"])
async def test_b1_a_renewal_never_reopens_a_handed_back_lease(dsn, marked):
    """Renewal is conditional on `running` AND the accounting mark null: a row carrying the mark keeps its lapsed lease. (B1, B11, r5 item 1)"""
    lapsed = _plant_running(dsn, alert_id=_plant_alert(dsn), key="k", attempt=1, lapsed=True, marked=marked)
    before = _snap(dsn, lapsed)
    async with job_store(dsn) as store:
        covered = set(await store.renew({lapsed}))
    assert covered == (set() if marked else {lapsed})
    if marked:
        assert _snap(dsn, lapsed) == before
        assert lease_left(dsn, lapsed) < 0


async def test_b2_a_renewal_copies_the_cost_it_is_given_to_the_rows_it_covers(dsn):
    """`costs` lands on the held rows it names; a held row without a figure keeps its cost; a figure for a row not held is ignored; no `costs` leaves every cost. (B2, r5 item 4)"""
    a, b, c = (_plant_running(dsn, alert_id=_plant_alert(dsn, ticket=f"P-{n}"), key="k", attempt=1, lapsed=False)
               for n in range(3))
    async with job_store(dsn) as store:
        await store.renew({a, b, c})
        assert [row(dsn, i)["cost_usd"] for i in (a, b, c)] == [1.25, 1.25, 1.25], "a renewal without costs moved a cost"
        await store.renew({a, b}, costs={a: 3.5, c: 9.0})
    assert [row(dsn, i)["cost_usd"] for i in (a, b, c)] == [3.5, 1.25, 1.25]


# --- B4/B11: the end writes -------------------------------------------------------------------------------------------

async def test_b4_a_finish_with_an_unreadable_cost_writes_null_not_the_cost_so_far(dsn):
    """Finish writes the cost it is given, null included (R2): a failed final read does not keep the copied figure. (B4, r5 R2)"""
    running = _plant_running(dsn, alert_id=_plant_alert(dsn), key="k", attempt=1, lapsed=False)
    async with job_store(dsn) as store:
        done = await store.finish(T1, running, stage="completed", disposition="benign", cost_usd=None)
    assert done.cost_usd is None
    assert row(dsn, running)["cost_usd"] is None
    assert accounting_written(dsn, running) is not None


@pytest.mark.parametrize("stage", TERMINAL)
async def test_b4_a_final_accounting_writes_cost_knowledge_and_the_mark_and_nothing_else(dsn, stage):
    """On an ended row with no mark: cost, knowledge and mark change; stage, times, disposition and failure detail do not. (B4, Writes table)"""
    inv = _ended_with_cost(dsn, stage, "A")
    before = _snap(dsn, inv)
    async with job_store(dsn) as store:
        got = await store.write_accounting(T1, inv, cost_usd=4.5, knowledge=KNOWLEDGE)
    assert got is not None
    assert (got.stage, got.cost_usd, got.knowledge) == (stage, 4.5, KNOWLEDGE)
    assert _changed(before, _snap(dsn, inv)) == {"cost_usd", "knowledge", "accounting_written_at"}
    assert accounting_written(dsn, inv) is not None


async def test_b4_a_final_accounting_is_written_once(dsn):
    """A second final accounting is refused and changes nothing, whatever it carries; so is one after a finish, which set the mark. (B4)"""
    inv = _ended_with_cost(dsn, "failed", "A")
    finished = _plant_running(dsn, alert_id=_plant_alert(dsn, ticket="F"), key="k", attempt=1, lapsed=False)
    async with job_store(dsn) as store:
        assert await store.write_accounting(T1, inv, cost_usd=4.5, knowledge=KNOWLEDGE) is not None
        first = _snap(dsn, inv)
        assert await store.write_accounting(T1, inv, cost_usd=99.0, knowledge=None) is None
        await store.finish(T1, finished, stage="completed", disposition="benign", cost_usd=2.0, knowledge=KNOWLEDGE)
        after_finish = _snap(dsn, finished)
        assert await store.write_accounting(T1, finished, cost_usd=99.0, knowledge=None) is None
    assert _snap(dsn, inv) == first
    assert _snap(dsn, finished) == after_finish


@pytest.mark.parametrize("target", ["running", "queued", "other tenant", "unknown"])
async def test_b4_a_final_accounting_is_refused_for_a_row_that_is_not_an_ended_one_of_this_tenant(dsn, target):
    """Only a terminal row of the caller's tenant takes it: running and queued rows, another tenant's, a deleted id are unchanged. (B4, Writes table)"""
    inv = {"running": lambda: _plant_running(dsn, alert_id=_plant_alert(dsn), key="k", attempt=1, lapsed=False),
           "queued": lambda: _plant_investigation(dsn, tenant=T1, alert_id=_plant_alert(dsn), key="k", attempt=1, stage="queued"),
           "other tenant": lambda: _ended_with_cost(dsn, "failed", "A"),
           "unknown": lambda: str(uuid.uuid4())}[target]()
    ended = _ended_with_cost(dsn, "failed", "Z")  # positive control: the same call accepts this one
    before = _snap(dsn, inv) if target != "unknown" else None
    async with job_store(dsn) as store:
        tenant = T2 if target == "other tenant" else T1
        assert await store.write_accounting(tenant, inv, cost_usd=4.5, knowledge=KNOWLEDGE) is None
        assert await store.write_accounting(T1, ended, cost_usd=4.5, knowledge=KNOWLEDGE) is not None
    if before is not None:
        assert _snap(dsn, inv) == before


async def test_b4_a_final_accounting_with_an_unreadable_cost_writes_null(dsn):
    """Null cost replaces the copied figure on the ended row; the mark is still set. (B4, r5 R2)"""
    inv = _ended_with_cost(dsn, "failed", "A")
    async with job_store(dsn) as store:
        await store.write_accounting(T1, inv, cost_usd=None, knowledge=None)
    assert row(dsn, inv)["cost_usd"] is None
    assert accounting_written(dsn, inv) is not None


async def test_b4_a_taken_over_row_accepts_its_holders_final_accounting(dsn):
    """Take-over writes no accounting; the cut-off holder's later write lands on the old row, leaves its `failed`/`lease_lapsed` and its retry alone. (B-P2, B6)"""
    lapsed = _plant_running(dsn, alert_id=_plant_alert(dsn), key="k", attempt=1, lapsed=True)
    async with job_store(dsn) as store:
        await store.take_over(held=frozenset())
        assert accounting_written(dsn, lapsed) is None
        [retry] = _retries_of(dsn, lapsed)
        retry_before = _snap(dsn, retry)
        got = await store.write_accounting(T1, lapsed, cost_usd=7.0, knowledge=KNOWLEDGE)
    assert got is not None
    stored = row(dsn, lapsed)
    assert (stored["stage"], stored["failure_reason"], stored["cost_usd"], stored["knowledge"]) == (
        "failed", "lease_lapsed", 7.0, KNOWLEDGE)
    assert _snap(dsn, retry) == retry_before


async def test_b4_a_cancelled_running_row_accepts_its_holders_final_accounting(dsn):
    """Cancel writes no accounting either: the holder's final cost and knowledge land on the `aborted` row. (B-P2, B9)"""
    running = _plant_running(dsn, alert_id=_plant_alert(dsn), key="k", attempt=1, lapsed=False)
    async with job_store(dsn) as store:
        await store.cancel_investigation(T1, running, actor="u-1")
        assert accounting_written(dsn, running) is None
        await store.write_accounting(T1, running, cost_usd=2.0, knowledge=KNOWLEDGE)
    stored = row(dsn, running)
    assert (stored["stage"], stored["failure_reason"], stored["cost_usd"], stored["knowledge"]) == (
        "aborted", "cancelled", 2.0, KNOWLEDGE)


async def test_b11_a_hand_back_lapses_the_lease_keeps_the_row_running_and_copies_cost_knowledge_and_the_mark(dsn, caplog):
    """A running row with a fresh lease: lease lapsed, final cost and knowledge written, mark set, still `running`, nothing else changed. (B11, Writes table)"""
    audit = JobsAudit(caplog)
    running = _plant_running(dsn, alert_id=_plant_alert(dsn), key="k", attempt=1, lapsed=False)
    before = _snap(dsn, running)
    async with job_store(dsn) as store:
        got = await store.hand_back(T1, running, cost_usd=3.0, knowledge=KNOWLEDGE)
    assert got is not None
    assert (got.stage, got.cost_usd, got.knowledge) == ("running", 3.0, KNOWLEDGE)
    assert lease_left(dsn, running) < 0
    assert accounting_written(dsn, running) is not None
    assert _changed(before, _snap(dsn, running)) == {"lease_expires_at", "cost_usd", "knowledge", "accounting_written_at"}
    assert audit.events() == []


async def test_b11_a_hand_back_with_an_unreadable_cost_writes_null(dsn):
    """Null cost replaces the copied figure in the hand-back too. (B11, r5 R2)"""
    running = _plant_running(dsn, alert_id=_plant_alert(dsn), key="k", attempt=1, lapsed=False)
    async with job_store(dsn) as store:
        await store.hand_back(T1, running, cost_usd=None, knowledge=None)
    assert row(dsn, running)["cost_usd"] is None


@pytest.mark.parametrize("stage", ["queued", *TERMINAL])
async def test_b11_a_hand_back_is_conditional_on_running(dsn, stage):
    """A queued or ended row is refused and unchanged; a running one beside it is handed back. (B11, Writes table)"""
    other = _plant_investigation(dsn, tenant=T1, alert_id=_plant_alert(dsn, ticket="O"), key="k", attempt=1, stage=stage)
    control = _plant_running(dsn, alert_id=_plant_alert(dsn, ticket="C"), key="k", attempt=1, lapsed=False)
    before = _snap(dsn, other)
    async with job_store(dsn) as store:
        assert await store.hand_back(T1, other, cost_usd=3.0, knowledge=None) is None
        assert await store.hand_back(T1, control, cost_usd=3.0, knowledge=None) is not None
    assert _snap(dsn, other) == before


async def test_b11_a_handed_back_row_is_not_renewed_not_reclaimed_and_is_taken_over_with_its_cost(dsn):
    """After the hand-back a renewal omits it, claim ignores it, and a take-over fails it `lease_lapsed` with a queued retry, keeping the handed-back cost and mark. (B11, B6, r4 item 2)"""
    running = _plant_running(dsn, alert_id=_plant_alert(dsn), key="k", attempt=1, lapsed=False)
    async with job_store(dsn) as store:
        await store.hand_back(T1, running, cost_usd=3.0, knowledge=KNOWLEDGE)
        mark = accounting_written(dsn, running)
        assert set(await store.renew({running})) == set()
        assert lease_left(dsn, running) < 0
        assert await store.claim() is None
        await store.take_over(held=frozenset())
    stored = row(dsn, running)
    assert (stored["stage"], stored["failure_reason"], stored["cost_usd"], stored["knowledge"]) == (
        "failed", "lease_lapsed", 3.0, KNOWLEDGE)
    assert accounting_written(dsn, running) == mark
    [retry] = _retries_of(dsn, running)
    assert (row(dsn, retry)["stage"], row(dsn, retry)["attempt"]) == ("queued", 2)



@pytest.mark.parametrize("attempt", [1, 3], ids=["retried", "capped"])
async def test_b11_take_over_tells_a_handed_back_row_from_a_lost_workers_in_its_message(dsn, attempt):
    """A handed-back row's take-over message says its worker stopped and handed it back; a lapsed row beside it, whose worker was lost, says its worker stopped renewing. Reasons are unchanged. (#1343 review, B6, B11)"""
    handed = _plant_running(dsn, alert_id=_plant_alert(dsn, ticket="H"), key="kh", attempt=attempt, lapsed=False)
    lost = _plant_running(dsn, alert_id=_plant_alert(dsn, ticket="L"), key="kl", attempt=attempt, lapsed=True)
    async with job_store(dsn) as store:
        await store.hand_back(T1, handed, cost_usd=1.0, knowledge=None)
        await store.take_over(held=frozenset())
    reason = "lease_lapsed" if attempt == 1 else "retry_cap"
    got_handed, got_lost = row(dsn, handed), row(dsn, lost)
    assert (got_handed["failure_reason"], got_lost["failure_reason"]) == (reason, reason)
    assert "handed it back" in got_handed["failure_message"], got_handed["failure_message"]
    assert "stopped renewing" not in got_handed["failure_message"]
    assert "stopped renewing its lease" in got_lost["failure_message"], got_lost["failure_message"]


# --- #1377: the cost's lower-limit mark (`cost_is_lower_limit`) ---------------------------------------------------

def _mark(dsn: str, inv: str, value: bool) -> None:
    """Plant the row's mark (a cost from before the write under test)."""
    execute(dsn, "UPDATE jobs.investigations SET cost_is_lower_limit = %s WHERE id = %s", (value, inv))


@pytest.mark.parametrize("value", [True, False])
@pytest.mark.parametrize("path", ["finish", "hand_back", "write_accounting"])
async def test_s2_every_final_cost_write_sets_the_mark_to_the_value_it_is_given(dsn, path, value):
    """The worker's final figure lands with the mark it passes, over whatever the row held, on each path that writes one; the record answers it too. (S2)"""
    if path == "write_accounting":
        inv = _ended_with_cost(dsn, "aborted", "A")
    else:
        inv = _plant_running(dsn, alert_id=_plant_alert(dsn), key="k", attempt=1, lapsed=False)
    _mark(dsn, inv, not value)
    async with job_store(dsn) as store:
        if path == "finish":
            got = await store.finish(T1, inv, stage="completed", disposition="benign", cost_usd=4.5,
                                     cost_is_lower_limit=value)
        else:
            got = await getattr(store, path)(T1, inv, cost_usd=4.5, knowledge=KNOWLEDGE, cost_is_lower_limit=value)
    assert (got.cost_usd, got.cost_is_lower_limit) == (4.5, value)
    assert (row(dsn, inv)["cost_usd"], lower_limit(dsn, inv)) == (4.5, value)


@pytest.mark.parametrize("path", ["finish", "hand_back", "write_accounting"])
async def test_s4_the_job_row_refuses_a_lower_limit_mark_beside_an_unknown_cost(dsn, path):
    """The database refuses true beside a null cost, so no write path stores it; the refused write changes nothing and a null cost with no mark still lands. (S4)"""
    from defender.jobs.store import is_refusal

    if path == "write_accounting":
        inv = _ended_with_cost(dsn, "failed", "A")
    else:
        inv = _plant_running(dsn, alert_id=_plant_alert(dsn), key="k", attempt=1, lapsed=False)
    before = _snap(dsn, inv)

    async def write(*, cost, mark):
        async with job_store(dsn) as store:
            if path == "finish":
                return await store.finish(T1, inv, stage="completed", disposition="benign", cost_usd=cost,
                                          cost_is_lower_limit=mark)
            return await getattr(store, path)(T1, inv, cost_usd=cost, knowledge=None, cost_is_lower_limit=mark)

    with pytest.raises(Exception) as refused:  # noqa: PT011 — the class is the database's, tested through is_refusal
        await write(cost=None, mark=True)
    assert is_refusal(refused.value), refused.value
    assert _snap(dsn, inv) == before, "a refused write changed the row"
    assert (await write(cost=None, mark=False)).cost_usd is None


async def test_s4_the_check_is_the_databases_own_not_only_the_stores(dsn):
    """Raw SQL cannot store a lower limit beside a null cost either; the control, a number marked, can be stored. (S4)"""
    inv = _plant_running(dsn, alert_id=_plant_alert(dsn), key="k", attempt=1, lapsed=False)
    execute(dsn, "UPDATE jobs.investigations SET cost_usd = 2.0, cost_is_lower_limit = true WHERE id = %s", (inv,))
    assert (row(dsn, inv)["cost_usd"], lower_limit(dsn, inv)) == (2.0, True)
    with pytest.raises(Exception, match="cost_is_lower_limit|check"):  # noqa: PT011
        execute(dsn, "UPDATE jobs.investigations SET cost_usd = NULL WHERE id = %s", (inv,))
    assert row(dsn, inv)["cost_usd"] == 2.0


async def test_s2_a_live_rows_cost_so_far_and_a_cancelled_queued_row_are_not_marked(dsn):
    """A renewal never marks, with or without a copied figure ("so far" already says it); a queued row cancelled before any run is exactly 0. (S2, S4)"""
    running = _plant_running(dsn, alert_id=_plant_alert(dsn, ticket="R"), key="k", attempt=1, lapsed=False)
    async with job_store(dsn) as store:
        await store.renew({running})
        assert lower_limit(dsn, running) is False
        await store.renew({running}, costs={running: 3.5})
        queued, _ = await store.create_investigation(T1, _plant_alert(dsn, ticket="Q"), "kq", actor="u-1")
        cancelled = await store.cancel_investigation(T1, queued.investigation_id, actor="u-1")
        claimed = await store.get_investigation(T1, running)
    assert (row(dsn, running)["cost_usd"], lower_limit(dsn, running), claimed.cost_is_lower_limit) == (3.5, False, False)
    assert (queued.cost_is_lower_limit, cancelled.cost_usd, cancelled.cost_is_lower_limit) == (False, 0, False)
    assert lower_limit(dsn, queued.investigation_id) is False


async def test_s2_cancelling_a_running_row_reads_at_least_without_storing_the_mark_and_the_holders_final_write_then_stores_its_own(dsn):
    """Cancel of a running row stores no mark (B1): the record reads "at least" by derivation (B2); the holder's later accounting stores its own value, either way. (S2, B1)"""
    async with job_store(dsn) as store:
        marked = _plant_running(dsn, alert_id=_plant_alert(dsn, ticket="A"), key="ka", attempt=1, lapsed=False)
        cleared = _plant_running(dsn, alert_id=_plant_alert(dsn, ticket="B"), key="kb", attempt=1, lapsed=False)
        for inv in (marked, cleared):
            got = await store.cancel_investigation(T1, inv, actor="u-1")
            assert (got.stage, got.cost_usd, got.cost_is_lower_limit) == ("aborted", 1.25, True)
            assert (await store.get_investigation(T1, inv)).cost_is_lower_limit is True
            assert (row(dsn, inv)["cost_usd"], lower_limit(dsn, inv)) == (1.25, False), "cancel wrote the stored mark"
        await store.write_accounting(T1, marked, cost_usd=2.0, knowledge=None, cost_is_lower_limit=True)
        await store.write_accounting(T1, cleared, cost_usd=2.0, knowledge=None, cost_is_lower_limit=False)
        records = [(await store.get_investigation(T1, i)).cost_is_lower_limit for i in (marked, cleared)]
    assert [(row(dsn, i)["cost_usd"], lower_limit(dsn, i)) for i in (marked, cleared)] == [(2.0, True), (2.0, False)]
    assert records == [True, False], "the holder's final figure no longer reads as written"


@pytest.mark.parametrize(("cost", "mark"), [(2.0, False), (2.0, True), (None, False)])
async def test_s2_cancelling_a_handed_back_row_keeps_the_figure_and_mark_its_holder_wrote(dsn, cost, mark):
    """A handed-back row still `running` already has its holder's final figure: a cancel before the take-over leaves cost and mark as written, and an unknown cost stays unmarked. (S2, S4)"""
    inv = _plant_running(dsn, alert_id=_plant_alert(dsn), key="k", attempt=1, lapsed=False)
    async with job_store(dsn) as store:
        await store.hand_back(T1, inv, cost_usd=cost, knowledge=None, cost_is_lower_limit=mark)
        got = await store.cancel_investigation(T1, inv, actor="u-1")
    assert (got.stage, got.cost_usd, got.cost_is_lower_limit) == ("aborted", cost, mark)
    assert (row(dsn, inv)["cost_usd"], lower_limit(dsn, inv)) == (cost, mark)


@pytest.mark.parametrize("attempt", [1, 3], ids=["lease_lapsed", "retry_cap"])
async def test_s2_a_lost_workers_row_is_taken_over_reading_at_least_without_a_stored_mark_and_a_handed_back_row_keeps_its_mark(dsn, attempt):
    """Take-over stores no mark on a lost worker's row (B1) but its record reads "at least" (B2); a handed-back row keeps the mark its holder wrote; the retry starts unmarked at 0; the holder's later accounting stores its value. (S2, B1)"""
    lost = _plant_running(dsn, alert_id=_plant_alert(dsn, ticket="L"), key="kl", attempt=attempt, lapsed=True)
    handed = {mark: _plant_running(dsn, alert_id=_plant_alert(dsn, ticket=f"H{mark}"), key=f"kh{mark}", attempt=1,
                                   lapsed=False) for mark in (True, False)}
    async with job_store(dsn) as store:
        for mark, inv in handed.items():
            await store.hand_back(T1, inv, cost_usd=2.0, knowledge=None, cost_is_lower_limit=mark)
        await store.take_over(held=frozenset())
        record = await store.get_investigation(T1, lost)
        handed_records = [(await store.get_investigation(T1, handed[m])).cost_is_lower_limit for m in (True, False)]
    assert (row(dsn, lost)["failure_reason"], row(dsn, lost)["cost_usd"], lower_limit(dsn, lost)) == (
        "lease_lapsed" if attempt == 1 else "retry_cap", 1.25, False), "take-over wrote the stored mark"
    assert (record.cost_usd, record.cost_is_lower_limit) == (1.25, True)
    assert [(row(dsn, handed[m])["cost_usd"], lower_limit(dsn, handed[m])) for m in (True, False)] == [(2.0, True), (2.0, False)]
    assert handed_records == [True, False]
    retries = _retries_of(dsn, lost)
    if attempt == 1:
        [retry] = retries
        assert (row(dsn, retry)["cost_usd"], lower_limit(dsn, retry)) == (0, False)
    else:
        assert retries == []
    async with job_store(dsn) as store:
        await store.write_accounting(T1, lost, cost_usd=2.0, knowledge=None, cost_is_lower_limit=True)
    assert (row(dsn, lost)["cost_usd"], lower_limit(dsn, lost)) == (2.0, True), "the holder's accounting did not store its mark"


#: The class of a write that ends a running row (r4 S2, store side): the ending write; the cost the row holds (a renewal's copy,
#: or its holder's figure); its lease (a take-over takes only a lapsed one); and whether its holder already wrote its final figure,
#: with which mark (a hand-back does, and lapses the lease at once; the live-lease case is planted all the same).
_ENDED_WITHOUT_FIGURE = [
    (write, cost, lease, figure)
    for write in ("cancel", "take_over")
    for cost in (0.0, 1.25)
    for lease in (("live", "lapsed") if write == "cancel" else ("lapsed",))
    for figure in ("not written", "written marked", "written unmarked")
]


@pytest.mark.parametrize(("write", "cost", "lease", "figure"), _ENDED_WITHOUT_FIGURE,
                         ids=["-".join(map(str, case)) for case in _ENDED_WITHOUT_FIGURE])
async def test_s2_a_write_that_ends_a_running_row_marks_it_exactly_when_its_holder_never_wrote_its_figure(
        dsn, write, cost, lease, figure):
    """Cancel or take-over of a running row: the record reads "at least" when its holder has not written its final figure,
    whatever the cost (0 included) or the lease, else the holder's mark; the STORED mark is only ever the holder's. (S2, B1)"""
    written = figure != "not written"
    inv = _plant_running(dsn, alert_id=_plant_alert(dsn), key="k", attempt=1, lapsed=lease == "lapsed", marked=written)
    execute(dsn, "UPDATE jobs.investigations SET cost_usd = %s, cost_is_lower_limit = %s WHERE id = %s",
            (cost, figure == "written marked", inv))
    async with job_store(dsn) as store:
        if write == "cancel":
            got = await store.cancel_investigation(T1, inv, actor="u-1")
            assert got.stage == "aborted", got
        else:
            assert inv in await store.take_over(held=frozenset())
    ended = row(dsn, inv)
    assert ended["stage"] == ("aborted" if write == "cancel" else "failed"), ended
    async with job_store(dsn) as store:
        record = await store.get_investigation(T1, inv)
    assert (ended["cost_usd"], lower_limit(dsn, inv)) == (cost, figure == "written marked"), (
        "the stored mark is not the holder's own: cancel or take-over wrote it")
    assert (record.cost_usd, record.cost_is_lower_limit) == (cost, figure != "written unmarked"), (
        "the record's mark is not (no holder's figure) or the holder's own")


#: B2: (stage, started, accounting written, cost, stored mark) -> what the record reads.
_DERIVATION = [
    ("failed", True, False, 1.25, False, True),
    ("aborted", True, False, 1.25, False, True),
    ("completed", True, False, 1.25, False, True),
    ("aborted", True, False, 0.0, False, True),
    ("aborted", False, False, 0.0, False, False),
    ("failed", True, True, 2.0, False, False),
    ("failed", True, True, 2.0, True, True),
    ("failed", True, False, None, False, False),
    ("running", True, False, 1.25, False, False),
]


@pytest.mark.parametrize(("stage", "started", "written", "cost", "stored", "reads"), _DERIVATION,
                         ids=[f"{s}-{'started' if st else 'unstarted'}-{'written' if w else 'unwritten'}-{c}-stored{m}"
                              for s, st, w, c, m, _ in _DERIVATION])
async def test_b2_the_record_reads_at_least_for_a_terminal_started_row_with_a_cost_and_no_holders_figure(
        dsn, stage, started, written, cost, stored, reads):
    """The record derives the mark: stored OR (terminal AND started AND no accounting AND cost not null); a never-started row, a written row, a null cost and a live row do not. (B2)"""
    inv = _plant_investigation(dsn, tenant=T1, alert_id=_plant_alert(dsn), key="k", attempt=1, stage=stage)
    execute(dsn, "UPDATE jobs.investigations SET started_at = %s, finished_at = %s, cost_usd = %s, "
                 "accounting_written_at = %s, cost_is_lower_limit = %s, disposition = %s, failure_reason = %s WHERE id = %s",
            (NOW if started else None, None if stage == "running" else NOW, cost, NOW if written else None, stored,
             "benign" if stage == "completed" else None, "no_report" if stage in ("failed", "aborted") else None, inv))
    async with job_store(dsn) as store:
        record = await store.get_investigation(T1, inv)
    assert record.cost_is_lower_limit is reads, (stage, started, written, cost, stored)
    assert lower_limit(dsn, inv) is stored, "the read changed the stored column"


async def test_s2_a_claimed_row_and_a_stored_marked_row_carry_the_mark_in_their_records(dsn):
    """The record the store answers (claim, read) has the row's mark, so the API can serve it. (S2, G10)"""
    queued = await _queued_row(dsn)
    async with job_store(dsn) as store:
        claim = await store.claim()
        execute(dsn, "UPDATE jobs.investigations SET cost_usd = 3.0, cost_is_lower_limit = true WHERE id = %s",
                (claim.record.investigation_id,))
        read = await store.get_investigation(T1, claim.record.investigation_id)
    assert (claim.record.cost_is_lower_limit, read.cost_is_lower_limit) == (False, True)
    assert claim.record.investigation_id == queued


async def test_o6_the_store_tells_a_value_it_refuses_from_a_read_only_database_on_real_faults(dsn):
    """Against real PostgreSQL: a value JSONB cannot hold (NUL) is a refusal, not an outage; a read-only transaction, as a standby answers during a failover, is an outage, not a refusal. (#1343 review, B5)"""
    from sqlalchemy import text

    from defender.jobs import is_outage, is_refusal

    running = _plant_running(dsn, alert_id=_plant_alert(dsn), key="k", attempt=1, lapsed=False)
    async with job_store(dsn) as store:
        with pytest.raises(Exception) as refused:  # noqa: PT011 — the classification is what is under test
            await store.finish(T1, running, stage="completed", knowledge={"bad": "\u0000"})
    assert is_refusal(refused.value), repr(refused.value)
    assert not is_outage(refused.value), repr(refused.value)
    async with job_store(dsn) as store:
        async def write_read_only() -> None:
            async with store._tx() as s:
                await s.execute(text("SET TRANSACTION READ ONLY"))
                await s.execute(text("UPDATE jobs.investigations SET cost_usd = 0"))

        with pytest.raises(Exception) as read_only:  # noqa: PT011 — the classification is what is under test
            await write_read_only()
    assert is_outage(read_only.value), repr(read_only.value)
    assert not is_refusal(read_only.value), repr(read_only.value)

# --- B6/B7/B8: take-over -------------------------------------------------------------------------------------------

async def test_b6_a_lapsed_running_row_is_failed_and_retried_in_one_take_over_and_audited(dsn, caplog):
    """Lapsed attempt 1: `failed`/`lease_lapsed`, no accounting, + queued attempt 2 (same key, created now, cost 0, no lease or mark); a fresh or held lease is left. (B6, B8, B-P3)"""
    audit = JobsAudit(caplog)
    lapsed = _plant_running(dsn, alert_id=_plant_alert(dsn, ticket="P-1"), key="k1", attempt=1, lapsed=True)
    fresh = _plant_running(dsn, alert_id=_plant_alert(dsn, ticket="P-2"), key="k2", attempt=1, lapsed=False)
    held = _plant_running(dsn, alert_id=_plant_alert(dsn, ticket="P-3"), key="k3", attempt=1, lapsed=True)
    fresh_before, held_before = _snap(dsn, fresh), _snap(dsn, held)
    async with job_store(dsn) as store:
        await store.take_over(held=frozenset({held}))

    old = row(dsn, lapsed)
    assert (old["stage"], old["failure_reason"], old["finished_at"]) == ("failed", "lease_lapsed", NOW)
    assert old["cost_usd"] == 1.25, "a take-over writes no accounting"
    assert accounting_written(dsn, lapsed) is None
    retries = execute(dsn, "SELECT id, tenant_id, request_key, attempt, stage, created_at, cost_usd, started_at, "
                           "lease_expires_at, accounting_written_at, knowledge IS NULL FROM jobs.investigations "
                           "WHERE alert_id = (SELECT alert_id FROM jobs.investigations WHERE id = %s) AND id <> %s",
                      (lapsed, lapsed))
    assert [r[1:] for r in retries] == [(T1, "k1", 2, "queued", NOW, 0.0, None, None, None, True)]
    assert _snap(dsn, fresh) == fresh_before, "a row whose lease is fresh was taken over (B8)"
    assert _snap(dsn, held) == held_before, "a row in the caller's held set was taken over (B-P3)"
    events = [(e.action, e.actor, e.tenant_id, e.target) for e in audit.events() if e.action.startswith("investigation.")]
    assert events == [("investigation.takeover", "system", T1, lapsed), ("investigation.retry", "system", T1, retries[0][0])]
    assert "lease_lapsed" in next(e.detail for e in audit.events() if e.action == "investigation.takeover")


async def test_b6_a_lapsed_second_attempt_is_retried_as_attempt_three(dsn):
    """Below the cap every lapsed attempt queues the next one; attempt 2 → `lease_lapsed` + attempt 3. (B6)"""
    alert_id = _plant_alert(dsn)
    _plant_investigation(dsn, tenant=T1, alert_id=alert_id, key="k1", attempt=1, stage="failed")
    second = _plant_running(dsn, alert_id=alert_id, key="k1", attempt=2, lapsed=True)
    async with job_store(dsn) as store:
        await store.take_over(held=frozenset())
    assert row(dsn, second)["failure_reason"] == "lease_lapsed"
    [retry] = _retries_of(dsn, second)
    assert (row(dsn, retry)["attempt"], row(dsn, retry)["stage"]) == (3, "queued")


async def test_b6_a_lapsed_third_attempt_ends_retry_cap_with_no_retry(dsn, caplog):
    """Attempt 3 lapsed: `failed`/`retry_cap`, nothing inserted, the alert is free, one takeover event naming the reason. (B6)"""
    audit = JobsAudit(caplog)
    alert_id = _plant_alert(dsn)
    third = _plant_running(dsn, alert_id=alert_id, key="k1", attempt=3, lapsed=True)
    async with job_store(dsn) as store:
        await store.take_over(held=frozenset())

    assert (row(dsn, third)["stage"], row(dsn, third)["failure_reason"]) == ("failed", "retry_cap")
    assert _count(dsn, "investigations") == 1
    assert [e.action for e in audit.events() if e.action.startswith("investigation.")] == ["investigation.takeover"]
    assert "retry_cap" in audit.events()[-1].detail


async def test_b6_one_pass_takes_over_every_lapsed_row_each_in_its_own_tenant(dsn, caplog):
    """Four lapsed rows (two tenants, attempts 1, 2, 3, 1): all ended in one pass, retries in the row's tenant, one takeover event each. (B6, B7)"""
    audit = JobsAudit(caplog)
    rows = [(T1, 1), (T2, 2), (T1, 3), (T2, 1)]
    ids = [_plant_running(dsn, alert_id=_plant_alert(dsn, tenant=tenant, ticket=f"P-{n}"), key="k", attempt=attempt,
                          lapsed=True, tenant=tenant) for n, (tenant, attempt) in enumerate(rows)]
    async with job_store(dsn) as store:
        await store.take_over(held=frozenset())
    assert [row(dsn, i)["failure_reason"] for i in ids] == ["lease_lapsed", "lease_lapsed", "retry_cap", "lease_lapsed"]
    assert [[(row(dsn, r)["attempt"]) for r in _retries_of(dsn, i)] for i in ids] == [[2], [3], [], [2]]
    takeovers = sorted((e.tenant_id, e.target) for e in audit.events() if e.action == "investigation.takeover")
    assert takeovers == sorted((tenant, i) for (tenant, _), i in zip(rows, ids, strict=True))
    retry_tenants = {execute(dsn, "SELECT tenant_id FROM jobs.investigations WHERE id = %s", (e.target,))[0][0] == e.tenant_id
                     for e in audit.events() if e.action == "investigation.retry"}
    assert retry_tenants == {True}


async def test_b8_only_a_running_row_with_a_lapsed_lease_is_retried(dsn, caplog):
    """A queued row, a finished row and a cancelled row, each with a lease in the past, are left; no retry, no event; the lapsed running row beside them is taken over. (B8)"""
    audit = JobsAudit(caplog)
    queued = _plant_investigation(dsn, tenant=T1, alert_id=_plant_alert(dsn, ticket="Q"), key="k", attempt=1, stage="queued")
    async with job_store(dsn) as store:
        finished = _plant_running(dsn, alert_id=_plant_alert(dsn, ticket="F"), key="k", attempt=1, lapsed=False)
        await store.finish(T1, finished, stage="completed", disposition="benign", cost_usd=1.0)
        cancelled = _plant_running(dsn, alert_id=_plant_alert(dsn, ticket="X"), key="k", attempt=1, lapsed=False)
        await store.cancel_investigation(T1, cancelled, actor="u-1")
        for i in (finished, cancelled):
            lapse_lease(dsn, i)
        control = _plant_running(dsn, alert_id=_plant_alert(dsn, ticket="C"), key="k", attempt=1, lapsed=True)
        before = {i: _snap(dsn, i) for i in (queued, finished, cancelled)}
        await store.take_over(held=frozenset())
    assert {i: _snap(dsn, i) for i in before} == before
    assert row(dsn, control)["failure_reason"] == "lease_lapsed"
    assert _count(dsn, "investigations") == 5, "only the control row was retried"
    assert [e.target for e in audit.events() if e.action == "investigation.takeover"] == [control]


async def test_b6_the_audit_events_leave_after_the_commit(dsn, caplog):
    """When each takeover/retry event is emitted another connection already sees `failed` / `queued`. (B6, O13)"""
    audit = JobsAudit(caplog)
    seen = VisibleAtEmit(dsn)
    lapsed = _plant_running(dsn, alert_id=_plant_alert(dsn), key="k", attempt=1, lapsed=True)
    async with job_store(dsn) as store:
        logging.getLogger(JOBS_AUDIT).addHandler(seen)
        try:
            await store.take_over(held=frozenset())
        finally:
            logging.getLogger(JOBS_AUDIT).removeHandler(seen)
    assert seen.seen == [("investigation.takeover", "failed"), ("investigation.retry", "queued")]
    assert audit.events()[0].target == lapsed


async def test_b6_a_take_over_that_fails_at_commit_changes_and_emits_nothing(dsn, caplog):
    """A real commit-time fault: no row moves, no retry exists, no event leaves; without the fault the same pass commits. (B6, O13)"""
    audit = JobsAudit(caplog)
    execute(dsn, "CREATE FUNCTION public.boom_1342() RETURNS trigger LANGUAGE plpgsql AS "
                 "$$ BEGIN RAISE EXCEPTION 'boom 1342'; END $$")
    lapsed = _plant_running(dsn, alert_id=_plant_alert(dsn), key="k", attempt=1, lapsed=True)
    before = execute(dsn, "SELECT id, stage FROM jobs.investigations ORDER BY id")
    async with job_store(dsn) as store:
        execute(dsn, _BOOM)
        with contextlib.suppress(Exception):  # whether the pass raises or logs and carries on is the worker's seam, not the contract's
            await store.take_over(held=frozenset())
        assert execute(dsn, "SELECT id, stage FROM jobs.investigations ORDER BY id") == before
        assert [e for e in audit.events() if e.action.startswith("investigation.")] == []
        execute(dsn, "DROP TRIGGER boom_1342 ON jobs.investigations")
        await store.take_over(held=frozenset())  # control
    assert row(dsn, lapsed)["stage"] == "failed"
    assert len([e for e in audit.events() if e.action.startswith("investigation.")]) == 2


async def test_b7_a_take_over_skips_a_row_another_transaction_holds_and_takes_it_later(dsn):
    """`SKIP LOCKED`: a locked lapsed row is passed over at once while an unlocked one is taken; once released the next pass takes it. (B7)"""
    import psycopg

    locked = _plant_running(dsn, alert_id=_plant_alert(dsn, ticket="L"), key="k", attempt=1, lapsed=True)
    free = _plant_running(dsn, alert_id=_plant_alert(dsn, ticket="F"), key="k", attempt=1, lapsed=True)
    async with job_store(dsn) as store:
        async with await psycopg.AsyncConnection.connect(dsn) as conn:
            await conn.execute("SELECT id FROM jobs.investigations WHERE id = %s FOR UPDATE", (locked,))
            await asyncio.wait_for(store.take_over(held=frozenset()), timeout=5)
            assert (row(dsn, locked)["stage"], row(dsn, free)["stage"]) == ("running", "failed")
            assert _retries_of(dsn, locked) == []
            await conn.commit()
        await store.take_over(held=frozenset())
    assert row(dsn, locked)["failure_reason"] == "lease_lapsed"
    assert len(_retries_of(dsn, locked)) == 1


async def test_b7_two_take_over_passes_at_once_take_each_row_once(dsn, caplog):
    """Six lapsed rows, two workers' passes together: exactly one retry and one takeover event per row, no pass fails. (B7, B6)"""
    audit = JobsAudit(caplog)
    ids = [_plant_running(dsn, alert_id=_plant_alert(dsn, ticket=f"P-{n}"), key="k", attempt=1, lapsed=True) for n in range(6)]
    async with job_store(dsn) as a, job_store(dsn) as b:
        results = await asyncio.gather(a.take_over(held=frozenset()), b.take_over(held=frozenset()), return_exceptions=True)
    assert [r for r in results if isinstance(r, BaseException)] == []
    assert [len(_retries_of(dsn, i)) for i in ids] == [1] * 6
    assert _count(dsn, "investigations") == 12
    assert sorted(e.target for e in audit.events() if e.action == "investigation.takeover") == sorted(ids)
    assert len([e for e in audit.events() if e.action == "investigation.retry"]) == 6


async def test_r4_a_row_is_claimed_at_most_once(dsn):
    """A running row, lapsed or not, is never claimed again and never goes back to `queued`; after a take-over only the retry is claimable. (r4 item 2, B6)"""
    async with job_store(dsn) as store:
        alert = await an_alert(store, T1)
        inv, _ = await store.create_investigation(T1, alert.alert_id, "k1", actor="u-1")
        assert (await store.claim()).record.investigation_id == inv.investigation_id
        lease = lease_left(dsn, inv.investigation_id)
        assert await store.claim() is None
        lapse_lease(dsn, inv.investigation_id)
        assert await store.claim() is None, "a lapsed running row was claimed again"
        assert lease_left(dsn, inv.investigation_id) < 0 <= lease, "a second claim re-leased the row"
        await store.take_over(held=frozenset())
        [retry] = _retries_of(dsn, inv.investigation_id)
        claimed = await store.claim()
        assert await store.claim() is None
    assert claimed.record.investigation_id == retry
    assert row(dsn, inv.investigation_id)["stage"] == "failed"
    assert row(dsn, inv.investigation_id)["started_at"] == NOW


# --- B6 interactions: create, delete, cancel, finish ----------------------------------------------------------------

async def test_b6_a_create_after_a_take_over_answers_the_live_retry_and_inserts_nothing(dsn):
    """Same key or a new one, a create finds the retry (live) and inserts nothing. (B6, Interactions)"""
    alert_id = _plant_alert(dsn)
    lapsed = _plant_running(dsn, alert_id=alert_id, key="k1", attempt=1, lapsed=True)
    async with job_store(dsn) as store:
        await store.take_over(held=frozenset())
        [retry] = _retries_of(dsn, lapsed)
        same, same_created = await store.create_investigation(T1, alert_id, "k1", actor="u-1")
        other, other_created = await store.create_investigation(T1, alert_id, "k2", actor="u-1")
    assert (same.investigation_id, same_created) == (retry, False)
    assert (other.investigation_id, other_created) == (retry, False)
    assert _count(dsn, "investigations") == 2


async def test_b6_a_create_racing_a_take_over_always_finds_a_live_row(dsn):
    """Fifteen rounds of take-over against a create of a new key: the create never inserts (it sees the running row or the retry), and exactly one live row remains. (B6, Interactions)"""
    async with job_store(dsn) as a, job_store(dsn) as b:
        for n in range(15):
            alert_id = _plant_alert(dsn, ticket=f"R-{n}")
            lapsed = _plant_running(dsn, alert_id=alert_id, key="k1", attempt=1, lapsed=True)
            _, got = await asyncio.gather(a.take_over(held=frozenset()), b.create_investigation(T1, alert_id, "k2", actor="u-1"))
            assert got[1] is False, "the create inserted beside a live row"
            assert _count(dsn, "investigations", f"alert_id = '{alert_id}'") == 2
            assert _count(dsn, "investigations", f"alert_id = '{alert_id}' AND stage IN ('queued', 'running')") == 1
            assert row(dsn, lapsed)["failure_reason"] == "lease_lapsed"


async def test_b6_delete_is_refused_while_a_take_over_left_a_live_retry_and_allowed_at_the_cap(dsn):
    """After a take-over below the cap the retry is live, so delete through either attempt is a `Conflict` that removes nothing; after `retry_cap` nothing is live and delete removes the request. (B6, Interactions)"""
    from defender.jobs import Conflict

    lapsed = _plant_running(dsn, alert_id=_plant_alert(dsn, ticket="A"), key="k", attempt=1, lapsed=True)
    capped = _plant_running(dsn, alert_id=_plant_alert(dsn, ticket="B"), key="k", attempt=3, lapsed=True)
    async with job_store(dsn) as store:
        await store.take_over(held=frozenset())
        [retry] = _retries_of(dsn, lapsed)
        for named in (lapsed, retry):
            with pytest.raises(Conflict):
                await store.delete_investigation(T1, named, actor="u-1")
        await store.delete_investigation(T1, capped, actor="u-1")
    assert row(dsn, capped) is None
    assert row(dsn, lapsed) is not None
    assert row(dsn, retry) is not None


async def test_b6_a_cancelled_row_is_not_taken_over(dsn, caplog):
    """Cancel first: the lapsed running row is `aborted`; a take-over after it inserts no retry and emits no takeover. (B6, B9, Interactions)"""
    audit = JobsAudit(caplog)
    lapsed = _plant_running(dsn, alert_id=_plant_alert(dsn), key="k", attempt=1, lapsed=True)
    async with job_store(dsn) as store:
        await store.cancel_investigation(T1, lapsed, actor="u-1")
        await store.take_over(held=frozenset())
    assert (row(dsn, lapsed)["stage"], row(dsn, lapsed)["failure_reason"]) == ("aborted", "cancelled")
    assert _count(dsn, "investigations") == 1
    assert [e.action for e in audit.events() if e.action.startswith("investigation.")] == ["investigation.cancel"]


async def test_b9_cancel_racing_a_take_over_has_exactly_one_winner(dsn):
    """Fifteen rounds on a lapsed running row: cancel won ⇒ `aborted`, no retry; take-over won ⇒ `failed`/`lease_lapsed`, a retry, and cancel's `Conflict` names it. (B9, B6, Interactions)"""
    from defender.jobs import Conflict

    outcomes = set()
    async with job_store(dsn) as a, job_store(dsn) as b:
        for n in range(15):
            lapsed = _plant_running(dsn, alert_id=_plant_alert(dsn, ticket=f"R-{n}"), key="k", attempt=1, lapsed=True)
            cancelled, _ = await asyncio.gather(a.cancel_investigation(T1, lapsed, actor="u-1"),
                                                b.take_over(held=frozenset()), return_exceptions=True)
            retries = _retries_of(dsn, lapsed)
            if isinstance(cancelled, Conflict):
                assert row(dsn, lapsed)["failure_reason"] == "lease_lapsed"
                assert len(retries) == 1
                assert retries[0] in str(cancelled)
                outcomes.add("take-over")
            else:
                assert not isinstance(cancelled, BaseException), cancelled
                assert (row(dsn, lapsed)["stage"], retries) == ("aborted", [])
                outcomes.add("cancel")
    assert outcomes <= {"cancel", "take-over"}


@pytest.mark.parametrize("first", ["finish", "take_over"])
async def test_b4_finish_and_take_over_of_one_lapsed_row_have_one_winner(dsn, first):
    """Whichever commits first decides: finish first ⇒ `completed` and no retry; take-over first ⇒ the late finish returns None and the row is `failed`/`lease_lapsed`. (B4, B6, Interactions)"""
    lapsed = _plant_running(dsn, alert_id=_plant_alert(dsn), key="k", attempt=1, lapsed=True)
    async with job_store(dsn) as store:
        if first == "finish":
            assert await store.finish(T1, lapsed, stage="completed", disposition="benign", cost_usd=2.0) is not None
            await store.take_over(held=frozenset())
        else:
            await store.take_over(held=frozenset())
            assert await store.finish(T1, lapsed, stage="completed", disposition="benign", cost_usd=2.0) is None
    stored = row(dsn, lapsed)
    if first == "finish":
        assert (stored["stage"], stored["cost_usd"], _retries_of(dsn, lapsed)) == ("completed", 2.0, [])
    else:
        assert (stored["stage"], stored["failure_reason"], stored["cost_usd"]) == ("failed", "lease_lapsed", 1.25)
        assert len(_retries_of(dsn, lapsed)) == 1


# --- B9: cancel of a running row, and what an ended row's cancel says ------------------------------------------------

async def test_b9_cancel_of_a_running_row_aborts_it_at_once(dsn, caplog):
    """`running` → `aborted`/`cancelled`, finished now, answered at once and audited with the caller. (B9)"""
    audit = JobsAudit(caplog)
    async with job_store(dsn) as store:
        alert = await an_alert(store, T1)
        inv, _ = await store.create_investigation(T1, alert.alert_id, "k1", actor="u-1")
        await store.claim()
        got = await store.cancel_investigation(T1, inv.investigation_id, actor="u-1")

    assert (got.stage, got.failure_reason) == ("aborted", "cancelled")
    stored = row(dsn, inv.investigation_id)
    assert (stored["stage"], stored["failure_reason"], stored["finished_at"]) == ("aborted", "cancelled", NOW)
    assert [(e.action, e.actor) for e in audit.events() if e.action == "investigation.cancel"] == [
        ("investigation.cancel", "u-1")]


async def test_b3_a_cancelled_row_drops_out_of_the_holders_renewal(dsn):
    """The renewal that covered the row before the cancel no longer does: the signal for the holder to end its child. (B3, B9)"""
    running = _plant_running(dsn, alert_id=_plant_alert(dsn), key="k", attempt=1, lapsed=False)
    async with job_store(dsn) as store:
        assert set(await store.renew({running})) == {running}
        await store.cancel_investigation(T1, running, actor="u-1")
        assert set(await store.renew({running})) == set()
    assert row(dsn, running)["stage"] == "aborted"


async def test_b9_cancel_racing_a_finish_has_exactly_one_winner(dsn):
    """Fifteen rounds on a running row: cancel won ⇒ `aborted` and finish returns None; finish won ⇒ the stage it wrote and cancel's `Conflict` "already ended". (B9, B4, Interactions)"""
    from defender.jobs import Conflict

    outcomes = set()
    async with job_store(dsn) as a, job_store(dsn) as b:
        for n in range(15):
            running = _plant_running(dsn, alert_id=_plant_alert(dsn, ticket=f"R-{n}"), key="k", attempt=1, lapsed=False)
            cancelled, finished = await asyncio.gather(
                a.cancel_investigation(T1, running, actor="u-1"),
                b.finish(T1, running, stage="completed", disposition="benign", cost_usd=2.0), return_exceptions=True)
            assert not isinstance(finished, BaseException), finished
            if finished is None:
                assert not isinstance(cancelled, BaseException), cancelled
                assert row(dsn, running)["stage"] == "aborted"
                outcomes.add("cancel")
            else:
                assert isinstance(cancelled, Conflict)
                assert "already ended" in str(cancelled)
                assert row(dsn, running)["stage"] == "completed"
                outcomes.add("finish")
    assert outcomes <= {"cancel", "finish"}


async def test_b9_cancel_of_a_taken_over_attempt_names_its_live_retry(dsn):
    """Cancel of the failed attempt 1 whose retry is live: `Conflict` naming the retry's id; once the retry is cancelled, "already ended". (B9)"""
    from defender.jobs import Conflict

    lapsed = _plant_running(dsn, alert_id=_plant_alert(dsn, ticket="P-1"), key="k1", attempt=1, lapsed=True)
    async with job_store(dsn) as store:
        await store.take_over(held=frozenset())
        [retry] = _retries_of(dsn, lapsed)
        with pytest.raises(Conflict) as named:
            await store.cancel_investigation(T1, lapsed, actor="u-1")
        await store.cancel_investigation(T1, retry, actor="u-1")
        with pytest.raises(Conflict, match="already ended") as ended:
            await store.cancel_investigation(T1, lapsed, actor="u-1")
    assert retry in str(named.value)
    assert retry not in str(ended.value)
    assert row(dsn, lapsed)["failure_reason"] == "lease_lapsed", "a refused cancel changed the row"


async def test_b9_a_cancel_names_a_retry_only_when_one_is_live_under_the_same_request(dsn):
    """Named: a live higher attempt of the same tenant/alert/key, whichever earlier attempt is cancelled. Not named: an ended later attempt, a live row of another key, a live row of another alert. (B9, r5 item 11)"""
    from defender.jobs import Conflict

    chain = _plant_alert(dsn, ticket="A")
    first = _plant_investigation(dsn, tenant=T1, alert_id=chain, key="k", attempt=1, stage="failed")
    second = _plant_investigation(dsn, tenant=T1, alert_id=chain, key="k", attempt=2, stage="failed")
    third = _plant_running(dsn, alert_id=chain, key="k", attempt=3, lapsed=False)

    done = _plant_alert(dsn, ticket="B")
    early = _plant_investigation(dsn, tenant=T1, alert_id=done, key="k", attempt=1, stage="failed")
    _plant_investigation(dsn, tenant=T1, alert_id=done, key="k", attempt=2, stage="completed")

    shared = _plant_alert(dsn, ticket="C")
    old_key = _plant_investigation(dsn, tenant=T1, alert_id=shared, key="k", attempt=1, stage="failed")
    other_key = _plant_running(dsn, alert_id=shared, key="other", attempt=1, lapsed=False)

    elsewhere = _plant_investigation(dsn, tenant=T1, alert_id=_plant_alert(dsn, ticket="D"), key="k", attempt=1, stage="failed")
    _plant_running(dsn, alert_id=_plant_alert(dsn, ticket="E"), key="k", attempt=2, lapsed=False)

    async def message(target: str) -> str:
        with pytest.raises(Conflict) as refused:
            await store.cancel_investigation(T1, target, actor="u-1")
        return str(refused.value)

    async with job_store(dsn) as store:
        assert [third in await message(i) for i in (first, second)] == [True, True]
        for unrelated, live in ((early, None), (old_key, other_key), (elsewhere, None)):
            text = await message(unrelated)
            assert "already ended" in text
            assert live is None or live not in text
    assert row(dsn, third)["stage"] == "running", "the refused cancels touched the live retry"


@pytest.mark.parametrize("differs", ["tenant", "alert", "request key"])
async def test_b9_a_cancel_never_names_a_live_higher_attempt_that_differs_in_tenant_alert_or_request_key(dsn, differs):
    """A live higher attempt differing from the ended one in that field alone is not named ("already ended"); the control matching all three is. (B9, r5 item 11)"""
    from defender.jobs import Conflict

    chain = _plant_alert(dsn, ticket="E")
    ended = _plant_investigation(dsn, tenant=T1, alert_id=chain, key="k", attempt=1, stage="failed")
    # (the "tenant" variant necessarily differs in alert too: a tenant's alert belongs to it)
    # a tenant's alert belongs to it, so the other tenant's row necessarily stands on an alert of its own
    live = {"tenant": lambda: _plant_running(dsn, alert_id=_plant_alert(dsn, tenant=T2, ticket="X"), key="k", attempt=2,
                                             lapsed=False, tenant=T2),
            "alert": lambda: _plant_running(dsn, alert_id=_plant_alert(dsn, ticket="Y"), key="k", attempt=2, lapsed=False),
            "request key": lambda: _plant_running(dsn, alert_id=chain, key="other", attempt=2, lapsed=False)}[differs]()
    control_chain = _plant_alert(dsn, ticket="C")
    control_ended = _plant_investigation(dsn, tenant=T1, alert_id=control_chain, key="k", attempt=1, stage="failed")
    control = _plant_running(dsn, alert_id=control_chain, key="k", attempt=2, lapsed=False)
    async with job_store(dsn) as store:
        with pytest.raises(Conflict) as refused:
            await store.cancel_investigation(T1, ended, actor="u-1")
        with pytest.raises(Conflict) as named:
            await store.cancel_investigation(T1, control_ended, actor="u-1")
    assert "already ended" in str(refused.value)
    assert live not in str(refused.value), f"named a live row differing in {differs}"
    assert control in str(named.value), "premise: the matching live retry was not named"
    assert row(dsn, live)["stage"] == "running", "the refused cancel touched the live row"


_FAR_PAST = dt.datetime(2001, 2, 3, 4, 5, 6, 123456, tzinfo=dt.UTC)
_FAR_FUTURE = dt.datetime(2100, 2, 3, 4, 5, 6, 123456, tzinfo=dt.UTC)


def _created_at(dsn: str, investigation_id: str) -> dt.datetime:
    return execute(dsn, "SELECT created_at FROM jobs.investigations WHERE id = %s", (investigation_id,))[0][0]


@pytest.mark.parametrize("instant", [_FAR_PAST, _FAR_FUTURE], ids=["clock-in-the-past", "clock-in-the-future"])
async def test_b1_b11_every_store_write_dates_its_lease_by_the_database_clock_and_every_other_stamp_by_the_injected_one(dsn, instant):
    """With the injected clock far from the planted rows and the database's now(): leases follow now() (a hand-back's is already lapsed), created_at, finished_at and the mark follow the clock. (B1, B11, B Clock)"""
    clock = Clock(instant)
    queued = _plant_investigation(dsn, tenant=T1, alert_id=_plant_alert(dsn, ticket="Q"), key="k", attempt=1, stage="queued")
    renewed = _plant_running(dsn, alert_id=_plant_alert(dsn, ticket="R"), key="k", attempt=1, lapsed=False)
    execute(dsn, "UPDATE jobs.investigations SET lease_expires_at = now() + interval '5 seconds' WHERE id = %s", (renewed,))
    handed = _plant_running(dsn, alert_id=_plant_alert(dsn, ticket="H"), key="k", attempt=1, lapsed=False)
    lapsed = _plant_running(dsn, alert_id=_plant_alert(dsn, ticket="L"), key="k", attempt=1, lapsed=True)
    cancelled = _plant_running(dsn, alert_id=_plant_alert(dsn, ticket="C"), key="k", attempt=1, lapsed=False)
    finished = _plant_running(dsn, alert_id=_plant_alert(dsn, ticket="F"), key="k", attempt=1, lapsed=False)
    accounted = _ended_with_cost(dsn, "failed", "A")
    created_alert = _plant_alert(dsn, ticket="N")

    async with store_with(dsn, clock) as store:
        claimed = (await store.claim()).record.investigation_id
        assert claimed == queued
        assert 25 < lease_left(dsn, claimed) < 31, "a claim's lease is not 30 s from the database's now()"
        assert row(dsn, claimed)["started_at"] == instant

        assert set(await store.renew({renewed})) == {renewed}
        assert 25 < lease_left(dsn, renewed) < 31, "a renewal's lease is not 30 s from the database's now()"

        assert await store.hand_back(T1, handed, cost_usd=1.0, knowledge=None) is not None
        assert lease_left(dsn, handed) < 0, "a hand-back's lease is not already lapsed by the database's clock"
        assert accounting_written(dsn, handed) == instant
        assert row(dsn, handed)["finished_at"] is None

        await store.take_over(held={handed})  # the handed-back row's lease is lapsed too
        assert row(dsn, lapsed)["stage"] == "failed"
        assert row(dsn, lapsed)["finished_at"] == instant
        [retry] = _retries_of(dsn, lapsed)
        assert _created_at(dsn, retry) == instant, "a retry's created_at is not the clock"

        await store.cancel_investigation(T1, cancelled, actor="u-1")
        assert row(dsn, cancelled)["finished_at"] == instant

        assert await store.finish(T1, finished, stage="completed", disposition="benign", cost_usd=1.0) is not None
        assert row(dsn, finished)["finished_at"] == instant
        assert accounting_written(dsn, finished) == instant

        assert await store.write_accounting(T1, accounted, cost_usd=2.0, knowledge=None) is not None
        assert accounting_written(dsn, accounted) == instant
        assert row(dsn, accounted)["finished_at"] == NOW, "a final accounting restamped the end"

        created, _ = await store.create_investigation(T1, created_alert, "k-new", actor="u-1")
        assert _created_at(dsn, created.investigation_id) == instant


# --- #1360: offboarding ends the tenant's jobs (O3, O4, O5) ---------------------------------------------------------

OFFBOARDED = "tenant_offboarded"
#: What the tenant row reads after the transition (the same four-and-failure `request_offboard` leaves).
OFFBOARDING = ("offboarding", "offboard", "offboard", "service", None)
STALL_KEY = 1360


def _offboard(store: Any, tenant: str, *, actor: str) -> Any:
    return store.offboard_tenant(tenant, actor=actor)


def _learning(dsn: str, job_id: str) -> dict[str, Any]:
    cols = ("status", "reason", "message", "finished_at", "lease_expires_at")
    found = execute(dsn, f"SELECT {', '.join(cols)} FROM jobs.learning_jobs WHERE id = %s", (job_id,))  # noqa: S608
    return dict(zip(cols, found[0], strict=True))


def _live_of(dsn: str, tenant: str) -> int:
    return (_count(dsn, "investigations", f"tenant_id = '{tenant}' AND stage IN ('queued', 'running')")
            + _count(dsn, "learning_jobs", f"tenant_id = '{tenant}' AND status IN ('queued', 'running')"))


def _job_rows(dsn: str) -> dict[str, Any]:
    """Every row of both job tables, whole (the database's own JSON), by id."""
    return dict(execute(dsn, "SELECT id, to_jsonb(i) FROM jobs.investigations i "
                             "UNION ALL SELECT id, to_jsonb(l) FROM jobs.learning_jobs l"))


def _tenant_json(dsn: str, tenant: str) -> Any:
    return execute(dsn, "SELECT to_jsonb(t) FROM tenancy.tenants t WHERE id = %s", (tenant,))[0][0]


def _auto_job_of(dsn: str, investigation: str) -> str:
    return str(execute(dsn, "SELECT id FROM jobs.learning_jobs WHERE investigation_id = %s", (investigation,))[0][0])


async def _live_jobs(dsn: str, store: Any) -> dict[str, Any]:
    """T1: a queued and a running investigation; a handed-back, a running and a queued learning job (and the three
    completed investigations they follow). T2: one queued investigation and one queued learning job."""
    from defender.tests.jobs.test_1344_learning_jobs import completed_investigation

    handed_parent = await completed_investigation(store, ticket="L-1")
    handed = _auto_job_of(dsn, handed_parent)
    assert (await store.claim_learning_job()).record.learning_job_id == handed
    assert await store.hand_back_learning_job(T1, handed) is not None
    # The hand-back stamped `finished_at` with the fixed clock's NOW: move it back, so the offboard's overwrite with "now" is observable.
    execute(dsn, "UPDATE jobs.learning_jobs SET finished_at = %s WHERE id = %s", (NOW - HOUR, handed))
    running_parent = await completed_investigation(store, ticket="L-2")
    running_job = _auto_job_of(dsn, running_parent)
    assert (await store.claim_learning_job()).record.learning_job_id == running_job
    parents = [handed_parent, running_parent]
    parents.append(await completed_investigation(store, ticket="L-3"))
    other_parent = await completed_investigation(store, ticket="L-9", tenant=T2)
    running_alert, queued_alert = await an_alert(store, T1, ticket="R-1"), await an_alert(store, T1, ticket="Q-1")
    running, _ = await store.create_investigation(T1, running_alert.alert_id, "k-run", actor="u-1")
    assert (await store.claim()).record.investigation_id == running.investigation_id
    queued, _ = await store.create_investigation(T1, queued_alert.alert_id, "k-q", actor="u-1")
    other_alert = await an_alert(store, T2, ticket="Q-9")
    other, _ = await store.create_investigation(T2, other_alert.alert_id, "k-q", actor="u-2")
    return {"investigations": [queued.investigation_id, running.investigation_id], "completed": parents,
            "learning": [handed, running_job, _auto_job_of(dsn, parents[2])], "running_job": running_job,
            "running": running.investigation_id, "other_investigation": other.investigation_id,
            "other_learning": _auto_job_of(dsn, other_parent)}


def _assert_ended(dsn: str, jobs: dict[str, Any]) -> None:
    for inv in jobs["investigations"]:
        stored = row(dsn, inv)
        assert (stored["stage"], stored["failure_reason"], stored["finished_at"]) == ("aborted", OFFBOARDED, NOW), inv
        assert lease_left(dsn, inv) is None
        assert "offboard" in (stored["failure_message"] or "").lower(), "the ending does not say the tenant was offboarded"
    for job in jobs["learning"]:
        stored = _learning(dsn, job)
        assert (stored["status"], stored["reason"], stored["finished_at"], stored["lease_expires_at"]) == (
            "skipped", OFFBOARDED, NOW, None), job
        assert "offboard" in (stored["message"] or "").lower(), "the ending does not say the tenant was offboarded"


async def test_1360_o3_the_offboard_commit_ends_every_live_job_of_the_tenant_and_no_other(dsn):
    """Queued/running investigations -> aborted/tenant_offboarded; queued/running/handed-back learning jobs ->
    skipped/tenant_offboarded; every other row and tenant untouched; the holders' later writes still work. (#1360 O3, D3)"""
    async with job_store(dsn) as store:
        jobs = await _live_jobs(dsn, store)
        held = {jobs["running"], jobs["running_job"]}
        assert set(await store.renew(held)) == held, "premise: both are renewable before the offboard"
        before, other_tenant = _job_rows(dsn), _tenant_json(dsn, T2)
        record = await _offboard(store, T1, actor="admin-1")
        renewed = await store.renew(held)
        accounted = await store.write_accounting(T1, jobs["running"], cost_usd=0.5, knowledge=None)

    assert (record.id, record.state, record.pending_action, record.step, record.step_actor, record.failure) == (T1, *OFFBOARDING)
    assert _tenant_json(dsn, T1)["state"] == "offboarding"
    assert _tenant_json(dsn, T2) == other_tenant
    _assert_ended(dsn, jobs)
    assert _live_of(dsn, T1) == 0
    ended = {*jobs["investigations"], *jobs["learning"]}
    after = _job_rows(dsn)
    assert set(after) == set(before)
    assert ended < set(before)
    assert {i for i in before if after[i] != before[i]} == ended, "a row that was not live changed, or a live one did not"
    assert {jobs["other_investigation"], jobs["other_learning"], *jobs["completed"]} <= set(before) - ended
    assert renewed == [], "the holder's renewal still covers a row the offboard ended"
    assert accounted is not None, "the holder's final accounting is refused on a row the offboard ended"


async def test_1360_o3_a_creating_tenant_is_offboarded_too_and_its_jobs_end(dsn):
    """A tenant still `creating` moves to `offboarding` and its live job ends like an active tenant's. (#1360 O3, D7)"""
    from defender.tests.support.jobs._jobs1342 import move_tenant

    async with job_store(dsn) as store:
        alert = await an_alert(store, T1)
        queued, _ = await store.create_investigation(T1, alert.alert_id, "k1", actor="u-1")
        move_tenant(dsn, T1, state="creating")
        record = await _offboard(store, T1, actor="admin-1")

    assert (record.state, record.pending_action, record.step, record.step_actor) == OFFBOARDING[:4]
    assert _tenant_json(dsn, T1)["state"] == "offboarding"
    _assert_ended(dsn, {"investigations": [queued.investigation_id], "learning": []})


@pytest.mark.parametrize("state", ["absent", "offboarding", "offboarded"])
async def test_1360_o3_a_tenant_that_cannot_be_offboarded_is_refused_and_no_job_row_or_audit_changes(dsn, caplog, state):
    """An absent tenant is tenancy's `NotFound`; an offboarding or offboarded one its `Conflict`; nothing changes
    and nothing is audited, while another tenant's offboard (control) ends its jobs and audits them. (#1360 O3, D1)"""
    from defender.tests.support.jobs._jobs1342 import move_tenant
    from defender.tenancy import Conflict, NotFound

    async with job_store(dsn) as store:
        jobs = await _live_jobs(dsn, store)
        target = str(uuid.uuid4()) if state == "absent" else T1
        if state != "absent":
            move_tenant(dsn, T1, state=state)  # its live rows stay: a refusal must not tidy them
        before = (_job_rows(dsn), _tenant_json(dsn, T1))
        audit = JobsAudit(caplog)
        mark = len(audit.events())
        with pytest.raises(NotFound if state == "absent" else Conflict):
            await _offboard(store, target, actor="admin-1")
        assert (_job_rows(dsn), _tenant_json(dsn, T1)) == before
        assert audit.events()[mark:] == []

        await _offboard(store, T2, actor="admin-1")  # control: the same call for an active tenant
    assert row(dsn, jobs["other_investigation"])["failure_reason"] == OFFBOARDED
    assert {(e.action, e.tenant_id) for e in audit.events()[mark:]} == {
        ("investigation.cancel", T2), ("learning_job.finish", T2)}


class _EndedAtEmit(logging.Handler):
    """On each audit event, reads the stage or status of the job it names from a separate connection."""

    def __init__(self, dsn: str) -> None:
        super().__init__(logging.DEBUG)
        self.dsn = dsn
        self.seen: list[tuple[str, str | None]] = []

    def emit(self, record: logging.LogRecord) -> None:
        target = getattr(record, "target", None)
        found = execute(self.dsn, "SELECT stage FROM jobs.investigations WHERE id = %s "
                                  "UNION ALL SELECT status FROM jobs.learning_jobs WHERE id = %s", (target, target))
        self.seen.append((record.action, found[0][0] if found else None))


async def test_1360_o5_each_ended_job_is_audited_with_the_admin_and_the_reason_unlike_a_user_cancel(dsn, caplog):
    """One ending event per ended job after the commit, actor the offboarding admin, `reason=tenant_offboarded`; a
    user's cancel of another tenant's job stays `cancelled`. (#1360 O5, Flow 1 audit)"""
    async with job_store(dsn) as store:
        jobs = await _live_jobs(dsn, store)
        audit = JobsAudit(caplog)
        mark = len(audit.events())
        seen = _EndedAtEmit(dsn)
        logging.getLogger(JOBS_AUDIT).addHandler(seen)
        try:
            await _offboard(store, T1, actor="admin-1")
        finally:
            logging.getLogger(JOBS_AUDIT).removeHandler(seen)
        await store.cancel_investigation(T2, jobs["other_investigation"], actor="u-2")

    events = [e for e in audit.events()[mark:] if e.tenant_id == T1]
    assert sorted((e.action, e.actor, e.target) for e in events) == sorted(
        [("investigation.cancel", "admin-1", inv) for inv in jobs["investigations"]]
        + [("learning_job.finish", "admin-1", job) for job in jobs["learning"]])
    for event in events:
        assert f"reason={OFFBOARDED}" in (event.detail or ""), event
        if event.action == "learning_job.finish":
            assert event.detail == f"status=skipped reason={OFFBOARDED}"
    assert sorted(seen.seen) == sorted([("investigation.cancel", "aborted")] * 2 + [("learning_job.finish", "skipped")] * 3), \
        "an ending was announced before its row was committed"
    cancel = row(dsn, jobs["other_investigation"])
    assert cancel["failure_reason"] == "cancelled" != OFFBOARDED


# --- Flow 1: the repeat until a fresh read finds no live row -----------------------------------------------------

@asynccontextmanager
async def _holding_advisory(dsn: str) -> AsyncIterator[None]:
    """The session advisory lock a stalled insert waits for (`_stall_inserts`), released on exit."""
    import psycopg

    async with await psycopg.AsyncConnection.connect(dsn, autocommit=True) as conn:
        await conn.execute("SELECT pg_advisory_lock(%s)", (STALL_KEY,))
        try:
            yield
        finally:
            await conn.execute("SELECT pg_advisory_unlock(%s)", (STALL_KEY,))


def _stall_inserts(dsn: str, table: str, when: str) -> None:
    """A real fault: an insert into `jobs.<table>` matching `when` waits for the advisory lock, so the transaction making
    it keeps the row locks it already took until the test lets go (a take-over or a finish caught mid-flight)."""
    execute(dsn, "CREATE FUNCTION jobs.stall_1360() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN "
                 f"PERFORM pg_advisory_xact_lock({STALL_KEY}); RETURN NEW; END $$")
    execute(dsn, f"CREATE TRIGGER stall_1360 BEFORE INSERT ON jobs.{table} FOR EACH ROW WHEN ({when}) "  # noqa: S608
                 "EXECUTE FUNCTION jobs.stall_1360()")


@asynccontextmanager
async def _holding_row(dsn: str, table: str, row_id: str) -> AsyncIterator[None]:
    import psycopg

    async with await psycopg.AsyncConnection.connect(dsn) as conn:
        await conn.execute(f"SELECT id FROM jobs.{table} WHERE id = %s FOR UPDATE", (row_id,))  # noqa: S608
        try:
            yield
        finally:
            await conn.commit()


@pytest.mark.parametrize("overlap", ["take_over_investigation", "take_over_learning", "finish"])
async def test_1360_o3_a_row_a_take_over_or_a_finish_inserts_while_the_offboard_waits_is_ended_too(dsn, caplog, overlap):
    """The offboard waits for a take-over's lapsed row or a finish's investigation; the retry or auto learning job that
    transaction commits is ended too, and the only live row it first met ends as it was. (#1360 O3, Flow 1 step 3)

    The `finish` case guards that the auto learning job the finish queued is ended; it passes with a single pass, so it
    does not test step 3's repeat (the cap test and the cases that insert a row on every ending do)."""
    from defender.tests.jobs.test_1344_learning_jobs import completed_investigation

    async with job_store(dsn) as store:
        if overlap == "take_over_learning":
            parent = await completed_investigation(store, ticket="S-1")
            job = _auto_job_of(dsn, parent)
            assert (await store.claim_learning_job()).record.learning_job_id == job
            execute(dsn, "UPDATE jobs.learning_jobs SET lease_expires_at = now() - interval '1 second' WHERE id = %s", (job,))
            _stall_inserts(dsn, "learning_jobs", "NEW.attempt > 1")
            work, first = store.take_over(), job
        else:
            alert = await an_alert(store, T1, ticket="S-1")
            inv, _ = await store.create_investigation(T1, alert.alert_id, "k1", actor="u-1")
            assert (await store.claim()).record.investigation_id == inv.investigation_id
            if overlap == "take_over_investigation":
                lapse_lease(dsn, inv.investigation_id)
                _stall_inserts(dsn, "investigations", "NEW.attempt > 1")
                work = store.take_over()
            else:
                _stall_inserts(dsn, "learning_jobs", "true")
                work = store.finish(T1, inv.investigation_id, stage="completed", disposition="malicious", cost_usd=0.0)
            first = inv.investigation_id
        audit = JobsAudit(caplog)
        mark = len(audit.events())
        async with _holding_advisory(dsn):
            started = asyncio.ensure_future(work)
            await until_blocked(dsn, 1)  # the take-over or finish holds its row and waits to insert
            offboard = asyncio.ensure_future(_offboard(store, T1, actor="admin-1"))
            await until_blocked(dsn, 2)  # the offboard waits for that row
        await asyncio.wait_for(asyncio.gather(started, offboard), 10)

    assert _live_of(dsn, T1) == 0
    admin = [(e.action, e.target) for e in audit.events()[mark:] if e.actor == "admin-1"]
    if overlap == "finish":
        assert row(dsn, first)["stage"] == "completed"
        [auto] = execute(dsn, "SELECT id FROM jobs.learning_jobs")
        ended, expected = _learning(dsn, auto[0]), [("learning_job.finish", auto[0])]
        assert (ended["status"], ended["reason"], ended["finished_at"]) == ("skipped", OFFBOARDED, NOW)
    elif overlap == "take_over_investigation":
        assert (row(dsn, first)["stage"], row(dsn, first)["failure_reason"]) == ("failed", "lease_lapsed")
        [retry] = execute(dsn, "SELECT id FROM jobs.investigations WHERE attempt = 2")
        stored = row(dsn, retry[0])
        assert (stored["stage"], stored["failure_reason"], stored["finished_at"]) == ("aborted", OFFBOARDED, NOW)
        expected = [("investigation.cancel", retry[0])]
    else:
        assert (_learning(dsn, first)["status"], _learning(dsn, first)["reason"]) == ("failed", "lease_lapsed")
        [retry] = execute(dsn, "SELECT id FROM jobs.learning_jobs WHERE attempt = 2")
        ended = _learning(dsn, retry[0])
        assert (ended["status"], ended["reason"], ended["finished_at"]) == ("skipped", OFFBOARDED, NOW)
        expected = [("learning_job.finish", retry[0])]
    assert admin == expected, "the offboard ended a row other than the one the overlapping transaction inserted"


async def test_1360_o3_an_offboard_that_locks_the_investigation_first_leaves_the_finish_nothing_to_end_or_queue(dsn):
    """The offboard holds the running row first: it ends `aborted`, the finish changes nothing and queues no learning
    job. (#1360 O3, Flow 1 scenario)"""
    async with job_store(dsn) as store:
        alert = await an_alert(store, T1)
        inv, _ = await store.create_investigation(T1, alert.alert_id, "k1", actor="u-1")
        assert (await store.claim()).record.investigation_id == inv.investigation_id
        async with _holding_row(dsn, "investigations", inv.investigation_id):
            offboard = asyncio.ensure_future(_offboard(store, T1, actor="admin-1"))
            await until_blocked(dsn, 1)
            finished = asyncio.ensure_future(
                store.finish(T1, inv.investigation_id, stage="completed", disposition="malicious", cost_usd=0.0))
            await until_blocked(dsn, 2)
        await asyncio.wait_for(offboard, 10)
        assert await asyncio.wait_for(finished, 10) is None

    assert (row(dsn, inv.investigation_id)["stage"], row(dsn, inv.investigation_id)["failure_reason"]) == ("aborted", OFFBOARDED)
    assert _count(dsn, "learning_jobs") == 0


def _reinsert_on_end(dsn: str, kind: str, *, up_to: int) -> None:
    """A real fault: ending a live row of `kind` inserts a fresh queued row for the same alert (investigation), or the
    same investigation (learning job), while fewer than `up_to` such rows exist: a late writer the offboard keeps meeting."""
    table, family, live, ended, reset = (
        ("investigations", "alert_id", "('queued', 'running')", "NEW.stage = 'aborted'", "stage")
        if kind == "investigation" else
        ("learning_jobs", "investigation_id", "('queued', 'running')", "NEW.status = 'skipped'", "status"))
    fresh = (", 'attempt', 1, 'stage', 'queued', 'started_at', NULL, 'finished_at', NULL, 'failure_reason', NULL, "
             "'failure_message', NULL, 'lease_expires_at', NULL, 'accounting_written_at', NULL"
             if kind == "investigation" else
             ", 'attempt', 1, 'status', 'queued', 'started_at', NULL, 'finished_at', NULL, 'reason', NULL, "
             "'message', NULL, 'lease_expires_at', NULL, 'publish_state', 'none'")
    execute(dsn, "CREATE FUNCTION jobs.again_1360() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN "  # noqa: S608
                 f"IF (SELECT count(*) FROM jobs.{table} WHERE {family} = NEW.{family}) < {up_to} THEN "
                 f"INSERT INTO jobs.{table} SELECT * FROM jsonb_populate_record(NULL::jobs.{table}, to_jsonb(NEW) || "
                 f"jsonb_build_object('id', gen_random_uuid(), 'request_key', gen_random_uuid()::text{fresh})); "
                 "END IF; RETURN NULL; END $$")
    execute(dsn, f"CREATE TRIGGER again_1360 AFTER UPDATE ON jobs.{table} FOR EACH ROW "  # noqa: S608
                 f"WHEN (OLD.{reset} IN {live} AND {ended}) EXECUTE FUNCTION jobs.again_1360()")


async def _one_live_job(dsn: str, store: Any, kind: str) -> None:
    if kind == "investigation":
        await store.create_investigation(T1, _plant_alert(dsn), "k1", actor="u-1")
        return
    from defender.tests.jobs.test_1344_learning_jobs import completed_investigation

    await completed_investigation(store, ticket="D-1")


@pytest.mark.parametrize("kind", ["investigation", "learning"])
async def test_1360_d8_a_live_row_inserted_again_on_every_pass_rolls_the_whole_offboard_back_and_fails_loudly(dsn, caplog, kind):
    """Every ending inserts a new live row: past the cap the transaction rolls back (tenant and every job row as they
    were, nothing audited) and the call raises something other than a tenancy refusal. (#1360 D8)"""
    from defender.jobs import Conflict as JobsConflict
    from defender.tenancy import Conflict, NotFound

    async with job_store(dsn) as store:
        await _one_live_job(dsn, store, kind)
        _reinsert_on_end(dsn, kind, up_to=10**9)
        before, tenant = _job_rows(dsn), _tenant_json(dsn, T1)
        audit = JobsAudit(caplog)
        mark = len(audit.events())
        with pytest.raises(Exception) as failed:  # noqa: PT011
            await asyncio.wait_for(_offboard(store, T1, actor="admin-1"), 60)
        assert not isinstance(failed.value, (TimeoutError, StopIteration, NotFound, Conflict, JobsConflict)), repr(failed.value)
        assert _job_rows(dsn) == before
        assert _tenant_json(dsn, T1) == tenant
        assert audit.events()[mark:] == []

        execute(dsn, f"DROP TRIGGER again_1360 ON jobs.{'investigations' if kind == 'investigation' else 'learning_jobs'}")
        await _offboard(store, T1, actor="admin-1")  # control: the same call, once nothing is inserted behind it
    assert _live_of(dsn, T1) == 0
    assert _tenant_json(dsn, T1)["state"] == "offboarding"


@pytest.mark.parametrize("kind", ["investigation", "learning"])
async def test_1360_d8_a_row_inserted_once_costs_a_second_pass_and_the_offboard_still_ends_everything(dsn, kind):
    """Control for the cap: the first ending inserts one more live row, the second inserts none; both are ended and the
    offboard commits. (#1360 D8, Flow 1 step 3)"""
    async with job_store(dsn) as store:
        await _one_live_job(dsn, store, kind)
        _reinsert_on_end(dsn, kind, up_to=2)
        await asyncio.wait_for(_offboard(store, T1, actor="admin-1"), 60)

    table, column = ("investigations", "stage") if kind == "investigation" else ("learning_jobs", "status")
    ended = "aborted" if kind == "investigation" else "skipped"
    assert _count(dsn, table, f"{column} = '{ended}'") == 2
    assert _live_of(dsn, T1) == 0
    assert _tenant_json(dsn, T1)["state"] == "offboarding"


async def test_1360_o3_a_job_the_database_refuses_to_end_takes_the_tenant_transition_back_with_it(dsn):
    """A learning job cannot be ended: the offboard fails, the tenant stays `active` and no investigation it had
    already ended stays ended; without the fault the same call commits all of it. (#1360 O3, D1 one transaction)"""
    from defender.tenancy import Conflict, NotFound

    async with job_store(dsn) as store:
        jobs = await _live_jobs(dsn, store)
        execute(dsn, "CREATE FUNCTION jobs.refuse_1360() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN "
                     "RAISE EXCEPTION 'cannot end this job'; END $$")
        execute(dsn, "CREATE TRIGGER refuse_1360 BEFORE UPDATE ON jobs.learning_jobs FOR EACH ROW "
                     "WHEN (NEW.status = 'skipped') EXECUTE FUNCTION jobs.refuse_1360()")
        before, tenant = _job_rows(dsn), _tenant_json(dsn, T1)
        with pytest.raises(Exception) as failed:  # noqa: PT011
            await _offboard(store, T1, actor="admin-1")
        assert not isinstance(failed.value, (NotFound, Conflict)), repr(failed.value)
        assert _job_rows(dsn) == before
        assert _tenant_json(dsn, T1) == tenant

        execute(dsn, "DROP TRIGGER refuse_1360 ON jobs.learning_jobs")
        await _offboard(store, T1, actor="admin-1")
    assert _tenant_json(dsn, T1)["state"] == "offboarding"
    _assert_ended(dsn, jobs)


def _plant_running_pair(dsn: str, investigation_ids: list[str], job_ids: list[str]) -> None:
    """Running investigations and running learning jobs of T1 with the given ids, inserted in the order given. The alerts
    and parents they hang on are inserted in that same order with ids ascending in it, so any scan (table order or a
    unique index, which reads ascending) meets the rows in the order given."""
    for inv, alert_id in zip(investigation_ids, sorted(str(uuid.uuid4()) for _ in investigation_ids), strict=True):
        execute(dsn, "INSERT INTO jobs.investigations (id, tenant_id, alert_id, request_key, attempt, stage, created_at, "
                     "started_at, cost_usd, cost_is_lower_limit, lease_expires_at) "
                     "VALUES (%s, %s, %s, 'k', 1, 'running', %s, %s, 0, false, now() + interval '30 seconds')",
                (inv, T1, _plant_alert(dsn, ticket=f"W-{inv}", alert_id=alert_id), NOW, NOW))
    alerts, parents = (sorted(str(uuid.uuid4()) for _ in job_ids) for _ in range(2))
    for job, alert_id, parent_id in zip(job_ids, alerts, parents, strict=True):
        alert = _plant_alert(dsn, ticket=f"V-{job}", alert_id=alert_id)
        parent = _plant_investigation(dsn, tenant=T1, alert_id=alert, key="k", attempt=1, stage="completed")
        execute(dsn, "UPDATE jobs.investigations SET id = %s WHERE id = %s", (parent_id, parent))
        parent = parent_id
        execute(dsn, "INSERT INTO jobs.learning_jobs (id, tenant_id, alert_id, investigation_id, request_key, attempt, trigger, "
                     "status, created_at, started_at, lease_expires_at, sibling_cost_usd, findings_count, publish_state) "
                     "VALUES (%s, %s, %s, %s, 'k', 1, 'explicit', 'running', %s, %s, now() + interval '30 seconds', 0, 0, 'none')",
                (job, T1, alert, parent, NOW, NOW))


@pytest.mark.parametrize("kind", ["investigations", "learning_jobs"])
async def test_1360_flow1_an_offboard_and_a_renewal_of_several_of_the_tenants_running_rows_do_not_deadlock(dsn, kind):
    """The real `renew` of several running rows and the real `offboard_tenant` of their tenant, the table holding the
    rows in the opposite physical order to their ids and a held middle row making the two overlap: both lock several
    rows, so both must take them in id order, and neither fails with a deadlock. (#1360 Flow 1 lock order, D9)"""
    import psycopg

    ids = sorted(str(uuid.uuid4()) for _ in range(6))
    table = f"jobs.{kind}"
    _plant_running_pair(dsn, ids[::-1] if kind == "investigations" else [], ids[::-1] if kind == "learning_jobs" else [])
    heap = [row[0] for row in execute(dsn, f"SELECT id::text FROM {table} WHERE id = ANY(%s::uuid[]) ORDER BY ctid", (ids,))]  # noqa: S608
    assert heap == ids[::-1]  # the setup: a scan in table order meets the high ids first, against id order

    async with job_store(dsn) as store, await psycopg.AsyncConnection.connect(dsn) as holder:
        await holder.execute(f"SELECT 1 FROM {table} WHERE id = %s FOR UPDATE", (ids[3],))  # noqa: S608
        renewal = asyncio.ensure_future(store.renew(set(ids)))
        offboard = None
        try:
            await until_blocked(dsn, 1)  # the renewal has taken what it can and waits for the held middle row
            offboard = asyncio.ensure_future(_offboard(store, T1, actor="admin-1"))
            await until_blocked(dsn, 2)  # and the offboard overlaps it: the contention is real before the holder lets go
            await holder.commit()
            outcomes = await asyncio.wait_for(asyncio.gather(renewal, offboard, return_exceptions=True), 20)
        finally:
            for pending in (renewal, offboard):
                if pending is not None:
                    pending.cancel()

    renewed, offboarded = outcomes
    assert not isinstance(renewed, BaseException), f"renew failed: {renewed!r}"
    assert not isinstance(offboarded, BaseException), f"offboard failed: {offboarded!r}"
    assert sorted(renewed) == ids  # the renewal was already under way, so it covered every row it held
    assert _live_of(dsn, T1) == 0
    if kind == "investigations":
        assert _count(dsn, "investigations", "stage = 'aborted' AND failure_reason = 'tenant_offboarded'") == 6
    else:
        assert _count(dsn, "learning_jobs", "status = 'skipped' AND reason = 'tenant_offboarded'") == 6


async def _lock_in_id_order(conn: Any, table: str, row_ids: list[str]) -> None:
    """Lock the rows one after another, lowest id first, in the connection's open transaction."""
    for row_id in row_ids:
        await conn.execute(f"SELECT 1 FROM {table} WHERE id = %s FOR UPDATE", (row_id,))  # noqa: S608


@pytest.mark.parametrize("target", ["renew", "offboard"])
@pytest.mark.parametrize("kind", ["investigations", "learning_jobs"])
async def test_1360_flow1_each_side_locks_rows_in_id_order_against_a_counterpart_that_does(dsn, kind, target):
    """Anchor for D9, one side at a time: a raw connection that locks the tenant's rows strictly in id order (the low
    half now, the high half once the real operation has started and waited) against the real `renew` or the real
    `offboard_tenant`, the table holding the rows in the opposite physical order. An operation that takes its rows in
    id order waits on the first low row holding nothing, so the counterpart finishes and nothing deadlocks; one that
    scans in table order takes the high rows first and the two wait on each other. (#1360 Flow 1 lock order, D9)"""
    import psycopg

    ids = sorted(str(uuid.uuid4()) for _ in range(6))
    table = f"jobs.{kind}"
    _plant_running_pair(dsn, ids[::-1] if kind == "investigations" else [], ids[::-1] if kind == "learning_jobs" else [])
    heap = [row[0] for row in execute(dsn, f"SELECT id::text FROM {table} WHERE id = ANY(%s::uuid[]) ORDER BY ctid", (ids,))]  # noqa: S608
    assert heap == ids[::-1]  # the setup: a scan in table order meets the high ids first, against id order

    async with job_store(dsn) as store, await psycopg.AsyncConnection.connect(dsn) as counterpart:
        await _lock_in_id_order(counterpart, table, ids[:3])
        operation = asyncio.ensure_future(store.renew(set(ids)) if target == "renew" else _offboard(store, T1, actor="admin-1"))
        rest = None
        try:
            await until_blocked(dsn, 1)  # the operation has taken what it will before the rows the counterpart holds
            rest = asyncio.ensure_future(_lock_in_id_order(counterpart, table, ids[3:]))
            await asyncio.wait({operation, rest}, timeout=20, return_when=asyncio.FIRST_COMPLETED)
            await asyncio.wait({rest}, timeout=20)  # whichever was chosen the victim, the other goes on
            assert rest.done(), "the counterpart is stuck, and neither side was ended by the server"
            counterpart_out = rest.exception()
            await (counterpart.rollback() if counterpart_out else counterpart.commit())
            outcome = (await asyncio.wait_for(asyncio.gather(operation, return_exceptions=True), 20))[0]
        finally:
            for pending in (operation, rest):
                if pending is not None:
                    pending.cancel()

    assert counterpart_out is None, f"the id-ordered counterpart failed: {counterpart_out!r}"
    assert not isinstance(outcome, BaseException), f"{target} failed: {outcome!r}"
    if target == "renew":
        assert sorted(outcome) == ids
    else:
        assert _live_of(dsn, T1) == 0


async def test_1360_flow1_an_offboard_and_a_renewal_over_both_tables_take_investigations_before_learning_jobs(dsn):
    """One renewal of running investigations and running learning jobs of a tenant, the held row a middle investigation:
    the renewal holds the investigations below it and waits, then needs the learning jobs. An offboard that took the
    learning jobs first would hold what the renewal needs next while waiting for what the renewal holds; the table order
    (investigations, then learning jobs) is part of D9, so neither side fails with a deadlock and the offboard ends
    every live row of both kinds. (#1360 Flow 1 lock order, D9 as amended by r3.2)"""
    import psycopg

    inv_ids = sorted(str(uuid.uuid4()) for _ in range(6))
    job_ids = sorted(str(uuid.uuid4()) for _ in range(6))
    _plant_running_pair(dsn, inv_ids[::-1], job_ids[::-1])

    async with job_store(dsn) as store, await psycopg.AsyncConnection.connect(dsn) as holder:
        await holder.execute("SELECT 1 FROM jobs.investigations WHERE id = %s FOR UPDATE", (inv_ids[3],))
        renewal = asyncio.ensure_future(store.renew({*inv_ids, *job_ids}))
        offboard = None
        try:
            await until_blocked(dsn, 1)  # the renewal waits for the held middle investigation
            offboard = asyncio.ensure_future(_offboard(store, T1, actor="admin-1"))
            await until_blocked(dsn, 2)  # and the offboard waits behind what the renewal holds
            await holder.commit()
            outcomes = await asyncio.wait_for(asyncio.gather(renewal, offboard, return_exceptions=True), 20)
        finally:
            for pending in (renewal, offboard):
                if pending is not None:
                    pending.cancel()

    renewed, offboarded = outcomes
    assert not isinstance(renewed, BaseException), f"renew failed: {renewed!r}"
    assert not isinstance(offboarded, BaseException), f"offboard failed: {offboarded!r}"
    assert sorted(renewed) == sorted([*inv_ids, *job_ids])
    assert _live_of(dsn, T1) == 0
    assert _count(dsn, "investigations", "stage = 'aborted' AND failure_reason = 'tenant_offboarded'") == 6
    assert _count(dsn, "learning_jobs", "status = 'skipped' AND reason = 'tenant_offboarded'") == 6


# --- O4: no job is created for an offboarding or offboarded tenant -----------------------------------------------

@pytest.mark.parametrize("state", ["offboarding", "offboarded"])
async def test_1360_o4_an_outside_create_for_an_offboarding_or_offboarded_tenant_is_refused_and_inserts_nothing(dsn, state):
    """create_investigation and create_learning_job refuse such a tenant with a conflict naming its state; the other
    tenant's creates succeed. (#1360 O4, D7)"""
    from defender.jobs import Conflict
    from defender.tests.jobs.test_1344_learning_jobs import completed_investigation
    from defender.tests.support.jobs._jobs1342 import move_tenant

    async with job_store(dsn) as store:
        done = await completed_investigation(store, ticket="C-1")
        other_done = await completed_investigation(store, ticket="C-9", tenant=T2)
        alert, other_alert = await an_alert(store, T1, ticket="N-1"), await an_alert(store, T2, ticket="N-9")
        move_tenant(dsn, T1, state=state)
        before = _job_rows(dsn)
        with pytest.raises(Conflict, match=state):
            await store.create_investigation(T1, alert.alert_id, "k-new", actor="u-1")
        with pytest.raises(Conflict, match=state):
            await store.create_learning_job(T1, done, "c-1", actor="u-1")
        assert _job_rows(dsn) == before
        assert (await store.create_investigation(T2, other_alert.alert_id, "k-new", actor="u-2"))[1] is True
        assert (await store.create_learning_job(T2, other_done, "c-1", actor="u-2"))[1] is True


async def test_1360_o4_a_creating_tenant_is_not_refused_by_its_state(dsn):
    """A `creating` tenant that has a mapping still creates both kinds of job. (#1360 O4, D7)"""
    from defender.tests.jobs.test_1344_learning_jobs import completed_investigation
    from defender.tests.support.jobs._jobs1342 import move_tenant

    async with job_store(dsn) as store:
        done = await completed_investigation(store, ticket="C-1")
        alert = await an_alert(store, T1, ticket="N-1")
        move_tenant(dsn, T1, state="creating")
        assert (await store.create_investigation(T1, alert.alert_id, "k-new", actor="u-1"))[1] is True
        assert (await store.create_learning_job(T1, done, "c-1", actor="u-1"))[1] is True


async def test_1360_o4_a_creating_tenant_without_a_mapping_is_still_refused_for_the_mapping_not_the_state(unmapped_dsn):
    """#1345 D2 stands: such a tenant's create is the mapping-missing conflict, word for word. (#1360 O4, D7)"""
    from defender.jobs import Conflict
    from defender.records.formats import ALERT_MAPPING_MISSING
    from defender.tests.support.jobs._jobs1342 import move_tenant

    dsn = unmapped_dsn
    alert = _plant_alert(dsn)
    move_tenant(dsn, T1, state="creating")
    async with job_store(dsn) as store:
        with pytest.raises(Conflict) as refused:
            await store.create_investigation(T1, alert, "k1", actor="u-1")
        assert str(refused.value) == ALERT_MAPPING_MISSING
        await store.put_alert_mapping(T1, mapping_value({}), actor="u-1")  # control: the same tenant, once it has one
        assert (await store.create_investigation(T1, alert, "k1", actor="u-1"))[1] is True


async def test_1360_o4_an_offboarding_tenant_still_gets_a_replay_a_live_row_and_an_unknown_reference_not_a_state_conflict(dsn):
    """The refusal comes only when a new row would be inserted: a replayed request, a live row and an unknown alert or
    investigation answer as before. (#1360 O4, D7)"""
    from defender.jobs import Conflict, UnknownReference
    from defender.tests.jobs.test_1344_learning_jobs import completed_investigation
    from defender.tests.support.jobs._jobs1342 import move_tenant

    async with job_store(dsn) as store:
        done = await completed_investigation(store, ticket="C-1", key="kc")
        theirs = await completed_investigation(store, ticket="C-9", key="kc", tenant=T2)
        explicit, _ = await store.create_learning_job(T1, done, "c-1", actor="u-1")
        ended_alert = await an_alert(store, T1, ticket="E-1")
        live_alert = await an_alert(store, T1, ticket="L-1")
        new_alert = await an_alert(store, T1, ticket="N-1")
        ended, _ = await store.create_investigation(T1, ended_alert.alert_id, "k-ended", actor="u-1")
        await store.cancel_investigation(T1, ended.investigation_id, actor="u-1")
        live, _ = await store.create_investigation(T1, live_alert.alert_id, "k-live", actor="u-1")
        move_tenant(dsn, T1, state="offboarding")
        before = _job_rows(dsn)

        replayed = await store.create_investigation(T1, ended_alert.alert_id, "k-ended", actor="u-1")
        answered = await store.create_investigation(T1, live_alert.alert_id, "k-other", actor="u-1")
        job = await store.create_learning_job(T1, done, "c-1", actor="u-1")
        assert (replayed[0].investigation_id, replayed[1]) == (ended.investigation_id, False)
        assert (answered[0].investigation_id, answered[1]) == (live.investigation_id, False)
        assert (job[0].learning_job_id, job[1]) == (explicit.learning_job_id, False)
        with pytest.raises(UnknownReference):
            await store.create_investigation(T1, str(uuid.uuid4()), "k1", actor="u-1")
        with pytest.raises(UnknownReference):
            await store.create_learning_job(T1, theirs, "c-1", actor="u-1")
        assert _job_rows(dsn) == before
        with pytest.raises(Conflict, match="offboarding"):  # control: a request that would insert
            await store.create_investigation(T1, new_alert.alert_id, "k-new", actor="u-1")


async def test_1360_o4_an_absent_tenant_is_an_unknown_reference_like_an_absent_alert(dsn):
    """A create naming a tenant with no row answers `UnknownReference`, as for an alert or investigation that is
    absent, and inserts nothing. (#1360 O4, D7)"""
    from defender.jobs import UnknownReference
    from defender.tests.jobs.test_1344_learning_jobs import completed_investigation

    absent = str(uuid.uuid4())
    async with job_store(dsn) as store:
        done = await completed_investigation(store, ticket="C-1")
        alert = await an_alert(store, T1, ticket="N-1")
        before = _job_rows(dsn)
        for name, args in (("create_investigation", (absent, alert.alert_id, "k")),
                           ("create_investigation", (T1, str(uuid.uuid4()), "k")),  # control: the absent alert
                           ("create_learning_job", (absent, done, "c-1")),
                           ("create_learning_job", (T1, str(uuid.uuid4()), "c-1"))):  # control: the absent investigation
            with pytest.raises(UnknownReference):
                await getattr(store, name)(*args, actor="u-1")
        assert _job_rows(dsn) == before


@pytest.mark.parametrize("kind", ["investigation", "learning"])
async def test_1360_o4_a_create_that_meets_an_uncommitted_offboard_waits_and_then_refuses(dsn, kind):
    """The create reads the tenant's state under a share lock inside its transaction: it waits for the offboard's
    commit, then refuses, inserting nothing. (#1360 O4, Flow 2)"""
    import psycopg

    from defender.jobs import Conflict
    from defender.tests.jobs.test_1344_learning_jobs import completed_investigation

    async with job_store(dsn) as store:
        done = await completed_investigation(store, ticket="C-1")
        alert = await an_alert(store, T1, ticket="N-1")
        before = _job_rows(dsn)
        async with await psycopg.AsyncConnection.connect(dsn) as conn:
            await conn.execute("UPDATE tenancy.tenants SET state = 'offboarding', pending_action = 'offboard', "
                               "step = 'offboard', step_actor = 'service' WHERE id = %s", (T1,))
            pending = asyncio.ensure_future(
                store.create_investigation(T1, alert.alert_id, "k1", actor="u-1") if kind == "investigation"
                else store.create_learning_job(T1, done, "c-1", actor="u-1"))

            async def waiting_or_done() -> bool:
                return pending.done() or await blocked(dsn) == 1
            await until(waiting_or_done)
            assert not pending.done(), "the create answered without waiting for the tenant row"
            await conn.commit()
        with pytest.raises(Conflict, match="offboarding"):
            await asyncio.wait_for(pending, 10)
    assert _job_rows(dsn) == before


@pytest.mark.parametrize("kind", ["investigation", "learning"])
async def test_1360_o4_an_offboard_that_meets_an_uncommitted_create_waits_for_it_and_ends_the_row_it_inserted(dsn, kind):
    """The create holds the tenant's share lock before any other (here it waits at the alert): the offboard waits for it,
    then ends the row the create inserted. (#1360 O4, Flow 2)"""
    from defender.tests.jobs.test_1344_learning_jobs import completed_investigation

    async with job_store(dsn) as store:
        done = await completed_investigation(store, ticket="C-1")
        alert = await an_alert(store, T1, ticket="N-1")
        held = alert.alert_id if kind == "investigation" else execute(
            dsn, "SELECT alert_id FROM jobs.investigations WHERE id = %s", (done,))[0][0]
        before = _job_rows(dsn)
        async with holding_alert(dsn, held):
            create = asyncio.ensure_future(
                store.create_investigation(T1, alert.alert_id, "k1", actor="u-1") if kind == "investigation"
                else store.create_learning_job(T1, done, "c-1", actor="u-1"))
            await until_blocked(dsn, 1)  # at the alert, holding the tenant's share lock
            offboard = asyncio.ensure_future(_offboard(store, T1, actor="admin-1"))
            await until_blocked(dsn, 2)  # the offboard waits for the create
        created, _ = await asyncio.wait_for(create, 10)
        await asyncio.wait_for(offboard, 10)

    new = created.investigation_id if kind == "investigation" else created.learning_job_id
    assert new not in before
    assert _live_of(dsn, T1) == 0
    if kind == "investigation":
        assert (row(dsn, new)["stage"], row(dsn, new)["failure_reason"]) == ("aborted", OFFBOARDED)
    else:
        assert (_learning(dsn, new)["status"], _learning(dsn, new)["reason"]) == ("skipped", OFFBOARDED)
