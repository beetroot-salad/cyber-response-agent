"""#1581: the revision `0025_alert_outcome` (found by its suffix, never by number) gives `jobs.alerts` the stored outcome
(`outcome`, `outcome_investigation_id`, `outcome_created_at`, all null or all set, `outcome` one of the five codes), an
index over `(tenant_id, outcome, fired_at DESC, id DESC)`, and `jobs.investigations` the checks `completed_has_a_disposition`
and a disposition value check (O10). The upgrade backfills each alert from its newest completed investigation, and refuses,
changing nothing and naming both counts, over completed rows with no disposition or any disposition outside the five codes.
Rows are planted by SQL at the revision before it (the head store cannot write them)."""
from __future__ import annotations

import datetime as dt
import re

import psycopg
import pytest

from defender._vocab import DISPOSITION_VALUES
from defender.tests.migrations.test_1214_migrations import _upgrade_to
from defender.tests.migrations.test_1343_migrations import _id
from defender.tests.support.jobs._jobs1342 import T1, T2, register_tenant
from defender.tests.support.shared import _revisions1485 as revisions
from defender.tests.support.shared._postgres1339 import execute

pytestmark = pytest.mark.postgres

T0 = dt.datetime(2026, 11, 1, 8, 0, tzinfo=dt.UTC)
HOUR = dt.timedelta(hours=1)
LOW, HIGH = "00000000-0000-4000-8000-0000000000b1", "ffffffff-ffff-4fff-8fff-0000000000b2"
COLUMNS = {"outcome", "outcome_investigation_id", "outcome_created_at"}


def _revision() -> str:
    return revisions.by_suffix("_alert_outcome")


def _prior() -> str:
    return revisions.down_of(_revision())


def _tenants(dsn: str) -> None:
    for tenant in (T1, T2):
        execute(dsn, "INSERT INTO tenancy.tenants (id, created_at, state) VALUES (%s, now(), 'active')", (tenant,))


def _alert(dsn: str, name: str, *, tenant: str = T1) -> str:
    alert = _id("alert", name)
    execute(dsn, "INSERT INTO jobs.alerts (id, tenant_id, vendor, vendor_ticket_id, fired_at, changed_at, received_at, "
                 "title, description, raw) VALUES (%s, %s, 'elastic', %s, %s, %s, %s, 't', 'd', '\\x7b7d')",
            (alert, tenant, name, T0, T0, T0))
    return alert


def _investigation(dsn: str, alert: str, key: str, stage: str, disposition: str | None, created_at: dt.datetime, *,
                   inv_id: str | None = None, tenant: str = T1) -> str:
    """A row at the prior revision, in `stage` (a running one holds a lease), written with exactly the columns that
    schema requires."""
    inv_id = inv_id or _id("inv", f"{alert}-{key}")
    lease = "now() + interval '30 seconds'" if stage == "running" else "NULL"
    execute(dsn, "INSERT INTO jobs.investigations (id, tenant_id, alert_id, request_key, attempt, stage, created_at, "
                 "disposition, cost_usd, cost_is_lower_limit, update_ticket, lease_expires_at) "
                 f"VALUES (%s, %s, %s, %s, 1, %s, %s, %s, 0, false, false, {lease})",  # noqa: S608 — test-built SQL: the lease clause is a literal of this file
            (inv_id, tenant, alert, key, stage, created_at, disposition))
    return inv_id


def _alert_columns(dsn: str) -> set[str]:
    return {c for (c,) in execute(dsn, "SELECT column_name FROM information_schema.columns "
                                       "WHERE table_schema = 'jobs' AND table_name = 'alerts'")}


def _version(dsn: str) -> list[tuple[str]]:
    return execute(dsn, "SELECT version_num FROM public.alembic_version")  # type: ignore[return-value]


def test_the_revision_sits_directly_on_the_drop_findings_count_revision_and_on_the_one_line_to_the_head():
    """`_alert_outcome` is built on `_drop_findings_count` (#1589, merged to main after the contract), and is the head
    or an ancestor of it on a single line. (data model)"""
    from defender.migrations import head, heads

    assert revisions.down_of(_revision()) == revisions.by_suffix("_drop_findings_count")
    assert heads() == (head(),)
    assert _revision() == head() or _revision() in revisions.ancestors(head())


# --- the backfill ------------------------------------------------------------------------------------------------------

def test_the_upgrade_backfills_each_alert_from_its_newest_completed_investigation(empty_database):
    """Over alerts with no investigation, only a failed one, one completed, a completed superseded by a newer completed and
    followed by a failed, two completed at one instant (the higher id wins), a completed under a running rerun, and another
    tenant's alert: each alert's three columns are its newest completed investigation's (all null with none); no
    investigation row changes. (backfill)"""
    dsn = empty_database
    _upgrade_to(dsn, _prior())
    _tenants(dsn)
    none, failed, one, two, tie, rerun = (_alert(dsn, n) for n in ("none", "failed", "one", "two", "tie", "rerun"))
    theirs = _alert(dsn, "theirs", tenant=T2)
    _investigation(dsn, failed, "k1", "failed", None, T0)
    one_inv = _investigation(dsn, one, "k1", "completed", "malicious", T0)
    _investigation(dsn, two, "k1", "completed", "benign", T0)
    two_new = _investigation(dsn, two, "k2", "completed", "false-positive", T0 + HOUR)
    _investigation(dsn, two, "k3", "failed", None, T0 + 2 * HOUR)
    _investigation(dsn, tie, "k-low", "completed", "benign", T0, inv_id=LOW)
    _investigation(dsn, tie, "k-high", "completed", "inconclusive", T0, inv_id=HIGH)
    rerun_done = _investigation(dsn, rerun, "k1", "completed", "unresolved", T0)
    _investigation(dsn, rerun, "k2", "running", None, T0 + HOUR)
    their_inv = _investigation(dsn, theirs, "k1", "completed", "benign", T0, tenant=T2)
    before = execute(dsn, "SELECT id, stage, disposition, created_at FROM jobs.investigations ORDER BY id")

    _upgrade_to(dsn, _revision())

    copy = {a: tuple(rest) for a, *rest in execute(
        dsn, "SELECT id, outcome, outcome_investigation_id, outcome_created_at FROM jobs.alerts")}
    assert copy == {
        none: (None, None, None), failed: (None, None, None),
        one: ("malicious", one_inv, T0), two: ("false-positive", two_new, T0 + HOUR),
        tie: ("inconclusive", HIGH, T0), rerun: ("unresolved", rerun_done, T0),
        theirs: ("benign", their_inv, T0),
    }
    assert execute(dsn, "SELECT id, stage, disposition, created_at FROM jobs.investigations ORDER BY id") == before
    assert _version(dsn) == [(_revision(),)]


# --- the refusal ---------------------------------------------------------------------------------------------------------

def _plant_refusable(dsn: str, *, nulls: int, off_vocabulary: int) -> None:
    """A database at the prior revision with `nulls` completed rows lacking a disposition and `off_vocabulary` rows (of
    differing stages) whose disposition is outside the five codes, beside a clean completed row."""
    _upgrade_to(dsn, _prior())
    _tenants(dsn)
    _investigation(dsn, _alert(dsn, "clean"), "k1", "completed", "benign", T0)
    for n in range(nulls):
        _investigation(dsn, _alert(dsn, f"null-{n}"), "k1", "completed", None, T0)
    stages = ("completed", "failed", "aborted", "unparseable")
    for n in range(off_vocabulary):
        stage = stages[n % len(stages)]
        _investigation(dsn, _alert(dsn, f"off-{n}"), "k1", stage, "unsanctioned-benign", T0)


@pytest.mark.parametrize(("nulls", "off_vocabulary"), [(6, 0), (0, 5), (6, 5)])
def test_the_upgrade_refuses_over_completed_rows_without_a_disposition_or_off_vocabulary_ones_and_changes_nothing(
        empty_database, nulls, off_vocabulary):
    """From the prior revision, with completed rows lacking a disposition, rows whose disposition is not one of the five
    codes, or both, the upgrade fails with a RuntimeError naming both counts, zero included, each beside its noun, the database stays at the prior revision, no
    column or index appears and every row is as it was. (refusal; 0012's precedent)"""
    dsn = empty_database
    _plant_refusable(dsn, nulls=nulls, off_vocabulary=off_vocabulary)
    before = execute(dsn, "SELECT id, stage, disposition FROM jobs.investigations ORDER BY id")
    indexes = execute(dsn, "SELECT indexname FROM pg_indexes WHERE schemaname = 'jobs' ORDER BY indexname")

    with pytest.raises(RuntimeError) as refused:
        _upgrade_to(dsn, _revision())

    message = str(refused.value)
    # Planted counts (6, 5, 0) share no digit with each other or with the revision ids; a count's noun follows it with no digit between.
    for count, noun in ((nulls, r"disposition"), (off_vocabulary, r"unknown|invalid|not one|unrecogni|allowed|codes?|vocabular|outside|five")):
        assert re.search(rf"\b{count}\b\D{{0,80}}?(?:{noun})", message, re.IGNORECASE), f"{count} is not named beside its noun: {message}"
    assert _version(dsn) == [(_prior(),)]
    assert not COLUMNS & _alert_columns(dsn)
    assert execute(dsn, "SELECT indexname FROM pg_indexes WHERE schemaname = 'jobs' ORDER BY indexname") == indexes
    assert execute(dsn, "SELECT id, stage, disposition FROM jobs.investigations ORDER BY id") == before
    assert not execute(dsn, "SELECT 1 FROM pg_constraint WHERE conname LIKE '%completed_has_a_disposition'")


# --- the table at head (O10) -----------------------------------------------------------------------------------------------

@pytest.fixture
def at_head(migrated_database: str) -> str:
    register_tenant(migrated_database, T1)
    return migrated_database


def _head_alert(dsn: str, ticket: str) -> str:
    alert = _id("head-alert", ticket)
    execute(dsn, "INSERT INTO jobs.alerts (id, tenant_id, vendor, vendor_ticket_id, fired_at, changed_at, received_at, raw) "
                 "VALUES (%s, %s, 'elastic', %s, %s, %s, %s, '\\x7b7d')", (alert, T1, ticket, T0, T0, T0))
    return alert


def _head_investigation(dsn: str, alert: str, stage: str, disposition: str | None, key: str = "k") -> str:
    inv = _id("head-inv", f"{alert}-{key}-{stage}")
    lease = "now() + interval '30 seconds'" if stage == "running" else "NULL"
    ended = stage not in ("queued", "running")  # #1546 A-O4: an ended row has an evidence state (and its scrub)
    execute(dsn, "INSERT INTO jobs.investigations (id, tenant_id, alert_id, request_key, attempt, stage, created_at, "
                 "disposition, cost_usd, cost_is_lower_limit, update_ticket, lease_expires_at, evidence_state, scrub) "
                 f"VALUES (%s, %s, %s, %s, 1, %s, %s, %s, 0, false, false, {lease}, %s, %s)",  # noqa: S608 — test-built SQL: the lease clause is a literal of this file
            (inv, T1, alert, key, stage, T0, disposition, "none" if ended else None, "not_run" if ended else None))
    return inv


@pytest.mark.parametrize("disposition", DISPOSITION_VALUES)
def test_o10_a_completed_investigation_is_stored_with_each_of_the_five_codes(at_head, disposition):
    """Control for the refusals: `completed` holds each code the vocabulary has. (O10)"""
    _head_investigation(at_head, _head_alert(at_head, "t"), "completed", disposition)
    assert execute(at_head, "SELECT disposition FROM jobs.investigations") == [(disposition,)]


def test_o10_a_completed_investigation_without_a_disposition_is_refused_on_insert_and_on_update(at_head):
    """`completed` with a null disposition is refused by the table, named `completed_has_a_disposition`: as an insert, and as
    a running row's update; an ended-otherwise row holds none (control). (O10)"""
    alert = _head_alert(at_head, "t")
    with pytest.raises(psycopg.errors.CheckViolation, match="completed_has_a_disposition"):
        _head_investigation(at_head, alert, "completed", None)
    running = _head_investigation(at_head, alert, "running", None)
    with pytest.raises(psycopg.errors.CheckViolation, match="completed_has_a_disposition"):
        execute(at_head, "UPDATE jobs.investigations SET stage = 'completed', finished_at = now(), "
                        "evidence_state = 'none', scrub = 'not_run' WHERE id = %s", (running,))
    for n, stage in enumerate(("queued", "failed", "aborted", "unparseable")):  # control: no other stage needs one
        _head_investigation(at_head, _head_alert(at_head, f"c{n}"), stage, None)
    assert execute(at_head, "SELECT stage FROM jobs.investigations WHERE disposition IS NULL AND stage <> 'running'"
                            " ORDER BY stage") == [("aborted",), ("failed",), ("queued",), ("unparseable",)]


@pytest.mark.parametrize("stage", ["completed", "failed", "queued"])
@pytest.mark.parametrize("disposition", ["unsanctioned-benign", "", "Benign", "malicious "])
def test_o10_a_disposition_outside_the_five_codes_is_refused_at_any_stage(at_head, stage, disposition):
    """A disposition that is not exactly one of the five codes is refused, whatever the stage (a null is fine, above). (O10)"""
    with pytest.raises(psycopg.errors.CheckViolation):
        _head_investigation(at_head, _head_alert(at_head, "t"), stage, disposition)
    assert execute(at_head, "SELECT count(*) FROM jobs.investigations") == [(0,)]


def test_the_alert_columns_hold_all_or_none_of_the_three_and_only_the_five_codes(at_head):
    """`outcome`, `outcome_investigation_id` and `outcome_created_at` are all null or all set; `outcome` is one of the five
    codes; the source is no foreign key (a deleted source leaves no dangling constraint to violate). (data model)"""
    alert = _head_alert(at_head, "t")
    inv = _id("head-inv", "source")
    set_all = ("UPDATE jobs.alerts SET outcome = %s, outcome_investigation_id = %s, outcome_created_at = %s WHERE id = %s")
    execute(at_head, set_all, ("malicious", inv, T0, alert))  # control: all three, a code, a source with no row behind it
    assert execute(at_head, "SELECT outcome, outcome_investigation_id, outcome_created_at FROM jobs.alerts") == [("malicious", inv, T0)]
    execute(at_head, "UPDATE jobs.alerts SET outcome = NULL, outcome_investigation_id = NULL, outcome_created_at = NULL")
    for partial in ("outcome = 'malicious'", f"outcome_investigation_id = '{inv}'", "outcome_created_at = now()"):
        with pytest.raises(psycopg.errors.CheckViolation):
            execute(at_head, f"UPDATE jobs.alerts SET {partial}")  # noqa: S608 — test-built SQL: the partial SET is a literal of this file
    with pytest.raises(psycopg.errors.CheckViolation):
        execute(at_head, set_all, ("unsanctioned-benign", inv, T0, alert))
    assert execute(at_head, "SELECT outcome FROM jobs.alerts") == [(None,)]


def test_the_alert_outcome_index_is_keyed_tenant_outcome_newest_first(at_head):
    """The index `alerts_outcome_newest_first` is on `(tenant_id, outcome, fired_at DESC, id DESC)`, whole-table. (data model)"""
    [(definition,)] = execute(at_head, "SELECT indexdef FROM pg_indexes WHERE schemaname = 'jobs' AND tablename = 'alerts' "
                                       "AND indexname = 'alerts_outcome_newest_first'")
    assert "(tenant_id, outcome, fired_at DESC, id DESC)" in definition
    assert "WHERE" not in definition
