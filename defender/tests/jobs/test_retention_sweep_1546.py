# ruff: noqa: F811, PLR0913, PT018
"""#1546 A-O7: the retention sweep over the real job store, Postgres and Garage (the objects are the store's, observed with
plain S3 calls), and the learning insert's serialization with it (database locks held by raw connections).

Pinned (missing): `defender.lifecycle.sweep_evidence(jobs=JobStore, blob=BlobStore)` — one pass of the sweep; the pass
reads the database clock and lists only the store prefixes of tenants the database holds (a bucket listing of `t/` would
delete other tests' objects in the shared bucket)."""
from __future__ import annotations

import asyncio
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import pytest

from defender.tests.support.evidence._evidence1546 import garage  # noqa: F401 — fixture
from defender.tests.support.evidence._retention1546 import (
    blob_store,
    evidence_state,
    facts,
    gone,
    make_owner,
    planted_before_the_foreign_key,
    present,
    retention_fk_validated,
    set_retention,
    stage_fact,
    uploads,
)
from defender.tests.support.jobs._jobs1342 import job_store, register_tenant
from defender.tests.support.shared import _pglocks1339 as pglocks
from defender.tests.support.shared._postgres1339 import execute, migrated_database  # noqa: F401 — fixture

pytestmark = [pytest.mark.anyio, pytest.mark.postgres, pytest.mark.garage]


def _sweep():
    from defender import lifecycle

    return lifecycle.sweep_evidence


async def _run(store, garage) -> None:
    await _sweep()(jobs=store, blob=blob_store(garage))


def _fresh_tenant(dsn: str) -> str:
    tenant = str(uuid.uuid4())
    register_tenant(dsn, tenant)
    return tenant


# --- expiry: per tenant, per kind, from acceptance -------------------------------------------------------------------

@pytest.mark.parametrize(("kind", "accepted", "expires"), [
    ("investigation", 29, False), ("investigation", 31, True),   # the tenant's investigation value is 30
    ("learning", 31, False), ("learning", 89, False), ("learning", 91, True),  # its learning value is 90
])
async def test_the_sweep_expires_an_accepted_object_past_the_tenants_value_for_its_kind(
        migrated_database, garage, kind, accepted, expires):
    """With 30 days for investigations and 90 for learning jobs, an owner whose bundle was accepted `accepted` days ago is
    `expired`, its object and upload row gone, exactly when that is past its own kind's value. (A-O7)"""
    dsn = migrated_database
    tenant = _fresh_tenant(dsn)
    set_retention(dsn, tenant, 30, 90)
    async with job_store(dsn) as store:
        made = make_owner(dsn, garage, tenant, "T-1", kind=kind, accepted_days_ago=accepted)
        await _run(store, garage)
    if expires:
        assert evidence_state(dsn, kind, made["owner"]) == "expired"
        assert gone(garage, made["key"]) and uploads(dsn, made["claim"]) == {}
    else:
        assert evidence_state(dsn, kind, made["owner"]) == "complete"
        assert present(garage, made["key"]) and list(uploads(dsn, made["claim"])) == ["bundle"]


async def test_the_sweep_counts_age_from_acceptance_not_from_the_uploads_creation(migrated_database, garage):
    """A bundle uploaded 100 days ago and accepted 10 days ago, under a 30-day value, is kept; one accepted 40 days ago is
    expired (control on the same tenant). (A-O7, "age from acceptance")"""
    dsn = migrated_database
    tenant = _fresh_tenant(dsn)
    set_retention(dsn, tenant, 30)
    async with job_store(dsn) as store:
        young = make_owner(dsn, garage, tenant, "T-young", accepted_days_ago=10, hours_old=24 * 100)
        old = make_owner(dsn, garage, tenant, "T-old", accepted_days_ago=40)
        await _run(store, garage)
    assert evidence_state(dsn, "investigation", young["owner"]) == "complete" and present(garage, young["key"])
    assert evidence_state(dsn, "investigation", old["owner"]) == "expired" and gone(garage, old["key"])


@pytest.mark.parametrize("state", ["complete", "partial", "lost"])
async def test_expired_replaces_every_state_that_had_accepted_objects(migrated_database, garage, state):
    """A `complete`, `partial` or `lost` owner whose accepted object is past the value reads `expired` (objects and rows
    gone); an owner of state `none` (nothing accepted) in the same tenant keeps `none`, so the change is the sweep's
    own. (A-O4, A-O7)"""
    dsn = migrated_database
    tenant = _fresh_tenant(dsn)
    set_retention(dsn, tenant, 30)
    async with job_store(dsn) as store:
        had = make_owner(dsn, garage, tenant, "T-had", state=state, accepted_days_ago=40)
        nothing = make_owner(dsn, garage, tenant, "T-none", state="none", accepted_days_ago=None,
                                   put_object=False)
        execute(dsn, "DELETE FROM jobs.uploads WHERE token = %s", (nothing["claim"],))
        await _run(store, garage)
    assert evidence_state(dsn, "investigation", had["owner"]) == "expired"
    assert gone(garage, had["key"]) and uploads(dsn, had["claim"]) == {}
    assert evidence_state(dsn, "investigation", nothing["owner"]) == "none"


async def test_the_sweep_applies_each_tenants_own_value(migrated_database, garage):
    """One tenant keeps 30 days and another 90, each with a bundle accepted 40 days ago: only the first's expires. (A-O7)"""
    dsn = migrated_database
    first, second = _fresh_tenant(dsn), _fresh_tenant(dsn)  # fresh ids: the Garage bucket is shared (R13)
    set_retention(dsn, first, 30)
    set_retention(dsn, second, 90)
    async with job_store(dsn) as store:
        mine = make_owner(dsn, garage, first, "T-1", accepted_days_ago=40)
        theirs = make_owner(dsn, garage, second, "T-2", accepted_days_ago=40)
        await _run(store, garage)
    assert evidence_state(dsn, "investigation", mine["owner"]) == "expired" and gone(garage, mine["key"])
    assert evidence_state(dsn, "investigation", theirs["owner"]) == "complete"
    assert present(garage, theirs["key"]) and list(uploads(dsn, theirs["claim"])) == ["bundle"]


async def test_an_offboarded_tenant_with_investigations_and_no_row_expires_nothing_and_the_foreign_key_stays_not_valid(
        migrated_database, garage):
    """An offboarded tenant (investigations planted before the foreign key, no retention row) keeps a bundle accepted 400 days
    ago and a claim ended 400 days ago; a tenant with a 30-day row expires its own (control); the key is still `NOT VALID`.
    (A-O7, D16)"""
    dsn = migrated_database
    gone_tenant, live = str(uuid.uuid4()), _fresh_tenant(dsn)
    register_tenant(dsn, gone_tenant, state="offboarded")
    set_retention(dsn, live, 30)
    async with job_store(dsn) as store:
        with planted_before_the_foreign_key(dsn):
            old = make_owner(dsn, garage, gone_tenant, "T-off", accepted_days_ago=400)
            ended = make_owner(dsn, garage, gone_tenant, "T-off-claim", state="none", accepted_days_ago=None,
                               put_object=False, ended_days_ago=400)
            execute(dsn, "DELETE FROM jobs.uploads WHERE token = %s", (ended["claim"],))
        stage_fact(dsn, ended["claim"], "started", {"container": "started"})
        control = make_owner(dsn, garage, live, "T-live", accepted_days_ago=40)
        assert execute(dsn, "SELECT count(*) FROM tenancy.evidence_retention WHERE tenant_id = %s", (gone_tenant,)) == [(0,)]
        await _run(store, garage)
    assert evidence_state(dsn, "investigation", old["owner"]) == "complete"
    assert present(garage, old["key"]) and list(uploads(dsn, old["claim"])) == ["bundle"]
    assert execute(dsn, "SELECT count(*) FROM jobs.claims WHERE token = %s", (ended["claim"],)) == [(1,)]
    assert "started" in facts(dsn, ended["claim"])
    assert evidence_state(dsn, "investigation", control["owner"]) == "expired" and gone(garage, control["key"])
    assert retention_fk_validated(dsn) == [False]


# --- the learning source exception -----------------------------------------------------------------------------------

def _learning_job(dsn: str, investigation_id: str, status: str, ticket: str) -> None:
    lease = "now() + interval '1 hour'" if status == "running" else "NULL"
    done = "now()" if status in ("completed", "failed", "skipped") else "NULL"
    evidence = "'none'" if status in ("completed", "failed", "skipped") else "NULL"
    execute(dsn, "INSERT INTO jobs.learning_jobs (id, tenant_id, alert_id, investigation_id, request_key, attempt, trigger, "  # noqa: S608
                 "status, created_at, sibling_cost_usd, sibling_cost_is_lower_limit, publish_state, started_at, finished_at, lease_expires_at, evidence_state) "
                 f"SELECT %s, tenant_id, alert_id, id, %s, 1, 'explicit', %s, now(), 0, false, 'none', NULL, {done}, {lease}, {evidence} "
                 "FROM jobs.investigations WHERE id = %s",
            (str(uuid.uuid4()), f"k-{ticket}", status, investigation_id))


@pytest.mark.parametrize(("status", "kept"), [("queued", True), ("running", True), ("completed", False)])
async def test_a_source_a_queued_or_running_learning_job_names_is_kept_past_its_value(migrated_database, garage, status, kept):
    """An expired-by-age investigation that a learning job of `status` names stays `complete` with its object while the
    job is queued or running; once the job has ended it expires. (A-O7)"""
    dsn = migrated_database
    tenant = _fresh_tenant(dsn)
    set_retention(dsn, tenant, 30)
    async with job_store(dsn) as store:
        source = make_owner(dsn, garage, tenant, "T-source", accepted_days_ago=40)
        _learning_job(dsn, source["owner"], status, "src")
        await _run(store, garage)
    if kept:
        assert evidence_state(dsn, "investigation", source["owner"]) == "complete"
        assert present(garage, source["key"]) and list(uploads(dsn, source["claim"])) == ["bundle"]
    else:
        assert evidence_state(dsn, "investigation", source["owner"]) == "expired" and gone(garage, source["key"])


@asynccontextmanager
async def _holding(dsn: str, lock: str, owner_id: str, table: str = "investigations") -> AsyncIterator:
    """A transaction of a raw connection that has locked the owner row (`FOR UPDATE`: a sweep in progress; `FOR SHARE`: a
    learning insert in progress) and may write; committed by the caller."""
    import psycopg
    from psycopg.types.string import TextLoader

    async with await psycopg.AsyncConnection.connect(dsn) as conn:
        conn.adapters.register_loader("uuid", TextLoader)
        cur = await conn.execute(f"SELECT id FROM jobs.{table} WHERE id = %s FOR {lock}", (owner_id,))  # noqa: S608
        assert await cur.fetchall() == [(owner_id,)], "the row to hold does not exist"
        yield conn
        await conn.commit()


async def test_a_learning_insert_in_flight_when_the_sweep_arrives_keeps_its_source(migrated_database, garage):
    """A learning job's insert holds `FOR SHARE` on its source and has not committed when the sweep reaches the expired
    source: the sweep waits, then sees the queued job and keeps the source `complete` with its object. (A-O7, PR7)"""
    dsn = migrated_database
    tenant = _fresh_tenant(dsn)
    set_retention(dsn, tenant, 30)
    async with job_store(dsn) as store:
        source = make_owner(dsn, garage, tenant, "T-source", accepted_days_ago=40)
        async with _holding(dsn, "SHARE", source["owner"]) as conn:
            await conn.execute(
                "INSERT INTO jobs.learning_jobs (id, tenant_id, alert_id, investigation_id, request_key, attempt, trigger, "
                "status, created_at, sibling_cost_usd, sibling_cost_is_lower_limit, publish_state) SELECT %s, tenant_id, alert_id, id, 'k-race', 1, "
                "'explicit', 'queued', now(), 0, false, 'none' FROM jobs.investigations WHERE id = %s",
                (str(uuid.uuid4()), source["owner"]))
            sweeping = asyncio.ensure_future(_run(store, garage))
            await pglocks.until_blocked(dsn, 1)
        await asyncio.wait_for(sweeping, pglocks.TIMEOUT)
    assert evidence_state(dsn, "investigation", source["owner"]) == "complete"
    assert present(garage, source["key"]) and list(uploads(dsn, source["claim"])) == ["bundle"]


async def test_a_learning_insert_arriving_while_the_sweep_holds_its_source_is_refused_once_it_expired(migrated_database, garage):
    """The sweep holds the expired source `FOR UPDATE` (nothing names it yet); a learning insert for it waits, and after the
    sweep commits `expired` the insert is refused with no learning job made. (A-O7, "insert takes FOR SHARE and requires complete")"""
    from defender.jobs import Conflict

    dsn = migrated_database
    tenant = _fresh_tenant(dsn)
    set_retention(dsn, tenant, 30)
    async with job_store(dsn) as store:
        source = make_owner(dsn, garage, tenant, "T-source", accepted_days_ago=40)
        async with _holding(dsn, "UPDATE", source["owner"]) as conn:
            inserting = asyncio.ensure_future(
                store.create_learning_job(tenant, source["owner"], "k-late", actor="u-1"))
            await pglocks.until_blocked(dsn, 1)
            await conn.execute("UPDATE jobs.investigations SET evidence_state = 'expired' WHERE id = %s", (source["owner"],))
            await conn.execute("DELETE FROM jobs.uploads WHERE token = %s", (source["claim"],))
        with pytest.raises(Conflict):
            await asyncio.wait_for(inserting, pglocks.TIMEOUT)
    assert execute(dsn, "SELECT count(*) FROM jobs.learning_jobs WHERE investigation_id = %s", (source["owner"],)) == [(0,)]


@pytest.mark.parametrize(("state", "accepted"), [("complete", True), ("partial", False), ("none", False),
                                                 ("lost", False), ("expired", False)])
async def test_a_learning_job_is_queued_only_on_a_source_whose_evidence_is_complete(migrated_database, garage, state, accepted):
    """An explicit learning insert over a completed investigation succeeds only when its evidence state is `complete`; every
    other state is refused with no row made. (A-O7)"""
    from defender.jobs import Conflict

    dsn = migrated_database
    tenant = _fresh_tenant(dsn)
    async with job_store(dsn) as store:
        source = make_owner(dsn, garage, tenant, "T-source", state=state, accepted_days_ago=1)
        if accepted:
            job, created = await store.create_learning_job(tenant, source["owner"], "k-1", actor="u-1")
            assert created
        else:
            with pytest.raises(Conflict):
                await store.create_learning_job(tenant, source["owner"], "k-1", actor="u-1")
    wanted = 1 if accepted else 0
    assert execute(dsn, "SELECT count(*) FROM jobs.learning_jobs WHERE investigation_id = %s", (source["owner"],)) == [(wanted,)]


# --- unpromoted uploads and orphan objects: the grace sweep ----------------------------------------------------------

@pytest.mark.parametrize("status", ["pending", "uploaded", "refused"])
async def test_an_unpromoted_upload_of_a_claim_no_longer_live_goes_after_an_hours_grace_by_the_database_clock(
        migrated_database, garage, status):
    """Unpromoted upload rows (`pending`, `uploaded`, `refused`) of an ended claim are removed with their objects once more
    than an hour old; at 30 minutes they stay, and a live claim's, however old, stays. The claim's own end and the upload's
    creation are the same age in each case, so either reading of "an hour's grace" gives one answer. (A-O7, PR7)"""
    dsn = migrated_database
    tenant = _fresh_tenant(dsn)
    async with job_store(dsn) as store:
        made = {}
        for name, hours, live in (("old", 2.0, False), ("recent", 0.5, False), ("live", 2.0, True)):
            made[name] = make_owner(dsn, garage, tenant, f"T-{name}", accepted_days_ago=None, live=live,
                                    hours_old=hours, state="none", ended_days_ago=hours / 24)
            execute(dsn, "UPDATE jobs.uploads SET status = %s WHERE token = %s", (status, made[name]["claim"]))
        await _run(store, garage)
    assert gone(garage, made["old"]["key"]) and uploads(dsn, made["old"]["claim"]) == {}
    for name in ("recent", "live"):
        assert present(garage, made[name]["key"]), name
        assert list(uploads(dsn, made[name]["claim"])) == ["bundle"], name


async def test_the_grace_sweep_removes_store_objects_no_upload_row_names(migrated_database, garage):
    """After an investigation's rows are deleted its object is still in the store; the sweep removes it, and leaves an
    object an upload row names (an accepted one, and a pending one of a live claim) beside it. (A-O1, A-O7)"""
    dsn = migrated_database
    tenant = _fresh_tenant(dsn)
    set_retention(dsn, tenant, 730)
    async with job_store(dsn) as store:
        deleted = make_owner(dsn, garage, tenant, "T-deleted", accepted_days_ago=1)
        named = make_owner(dsn, garage, tenant, "T-named", accepted_days_ago=1)
        live = make_owner(dsn, garage, tenant, "T-live", accepted_days_ago=None, live=True, hours_old=0.1,
                                state="none")
        execute(dsn, "UPDATE jobs.uploads SET status = 'pending' WHERE token = %s", (live["claim"],))
        execute(dsn, "DELETE FROM jobs.uploads WHERE token = %s", (deleted["claim"],))
        execute(dsn, "DELETE FROM jobs.claims WHERE token = %s", (deleted["claim"],))
        assert present(garage, deleted["key"]), "premise: the object outlived its rows"
        await _run(store, garage)
    assert gone(garage, deleted["key"])
    assert present(garage, named["key"]) and present(garage, live["key"])


# --- claims of long-ended references --------------------------------------------------------------------------------

async def test_claims_of_ended_references_older_than_the_longest_retention_go_with_their_facts(migrated_database, garage):
    """With 30 and 90 days, a claim whose investigation ended 100 days ago is removed with its staged facts, one whose row
    ended 60 days ago stays (older than one value, not the longest), and a live claim stays. (A-O7, "Claims lifecycle")"""
    dsn = migrated_database
    tenant = _fresh_tenant(dsn)
    set_retention(dsn, tenant, 30, 90)
    async with job_store(dsn) as store:
        made = {}
        for name, days, live in (("old", 100, False), ("mid", 60, False), ("live", 0, True)):
            made[name] = make_owner(dsn, garage, tenant, f"T-{name}", state="none", accepted_days_ago=None,
                                          put_object=False, live=live, ended_days_ago=days)
            execute(dsn, "DELETE FROM jobs.uploads WHERE token = %s", (made[name]["claim"],))
            stage_fact(dsn, made[name]["claim"], "started", {"container": "started"})
        await _run(store, garage)
    assert execute(dsn, "SELECT count(*) FROM jobs.claims WHERE token = %s", (made["old"]["claim"],)) == [(0,)]
    assert facts(dsn, made["old"]["claim"]) == {}
    for name in ("mid", "live"):
        assert execute(dsn, "SELECT count(*) FROM jobs.claims WHERE token = %s", (made[name]["claim"],)) == [(1,)], name
        assert "started" in facts(dsn, made[name]["claim"]), name
