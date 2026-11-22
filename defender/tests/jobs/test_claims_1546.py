"""#1546 PR7, A-O3: one minter (the store, in the claim's own transaction, holds included), liveness = the referenced row
has not ended, and the write fence: a staged fact or upload row written after a take-over, cancel, offboard or finish is
refused, one written before is kept and counted. Upload rows are create-once and never change once accepted. Deleting an
investigation removes its claims, facts and uploads."""
from __future__ import annotations

import asyncio

import pytest

from defender.tests.support.jobs._ending1546 import (
    BUNDLE,
    STARTED,
    accepted,
    end_row,
    facts_of,
    inv_outcome,
    inv_row,
    plant_complete_source,
    plant_facts,
    plant_uploads,
    queue_learning_job,
    token_of,
    uploads_of,
    up,
    KNOWLEDGE,
)
from defender.tests.support.jobs._jobs1342 import T1, job_store, lapse_lease, register_tenant
from defender.tests.support.jobs._worker1342 import _queued
from defender.tests.support.shared._postgres1339 import execute

pytestmark = [pytest.mark.anyio, pytest.mark.postgres]

DIGEST = "ab" * 32


def _claim_row(dsn, token):
    cols = ("kind", "tenant_id", "investigation_id", "learning_job_id", "host_request_id", "hold_tenant_id", "inputs")
    found = execute(dsn, f"SELECT {', '.join(cols)} FROM jobs.claims WHERE token = %s", (token,))  # noqa: S608
    return dict(zip(cols, found[0], strict=True)) if found else None


async def _fact(store, token, name="started", body=STARTED):
    return await store.stage_fact(token, name, body)


async def _upload(store, token, obj=BUNDLE, **kw):
    return await store.begin_upload(token, obj, size=3, sha256=DIGEST, wrapped_key="wrapped", **kw)


async def _running(store, dsn):
    inv = await _queued(store)
    claim = await store.claim()
    assert claim is not None
    return inv, claim.token


# --- PR7: one minter ---------------------------------------------------------------------------------------------------------


async def test_every_claim_returns_the_token_the_store_minted_in_the_claims_own_transaction(migrated_database):
    """Investigation, learning, readiness, adoption and post-step claims each leave exactly one claim row of their kind,
    tenant and lease reference under the token the claim returned; the post-step hold's `holder` is that token. (PR7)"""
    dsn = migrated_database
    register_tenant(dsn, T1)
    async with job_store(dsn) as store:
        inv, inv_token = await _running(store, dsn)
        alert, source = await plant_complete_source(dsn, store, T1)
        job = await queue_learning_job(dsn, T1, alert.alert_id, source)
        learn = await store.claim_learning_job()
        ready, _ = await store.create_readiness(T1, actor="u-1")
        host = await store.claim_host_request()
        hold = await store.hold_learning_check(T1)
    tokens = {inv_token, learn.token, host.token, hold}
    assert len(tokens) == 4 and None not in tokens
    got = {name: _claim_row(dsn, t) for name, t in (("inv", inv_token), ("learn", learn.token), ("host", host.token),
                                                    ("hold", hold))}
    assert (got["inv"]["kind"], got["inv"]["investigation_id"], got["inv"]["tenant_id"]) == ("investigation", inv, T1)
    assert (got["learn"]["kind"], got["learn"]["learning_job_id"]) == ("learning", job)
    assert (got["host"]["kind"], got["host"]["host_request_id"]) == ("readiness", ready.request_id)
    assert (got["hold"]["kind"], got["hold"]["hold_tenant_id"], got["hold"]["tenant_id"]) == ("post-step", T1, T1)
    assert execute(dsn, "SELECT holder FROM jobs.learning_checks WHERE tenant_id = %s", (T1,)) == [(hold,)]
    assert execute(dsn, "SELECT count(*) FROM jobs.claims") == [(4,)]


async def test_a_claims_inputs_are_not_null_and_a_learning_claim_names_its_sources_bundle_and_pin(migrated_database):
    """`inputs` is a list: empty for an investigation, the source's `bundle` for a learning job, whose launch facts
    carry the source's knowledge pin. (A-O6 input set, PR7)"""
    dsn = migrated_database
    register_tenant(dsn, T1)
    async with job_store(dsn) as store:
        _, inv_token = await _running(store, dsn)
        alert, source = await plant_complete_source(dsn, store, T1)
        await queue_learning_job(dsn, T1, alert.alert_id, source)
        learn = await store.claim_learning_job()
    assert _claim_row(dsn, inv_token)["inputs"] == []
    assert _claim_row(dsn, learn.token)["inputs"] == [{"owner": source, "object": BUNDLE}]
    [(launch,)] = execute(dsn, "SELECT launch::text FROM jobs.claims WHERE token = %s", (learn.token,))
    assert KNOWLEDGE["commit"] in launch
    with pytest.raises(Exception, match="null value|not-null"):
        execute(dsn, "INSERT INTO jobs.claims (token, tenant_id, kind, investigation_id, inputs) VALUES "
                     "('x', %s, 'investigation', %s, NULL)", (T1, _claim_row(dsn, inv_token)["investigation_id"]))


async def test_a_retry_after_take_over_is_a_new_row_with_a_new_token(migrated_database):
    """A claim is made once per row; the retried row's claim has its own token. (PR7)"""
    dsn = migrated_database
    register_tenant(dsn, T1)
    async with job_store(dsn) as store:
        inv, first = await _running(store, dsn)
        lapse_lease(dsn, inv)
        await store.take_over()
        again = await store.claim()
    assert again.token not in (None, first)
    assert execute(dsn, "SELECT count(*) FROM jobs.claims WHERE kind = 'investigation'") == [(2,)]


# --- PR7: liveness -------------------------------------------------------------------------------------------------------------


async def test_a_claim_is_live_until_its_row_ends_and_a_lapsed_lease_alone_does_not_end_it(migrated_database):
    """Live while the referenced row has not ended, lapsed lease included (a late renewal may revive it); not live after
    a take-over, cancel or offboard ends it. (PR7)"""
    dsn = migrated_database
    register_tenant(dsn, T1)
    async with job_store(dsn) as store:
        a, ta = await _running(store, dsn)
        lapse_lease(dsn, a)
        assert await store.claim_live(ta) is True
        await store.take_over()
        assert await store.claim_live(ta) is False
        b, tb = await _running(store, dsn)
        assert await store.claim_live(tb) is True
        await store.cancel_investigation(T1, b, actor="u-1")
        assert await store.claim_live(tb) is False
        c, tc = await _running(store, dsn)
        await store.offboard_tenant(T1, actor="u-1")
        assert await store.claim_live(tc) is False
        assert await store.claim_live("no-such-token") is False


async def test_a_post_step_claim_is_live_only_while_the_hold_names_its_token(migrated_database):
    """The hold's claim is live while `holder` equals its token, a lapsed hold included; letting go, or a later hold
    with another token, ends it. (PR7)"""
    dsn = migrated_database
    register_tenant(dsn, T1)
    async with job_store(dsn) as store:
        first = await store.hold_learning_check(T1)
        execute(dsn, "UPDATE jobs.learning_checks SET checking_until = now() - interval '1 minute' WHERE tenant_id = %s", (T1,))
        assert await store.claim_live(first) is True
        assert await store.end_learning_check(T1, first, idle=True)
        assert await store.claim_live(first) is False
        second = await store.hold_learning_check(T1)
        assert second != first
        assert (await store.claim_live(second), await store.claim_live(first)) == (True, False)


# --- PR7: the write fence ----------------------------------------------------------------------------------------------------


@pytest.mark.parametrize("ender", ["take_over", "cancel", "offboard", "finish"])
async def test_a_write_before_the_ender_is_kept_and_counted_and_one_after_it_is_refused(migrated_database, ender):
    """A staged fact and an upload row written while the claim is live land (the ending reflects them); after a take-over,
    cancel, offboard or finish the same writes raise `Conflict` and leave no row. (PR7, A-O3)"""
    from defender.jobs import Conflict

    dsn = migrated_database
    register_tenant(dsn, T1)
    async with job_store(dsn) as store:
        inv, token = await _running(store, dsn)
        await _fact(store, token)
        await _fact(store, token, "outcome", inv_outcome())
        await _upload(store, token)
        assert set(facts_of(dsn, token)) == {"started", "outcome"} and set(uploads_of(dsn, token)) == {BUNDLE}
        if ender == "take_over":
            lapse_lease(dsn, inv)
            await store.take_over()
        elif ender == "cancel":
            await store.cancel_investigation(T1, inv, actor="u-1")
        elif ender == "offboard":
            await store.offboard_tenant(T1, actor="u-1")
        else:
            await end_row(store, dsn, kind="investigation", tenant=T1, owner=inv, token=token, by="exited")
        with pytest.raises(Conflict):
            await _fact(store, token, "knowledge", KNOWLEDGE)
        with pytest.raises(Conflict):
            await _fact(store, token, "progress", {"cost_usd": 9.0})
        with pytest.raises(Conflict):
            await _upload(store, token, "page/late")
        with pytest.raises(Conflict):
            await store.finish_upload(token, BUNDLE, status="uploaded")
    assert set(facts_of(dsn, token)) == {"started", "outcome"}
    assert set(uploads_of(dsn, token)) == {BUNDLE}
    assert uploads_of(dsn, token)[BUNDLE]["status"] == "pending", "a late PUT never completes the row"
    if ender == "take_over":
        assert inv_row(dsn, inv, "stage", "disposition")["disposition"] == "benign", "the earlier outcome decided it"


async def test_a_post_step_claims_writes_are_refused_once_its_hold_is_gone(migrated_database):
    """The fence also covers a hold-referenced claim: after the hold ends a write under its token is refused. (PR7)"""
    from defender.jobs import Conflict

    dsn = migrated_database
    register_tenant(dsn, T1)
    async with job_store(dsn) as store:
        token = await store.hold_learning_check(T1)
        await _fact(store, token)
        assert await store.end_learning_check(T1, token, idle=True)
        with pytest.raises(Conflict):
            await _fact(store, token, "result", {"outcome": "x"})
    assert set(facts_of(dsn, token)) == {"started"}


async def test_a_write_racing_an_uncommitted_ender_waits_for_it_and_is_then_refused(migrated_database):
    """An ender holds the row `FOR UPDATE` and has changed it; a staged-fact write started meanwhile does not land
    before the ender commits and is refused after (liveness is checked under the row's lock, not read-then-write). (PR7)"""
    import psycopg

    from defender.jobs import Conflict

    dsn = migrated_database
    register_tenant(dsn, T1)
    async with job_store(dsn) as store:
        inv, token = await _running(store, dsn)
        async with await psycopg.AsyncConnection.connect(dsn) as ender:
            await ender.execute("SELECT id FROM jobs.investigations WHERE id = %s FOR UPDATE", (inv,))
            await ender.execute(
                "UPDATE jobs.investigations SET stage = 'aborted', failure_reason = 'cancelled', finished_at = now(), "
                "evidence_state = 'none', scrub = 'not_run' WHERE id = %s", (inv,))
            writer = asyncio.create_task(_fact(store, token, "outcome", inv_outcome()))
            done, _ = await asyncio.wait({writer}, timeout=0.5)
            assert not done, "the write returned while the ender was uncommitted: it did not wait for the row"
            await ender.commit()
        with pytest.raises(Conflict):
            await writer
    assert facts_of(dsn, token) == {}


# --- A-O3: upload rows ----------------------------------------------------------------------------------------------------------


async def test_an_upload_row_is_create_once_moves_only_pending_to_uploaded_or_refused_and_is_never_accepted_by_a_writer(
        migrated_database):
    """`begin_upload` twice for one object is refused and the first row stays; `finish_upload` takes `pending` to
    `uploaded` or `refused` once; neither verb sets `accepted_at`; the applier alone promotes, and an accepted row then
    never changes. (A-O3)"""
    from defender.jobs import Conflict

    dsn = migrated_database
    register_tenant(dsn, T1)
    async with job_store(dsn) as store:
        inv, token = await _running(store, dsn)
        await _upload(store, token, BUNDLE, scrub="clean")
        with pytest.raises(Conflict):
            await store.begin_upload(token, BUNDLE, size=99, sha256="cd" * 32, wrapped_key="other")
        await _upload(store, token, "page/a")
        await store.finish_upload(token, BUNDLE, status="uploaded")
        await store.finish_upload(token, "page/a", status="refused")
        with pytest.raises(Conflict):
            await store.finish_upload(token, BUNDLE, status="refused")
        with pytest.raises(Conflict):
            await store.finish_upload(token, "page/a", status="uploaded")
        got = uploads_of(dsn, token)
        assert (got[BUNDLE]["status"], got["page/a"]["status"]) == ("uploaded", "refused")
        assert accepted(dsn, token) == []
        assert execute(dsn, "SELECT size, sha256, wrapped_key FROM jobs.uploads WHERE token = %s AND object = %s",
                       (token, BUNDLE)) == [(3, DIGEST, "wrapped")]
        await store.stage_fact(token, "started", STARTED)
        await store.stage_fact(token, "outcome", inv_outcome(scrub="not_run"))
        await end_row(store, dsn, kind="investigation", tenant=T1, owner=inv, token=token, by="exited")
        promoted = uploads_of(dsn, token)
        with pytest.raises(Conflict):
            await store.finish_upload(token, BUNDLE, status="uploaded")
    assert accepted(dsn, token) == [BUNDLE]
    assert uploads_of(dsn, token) == promoted


async def test_the_progress_fact_is_the_one_replaced_fact_and_every_other_is_create_once(migrated_database):
    """`progress` takes the newest value; a second `outcome` or `started` is refused and the first body stays. (staged facts)"""
    from defender.jobs import Conflict

    dsn = migrated_database
    register_tenant(dsn, T1)
    async with job_store(dsn) as store:
        _, token = await _running(store, dsn)
        await _fact(store, token, "progress", {"cost_usd": 0.1})
        await _fact(store, token, "progress", {"cost_usd": 0.2})
        await _fact(store, token, "outcome", inv_outcome())
        with pytest.raises(Conflict):
            await _fact(store, token, "outcome", inv_outcome(scrub="tainted"))
        with pytest.raises(Conflict):
            await store.stage_fact("ffffffffffffffffffffffffffffffff", "started", STARTED)  # no such claim
    got = facts_of(dsn, token)
    assert got["progress"] == {"cost_usd": 0.2} and got["outcome"]["scrub"] == "clean"


# --- claims lifecycle --------------------------------------------------------------------------------------------------------------


async def test_deleting_an_investigation_removes_its_claims_facts_and_uploads_and_its_jobs_and_no_one_elses(migrated_database):
    """Delete takes the investigation's claims, staged facts and uploads (and its learning jobs' claims) with it, in the
    same transaction; another investigation's stay. (claims lifecycle)"""
    dsn = migrated_database
    register_tenant(dsn, T1)
    async with job_store(dsn) as store:
        gone, gone_token = await _running(store, dsn)
        plant_facts(dsn, gone_token, {"started": STARTED})
        plant_uploads(dsn, gone_token, {BUNDLE: up()})
        await store.cancel_investigation(T1, gone, actor="u-1")
        job_alert = execute(dsn, "SELECT alert_id FROM jobs.investigations WHERE id = %s", (gone,))[0][0]
        execute(dsn, "UPDATE jobs.investigations SET stage = 'completed', disposition = 'benign', evidence_state = "
                     "'complete', scrub = 'clean' WHERE id = %s", (gone,))
        job = await queue_learning_job(dsn, T1, job_alert, gone)
        assert await store.claim_learning_job() is not None
        job_token = token_of(dsn, "learning", job)
        plant_facts(dsn, job_token, {"started": STARTED})
        execute(dsn, "UPDATE jobs.learning_jobs SET status = 'failed', reason = 'worker_error', finished_at = now(), "
                     "lease_expires_at = NULL, evidence_state = 'none' WHERE id = %s", (job,))
        kept = await _queued(store, "T-2", "k2")
        kept_claim = await store.claim()
        plant_facts(dsn, kept_claim.token, {"started": STARTED})
        await store.cancel_investigation(T1, kept, actor="u-1")
        await store.delete_investigation(T1, gone, actor="u-1")
    for token in (gone_token, job_token):
        assert execute(dsn, "SELECT count(*) FROM jobs.claims WHERE token = %s", (token,)) == [(0,)]
        assert execute(dsn, "SELECT count(*) FROM jobs.staged_facts WHERE token = %s", (token,)) == [(0,)]
        assert execute(dsn, "SELECT count(*) FROM jobs.uploads WHERE token = %s", (token,)) == [(0,)]
    assert execute(dsn, "SELECT count(*) FROM jobs.claims WHERE token = %s", (kept_claim.token,)) == [(1,)]
    assert facts_of(dsn, kept_claim.token) == {"started": STARTED}
