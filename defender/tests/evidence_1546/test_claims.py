"""#1546 sketch (r6), "Data model": the claims table (one row per launched child, inserted in the claim's own
transaction, naming the row or hold whose lease it runs under), staged facts (create-once by `(token, name)`), and
PR7 liveness (a claim is live exactly while its lease is held). Through the store's real claims.

Seam (missing): `JobStore.claim_live(token) -> bool` (PR7's test, which the sweeps and the helper's pull gate share).
"""
from __future__ import annotations

import uuid

import pytest

from defender.tests.evidence_1546._support import (
    STARTED,
    claim_row,
    claim_token,
    inv_outcome,
    insert_claim,
    stage_fact,
)
from defender.tests.support.jobs._jobs1342 import T1, job_store, lapse_lease, register_tenant
from defender.tests.support.jobs._worker1342 import _queued
from defender.tests.support.shared._postgres1339 import execute

pytestmark = [pytest.mark.anyio, pytest.mark.postgres]


async def test_every_kinds_claim_inserts_its_claim_row_naming_its_lease(migrated_database):
    """An investigation's claim, a readiness request's claim and a post-step's hold each insert one claim row of their
    kind and tenant, naming the row (or the tenant's hold) whose lease it runs under; an owner row carries its token.
    FORCED CHOICE (post-step, drain): r6 makes the hold the lease reference and the claim token "the claim id the
    worker mints per child", but `hold_learning_check(tenant, holder)` takes a worker-minted hold token
    (`jobs/models.py:195-198`); either the holder IS the claim token (open probe in r6) or the claim row names the
    hold by tenant plus the hold's own token. This case asserts `holder == token`."""
    dsn = migrated_database
    register_tenant(dsn, T1)
    async with job_store(dsn) as store:
        inv = await _queued(store)
        assert await store.claim() is not None
        rec, _ = await store.create_readiness(T1, actor="u-1")
        assert await store.claim_host_request() is not None
        holder = uuid.uuid4().hex
        assert await store.hold_learning_check(T1, holder)

    token = claim_token(dsn, "investigations", inv)
    assert claim_row(dsn, token)["kind"] == "investigation"
    assert claim_row(dsn, token)["investigation_id"] == inv
    [(host_token,)] = execute(dsn, "SELECT token FROM jobs.claims WHERE host_request_id = %s", (rec.request_id,))
    assert claim_row(dsn, host_token)["kind"] == "readiness"
    post = claim_row(dsn, holder)
    assert post is not None, "the post-step's hold inserted no claim row under its holder token"
    assert (post["kind"], post["hold_tenant_id"], post["tenant_id"]) == ("post-step", T1, T1)


async def test_a_claim_kind_must_name_its_own_lease_reference(migrated_database):
    """The check constraint ties kind to which reference is set: an investigation claim naming a learning job (or
    nothing) is refused."""
    dsn = migrated_database
    register_tenant(dsn, T1)
    async with job_store(dsn) as store:
        inv = await _queued(store)
    with pytest.raises(Exception, match="check"):
        execute(dsn, "INSERT INTO jobs.claims (token, tenant_id, kind, learning_job_id) VALUES (%s, %s, "
                     "'investigation', %s)", (uuid.uuid4().hex, T1, inv))
    insert_claim(dsn, token=uuid.uuid4().hex, tenant=T1, kind="investigation", ref=inv)  # the control


async def test_a_staged_fact_is_create_once_and_needs_its_claim(migrated_database):
    """`outcome` staged twice under one token is refused (create-once); a fact under no claim is refused (FK)."""
    dsn = migrated_database
    register_tenant(dsn, T1)
    async with job_store(dsn) as store:
        inv = await _queued(store)
        assert await store.claim() is not None
    token = claim_token(dsn, "investigations", inv)
    stage_fact(dsn, token, "outcome", inv_outcome())
    with pytest.raises(Exception, match="duplicate|unique"):
        stage_fact(dsn, token, "outcome", inv_outcome(closing=None, report_committed=False))
    with pytest.raises(Exception, match="foreign key"):
        stage_fact(dsn, uuid.uuid4().hex, "started", STARTED)


async def test_a_claim_is_live_exactly_while_its_lease_is_held(migrated_database):
    """PR7: live while the referenced row is `running` with this token and an unexpired lease; a lapsed lease ends it
    though the row is still `running`; another claim naming the same row is never live."""
    dsn = migrated_database
    register_tenant(dsn, T1)
    async with job_store(dsn) as store:
        inv = await _queued(store)
        assert await store.claim() is not None
        token = claim_token(dsn, "investigations", inv)
        stale = uuid.uuid4().hex
        insert_claim(dsn, token=stale, tenant=T1, kind="investigation", ref=inv)
        assert await store.claim_live(token) is True
        assert await store.claim_live(stale) is False
        lapse_lease(dsn, inv)
        assert await store.claim_live(token) is False
