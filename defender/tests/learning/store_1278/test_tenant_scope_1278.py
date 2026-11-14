"""#1278 repair 2, family 1: every public store verb is scoped to the tenant it is called for.

One test over the store's public verbs (a verb with no entry in `ENTRIES` is a failing case), in a world where tenant
GREEN holds rows in every table and phase, and tenant BLUE, the caller, holds a few of its own under the same item
keys. Each verb runs for BLUE, with GREEN's batch ids and keys where it takes them, and a control shows it acts on
BLUE's own. (O6, O2, r8 tenant id first argument)
"""
from __future__ import annotations

import contextlib
import dataclasses
from types import SimpleNamespace
from typing import Any

import pytest

from defender.tests.support.jobs._jobs1342 import register_tenant
from defender.tests.support.learning.core._store1278 import (
    AUTHOR_LANE,
    LEAD_LANE,
    ONE,
    changes_of,
    finding,
    lapse_lease,
    learning_store,
    oid,
    store_mod,
)
from defender.tests.support.shared._fixture_uuid import fixture_uuid
from defender.tests.support.shared._postgres1339 import execute

pytestmark = [pytest.mark.anyio, pytest.mark.postgres]

BLUE = fixture_uuid("tenant:1278-scope-blue")
GREEN = fixture_uuid("tenant:1278-scope-green")

#: Strings only GREEN's rows can carry: none may reach a result BLUE is given.
GREEN_ONLY_KEYS = ("g-only-waiting-1", "g-only-waiting-2", "g-held", "g-published", "g-skipped", "g-dead", "g-pit-1", "g-pit-2")


@pytest.fixture
def dsn(migrated_database):
    register_tenant(migrated_database, BLUE)
    register_tenant(migrated_database, GREEN)
    return migrated_database


def _pitfall(pid: str) -> dict:
    return {"schema_version": 1, "pitfall_id": pid, "source_run": "r", "system": "elastic", "query_id": "elastic.esql",
            "goal": "g", "executed_query": "x", "stderr_digest": f"exit=1; {pid}", "error_class": "agent-fixable"}


async def _publish(store, tenant, *ids, run="run-1"):
    return await store.publish_findings(tenant, run, [finding(i) for i in ids], kind="finding")


def snapshot(dsn: str, tenant: str) -> dict[str, list[str]]:
    """Every row of `tenant`, as JSON text, in every `learning` table that carries a tenant id (a census, so a table
    added later is covered), and its tenancy record: byte-for-byte comparable."""
    tables = [t for (t,) in execute(dsn, "SELECT DISTINCT table_name FROM information_schema.columns "
                                         "WHERE table_schema = 'learning' AND column_name = 'tenant_id' ORDER BY 1")]
    assert tables, "premise: the learning schema has tables that carry a tenant id"
    rows = {t: sorted(r[0] for r in execute(dsn, f"SELECT row_to_json(x)::text FROM learning.{t} x WHERE tenant_id = %s",  # noqa: S608
                                            (tenant,))) for t in tables}
    rows["tenancy.tenants"] = [r[0] for r in execute(dsn, "SELECT row_to_json(x)::text FROM tenancy.tenants x WHERE id = %s", (tenant,))]
    return rows


async def _green_world(store, dsn):
    """GREEN: merged batch with items in every end status, an author batch in review with a commit, a live revert batch,
    a lead batch closed with its items due a replacement, and waiting items of every kind."""
    S = store_mod()
    g = SimpleNamespace(batches=[], commits=[oid(11), oid(12), oid(13), oid(21), oid(22), oid(23)])
    await _publish(store, GREEN, "h1", "g-held", "g-published", "g-skipped", "g-dead")
    first = await store.claim(GREEN, AUTHOR_LANE, owner="host-g", thresholds=ONE)
    await store.in_review(first, 5, {("finding", "h1"): S.Outcome.held("r"), ("finding", "g-held"): S.Outcome.held("r"),
                                     ("finding", "g-published"): S.Outcome.published(),
                                     ("finding", "g-skipped"): S.Outcome.skipped("s"),
                                     ("finding", "g-dead"): S.Outcome.dead("d")})
    assert await store.end_review(GREEN, first.batch_id, expect_phase="in_review", outcome="merged", published=[], held=[])
    await _publish(store, GREEN, "k1", "k2")
    g.review = await store.claim(GREEN, AUTHOR_LANE, owner="host-g", thresholds=ONE)
    await store.record_commit(g.review, oid(11), oid(12), oid(13), changes_of("agent/lessons/g.md"))
    await store.in_review(g.review, 7, {})
    g.revert = await store.claim_revert(GREEN, owner="cli")
    await store.add_pitfall(GREEN, _pitfall("g-pit-1"))
    await store.enqueue_request(GREEN, "run-g1", "case-1", {"case": "g"})
    g.lead = await store.claim(GREEN, LEAD_LANE, owner="host-g", thresholds=ONE)
    await store.record_commit(g.lead, oid(21), oid(22), oid(23), changes_of("agent/pitfalls/g.md"))
    await store.in_review(g.lead, 8, {})
    assert await store.end_review(GREEN, g.lead.batch_id, expect_phase="in_review", outcome="closed", published=[], held=[])
    await _publish(store, GREEN, "g-only-waiting-1", "g-only-waiting-2")
    await store.add_pitfall(GREEN, _pitfall("g-pit-2"))
    await store.enqueue_request(GREEN, "run-g2", "case-1", {"case": "g2"})
    g.ids = [str(b.id) for b in await store.batches(GREEN)]
    assert len(g.ids) == 4, "premise: GREEN has four batches"
    return g


async def _blue_world(store):
    """BLUE: an ended batch with a commit and a held `h1` (GREEN's key too), waiting `a1`, a pitfall and a request for
    `case-1` (GREEN's case too)."""
    await _publish(store, BLUE, "h1")
    spent = await store.claim(BLUE, AUTHOR_LANE, owner="host-b", thresholds=ONE)
    await store.record_commit(spent, oid(31), oid(32), oid(33), changes_of("agent/lessons/b.md"))
    await store.abandon(BLUE, spent.batch_id, by="person")
    await _publish(store, BLUE, "a1")
    await store.add_pitfall(BLUE, _pitfall("a-pit"))
    await store.enqueue_request(BLUE, "run-a1", "case-1", {"case": "a"})
    return spent


class Case:
    """What one verb's entry works with: the store, the two tenants, GREEN's ids, and the checks every entry shares."""

    def __init__(self, store, dsn, g, spent):
        self.store, self.dsn, self.g, self.spent = store, dsn, g, spent
        self.results: list[Any] = []
        self.frozen: dict[str, list[str]] | None = None
        self.S = store_mod()

    def freeze(self):
        """GREEN's rows as they are now: nothing a verb does for BLUE may change them."""
        self.frozen = snapshot(self.dsn, GREEN)

    def seen(self, result):
        self.results.append(result)
        return result

    async def refused(self, coro):
        """BLUE's call about a batch that is GREEN's: it raises one of the store's can't-act errors, or does nothing."""
        with contextlib.suppress(LookupError, self.S.NotLapsed, self.S.LeaseLost):
            return self.seen(await coro)
        return None

    async def control(self, coro):
        """The same verb on BLUE's own: it runs, and BLUE's rows change (so the verb is not refusing everything)."""
        before = snapshot(self.dsn, BLUE)
        result = self.seen(await coro)
        assert snapshot(self.dsn, BLUE) != before, "control: the verb changed none of BLUE's own rows"
        return result

    async def own_in_review(self, key):
        await _publish(self.store, BLUE, key)
        held = await self.store.claim(BLUE, AUTHOR_LANE, owner="host-b", thresholds=ONE)
        await self.store.in_review(held, 9, {})
        return held

    async def own_working(self, lane=AUTHOR_LANE):
        held = await self.store.claim(BLUE, lane, owner="host-b", thresholds=ONE)
        assert held is not None, "premise: BLUE has something due"
        return held

    def forged(self, held):
        """GREEN's holder proof with BLUE's tenant id on it."""
        return dataclasses.replace(held, tenant_id=type(held.tenant_id)(BLUE))


async def _publish_findings(c):
    c.freeze()
    assert c.seen(await c.store.publish_findings(BLUE, "run-9", [finding("k1"), finding("a1")], kind="finding")) == (1, 1), (
        "GREEN's k1 made BLUE's k1 a duplicate, or BLUE's a1 was added twice")


async def _add_pitfall(c):
    c.freeze()
    assert c.seen(await c.store.add_pitfall(BLUE, _pitfall("g-pit-1"))) is True, "GREEN's pitfall id made BLUE's a repeat"


async def _enqueue_request(c):
    c.freeze()
    assert c.seen(await c.store.enqueue_request(BLUE, "run-g1", "case-1", {"case": "again"})) is True, (
        "GREEN's request of that run made BLUE's a repeat")
    waiting = {i.key: i.status for i in await c.store.work(BLUE) if i.kind == "curation_request"}
    assert waiting == {"run-a1": "skipped", "run-g1": "waiting"}, "BLUE's later request did not supersede BLUE's own"


async def _work(c):
    c.freeze()
    keys = {(i.kind, i.key) for i in c.seen(await c.store.work(BLUE))}
    assert keys == {("finding", "h1"), ("finding", "a1"), ("pitfall", "a-pit"), ("curation_request", "run-a1")}


async def _item_keys(c):
    c.freeze()
    assert set(c.seen(await c.store.item_keys(BLUE, "finding"))) == {"h1", "a1"}


async def _set_aside(c):
    """BLUE's held and dead items, and only those: GREEN's `h1` (held), `g-held` and `g-dead` are not BLUE's. (#1485 O1)"""
    c.freeze()
    held = c.seen(await c.store.set_aside(BLUE, limit=50))
    assert [(i.kind, i.key, str(i.batch_id)) for i in held] == [("finding", "h1", str(c.spent.batch_id))], (
        "BLUE's one held item, in BLUE's batch")
    assert c.seen(await c.store.set_aside(BLUE, status="dead", limit=50)) == [], "GREEN's dead item is not BLUE's"
    assert [i.key for i in c.seen(await c.store.set_aside(BLUE, status="held", limit=50))] == ["h1"]


async def _parked(c):
    """GREEN's parked batch, with its items, is not BLUE's; BLUE's own parked batch is listed with its own items. (#1485 O2)"""
    await c.store.needs_person(GREEN, str(c.g.review.batch_id), "a person must look at GREEN's batch")
    own = await c.own_in_review("a2")
    c.freeze()
    assert c.seen(await c.store.parked(BLUE, limit=50)) == [], "control: BLUE has nothing parked yet"
    await c.control(c.store.needs_person(BLUE, str(own.batch_id), "by hand"))
    [mine] = c.seen(await c.store.parked(BLUE, limit=50))
    claimed = tuple(sorted((kind, key) for kind, key, _pending in own.items))  # the claim's threshold may take BLUE's other waiting items
    assert ("finding", "a2") in claimed, "premise: the claim took a2"
    assert (str(mine.id), mine.items) == (str(own.batch_id), claimed), "BLUE's own, with only BLUE's items"
    assert [(b.reason) for b in c.seen(await c.store.parked(BLUE, limit=50))] == ["by hand"]


async def _lane_work(c):
    """BLUE's lanes answered from BLUE's rows: GREEN's lead batch closed with items due names no replacement of BLUE's."""
    c.freeze()
    for lane in (AUTHOR_LANE, LEAD_LANE):
        c.seen(await c.store.lane_work(BLUE, lane, thresholds=ONE))


async def _batches(c):
    c.freeze()
    assert [str(b.id) for b in c.seen(await c.store.batches(BLUE))] == [str(c.spent.batch_id)]


async def _commit_record(c):
    c.freeze()
    assert [r.commit for r in c.seen(await c.store.commit_record(BLUE))] == [oid(31)]


async def _claim(c):
    """BLUE's claims are blocked by no batch of GREEN's, count none of GREEN's waiting rows, take none of them, and are
    not GREEN's replacement."""
    c.freeze()
    held = c.seen(await c.store.claim(BLUE, AUTHOR_LANE, owner="host-b", thresholds={**ONE, "finding": 3}))
    assert held is None, "GREEN's two waiting findings made BLUE's one reach a threshold of three"
    held = c.seen(await c.store.claim(BLUE, AUTHOR_LANE, owner="host-b", thresholds=ONE))
    assert held is not None, "GREEN's batch in review kept BLUE from claiming"
    assert (str(held.tenant_id), sorted((k, key) for k, key, _p in held.items), held.replaces) == (BLUE, [("finding", "a1")], None)
    lead = c.seen(await c.store.claim(BLUE, LEAD_LANE, owner="host-b", thresholds=ONE))
    assert lead is not None
    assert (str(lead.tenant_id), sorted((k, key) for k, key, _p in lead.items), lead.replaces) == (
        BLUE, [("curation_request", "run-a1"), ("pitfall", "a-pit")], None), "BLUE's lead claim took GREEN's replacement"


async def _claim_revert(c):
    c.freeze()
    held = c.seen(await c.store.claim_revert(BLUE, owner="cli"))
    assert (str(held.tenant_id), held.kind) == (BLUE, "revert"), "GREEN's working revert batch kept BLUE's revert out"


async def _take_over(c):
    own = await c.own_working()
    lapse_lease(c.dsn, c.g.revert.batch_id)
    lapse_lease(c.dsn, own.batch_id)
    c.freeze()
    await c.refused(c.store.take_over(BLUE, str(c.g.revert.batch_id), owner="host-b"))
    taken = await c.control(c.store.take_over(BLUE, str(own.batch_id), owner="host-b2"))
    assert taken.token != own.token


def _holder(name):
    calls = {
        "renew": lambda s, h: s.renew(h),
        "record_commit": lambda s, h: s.record_commit(h, oid(41), oid(42), oid(43), changes_of("agent/lessons/x.md")),
        "in_review": lambda s, h: s.in_review(h, 3, {}),
        "end_no_commits": lambda s, h: s.end_no_commits(h, {}),
        "abandon_clean": lambda s, h: s.abandon_clean(h),
        "abandon_crashed": lambda s, h: s.abandon_crashed(h),
        "expire_own": lambda s, h: s.expire_own(h),
    }[name]

    async def entry(c):
        # a lead-lane holder: its request, returned to waiting, is superseded only by a waiting request of its own tenant
        own = await c.own_working(LEAD_LANE)
        c.freeze()
        with pytest.raises(c.S.LeaseLost):
            await calls(c.store, c.forged(c.g.revert))
        await c.control(calls(c.store, own))
        if name in {"end_no_commits", "abandon_clean", "abandon_crashed"}:
            request = {i.key: i.status for i in await c.store.work(BLUE) if i.kind == "curation_request"}
            assert request == {"run-a1": "waiting"}, f"GREEN's waiting request for the same case decided BLUE's: {request}"
    return entry


async def _abandon(c):
    own_review = await c.own_in_review("a2")
    lead = await c.own_working(LEAD_LANE)
    lapse_lease(c.dsn, c.g.revert.batch_id)
    lapse_lease(c.dsn, lead.batch_id)
    c.freeze()
    for green in (c.g.review.batch_id, c.g.revert.batch_id, c.g.lead.batch_id):
        await c.refused(c.store.abandon(BLUE, str(green), by="person"))
        await c.refused(c.store.abandon(BLUE, str(green), by="recovery"))
    await c.control(c.store.abandon(BLUE, str(own_review.batch_id), by="person"))
    await c.control(c.store.abandon(BLUE, str(lead.batch_id), by="recovery"))


async def _release_held(c):
    c.freeze()
    await c.store.release_held(BLUE, "finding", "g-held")
    await c.control(c.store.release_held(BLUE, "finding", "h1"))
    assert {i.key: i.status for i in await c.store.work(BLUE) if i.key == "h1"} == {"h1": "waiting"}


async def _request_cancel(c):
    own = await c.own_working()
    c.freeze()
    await c.control(c.store.request_cancel(BLUE))
    assert [b.cancel_requested for b in await c.store.batches(BLUE) if b.id == own.batch_id] == [True]


async def _note_check(c):
    own = await c.own_in_review("a2")
    c.freeze()
    await c.refused(c.store.note_check(BLUE, str(c.g.review.batch_id)))
    await c.control(c.store.note_check(BLUE, str(own.batch_id)))


async def _note_refusal(c):
    own = await c.own_in_review("a2")
    c.freeze()
    await c.refused(c.store.note_refusal(BLUE, str(c.g.review.batch_id), "forge said no"))
    assert (await c.control(c.store.note_refusal(BLUE, str(own.batch_id), "forge said no")))[0] == 1


async def _needs_person(c):
    own = await c.own_in_review("a2")
    c.freeze()
    await c.refused(c.store.needs_person(BLUE, str(c.g.review.batch_id), "by hand"))
    await c.control(c.store.needs_person(BLUE, str(own.batch_id), "by hand"))
    assert [b.phase for b in await c.store.batches(BLUE) if b.id == own.batch_id] == ["needs_person"]


async def _end_review(c):
    own = await c.own_in_review("a2")
    c.freeze()
    for outcome in ("merged", "closed"):
        assert not await c.refused(c.store.end_review(
            BLUE, str(c.g.review.batch_id), expect_phase="in_review", outcome=outcome,
            published=[("finding", "k1")], held=[("finding", "k2")])), "BLUE ended GREEN's batch"
    assert await c.control(c.store.end_review(BLUE, str(own.batch_id), expect_phase="in_review", outcome="merged",
                                              published=[], held=[]))


async def _purge_like(c, run):
    c.freeze()
    await run()
    left = {t: rows for t, rows in snapshot(c.dsn, BLUE).items() if t != "tenancy.tenants" and rows}
    assert not left, f"control: BLUE's own rows are still there: {sorted(left)}"


async def _offboard(c):
    """Offboarding BLUE (the wait, then the purge) leaves every row of GREEN's."""
    await _purge_like(c, lambda: c.store.offboard(BLUE, wait=1.0))


async def _purge(c):
    await _purge_like(c, lambda: c.store.purge(BLUE))


#: Every public verb of the store and how BLUE calls it. `close` takes no tenant.
ENTRIES = {
    "publish_findings": _publish_findings, "add_pitfall": _add_pitfall, "enqueue_request": _enqueue_request,
    "work": _work, "set_aside": _set_aside, "parked": _parked, "item_keys": _item_keys, "lane_work": _lane_work, "batches": _batches,
    "commit_record": _commit_record,
    "claim": _claim, "claim_revert": _claim_revert, "take_over": _take_over,
    **{name: _holder(name) for name in ("renew", "record_commit", "in_review", "end_no_commits", "abandon_clean",
                                         "abandon_crashed", "expire_own")},
    "abandon": _abandon, "release_held": _release_held, "request_cancel": _request_cancel,
    "note_check": _note_check, "note_refusal": _note_refusal, "needs_person": _needs_person, "end_review": _end_review,
    "offboard": _offboard, "purge": _purge,
    "close": None,
}


def _public_verbs() -> list[str]:
    try:
        cls = store_mod().LearningStore
    except Exception:  # noqa: BLE001 — a missing store is each case's red, not a collection error
        return sorted(ENTRIES)
    return sorted({n for n, v in vars(cls).items() if not n.startswith("_") and callable(v)} | set(ENTRIES))


@pytest.mark.parametrize("verb", _public_verbs())
async def test_o6_every_verb_for_one_tenant_reads_and_changes_nothing_of_another_tenants_rows(dsn, verb):
    """Run for BLUE, with GREEN's ids and keys, a verb leaves GREEN's rows byte-identical and shows none of them. (O6, O2)"""
    assert verb in ENTRIES, f"the store has a public verb `{verb}` with no entry in this test: add how BLUE calls it"
    entry = ENTRIES[verb]
    async with learning_store(dsn) as store:
        assert hasattr(store, verb), f"`{verb}` is no longer a verb of the store: drop its entry"
        if entry is None:
            return
        green = await _green_world(store, dsn)
        spent = await _blue_world(store)
        case = Case(store, dsn, green, spent)

        await entry(case)

        assert case.frozen is not None, "the entry never froze GREEN's rows"
        assert snapshot(dsn, GREEN) == case.frozen, f"`{verb}` for BLUE changed GREEN's rows"
        shown = repr(case.results)
        for foreign in (GREEN, *green.ids, *green.commits, *GREEN_ONLY_KEYS):
            assert foreign not in shown, f"`{verb}` showed BLUE something of GREEN's: {foreign}"
