"""#1485: setting work aside and parking batches through the store's own verbs, for the read tests.

Nothing here knows what `set_aside` or `parked` answer: every row is made by a public verb, so what a verb stored (its
reason, its time, its batch) is read back from `work()` and `batches()`, never spelled twice.
"""
from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from defender.tests.support.learning.core._store1278 import ONE, QUESTIONER, claim, finding, publish, store_mod

#: A reason a model could write: markup and quotes must come back as the same text (P2).
HOSTILE_REASON = '<script>alert("x")</script> & "quotes" \\n </td>'
SILENT_CLOSE = "PR #7 of the batch was closed with no feedback: held for a person"


async def held_by_close(store: Any, tenant: str, items: Sequence[tuple[str, str]], *, pr: int = 7,
                        reason: str = SILENT_CLOSE) -> Any:
    """Publish `items` (kind, key), claim them as one author batch, open PR `pr`, and close it with every item held
    in ONE transaction (`end_review`): the items share one `updated_at`. The batch id."""
    for kind in dict.fromkeys(k for k, _ in items):
        await publish(store, tenant, *(key for k, key in items if k == kind), kind=kind)
    held = await claim(store, tenant)
    assert sorted((k, key) for k, key, _p in held.items) == sorted(items), "premise: the claim took exactly these"
    await store.in_review(held, pr, {})
    assert await store.end_review(tenant, held.batch_id, expect_phase="in_review", outcome="closed",
                                  published=[], held=list(items), reason=reason)
    return held.batch_id


async def dead_without_pr(store: Any, tenant: str, key: str, reason: str = "offered too often") -> Any:
    """One finding that a batch with no commits retired as dead: no PR. The batch id."""
    await publish(store, tenant, key, run="run-dead")
    held = await claim(store, tenant)
    await store.end_no_commits(held, {("finding", key): store_mod().Outcome.dead(reason)})
    return held.batch_id


async def settled_in_one_review(store: Any, tenant: str) -> Any:
    """One batch in review (PR 5) that settles `p1` published, `s1` skipped, `dd` dead and `hh` held at once, then
    ends merged. The batch id."""
    S = store_mod()
    await publish(store, tenant, "p1", "s1", "dd", "hh")
    held = await claim(store, tenant)
    await store.in_review(held, 5, {("finding", "p1"): S.Outcome.published(), ("finding", "s1"): S.Outcome.skipped("not a lesson"),
                                    ("finding", "dd"): S.Outcome.dead("retired for good"),
                                    ("finding", "hh"): S.Outcome.held("needs a person's eye")})
    assert await store.end_review(tenant, held.batch_id, expect_phase="in_review", outcome="merged", published=[], held=[])
    return held.batch_id


async def open_work(store: Any, tenant: str) -> None:
    """Leave `b1` in a working batch (in_batch) and `w1` waiting."""
    await publish(store, tenant, "b1")
    assert await claim(store, tenant) is not None
    await publish(store, tenant, "w1")


async def page_through(store: Any, tenant: str, *, limit: int, status: str | None = None) -> list[Any]:
    """Every page of `set_aside`, each asked `after` the last item of the one before; no page exceeds `limit`."""
    seen: list[Any] = []
    after = None
    while True:
        page = await store.set_aside(tenant, status=status, after=after, limit=limit)
        assert len(page) <= limit
        seen.extend(page)
        if len(page) < limit:
            return seen
        after = (page[-1].updated_at, page[-1].kind, page[-1].key)


async def page_parked(store: Any, tenant: str, *, limit: int) -> list[Any]:
    """Every page of `parked`, each asked `after` the (created_at, id) of the last batch of the one before."""
    seen: list[Any] = []
    after = None
    while True:
        page = await store.parked(tenant, after=after, limit=limit)
        assert len(page) <= limit
        seen.extend(page)
        if len(page) < limit:
            return seen
        after = (page[-1].created_at, page[-1].id)


def pitfall(pid: str) -> dict[str, Any]:
    return {"schema_version": 1, "pitfall_id": pid, "source_run": "r", "system": "elastic", "query_id": "elastic.esql",
            "goal": "g", "executed_query": "x", "stderr_digest": f"exit=1; {pid}", "error_class": "agent-fixable"}


async def parked_set(store: Any, tenant: str, *, tag: str = "") -> dict[str, Any]:
    """Four batches of `tenant`, created in this order: an author batch (items `f1`, `f2` and a questioner `q1`, PR 7),
    a revert, a lead-author batch (pitfall `p`, PR 8) and a registry batch; parked in a DIFFERENT order (revert,
    registry, lead, then author by three forge refusals), so creation order and parking order differ.
    Returns the `Held`/ids by name and the reasons the parking verbs were given."""
    ids: dict[str, Any] = {}
    await publish(store, tenant, f"f1{tag}", f"f2{tag}")
    await publish(store, tenant, f"q1{tag}", kind=QUESTIONER)
    author = await claim(store, tenant)
    await store.in_review(author, 7, {})
    revert = await store.claim_revert(tenant, owner="cli")
    await store.add_pitfall(tenant, pitfall(f"p{tag}"))
    lead = await store.claim(tenant, "lead_author", owner="host-a", thresholds=ONE)
    await store.in_review(lead, 8, {})
    tick = await store.begin_feedback_tick(tenant, owner="host-a")
    assert tick is not None
    registry = await store.claim_registry(tick)
    reasons = {"revert": "a foreign tip on its branch", "registry": "a PR the loop did not make is open on the lane",
               "lead": "local commits outside its record"}
    await store.needs_person(tenant, revert.batch_id, reasons["revert"])
    await store.needs_person(tenant, registry.batch_id, reasons["registry"])
    await store.needs_person(tenant, lead.batch_id, reasons["lead"])
    for _ in range(3):
        await store.note_refusal(tenant, author.batch_id, "403 Forbidden: <b>bad credentials</b>")
    ids.update(author=author.batch_id, revert=revert.batch_id, lead=lead.batch_id, registry=registry.batch_id)
    return {"ids": ids, "reasons": reasons}


__all__ = ["HOSTILE_REASON", "SILENT_CLOSE", "dead_without_pr", "finding", "open_work", "settled_in_one_review", "held_by_close", "page_parked",
           "page_through", "parked_set", "pitfall"]
