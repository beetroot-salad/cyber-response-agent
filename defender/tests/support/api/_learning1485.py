"""#1485 API half: the #1306 `World` whose `learning_work` port is the real adapter `StoreLearningWork` over a real
`LearningStore` on a test database, seeders that set work aside and park batches through the store's own verbs, and
the read-back oracles the wire is compared with — NO test functions.

The world's deps are the #1306 world's own (`World.build`), with `learning_work` replaced: no `ApiDeps(...)` call is
copied here. Rows are made only by the store's public verbs (plus one `UPDATE` of `created_at` to tie batches, as
`lapse_lease` moves a lease); what they stored is read back from the store's own views (`work()`, `batches()`),
never spelled twice, and every expected order is sorted here from those read-back values, never taken from the code
under test. Production names are imported inside functions, so a missing one is a per-test red.
"""
from __future__ import annotations

import dataclasses
import datetime as _dt
from collections.abc import Awaitable, Callable, Iterable, Sequence
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import anyio

from defender.api.app import create_app
from defender.tests.support.api._identity1306 import World
from defender.tests.support.learning.core._store1278 import QUESTIONER, call, claim, learning_store, publish, store_mod
from defender.tests.support.shared._postgres1339 import execute

#: A reason a model could write: markup and quotes must come back as the same text (P2).
HOSTILE_REASON = '<script>alert("x")</script> & "quotes" \\n </td> é'
SILENT_CLOSE = "PR #7 of the batch was closed with no feedback: held for a person"
#: About one kilobyte of a long world label: spaces, a slash, a quote and a two-byte character.
LONG_KEY = ("world label é/\"x\" " * 60)[:1000]
INSTANT = _dt.datetime(2026, 11, 2, 8, tzinfo=_dt.UTC)


def on_store(dsn: str, steps: Callable[..., Awaitable[Any]], *args: Any, **kw: Any) -> Any:
    """`await steps(store, *args, **kw)` on a learning store of its own, opened and closed in a thread of its own (so a
    sync test or a world on another loop can seed): what `steps` returned."""
    async def go() -> Any:
        async with learning_store(dsn) as store:
            return await steps(store, *args, **kw)
    with ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(anyio.run, go).result()


class LearningWorld(World):
    """`World(tenants=...)` whose app reads learning work through `StoreLearningWork(LearningStore(dsn))`. The adapter's
    store lives on the world's loop and is closed there (`close`)."""

    def __init__(self, dsn: str, **kw: Any) -> None:
        self.learning_dsn = dsn  # the world's own `dsn` is None without `database=True` (#1496): this one is the seeded database
        self.learning_store: Any = None
        super().__init__(**kw)

    def build(self, *, administrators: Any, tenants: Any) -> None:
        from defender.api.learning_work import StoreLearningWork
        from defender.learning_store import LearningStore

        super().build(administrators=administrators, tenants=tenants)
        if self.learning_store is None:
            self.learning_store = LearningStore(self.learning_dsn)
        self.app = create_app(dataclasses.replace(self.app.state.deps,
                                                  learning_work=StoreLearningWork(self.learning_store)))

    def close(self) -> None:
        if self.learning_store is not None and self._finalizer.alive:  # close is idempotent (#1496)
            self.call(self.learning_store.close)
            self.learning_store = None
        super().close()


# --- seeders: the store's own verbs --------------------------------------------------------------------------------

async def held_together(store: Any, tenant: str, items: Sequence[tuple[str, str]], *, pr: int = 7,
                        reason: str = SILENT_CLOSE) -> Any:
    """Publish `items` (kind, key), claim them as one author batch, open PR `pr`, and close it with every item held in
    ONE transaction (`end_review`): the items share one `updated_at`. The batch id."""
    for kind in dict.fromkeys(k for k, _ in items):
        await publish(store, tenant, *(key for k, key in items if k == kind), kind=kind)
    held = await claim(store, tenant)
    assert sorted((k, key) for k, key, _p in held.items) == sorted(items), "premise: the claim took exactly these"
    await store.in_review(held, pr, {})
    assert await store.end_review(tenant, held.batch_id, expect_phase="in_review", outcome="closed",
                                  published=[], held=list(items), reason=reason)
    return held.batch_id


async def dead_alone(store: Any, tenant: str, key: str, reason: str = "offered too often") -> Any:
    """One finding that a batch with no commits retired as dead: no PR. The batch id."""
    await publish(store, tenant, key, run="run-dead")
    held = await claim(store, tenant)
    await store.end_no_commits(held, {("finding", key): store_mod().Outcome.dead(reason)})
    return held.batch_id


async def curator_held(store: Any, tenant: str, key: str, reason: str) -> Any:
    """One finding the curator held with `reason` (a model-written text), in a batch with no commits: no PR."""
    await publish(store, tenant, key, run="run-c")
    held = await claim(store, tenant)
    await store.end_no_commits(held, {("finding", key): store_mod().Outcome.held(reason)})
    return held.batch_id


async def settled_mix(store: Any, tenant: str) -> None:
    """One batch in review (PR 5) settles `p1` published, `s1` skipped, `dd` dead and `hh` held, and ends merged; then `b1`
    sits in a working batch and `w1` waits."""
    S = store_mod()
    await publish(store, tenant, "p1", "s1", "dd", "hh")
    batch = await claim(store, tenant)
    await store.in_review(batch, 5, {("finding", "p1"): S.Outcome.published(),
                                     ("finding", "s1"): S.Outcome.skipped("not a lesson"),
                                     ("finding", "dd"): S.Outcome.dead("retired for good"),
                                     ("finding", "hh"): S.Outcome.held("needs a person's eye")})
    assert await store.end_review(tenant, batch.batch_id, expect_phase="in_review", outcome="merged",
                                  published=[], held=[])
    await publish(store, tenant, "b1")
    assert await claim(store, tenant) is not None
    await publish(store, tenant, "w1")


async def parked_author(store: Any, tenant: str, items: Sequence[tuple[str, str]], *, pr: int = 9) -> Any:
    """An author batch over `items` (kind, key) in review as PR `pr`, parked by three forge refusals. Its id."""
    for kind in dict.fromkeys(k for k, _ in items):
        await publish(store, tenant, *(key for k, key in items if k == kind), kind=kind)
    author = await claim(store, tenant)
    assert sorted((k, key) for k, key, _p in author.items) == sorted(items), "premise: the claim took exactly these"
    await store.in_review(author, pr, {})
    for _ in range(3):
        await store.note_refusal(tenant, author.batch_id, "403 Forbidden: <b>bad credentials</b>")
    return author.batch_id


async def in_review_author(store: Any, tenant: str, key: str, *, pr: int = 11) -> Any:
    """An author batch over one finding in review as PR `pr`, not parked. Its id."""
    await publish(store, tenant, key)
    batch = await claim(store, tenant)
    await store.in_review(batch, pr, {})
    return batch.batch_id


async def parked_revert(store: Any, tenant: str, reason: str = "a foreign tip on its branch") -> Any:
    """A revert batch parked by `needs_person`. Its id."""
    revert = await store.claim_revert(tenant, owner="host-a")
    await store.needs_person(tenant, revert.batch_id, reason)
    return revert.batch_id


async def parked_registry(store: Any, tenant: str, reason: str = "a PR the loop did not make is open on the lane") -> Any:
    """A registry batch holding no items, parked by `needs_person`. Its id."""
    tick = await store.begin_feedback_tick(tenant, owner="host-a")
    assert tick is not None, "premise: the feedback tick began"
    registry = await store.claim_registry(tick)
    await store.needs_person(tenant, registry.batch_id, reason)
    return registry.batch_id


def tie_batches(dsn: str, ids: Iterable[Any], at: _dt.datetime = INSTANT) -> None:
    """Stamp `created_at = at` on batches `ids`: the store has no clock seam, and batches made one after another never tie."""
    for batch in ids:
        execute(dsn, "UPDATE learning.batches SET created_at = %s WHERE id = %s", (at, str(batch)))


# --- read-back oracles ---------------------------------------------------------------------------------------------

def stored_items(dsn: str, tenant: str, *statuses: str) -> list[Any]:
    """The tenant's items in `statuses` (none given: every status) as `work()` holds them (`id` included), in no promised order."""
    return list(call(dsn, "work", tenant, statuses=list(statuses) or None))


def stored_batches(dsn: str, tenant: str, *phases: str) -> list[Any]:
    """The tenant's batches in `phases` as `batches()` holds them, in no promised order."""
    return [b for b in call(dsn, "batches", tenant) if b.phase in phases]


def newest_first(rows: Iterable[Any], at: Callable[[Any], _dt.datetime], ident: Callable[[Any], Any]) -> list[Any]:
    """`rows` by (time, id) descending, sorted here: an id is a lowercase UUID, so its text order is the database's."""
    return sorted(rows, key=lambda r: (at(r), str(ident(r))), reverse=True)


def wire_item(item: Any) -> dict[str, Any]:
    """A stored `WorkItem` as the wire should carry it, `updated_at` aside (compared as an instant). #1537 O4: `cause` too."""
    return {"item_id": str(item.id), "kind": item.kind, "key": item.key, "status": item.status, "reason": item.reason,
            "cause": item.cause, "source_run": item.source_run, "batch_id": None if item.batch_id is None else str(item.batch_id),
            "pr_number": item.pr_number}


def instant(text: str) -> _dt.datetime:
    return _dt.datetime.fromisoformat(text.replace("Z", "+00:00"))


def walk(browser: Any, path: str, *, limit: int, **params: Any) -> tuple[list[dict[str, Any]], list[int], list[str]]:
    """Every page of `path` by its cursors: (items, page sizes, cursors issued). Each page is a 200 no longer than `limit`."""
    items: list[dict[str, Any]] = []
    sizes: list[int] = []
    cursors: list[str] = []
    cursor = None
    for _ in range(200):
        r = browser.get(path, params={"limit": limit, **params, **({"cursor": cursor} if cursor else {})})
        assert r.status_code == 200, r.text
        body = r.json()
        assert len(body["items"]) <= limit
        items.extend(body["items"])
        sizes.append(len(body["items"]))
        cursor = body["next_cursor"]
        if cursor is None:
            return items, sizes, cursors
        cursors.append(cursor)
    raise AssertionError("the list never ran out")


__all__ = ["HOSTILE_REASON", "INSTANT", "LONG_KEY", "QUESTIONER", "SILENT_CLOSE", "LearningWorld", "curator_held",
           "dead_alone", "held_together", "in_review_author", "instant", "newest_first", "on_store", "parked_author",
           "parked_registry", "parked_revert", "settled_mix", "stored_batches", "stored_items", "tie_batches", "walk",
           "wire_item"]
