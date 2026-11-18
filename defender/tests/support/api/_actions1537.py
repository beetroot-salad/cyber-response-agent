"""#1537 API half: seeders and read-back oracles for the three learning actions (release item, release batch, abandon
request) — NO test functions, NO policy.

Rows are made by the store's own verbs where their call shape is settled at the base (`publish`, `claim`, `in_review`,
`end_review`, `enqueue_request`, `claim_revert`, `begin_feedback_tick`/`claim_registry`). What r3 changes the shape of
(`note_refusal` and `needs_person` gain a cause) is set by one SQL `UPDATE` over the columns the design names (`phase`,
`cause`, `reason`, `parked_at`, `abandon_requested_at`, `last_checked`, `refusals`), as `tie_batches` stamps a time: so
a red lands on the route or the field, not on a guessed store signature. Every stored value a test compares with the wire
is read back here by SQL, never spelled twice.
"""
from __future__ import annotations

import datetime as _dt
from typing import Any

from defender.tests.support.api._learning1485 import on_store
from defender.tests.support.learning.core._store1278 import claim, learning_store, publish
from defender.tests.support.shared._postgres1339 import execute

REFUSAL = "403 Forbidden: <b>bad credentials</b>"
CREDENTIAL = "forge_credential_refused"
#: Design r3's closed list of batch causes a batch can be parked with, other than the releasable one.
OTHER_PARK_CAUSES = ("forge_refused", "delivery_unavailable", "foreign_commits_remote", "foreign_commits_local",
                     "foreign_pr", "holder_lost", "holder_crashed", "stopped", "no_commits", "unrecorded")
OLD = _dt.datetime(2026, 1, 5, 9, tzinfo=_dt.UTC)


async def _held_at_ceiling(dsn: str, tenant: str, key: str) -> None:
    """One finding held by the store itself: claimed once under a one-attempt ceiling, its batch merged without it."""
    async with learning_store(dsn, max_attempts=1) as store:
        await publish(store, tenant, key)
        batch = await claim(store, tenant)
        await store.in_review(batch, 4, {})
        assert await store.end_review(tenant, batch.batch_id, expect_phase="in_review", outcome="merged",
                                      published=[], held=[])


def held_item(dsn: str, tenant: str, key: str) -> str:
    """The id of a finding the store held at its attempt ceiling."""
    import anyio

    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=1) as pool:
        pool.submit(anyio.run, _held_at_ceiling, dsn, tenant, key).result()
    return item_id(dsn, tenant, key)


async def in_review(store: Any, tenant: str, *keys: str, pr: int = 9) -> str:
    """An author batch over `keys` in review as PR `pr`. Its id."""
    await publish(store, tenant, *keys)
    batch = await claim(store, tenant)
    await store.in_review(batch, pr, {})
    return str(batch.batch_id)


async def working(store: Any, tenant: str, *keys: str) -> str:
    """An author batch over `keys`, working (no PR). Its id."""
    await publish(store, tenant, *keys)
    return str((await claim(store, tenant)).batch_id)


async def working_revert(store: Any, tenant: str) -> str:
    return str((await store.claim_revert(tenant, owner="host-a")).batch_id)


async def working_registry(store: Any, tenant: str) -> str:
    tick = await store.begin_feedback_tick(tenant, owner="host-a")
    assert tick is not None, "premise: the feedback tick began"
    return str((await store.claim_registry(tick)).batch_id)


async def merged(store: Any, tenant: str, key: str) -> str:
    batch_id = await in_review(store, tenant, key, pr=3)
    assert await store.end_review(tenant, batch_id, expect_phase="in_review", outcome="merged",
                                  published=[("finding", key)], held=[])
    return batch_id


def park(dsn: str, batch_id: str, *, cause: str = CREDENTIAL, reason: str | None = REFUSAL) -> None:
    """Park a working or in-review batch as r3's store would (parked_at set, lease gone, token moved, refusals at the
    ceiling): one UPDATE over the design's columns."""
    rows = execute(dsn, "UPDATE learning.batches SET phase = 'needs_person', cause = %s, reason = %s, parked_at = now(), "
                        "lease_owner = NULL, lease_expiry = NULL, fencing_token = fencing_token + 1, refusals = 3 "
                        "WHERE id = %s AND phase IN ('working', 'in_review') RETURNING id", (cause, reason, batch_id))
    assert len(rows) == 1, "premise: the batch was working or in review"


def set_batch(dsn: str, batch_id: str, **columns: Any) -> None:
    """Set `columns` of one batch (test fixture state over the design's columns)."""
    sets = ", ".join(f"{c} = %s" for c in columns)
    rows = execute(dsn, f"UPDATE learning.batches SET {sets} WHERE id = %s RETURNING id", (*columns.values(), batch_id))
    assert len(rows) == 1, "premise: the batch exists"


def set_item(dsn: str, tenant: str, key: str, **columns: Any) -> None:
    sets = ", ".join(f"{c} = %s" for c in columns)
    rows = execute(dsn, f"UPDATE learning.work_items SET {sets} WHERE tenant_id = %s AND item_key = %s RETURNING id",
                   (*columns.values(), tenant, key))
    assert len(rows) == 1, "premise: the item exists"


def item_id(dsn: str, tenant: str, key: str) -> str:
    [(found,)] = execute(dsn, "SELECT id FROM learning.work_items WHERE tenant_id = %s AND item_key = %s", (tenant, key))
    return str(found)


def item_row(dsn: str, item: str) -> dict[str, Any]:
    cols = ("status", "attempts", "deferrals", "cause", "reason", "batch_id")
    [row] = execute(dsn, f"SELECT {', '.join(cols)} FROM learning.work_items WHERE id = %s", (item,))
    return dict(zip(cols, row, strict=True))


def batch_row(dsn: str, batch: str) -> dict[str, Any]:
    cols = ("phase", "outcome", "cause", "reason", "pr_number", "parked_at", "abandon_requested_at",
            "abandon_requested_by", "last_checked", "refusals")
    [row] = execute(dsn, f"SELECT {', '.join(cols)} FROM learning.batches WHERE id = %s", (batch,))
    return dict(zip(cols, row, strict=True))


def items_in(dsn: str, batch: str) -> list[str]:
    return sorted(k for (k,) in execute(
        dsn, "SELECT item_key FROM learning.work_items WHERE batch_id = %s AND status = 'in_batch'", (batch,)))


def names(detail: str, word: str) -> bool:
    """Whether a 409's words name `word` (a status, phase or cause), `_` and a space alike."""
    return word.replace("_", " ") in detail.lower().replace("_", " ")


__all__ = ["CREDENTIAL", "OLD", "OTHER_PARK_CAUSES", "REFUSAL", "held_item", "in_review", "item_id", "item_row",
           "items_in", "merged", "names", "on_store", "park", "set_batch", "set_item", "batch_row", "working",
           "working_registry", "working_revert"]
