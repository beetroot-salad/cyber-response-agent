"""#1537: the store's person verbs as tests call them, and rows put in the states the design names.

Nothing here decides policy. The wrappers are the one place the verb names and argument shapes the design leaves open are
fixed (`release_item`, `release_batch`, `request_abandon`, each taking the tenant first; the actor by keyword where the row
records it). `park` and `set_held` write only the columns and values the design names (`cause`, `reason`, `parked_at`,
`refusals`), over a batch or item a store verb made, so a case reaches a state without a guessed seeder signature.
`row` and `item_row` read the stored columns, so an assertion sees the database rather than a view's shape.
"""
from __future__ import annotations

import importlib
from typing import Any

from defender.tests.support.shared._postgres1339 import execute

CREDENTIAL = "forge_credential_refused"
#: A reason as a park by three refusals writes it today (probed: `note_refusal` -> "the forge refused N times: <text>").
PARK_REASON = "the forge refused 3 times: 403 Forbidden: bad credentials"

BATCH_COLUMNS = ("phase", "outcome", "cause", "reason", "parked_at", "abandon_requested_at", "abandon_requested_by",
                 "last_checked", "refusals", "pr_number", "lease_owner", "lease_expiry", "fencing_token")
ITEM_COLUMNS = ("status", "cause", "reason", "attempts", "deferrals", "offers_declined", "batch_id")


def _store_mod() -> Any:
    return importlib.import_module("defender.learning_store")


def why(cause: str, detail: str) -> Any:
    """The design's one value for why (`Why(cause, detail)`), exported by `defender.learning_store` beside `Outcome` (r3.1)."""
    return _store_mod().Why(cause, detail)


def outcome_held(cause: str, detail: str) -> Any:
    return _store_mod().Outcome.held(cause, detail)


def outcome_dead(cause: str, detail: str) -> Any:
    return _store_mod().Outcome.dead(cause, detail)


def outcome_skipped(cause: str, detail: str) -> Any:
    return _store_mod().Outcome.skipped(cause, detail)


async def needs_person(store: Any, tenant: str, batch_id: Any, cause: str = "foreign_pr", detail: str = "by hand") -> None:
    """`needs_person(tenant, batch_id, why)` (r3.1). The cause defaults to one a person's hand-park is not special to."""
    await store.needs_person(tenant, batch_id, why(cause, detail))


async def note_refusal(store: Any, tenant: str, batch_id: Any, cause: str = "forge_refused", detail: str = "the forge said no") -> Any:
    """`note_refusal(tenant, batch_id, why)` (r3.1): the cause the ceiling parks with, and the text beside it."""
    return await store.note_refusal(tenant, batch_id, why(cause, detail))


async def release_item(store: Any, tenant: str, item_id: Any) -> Any:
    return await store.release_item(tenant, str(item_id))


async def release_item_of(store: Any, tenant: str, kind: str, key: str) -> Any:
    """Release the item `(kind, key)` by its id (the by-key verb `release_held` is gone)."""
    [item] = [i for i in await store.work(tenant) if (i.kind, i.key) == (kind, key)]
    return await release_item(store, tenant, item.id)


async def release_batch(store: Any, tenant: str, batch_id: Any, *, actor: str = "u-1537") -> Any:
    return await store.release_batch(tenant, str(batch_id), actor=actor)


async def request_abandon(store: Any, tenant: str, batch_id: Any, *, actor: str = "u-1537") -> Any:
    return await store.request_abandon(tenant, str(batch_id), actor=actor)


async def settle_abandon(store: Any, tenant: str, batch_id: Any, *, pr_number: int | None, pr_state: str | None,
                         published: Any = (), held: Any = ()) -> Any:
    """`settle_abandon(tenant, batch_id, *, pr_number, pr_state, published=(), held=())` (r3.1); `pr_state` is the forge's
    `open`, `merged` or `closed` (`pr.status`), None when no PR was found."""
    return await store.settle_abandon(tenant, str(batch_id), pr_number=pr_number, pr_state=pr_state,
                                      published=published, held=held)


def row(dsn: str, batch_id: Any) -> dict[str, Any]:
    [values] = execute(dsn, f"SELECT {', '.join(BATCH_COLUMNS)} FROM learning.batches WHERE id = %s", (str(batch_id),))  # noqa: S608
    return dict(zip(BATCH_COLUMNS, values, strict=True))


def item_row(dsn: str, tenant: str, key: str) -> dict[str, Any]:
    [values] = execute(dsn, f"SELECT {', '.join(ITEM_COLUMNS)} FROM learning.work_items WHERE tenant_id = %s AND item_key = %s",  # noqa: S608
                       (tenant, key))
    return dict(zip(ITEM_COLUMNS, values, strict=True))


def park(dsn: str, batch_id: Any, *, cause: str = CREDENTIAL, reason: str = PARK_REASON, refusals: int = 3) -> None:
    """The batch goes to a person with `cause`: the columns a park writes (design: `cause`, `reason`, `parked_at`; the
    holder's lease gone, its token moved). Its `pr_number` is left as it is, which says where it was parked from."""
    execute(dsn, "UPDATE learning.batches SET phase = 'needs_person', cause = %s, reason = %s, parked_at = now(), "
                 "lease_owner = NULL, lease_expiry = NULL, fencing_token = fencing_token + 1, refusals = %s, "
                 "last_checked = now() WHERE id = %s", (cause, reason, refusals, str(batch_id)))


def request(dsn: str, batch_id: Any, *, by: str = "u-1537") -> None:
    """A parked batch carries an abandon request: the two columns the request writes."""
    execute(dsn, "UPDATE learning.batches SET abandon_requested_at = now(), abandon_requested_by = %s WHERE id = %s",
            (by, str(batch_id)))


def set_held(dsn: str, tenant: str, key: str, *, cause: str = "curator_held", reason: str = "held by the curator") -> None:
    execute(dsn, "UPDATE learning.work_items SET status = 'held', cause = %s, reason = %s WHERE tenant_id = %s AND item_key = %s",
            (cause, reason, tenant, key))
