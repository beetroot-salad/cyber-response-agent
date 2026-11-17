"""The real adapter for the learning loop's set-aside work (#1485): a `LearningStore`'s records mapped to wire models.

It is handed an open store; opening it from the API's database settings and closing it at shutdown belong to the
real server's composition root (#1083 piece 1)."""

from __future__ import annotations

from typing import TYPE_CHECKING, Literal, cast

from defender.jobs.audit import AuditAction, announce
from defender.records.formats import BatchId, TenantId, WorkItemId

from .models import AbandonRequested, BatchReleased, ItemKind, ItemReleased, ParkedBatch, ParkedItemRef, SetAsideItem
from defender._text import one_line

from .ports import NotFound, Principal, TimePosition

if TYPE_CHECKING:
    from defender.learning_store import Acted, LearningStore

#: How much of the prior detail an audit event carries: model- and forge-written text is never logged whole.
_AUDIT_LINE = 200


def _audit_line(done: Acted) -> str:
    """The cause and detail the row had when acted on, as one bounded line."""
    return one_line(f"{done.cause}: {done.detail or ''}")[:_AUDIT_LINE]


def _announce_learning(principal: Principal, action: AuditAction, done: Acted) -> None:
    announce(action, actor=principal.actor_id, tenant_id=principal.tenant_id, target=done.id, detail=_audit_line(done),
             credential_id=principal.credential_id)


class StoreLearningWork:
    def __init__(self, store: LearningStore) -> None:
        self._store = store

    async def list_set_aside(self, tenant_id: TenantId, *, status: Literal["held", "dead"] | None,
                             after: TimePosition | None, limit: int) -> list[SetAsideItem]:
        rows = await self._store.set_aside(
            tenant_id, status=status, after=after, limit=limit)
        return [SetAsideItem(item_id=r.id, kind=cast("ItemKind", r.kind), key=r.key, status=cast("Literal['held', 'dead']", r.status), reason=r.reason, cause=r.cause,
                             source_run=r.source_run, batch_id=r.batch_id, pr_number=r.pr_number,
                             updated_at=r.updated_at) for r in rows]

    async def list_parked_batches(self, tenant_id: TenantId, *, after: TimePosition | None,
                                  limit: int) -> list[ParkedBatch]:
        rows = await self._store.parked(tenant_id, after=after, limit=limit)
        return [ParkedBatch(batch_id=b.id, batch_kind=cast("Literal['author', 'revert', 'registry']", b.kind),
                            lane=b.lane, blocks_lane=b.blocks_lane, branch=b.branch, pr_number=b.pr_number,
                            reason=b.reason, cause=b.cause, parked_at=b.parked_at, releasable=b.releasable,
                            abandon_requested_at=b.abandon_requested_at, last_checked=b.last_checked, created_at=b.created_at,
                            items=[ParkedItemRef(kind=cast("ItemKind", k), key=key) for k, key in b.items]) for b in rows]

    # --- a person's actions (#1537): the store decides, the API announces after the store commits -------------------

    async def release_item(self, principal: Principal, item_id: WorkItemId) -> ItemReleased:
        done = await self._store.release_item(principal.tenant_id, str(item_id))
        _announce_learning(principal, "learning.release_item", done)
        return ItemReleased(id=item_id, status=cast("Literal['waiting', 'skipped']", done.state))

    async def release_batch(self, principal: Principal, batch_id: BatchId) -> BatchReleased:
        done = await self._store.release_batch(principal.tenant_id, str(batch_id), actor=principal.actor_id)
        _announce_learning(principal, "learning.release_batch", done)
        return BatchReleased(id=batch_id, phase=cast("Literal['in_review', 'working']", done.state))

    async def request_abandon(self, principal: Principal, batch_id: BatchId) -> AbandonRequested:
        done = await self._store.request_abandon(principal.tenant_id, str(batch_id), actor=principal.actor_id)
        if done.at is None:
            raise NotFound(f"no batch {batch_id}")  # unreachable: the store always stamps the request
        _announce_learning(principal, "learning.request_abandon", done)
        return AbandonRequested(id=batch_id, abandon_requested_at=done.at)
