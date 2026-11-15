"""The real adapter for the learning loop's set-aside work (#1485): a `LearningStore`'s records mapped to wire models.

It is handed an open store; opening it from the API's database settings and closing it at shutdown belong to the
real server's composition root (#1083 piece 1)."""

from __future__ import annotations

from typing import TYPE_CHECKING, Literal, cast

from defender.records.formats import TenantId

from .models import ItemKind, ParkedBatch, ParkedItemRef, SetAsideItem
from .ports import TimePosition

if TYPE_CHECKING:
    from defender.learning_store import LearningStore


class StoreLearningWork:
    def __init__(self, store: LearningStore) -> None:
        self._store = store

    async def list_set_aside(self, tenant_id: TenantId, *, status: Literal["held", "dead"] | None,
                             after: TimePosition | None, limit: int) -> list[SetAsideItem]:
        rows = await self._store.set_aside(
            tenant_id, status=status, after=after, limit=limit)
        return [SetAsideItem(item_id=r.id, kind=cast("ItemKind", r.kind), key=r.key, status=cast("Literal['held', 'dead']", r.status), reason=r.reason,
                             source_run=r.source_run, batch_id=r.batch_id, pr_number=r.pr_number,
                             updated_at=r.updated_at) for r in rows]

    async def list_parked_batches(self, tenant_id: TenantId, *, after: TimePosition | None,
                                  limit: int) -> list[ParkedBatch]:
        rows = await self._store.parked(tenant_id, after=after, limit=limit)
        return [ParkedBatch(batch_id=b.id, batch_kind=cast("Literal['author', 'revert', 'registry']", b.kind),
                            lane=b.lane, blocks_lane=b.blocks_lane, branch=b.branch, pr_number=b.pr_number,
                            reason=b.reason, created_at=b.created_at,
                            items=[ParkedItemRef(kind=cast("ItemKind", k), key=key) for k, key in b.items]) for b in rows]
