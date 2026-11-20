"""Waking a tenant's family-less check clock (#1344 amendment 3): the one write every waker makes, in its own
transaction, so the wake commits or rolls back with what caused it."""
from __future__ import annotations

from typing import Any

from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql import func

from .models import LearningCheckRow


async def arm_learning_check(s: AsyncSession, tenant_id: str, *, mark_held: bool = False) -> None:
    """Make the tenant's check clock not idle, in the transaction `s` is in, creating it from now when there is none.
    Its time is left as it is. The wakers: a job queued, or one ended `completed`, or lapsed; and a person's request to
    abandon a parked batch (#1487 Amendment r5.3). `mark_held` (a `completed` end, an abandon request) also marks a
    clock a post-step holds, live or lapsed (#1487 O7), never clearing a mark already set: that post-step's answer may
    predate the wake, so the hold's end makes the tenant due at once. The queue-time arms leave the mark as it is."""
    insert = pg_insert(LearningCheckRow).values(tenant_id=tenant_id, checked_at=func.now(), idle=False,
                                                armed_while_held=False)
    armed: dict[str, Any] = {"idle": False}
    if mark_held:
        armed["armed_while_held"] = LearningCheckRow.armed_while_held | LearningCheckRow.holder.is_not(None)
    await s.execute(insert.on_conflict_do_update(index_elements=[LearningCheckRow.tenant_id], set_=armed))


__all__ = ["arm_learning_check"]
