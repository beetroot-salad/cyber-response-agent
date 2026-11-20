"""The learning store (#1278): learning's work tracking on PostgreSQL, from queued item to reviewed PR.

Published content stays in Git and review state on the forge; this records what is unpublished and which batch holds
it. `LearningStore` is the async store, `blocking(dsn)` its synchronous face.

The door is lazy: the item-key rules (`pitfall_key`, `is_reducer_row`) load without the database stack."""
from __future__ import annotations

from typing import TYPE_CHECKING

from defender.lazy_door import lazy_door

if TYPE_CHECKING:
    from defender.learning_store._blocking import (
        BlockingStore as BlockingStore,
        blocking as blocking,
    )
    from defender.learning_store._feedback import (
        FeedbackComment as FeedbackComment,
        FeedbackHeld as FeedbackHeld,
        FeedbackIssue as FeedbackIssue,
    )
    from defender.learning_store._store import (
        DEFAULT_GRACE_SECONDS as DEFAULT_GRACE_SECONDS,
        DEFAULT_LEASE_SECONDS as DEFAULT_LEASE_SECONDS,
        DEFAULT_RENEW_SECONDS as DEFAULT_RENEW_SECONDS,
        BatchView as BatchView,
        CommitRecord as CommitRecord,
        AbandonAsked as AbandonAsked,
        Acted as Acted,
        BatchCause as BatchCause,
        Held as Held,
        ItemCause as ItemCause,
        ItemRefused as ItemRefused,
        LaneBusy as LaneBusy,
        LaneWork as LaneWork,
        LearningStore as LearningStore,
        LeaseLost as LeaseLost,
        NotLapsed as NotLapsed,
        Outcome as Outcome,
        ParkedBatchView as ParkedBatchView,
        Stop as Stop,
        TenantInactive as TenantInactive,
        Why as Why,
        WorkItem as WorkItem,
    )
    from defender.learning_store._keys import (
        is_reducer_row as is_reducer_row,
        pitfall_key as pitfall_key,
    )

#: Each name this door serves, and the submodule that defines it.
_HOMES: dict[str, str] = {
    **dict.fromkeys(("BlockingStore", "blocking",), "_blocking"),
    **dict.fromkeys(("FeedbackComment", "FeedbackHeld", "FeedbackIssue",), "_feedback"),
    **dict.fromkeys(("DEFAULT_GRACE_SECONDS", "DEFAULT_LEASE_SECONDS", "DEFAULT_RENEW_SECONDS", "AbandonAsked", "Acted", "BatchCause", "BatchView", "CommitRecord", "Held", "ItemCause", "ItemRefused", "LaneBusy", "LaneWork", "LearningStore", "LeaseLost", "NotLapsed", "Outcome", "ParkedBatchView", "Stop", "TenantInactive", "Why", "WorkItem",), "_store"),
    **dict.fromkeys(("is_reducer_row", "pitfall_key",), "_keys"),
}


__getattr__ = lazy_door(globals(), _HOMES)
