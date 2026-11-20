"""The author tick's store (#1487 Flow 2, P2) and the post-step's "work still waiting" predicate (Flow 3).

`TickStore` is what the tick calls: the learning store's verbs with no tenant, lane, owner, threshold, `by` or settings
argument, since a step of the tick never chooses who or what it acts for (P1). It has two implementations:

- `StoreAdapter`, over the in-process store (`learning_store.blocking`), bound by its caller (a host CLI, a test) to a
  tenant, a lane, an owner and thresholds;
- the port (`learning_store.tick_port.TickPort`, reached in a job container as `JobContainer.tick_store()`), whose every
  call is a request to the per-job helper, which answers it through an adapter it bound itself.

The port has no semantics of its own: each call returns what the adapter returns and raises what it raises. The one
outage exception is `StoreUnavailable` (an `Exception`, never an `OSError`, which the tick reads as a forge fault);
`ForeignBatch` is the port's refusal of a batch reference its helper did not issue, which only hostile input reaches.
A listed batch is a `ListedBatch`: the store's view without its fencing token and lease owner, which the tick never reads;
a listed item is a `ListedItem`: the store's item without its payload, which only a claim or take-over carries.

`work_waiting` is Flow 3's predicate over a `TickStore`, which the helper asks with the adapter it bound once a post-step's
container exits (Amendment r5.2): the tenant, lane and thresholds are the adapter's.

Importing this module loads no `defender.learning` module and no database driver (`tests/api/test_api_loads.py`)."""
from __future__ import annotations

import dataclasses
import datetime as _dt
from collections.abc import Callable, Collection, Mapping, Sequence
from typing import Any, Protocol, TypeVar

from defender.records.formats import BatchId, TenantId, WorkItemId
from defender.records.learning_causes import BatchCause, ItemCause, Why

from ._store import BatchView, CommitRecord, Held, LaneWork, Outcome, WorkItem, parked_blocks_lane

__all__ = ["ForeignBatch", "ListedBatch", "ListedItem", "StoreAdapter", "StoreUnavailable", "TickStore", "work_waiting"]

_T = TypeVar("_T")
#: The curators' outcomes by `(kind, key)`, as the store applies them.
Outcomes = Mapping[tuple[str, str], Outcome]
#: One commit's changes: `(path, blob at base, blob left)`.
Changes = Sequence[tuple[str, str | None, str | None]]


class StoreUnavailable(Exception):  # noqa: N818 — named for what the tick meets
    """The learning store could not answer now: the database is unreachable (the adapter), or the helper, its store or
    the job socket did not answer (the port). Never an `OSError`: the tick reads those as forge faults. The tick's own
    handling applies: a renewal is retried, the main thread's crash path runs, and a lease it cannot reach lapses."""


class ForeignBatch(Exception):  # noqa: N818 — named for what the helper refuses
    """A batch reference the helper did not issue this session, or one of a kind the verb may not act on (another
    lane's batch for a lease verb, a batch listed but not leased for a holder's verb). Only the port raises it, and only
    hostile input reaches it: the tick acts on the ids its own listings and leases gave it."""


@dataclasses.dataclass(frozen=True)
class ListedBatch:
    """A batch as the tick lists it: the store's `BatchView` without its fencing token and lease owner."""

    id: BatchId
    tenant_id: TenantId
    kind: str
    lane: str
    branch: str
    base: str | None
    start: str | None
    phase: str
    outcome: str | None
    lease_expiry: _dt.datetime | None
    cancel_requested: bool
    pr_number: int | None
    replaces: BatchId | None
    generation: int
    refusals: int
    last_checked: _dt.datetime | None
    reason: str | None
    created_at: _dt.datetime
    ended_at: _dt.datetime | None
    lapsed: bool = False
    cause: BatchCause | None = None
    parked_at: _dt.datetime | None = None
    abandon_requested_at: _dt.datetime | None = None
    abandon_requested_by: str | None = None

    @classmethod
    def of(cls, view: BatchView) -> ListedBatch:
        return cls(**{f.name: getattr(view, f.name) for f in dataclasses.fields(cls)})

    @property
    def abandon_pending(self) -> bool:
        """Parked, with a person's abandon request the loop has yet to carry out (`BatchView.abandon_pending`)."""
        return self.phase == "needs_person" and self.abandon_requested_at is not None

    @property
    def blocks_lane(self) -> bool:
        """Parked, it still holds its lane (`BatchView.blocks_lane`)."""
        return parked_blocks_lane(self.kind)


@dataclasses.dataclass(frozen=True)
class ListedItem:
    """An item as the tick lists it: the store's `WorkItem` without its payload. The tick reads an item's kind, key,
    status and batch from the listing; the payloads it authors from come with its claim (`Held.items`), so a listing of
    every open item never carries every finding's text (#1487 review: the job socket's message bound)."""

    id: WorkItemId
    kind: str
    key: str
    status: str
    reason: str | None
    fault: str | None
    batch_id: BatchId | None
    pr_number: int | None
    attempts: int
    deferrals: int
    offers_declined: int
    coalesce_key: str | None
    mistake_key: str | None
    source_run: str | None
    enqueued_at: _dt.datetime
    updated_at: _dt.datetime
    cause: ItemCause | None = None

    @classmethod
    def of(cls, item: WorkItem) -> ListedItem:
        return cls(**{f.name: getattr(item, f.name) for f in dataclasses.fields(cls)})


class TickStore(Protocol):
    """The tick's store: the census of the verbs it calls, each bound to one tenant, lane, owner and set of thresholds by
    whoever built it. A holder's verb takes the `Held` its claim or take-over returned (only its batch id and token are
    its proof); a reconcile verb takes a batch id from the tick's own listing."""

    @property
    def renew_every(self) -> float: ...

    @property
    def generation_ceiling(self) -> int: ...

    def batches(self) -> list[ListedBatch]: ...

    def lane_work(self) -> LaneWork: ...

    def work(self, *, statuses: Sequence[str] | None = None, kind: str | None = None) -> list[ListedItem]: ...

    def commit_record(self) -> list[CommitRecord]: ...

    def claim(self) -> Held | None: ...

    def take_over(self, batch_id: str) -> Held: ...

    def renew(self, held: Held) -> None: ...

    def record_commit(self, held: Held, commit: str, base: str, start: str, changes: Changes) -> None: ...

    def in_review(self, held: Held, pr_number: int, outcomes: Outcomes) -> None: ...

    def end_no_commits(self, held: Held, outcomes: Outcomes) -> None: ...

    def abandon_clean(self, held: Held) -> None: ...

    def abandon_crashed(self, held: Held) -> None: ...

    def expire_own(self, held: Held) -> None: ...

    def abandon(self, batch_id: str) -> None: ...

    def note_check(self, batch_id: str, *, reset_refusals: bool = True) -> None: ...

    def note_refusal(self, batch_id: str, why: Why[BatchCause]) -> tuple[int, str]: ...

    def needs_person(self, batch_id: str, why: Why[BatchCause]) -> None: ...

    def end_review(self, batch_id: str, *, expect_phase: str, outcome: str, published: Sequence[tuple[str, str]],
                   held: Sequence[tuple[str, str]], detail: str | None = None,
                   items_why: Why[ItemCause] | None = None) -> bool: ...

    def settle_abandon(self, batch_id: str, *, pr_number: int | None, pr_state: str | None,
                       published: Sequence[tuple[str, str]] = (), held: Sequence[tuple[str, str]] = ()) -> bool: ...


def _is_outage(fault: BaseException) -> bool:
    """The jobs store's one reading of a database outage (`jobs.store.is_outage`): loaded when a verb fails, so this
    module's import stays free of the store's session stack."""
    from defender.jobs.store import is_outage

    return is_outage(fault)


class StoreAdapter:
    """`TickStore` over the in-process blocking store (`learning_store.blocking`), bound to `tenant`, `lane`, `owner`
    and `thresholds`. It adds nothing but the binding and the one outage exception: no batch reference is checked (the
    caller is trusted, as the host's own tick always was)."""

    def __init__(self, store: Any, *, tenant: str, lane: str, owner: str, thresholds: Mapping[str, int]) -> None:
        self._store = store
        self.tenant, self.lane, self.owner = str(tenant), lane, owner
        self.thresholds = dict(thresholds)

    def _call(self, verb: Callable[..., _T], *args: Any, **kwargs: Any) -> _T:
        try:
            return verb(*args, **kwargs)
        except Exception as fault:
            if isinstance(fault, StoreUnavailable) or not _is_outage(fault):
                raise
            raise StoreUnavailable(f"the learning store cannot be reached now: {type(fault).__name__}") from fault

    @property
    def renew_every(self) -> float:
        return float(self._store.renew_every)

    @property
    def generation_ceiling(self) -> int:
        return int(self._store.generation_ceiling)

    @property
    def lease(self) -> float:
        """The lease a claim or take-over is given (the helper answers it at the port's start)."""
        return float(self._store.lease)

    def batches(self) -> list[ListedBatch]:
        return [ListedBatch.of(v) for v in self._call(self._store.batches, self.tenant)]

    def lane_work(self) -> LaneWork:
        return self._call(self._store.lane_work, self.tenant, self.lane, thresholds=self.thresholds)

    def work(self, *, statuses: Sequence[str] | None = None, kind: str | None = None) -> list[ListedItem]:
        return [ListedItem.of(i) for i in self._call(self._store.work, self.tenant, statuses=statuses, kind=kind)]

    def commit_record(self) -> list[CommitRecord]:
        return self._call(self._store.commit_record, self.tenant)

    def claim(self) -> Held | None:
        return self._call(self._store.claim, self.tenant, self.lane, owner=self.owner, thresholds=self.thresholds)

    def take_over(self, batch_id: str) -> Held:
        return self._call(self._store.take_over, self.tenant, batch_id, owner=self.owner)

    def renew(self, held: Held) -> None:
        self._call(self._store.renew, held)

    def record_commit(self, held: Held, commit: str, base: str, start: str, changes: Changes) -> None:
        self._call(self._store.record_commit, held, commit, base, start, changes)

    def in_review(self, held: Held, pr_number: int, outcomes: Outcomes) -> None:
        self._call(self._store.in_review, held, pr_number, outcomes)

    def end_no_commits(self, held: Held, outcomes: Outcomes) -> None:
        self._call(self._store.end_no_commits, held, outcomes)

    def abandon_clean(self, held: Held) -> None:
        self._call(self._store.abandon_clean, held)

    def abandon_crashed(self, held: Held) -> None:
        self._call(self._store.abandon_crashed, held)

    def expire_own(self, held: Held) -> None:
        self._call(self._store.expire_own, held)

    def abandon(self, batch_id: str) -> None:
        """The recovery's abandon of a lapsed batch (`by="recovery"`, bound: a person's is `request_abandon`)."""
        self._call(self._store.abandon, self.tenant, batch_id, by="recovery")

    def note_check(self, batch_id: str, *, reset_refusals: bool = True) -> None:
        self._call(self._store.note_check, self.tenant, batch_id, reset_refusals=reset_refusals)

    def note_refusal(self, batch_id: str, why: Why[BatchCause]) -> tuple[int, str]:
        return self._call(self._store.note_refusal, self.tenant, batch_id, why)

    def needs_person(self, batch_id: str, why: Why[BatchCause]) -> None:
        self._call(self._store.needs_person, self.tenant, batch_id, why)

    def end_review(self, batch_id: str, *, expect_phase: str, outcome: str, published: Sequence[tuple[str, str]],
                   held: Sequence[tuple[str, str]], detail: str | None = None,
                   items_why: Why[ItemCause] | None = None) -> bool:
        return self._call(self._store.end_review, self.tenant, batch_id, expect_phase=expect_phase, outcome=outcome,
                          published=published, held=held, detail=detail, items_why=items_why)

    def settle_abandon(self, batch_id: str, *, pr_number: int | None, pr_state: str | None,
                       published: Sequence[tuple[str, str]] = (), held: Sequence[tuple[str, str]] = ()) -> bool:
        return self._call(self._store.settle_abandon, self.tenant, batch_id, pr_number=pr_number, pr_state=pr_state,
                          published=published, held=held)


def work_waiting(store: TickStore, lane: str, *, reconcile_lanes: Collection[str] | None = None) -> bool:
    """Whether a tick of `lane` (reconciling `reconcile_lanes`, by default its own) could act now or later without a
    person (G-T1, #1487 Flow 3), asked of the tick's store `store`, bound to the tenant, `lane` and the thresholds: a
    batch of its lane working (to recover should its lease lapse), one of a reconciled lane in review (its PR may
    change) or parked with a person's abandon request (its tick carries it out), or a claim the bound lane would make
    (`lane_work`, the claim's own rules). A batch waiting for a person with no request is none of these: no tick moves
    it, so it keeps no check clock running; the request, once recorded, wakes the tenant (Amendment r5.3)."""
    reconciled = set(reconcile_lanes or (lane,))
    for b in store.batches():
        if (b.lane == lane and b.phase == "working") or (
                b.lane in reconciled and (b.phase == "in_review" or b.abandon_pending)):
            return True
    work = store.lane_work()
    return bool(work.claimable and not work.busy)
