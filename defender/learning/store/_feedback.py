"""#1414's feedback records on the learning store (#1278 A4): the feedback issues, the comments taken in and their
decisions, and the tenant's feedback tick (its comment cursor and its one-tick-per-tenant lease).

One run is one row and one comment is one row; each one-time judgement (issue recorded, comment judged, decision
recorded, entry settled, reply settled) is a compare-and-set under the tick's token (P8). A tick's write is made only
while its lease is live by the database's clock and its token is the row's, so a tick that lost its lease changes
nothing (O12). The inserts (a run's request, a comment taken in, a decision with its instruction item) and the tick's
lease are decided against an active tenant in the same transaction (O6)."""

from __future__ import annotations

import dataclasses
import datetime as _dt
from collections.abc import Iterable, Mapping, Sequence
from typing import TYPE_CHECKING, Any, cast

from sqlalchemy import Table, func, literal, null, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert

from defender._clock import parse_iso_utc
from defender.jobs.learning_models import FeedbackCommentRow, FeedbackIssueRow, FeedbackTickRow, WorkItemRow
from defender.records.formats import TenantId

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

_FI = cast(Table, FeedbackIssueRow.__table__)
_FC = cast(Table, FeedbackCommentRow.__table__)
_FT = cast(Table, FeedbackTickRow.__table__)
_I = cast(Table, WorkItemRow.__table__)

#: The work item kind a person's instruction becomes (D11): the lessons author claims it like a finding.
INSTRUCTION_KIND = "feedback_instruction"


@dataclasses.dataclass(frozen=True)
class FeedbackHeld:
    """A tenant's feedback tick lease: the proof its writes present (tenant, owner, token), and the comment cursor as
    the tick began."""

    tenant_id: TenantId
    owner: str
    token: int
    comments_since: _dt.datetime | None


@dataclasses.dataclass(frozen=True)
class FeedbackIssue:
    """One run whose outcome the tenant's setting lists: a request while `issue_number` is None."""

    tenant_id: TenantId
    run_id: str
    case_id: str
    outcome: str
    lookups: tuple[dict[str, Any], ...]
    issue_number: int | None
    listed: bool
    judged_comment_ids: tuple[int, ...]
    requested_at: _dt.datetime
    recorded_at: _dt.datetime | None


@dataclasses.dataclass(frozen=True)
class FeedbackComment:
    """One comment taken in, with its framing run (and that run's issue number) and its decision once made."""

    tenant_id: TenantId
    comment_id: int
    run_id: str
    issue_number: int | None
    author: str
    created: str
    body: str
    issue_url: str
    attempts: int
    decision: dict[str, Any] | None
    settled: bool


def _cursor_time(value: str | _dt.datetime) -> _dt.datetime:
    """A forge time (ISO text, `Z` or an offset) as an aware datetime; text that is no ISO time refuses."""
    when = value if isinstance(value, _dt.datetime) else parse_iso_utc(str(value))
    if when is None:
        raise ValueError(f"a forge time that is no ISO time: {value!r}")
    if when.tzinfo is None:
        raise ValueError(f"a forge time carries no zone: {value!r}")
    return when


class FeedbackVerbs:
    """The feedback verbs of `LearningStore` (mixed in; the store's sessions, clock and tenant check are its own)."""

    if TYPE_CHECKING:
        lease: float
        grace: float
        _sessions: Any

        def _in(self, seconds: float) -> Any: ...
        async def _require_active(self, s: AsyncSession, tenant: str) -> None: ...
        async def _refuse_if_busy(self, s: AsyncSession, tenant: str, lane: str) -> None: ...
        async def _new_batch(  # noqa: PLR0913 — the store's own signature, declared for the type checker
                self, s: AsyncSession, tenant: str, lane: str, kind: str, owner: str,
                             kinds: list[str], *, generation: int, replaces: Any, feedback_pr: int | None,
                             only_batch: Any, branch: str | None = None) -> Any: ...

    # -- run end's request (F1) ----------------------------------------------------------------------------------

    async def enqueue_feedback_issue(self, tenant: str, run_id: str, case_id: str, *, outcome: str,
                                     lookups: Sequence[Mapping[str, Any]]) -> bool:
        """File a run's open-issue request: a row with no issue number. False when the run is already filed (nothing
        changes); `TenantInactive` off active; `ItemRefused` for text the store cannot hold."""
        from ._store import _refuse_unholdable

        rows = [dict(lk) for lk in lookups]
        _refuse_unholdable([run_id, case_id, outcome, rows])
        async with self._sessions.begin() as s:
            await self._require_active(s, tenant)
            done = (await s.execute(pg_insert(_FI).values(
                tenant_id=TenantId(tenant), run_id=run_id, case_id=case_id, outcome=outcome, lookups=rows,
                issue_number=None, listed=False, judged_comment_ids=[], requested_at=func.now(), recorded_at=None)
                .on_conflict_do_nothing(index_elements=["tenant_id", "run_id"]).returning(_FI.c.run_id))).first()
        return done is not None

    # -- the tick's lease (O12) ------------------------------------------------------------------------------------

    async def begin_feedback_tick(self, tenant: str, *, owner: str) -> FeedbackHeld | None:
        """Take the tenant's feedback tick lease, try-once: None while a holder's lease (and its grace) has not run out;
        a lapsed or released lease is taken with the next fencing token. `TenantInactive` off active (no row taken)."""
        t = TenantId(tenant)
        async with self._sessions.begin() as s:
            await self._require_active(s, tenant)
            await s.execute(pg_insert(_FT).values(
                tenant_id=t, comments_since=None, lease_owner=None, lease_expiry=None, fencing_token=0,
                cancel_requested=False).on_conflict_do_nothing(index_elements=["tenant_id"]))
            row = (await s.execute(select(_FT).where(_FT.c.tenant_id == t).with_for_update())).one()
            if row.lease_owner is not None and row.lease_expiry is not None:
                live = (await s.execute(select(
                    func.now() <= row.lease_expiry + literal(_dt.timedelta(seconds=self.grace))))).scalar_one()
                if live:
                    return None
            token = row.fencing_token + 1
            await s.execute(update(_FT).where(_FT.c.tenant_id == t).values(
                lease_owner=owner, lease_expiry=self._in(self.lease), fencing_token=token, cancel_requested=False))
            return FeedbackHeld(tenant_id=t, owner=owner, token=token, comments_since=row.comments_since)

    async def _tick_guard(self, s: AsyncSession, held: FeedbackHeld) -> Any:
        """The tenant's tick row, locked, if `held` is still its live holder; else `LeaseLost`."""
        from ._store import LeaseLost

        row = (await s.execute(select(_FT).where(
            _FT.c.tenant_id == held.tenant_id, _FT.c.fencing_token == held.token, _FT.c.lease_owner == held.owner,
            _FT.c.lease_expiry > func.now()).with_for_update())).first()
        if row is None:
            raise LeaseLost(f"the feedback tick of tenant {held.tenant_id}")
        return row

    async def renew_feedback_tick(self, held: FeedbackHeld) -> None:
        """Extend the lease; a cancel is a stop, after the extension (as `renew`)."""
        from ._store import Stop

        async with self._sessions.begin() as s:
            await self._tick_guard(s, held)
            cancelled = (await s.execute(update(_FT).where(_FT.c.tenant_id == held.tenant_id).values(
                lease_expiry=self._in(self.lease)).returning(_FT.c.cancel_requested))).scalar_one()
        if cancelled:
            raise Stop(f"the feedback tick of tenant {held.tenant_id} was cancelled")

    async def end_feedback_tick(self, held: FeedbackHeld) -> None:
        """A clean end: the lease is released at once. A holder that is no longer the lease's releases nothing
        (`LeaseLost`)."""
        from ._store import LeaseLost

        async with self._sessions.begin() as s:
            ended = (await s.execute(update(_FT).where(
                _FT.c.tenant_id == held.tenant_id, _FT.c.fencing_token == held.token, _FT.c.lease_owner == held.owner)
                .values(lease_owner=None, lease_expiry=None).returning(_FT.c.tenant_id))).first()
        if ended is None:
            raise LeaseLost(f"the feedback tick of tenant {held.tenant_id}")

    # -- views -------------------------------------------------------------------------------------------------------

    async def feedback_issues(self, tenant: str) -> list[FeedbackIssue]:
        """The tenant's runs owed or holding an issue (requests included: `issue_number` None), oldest first."""
        async with self._sessions() as s:
            rows = (await s.execute(select(_FI).where(_FI.c.tenant_id == TenantId(tenant))
                                    .order_by(_FI.c.requested_at, _FI.c.run_id))).all()
        return [FeedbackIssue(tenant_id=r.tenant_id, run_id=r.run_id, case_id=r.case_id, outcome=r.outcome,
                              lookups=tuple(r.lookups), issue_number=r.issue_number, listed=r.listed,
                              judged_comment_ids=tuple(int(c) for c in r.judged_comment_ids),
                              requested_at=r.requested_at, recorded_at=r.recorded_at) for r in rows]

    async def feedback_comments(self, tenant: str) -> list[FeedbackComment]:
        """The tenant's comments taken in, in (issue, comment id) order."""
        async with self._sessions() as s:
            rows = (await s.execute(
                select(_FC, _FI.c.issue_number).select_from(_FC.join(
                    _FI, (_FI.c.tenant_id == _FC.c.tenant_id) & (_FI.c.run_id == _FC.c.run_id)))
                .where(_FC.c.tenant_id == TenantId(tenant))
                .order_by(_FI.c.issue_number.asc().nulls_last(), _FC.c.comment_id))).all()
        return [FeedbackComment(tenant_id=r.tenant_id, comment_id=int(r.comment_id), run_id=r.run_id,
                                issue_number=r.issue_number, author=r.author, created=r.created, body=r.body,
                                issue_url=r.issue_url, attempts=r.attempts, decision=r.decision, settled=r.settled)
                for r in rows]

    # -- the tick's writes (each under its token) ----------------------------------------------------------------------

    async def record_feedback_issue(self, held: FeedbackHeld, run_id: str, number: int) -> bool:
        """Record the run's issue number where it has none yet. False: it had one (the first stays)."""
        async with self._sessions.begin() as s:
            await self._tick_guard(s, held)
            done = (await s.execute(update(_FI).where(
                _FI.c.tenant_id == held.tenant_id, _FI.c.run_id == run_id, _FI.c.issue_number.is_(None))
                .values(issue_number=int(number), recorded_at=func.now()).returning(_FI.c.run_id))).first()
        return done is not None

    async def judge_comments(self, held: FeedbackHeld, run_id: str, *, taken: Sequence[Mapping[str, Any]],
                             judged: Iterable[int], listed: bool = False) -> None:
        """One issue's read, in one transaction: the comments taken in are stored (one already there is kept as it
        was), every judged id (taken or passed over) is added to the run's judged ids, and `listed` is set when the
        read was the issue's whole listing. `TenantInactive` off active: nothing is stored."""
        from ._store import _refuse_unholdable

        rows = [dict(c) for c in taken]
        _refuse_unholdable(rows)
        ids = {int(i) for i in judged} | {int(c["comment_id"]) for c in rows}
        async with self._sessions.begin() as s:
            await self._tick_guard(s, held)
            await self._require_active(s, str(held.tenant_id))
            issue = (await s.execute(select(_FI.c.judged_comment_ids).where(
                _FI.c.tenant_id == held.tenant_id, _FI.c.run_id == run_id).with_for_update())).first()
            if issue is None:
                raise LookupError(f"no feedback issue row for run {run_id}")
            for c in rows:
                await s.execute(pg_insert(_FC).values(
                    tenant_id=held.tenant_id, comment_id=int(c["comment_id"]), run_id=run_id, author=str(c["author"]),
                    created=str(c["created"]), body=str(c["body"]), issue_url=str(c["issue_url"]), attempts=0,
                    decision=null(), settled=False).on_conflict_do_nothing(index_elements=["tenant_id", "comment_id"]))
            values: dict[str, Any] = {"judged_comment_ids": sorted({int(i) for i in issue.judged_comment_ids} | ids)}
            if listed:
                values["listed"] = True
            await s.execute(update(_FI).where(_FI.c.tenant_id == held.tenant_id, _FI.c.run_id == run_id)
                            .values(**values))

    async def advance_comment_cursor(self, held: FeedbackHeld, since: str | _dt.datetime) -> None:
        """Move the comment cursor to `since` (the forge's time of the newest comment read); it never moves back."""
        when = _cursor_time(since)
        async with self._sessions.begin() as s:
            await self._tick_guard(s, held)
            await s.execute(update(_FT).where(_FT.c.tenant_id == held.tenant_id).values(
                comments_since=func.greatest(func.coalesce(_FT.c.comments_since, literal(when)), literal(when))))

    async def count_failed_answer(self, held: FeedbackHeld, comment_id: int) -> int:
        """One more failed answer for the comment: the count after it."""
        async with self._sessions.begin() as s:
            await self._tick_guard(s, held)
            count = (await s.execute(update(_FC).where(
                _FC.c.tenant_id == held.tenant_id, _FC.c.comment_id == int(comment_id))
                .values(attempts=_FC.c.attempts + 1).returning(_FC.c.attempts))).scalar_one_or_none()
        if count is None:
            raise LookupError(f"no feedback comment {comment_id}")
        return int(count)

    async def record_decision(self, held: FeedbackHeld, comment_id: int, decision: Mapping[str, Any], *,
                              instruction: Mapping[str, Any] | None) -> bool:
        """Record the comment's decision where it has none, and, in the same transaction, its instruction as a waiting
        `feedback_instruction` item keyed by the comment id (one per comment, for good). False: the comment was
        already decided, and nothing changes. `TenantInactive` off active: nothing is recorded."""
        from ._store import _refuse_unholdable

        made, row = dict(decision), dict(instruction) if instruction is not None else None
        _refuse_unholdable([made, row])
        async with self._sessions.begin() as s:
            await self._tick_guard(s, held)
            await self._require_active(s, str(held.tenant_id))
            run = (await s.execute(update(_FC).where(
                _FC.c.tenant_id == held.tenant_id, _FC.c.comment_id == int(comment_id), _FC.c.decision.is_(None))
                .values(decision=made).returning(_FC.c.run_id))).scalar_one_or_none()
            if run is None:
                return False
            if row is not None:
                await s.execute(pg_insert(_I).values(
                    tenant_id=held.tenant_id, kind=INSTRUCTION_KIND, item_key=str(int(comment_id)), payload=row,
                    source_run=run, status="waiting", reason=None, fault=None, batch_id=None, attempts=0, deferrals=0,
                    offers_declined=0, coalesce_key=None, mistake_key=None, enqueued_at=func.now(),
                    updated_at=func.now()).on_conflict_do_nothing(index_elements=["tenant_id", "kind", "item_key"]))
        return True

    async def settle_entry(self, held: FeedbackHeld, comment_id: int, entry_id: str, how: Mapping[str, Any]) -> bool:
        """Settle one approved entry of the comment's decision where it is unsettled. False: it was settled already
        (the first settlement stays), or the decision names no such entry."""
        from ._store import _refuse_unholdable

        settled = dict(how)
        _refuse_unholdable(settled)
        async with self._sessions.begin() as s:
            await self._tick_guard(s, held)
            current = (await s.execute(select(_FC.c.decision).where(
                _FC.c.tenant_id == held.tenant_id, _FC.c.comment_id == int(comment_id)).with_for_update())).first()
            if current is None or current.decision is None:
                return False
            made = dict(current.decision)
            approved = [dict(a) for a in made.get("approved") or []]
            hit = next((a for a in approved if a.get("id") == entry_id and a.get("settled") is None), None)
            if hit is None:
                return False
            hit["settled"] = settled
            made["approved"] = approved
            await s.execute(update(_FC).where(_FC.c.tenant_id == held.tenant_id, _FC.c.comment_id == int(comment_id))
                            .values(decision=made))
        return True

    async def mark_settled(self, held: FeedbackHeld, comment_id: int) -> None:
        """The comment's reply is on its issue (or the issue is gone): it is never read again."""
        async with self._sessions.begin() as s:
            await self._tick_guard(s, held)
            await s.execute(update(_FC).where(_FC.c.tenant_id == held.tenant_id, _FC.c.comment_id == int(comment_id))
                            .values(settled=True))

    async def claim_registry(self, held: FeedbackHeld) -> Any:
        """An item-less registry batch of lane `feedback` (P6, A4), claimed under the live tick lease (`LeaseLost`
        otherwise): `LaneBusy` while the lane has a working or not-ended authoring batch, `TenantInactive` off active.
        The row exists before any commit (P2')."""
        from sqlalchemy.exc import IntegrityError

        from defender.jobs.learning_models import FEEDBACK_LANE

        from ._store import LaneBusy, _violates

        try:
            async with self._sessions.begin() as s:
                await self._tick_guard(s, held)
                await self._require_active(s, str(held.tenant_id))
                await self._refuse_if_busy(s, str(held.tenant_id), FEEDBACK_LANE)
                return await self._new_batch(s, str(held.tenant_id), FEEDBACK_LANE, "registry", held.owner, [],
                                             generation=0, replaces=None, feedback_pr=None, only_batch=None)
        except IntegrityError as raced:
            if _violates(raced, "batches_one_"):
                raise LaneBusy(FEEDBACK_LANE) from None
            raise

    # -- offboarding -----------------------------------------------------------------------------------------------

    async def _cancel_feedback_tick(self, s: AsyncSession, tenant: str) -> None:
        await s.execute(update(_FT).where(_FT.c.tenant_id == TenantId(tenant)).values(cancel_requested=True))

    async def _feedback_lease_live(self, s: AsyncSession, tenant: str) -> bool:
        """A feedback tick still holds the tenant's lease (or its grace): offboarding must not purge under it."""
        row = (await s.execute(select(_FT.c.tenant_id).where(
            _FT.c.tenant_id == TenantId(tenant), _FT.c.lease_owner.is_not(None),
            _FT.c.lease_expiry + literal(_dt.timedelta(seconds=self.grace)) >= func.now()))).first()
        return row is not None

    async def _purge_feedback(self, s: AsyncSession, tenant: str) -> None:
        from sqlalchemy import delete

        t = TenantId(tenant)
        await s.execute(delete(_FC).where(_FC.c.tenant_id == t))  # before the issues it references
        await s.execute(delete(_FI).where(_FI.c.tenant_id == t))
        await s.execute(delete(_FT).where(_FT.c.tenant_id == t))


__all__ = ["INSTRUCTION_KIND", "FeedbackComment", "FeedbackHeld", "FeedbackIssue", "FeedbackVerbs"]
