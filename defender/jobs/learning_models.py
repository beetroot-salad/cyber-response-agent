"""The learning store's tables (#1278): work items, batches and the commit-maker's record, and #1414's feedback
records (A4: the feedback issues, the comments taken in, the feedback tick's lease and cursor), in the
`learning` schema. Every value is set in Python (no server defaults); migration `0013_learning_store`
creates them. The rules the data holds on its own are constraints here, so #1339's catalog comparison
covers them: one item per (tenant, kind, key), one waiting request per case, at most one not-ended authoring
batch per lane and one working batch per lane, one run per feedback issue."""

from __future__ import annotations

import dataclasses
import datetime as _dt
import logging
from collections.abc import Mapping, Sequence
from typing import Any, cast

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKeyConstraint,
    Index,
    Integer,
    Table,
    Text,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Mapped, mapped_column

from defender._text import postgres_cannot_hold
from defender.database import Base, IdColumn
from defender.records.formats import BatchId, CommitId, TenantId, WorkItemId
from defender.records.learning_causes import BATCH_CAUSES, ITEM_CAUSES
from defender.tenancy.models import SCHEMA as TENANCY_SCHEMA

SCHEMA = "learning"

KINDS = ("finding", "questioner_finding", "pitfall", "curation_request", "feedback_instruction")
#: The lane each kind belongs to (r8: lane follows from kind).
AUTHOR_LANE = "author"
LEAD_LANE = "lead_author"  # lint-run-records: ok — the lane's database value, not a run record
#: #1414's registry lane (A4): its batches are item-less registry PRs; no kind belongs to it.
FEEDBACK_LANE = "feedback"
LANE_OF = {"finding": AUTHOR_LANE, "questioner_finding": AUTHOR_LANE, "pitfall": LEAD_LANE, "curation_request": LEAD_LANE,
           "feedback_instruction": AUTHOR_LANE}
LANES = (AUTHOR_LANE, LEAD_LANE, FEEDBACK_LANE)
#: Each lane's branch prefix on the tenant repository: the store mints every batch's branch under it, the tick scans it
#: for PRs no batch made, and the import places an open PR's lane by it. A revert batch's branch is under its own.
BRANCH_PREFIX = {AUTHOR_LANE: "lessons/", LEAD_LANE: "lead-author/", FEEDBACK_LANE: "feedback/"}
REVERT_PREFIX = "lessons/revert-"
STATUSES = ("waiting", "in_batch", "held", "published", "skipped", "dead")
BATCH_KINDS = ("author", "revert", "registry")
#: The batch kinds that hold their lane while not ended (O3, H4; A4: a registry batch is the feedback lane's writer
#: lease). One set, so no site lists the kinds by hand.
AUTHORING_KINDS = ("author", "registry")
PHASES = ("working", "in_review", "needs_person", "ended")
OUTCOMES = ("merged", "closed", "abandoned")
_TIME = DateTime(timezone=True)


def _in_list(column: str, allowed: tuple[str, ...]) -> str:
    return f"{column} IN ({', '.join(repr(v) for v in allowed)})"


class BatchRow(Base, kw_only=True):
    __tablename__ = "batches"
    __table_args__ = (
        ForeignKeyConstraint(["tenant_id"], [f"{TENANCY_SCHEMA}.tenants.id"]),
        ForeignKeyConstraint(["replaces"], [f"{SCHEMA}.batches.id"]),
        CheckConstraint(_in_list("kind", BATCH_KINDS), name="kind"),
        CheckConstraint(_in_list("lane", LANES), name="lane"),
        CheckConstraint(_in_list("phase", PHASES), name="phase"),
        CheckConstraint("outcome IS NULL OR " + _in_list("outcome", OUTCOMES), name="outcome"),
        CheckConstraint("(phase = 'ended') = (outcome IS NOT NULL)", name="ended_has_an_outcome"),
        CheckConstraint("phase <> 'working' OR (lease_owner IS NOT NULL AND lease_expiry IS NOT NULL)",
                        name="working_has_a_lease"),
        CheckConstraint("phase <> 'in_review' OR pr_number IS NOT NULL", name="in_review_has_a_pr"),
        # A cause exactly when the batch is parked or ended abandoned, from the batch list (#1537 PR1).
        CheckConstraint("(phase = 'needs_person' OR outcome IS NOT DISTINCT FROM 'abandoned') = (cause IS NOT NULL)", name="cause_follows_state"),
        CheckConstraint("cause IS NULL OR " + _in_list("cause", BATCH_CAUSES), name="cause"),
        CheckConstraint("parked_at IS NULL OR phase = 'needs_person'", name="parked_at_only_when_parked"),
        CheckConstraint("(abandon_requested_at IS NULL) = (abandon_requested_by IS NULL)", name="request_is_whole"),
        CheckConstraint("abandon_requested_at IS NULL OR phase IN ('needs_person', 'ended')", name="request_only_when_parked"),
        # One open authoring batch per lane (O3, H4): working, in review or waiting on a person.
        Index("batches_one_open_author_per_lane", "tenant_id", "lane", unique=True,
              postgresql_where=text(_in_list("kind", AUTHORING_KINDS) + " AND phase <> 'ended'")),
        # One working batch per lane, of any kind: the commit record and the lane's clone are one writer's.
        Index("batches_one_working_per_lane", "tenant_id", "lane", unique=True,
              postgresql_where=text("phase = 'working'")),
        # The API's read of parked batches (#1485 O2), newest first.
        Index("batches_needs_person", "tenant_id", text("created_at DESC"), text("id DESC"),
              postgresql_where=text("phase = 'needs_person'")),
        {"schema": SCHEMA},
    )

    id: Mapped[BatchId] = mapped_column(IdColumn(BatchId), primary_key=True)
    tenant_id: Mapped[TenantId] = mapped_column(IdColumn(TenantId))
    kind: Mapped[str] = mapped_column(Text)
    lane: Mapped[str] = mapped_column(Text)
    #: Set at claim, never re-derived (D5).
    branch: Mapped[str] = mapped_column(Text)
    #: Set with the first commit row (D5); null before.
    base: Mapped[str | None] = mapped_column(Text, default=None)
    start: Mapped[str | None] = mapped_column(Text, default=None)
    phase: Mapped[str] = mapped_column(Text)
    outcome: Mapped[str | None] = mapped_column(Text, default=None)
    lease_owner: Mapped[str | None] = mapped_column(Text, default=None)
    lease_expiry: Mapped[_dt.datetime | None] = mapped_column(_TIME, default=None)
    fencing_token: Mapped[int] = mapped_column(Integer)
    cancel_requested: Mapped[bool] = mapped_column(Boolean)
    pr_number: Mapped[int | None] = mapped_column(Integer, default=None)
    replaces: Mapped[BatchId | None] = mapped_column(IdColumn(BatchId), default=None)
    #: Replacement PRs opened in this chain (counted when the PR opens).
    generation: Mapped[int] = mapped_column(Integer)
    #: Consecutive non-transient forge refusals (H15); any successful forge read resets it.
    refusals: Mapped[int] = mapped_column(Integer)
    last_checked: Mapped[_dt.datetime | None] = mapped_column(_TIME, default=None)
    #: Why the batch ended abandoned, went to a person, or has no replacement.
    reason: Mapped[str | None] = mapped_column(Text, default=None)
    #: The closed-list cause behind `reason` (the detail): set exactly while parked or ended abandoned (#1537 PR1).
    cause: Mapped[str | None] = mapped_column(Text, default=None)
    #: When the batch entered `needs_person`; null otherwise and for batches parked before #1537.
    parked_at: Mapped[_dt.datetime | None] = mapped_column(_TIME, default=None)
    #: A person's request to abandon the parked batch (kept after the batch ends: the row's record of who asked).
    abandon_requested_at: Mapped[_dt.datetime | None] = mapped_column(_TIME, default=None)
    abandon_requested_by: Mapped[str | None] = mapped_column(Text, default=None)
    created_at: Mapped[_dt.datetime] = mapped_column(_TIME)
    ended_at: Mapped[_dt.datetime | None] = mapped_column(_TIME, default=None)


class WorkItemRow(Base, kw_only=True):
    __tablename__ = "work_items"
    __table_args__ = (
        ForeignKeyConstraint(["tenant_id"], [f"{TENANCY_SCHEMA}.tenants.id"]),
        ForeignKeyConstraint(["batch_id"], [f"{SCHEMA}.batches.id"]),
        CheckConstraint(_in_list("kind", KINDS), name="kind"),
        CheckConstraint(_in_list("status", STATUSES), name="status"),
        # A cause exactly when the item is held, dead or skipped, from the item list (#1537 PR1).
        CheckConstraint("(status IN ('held', 'dead', 'skipped')) = (cause IS NOT NULL)", name="cause_follows_status"),
        CheckConstraint("cause IS NULL OR " + _in_list("cause", ITEM_CAUSES), name="cause"),
        # A request case is unique while waiting; the later run wins (r8 coalesce key).
        Index("work_items_one_waiting_request_per_case", "tenant_id", "kind", "coalesce_key", unique=True,
              postgresql_where=text("status = 'waiting' AND coalesce_key IS NOT NULL")),
        Index("work_items_by_status", "tenant_id", "status"),
        Index("work_items_by_batch", "batch_id"),
        # The API's read of held and dead items (#1485 O1), in (updated_at, id) order.
        Index("work_items_set_aside", "tenant_id", text("updated_at DESC"), text("id DESC"),
              postgresql_where=text("status IN ('held', 'dead')")),
        {"schema": SCHEMA},
    )

    tenant_id: Mapped[TenantId] = mapped_column(IdColumn(TenantId), primary_key=True)
    kind: Mapped[str] = mapped_column(Text, primary_key=True)
    #: The item's id of its own (#1485 D12), minted in Python at insert (no server default), stable for its life.
    id: Mapped[WorkItemId] = mapped_column(IdColumn(WorkItemId), unique=True, insert_default=WorkItemId.mint)
    item_key: Mapped[str] = mapped_column(Text, primary_key=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB)
    #: The run the row came from, as text with no foreign key (a deleted investigation leaves it).
    source_run: Mapped[str | None] = mapped_column(Text, default=None)
    status: Mapped[str] = mapped_column(Text)
    reason: Mapped[str | None] = mapped_column(Text, default=None)
    #: The closed-list cause behind `reason` while held, dead or skipped (#1537 PR1).
    cause: Mapped[str | None] = mapped_column(Text, default=None)
    fault: Mapped[str | None] = mapped_column(Text, default=None)
    batch_id: Mapped[BatchId | None] = mapped_column(IdColumn(BatchId), default=None)
    attempts: Mapped[int] = mapped_column(Integer)
    deferrals: Mapped[int] = mapped_column(Integer)
    offers_declined: Mapped[int] = mapped_column(Integer)
    coalesce_key: Mapped[str | None] = mapped_column(Text, default=None)
    mistake_key: Mapped[str | None] = mapped_column(Text, default=None)
    enqueued_at: Mapped[_dt.datetime] = mapped_column(_TIME)
    updated_at: Mapped[_dt.datetime] = mapped_column(_TIME)


class CommitRow(Base, kw_only=True):
    """The commit-maker's record, kept for good and tenant-wide (D5). `batch_id` is null only for imported history."""

    __tablename__ = "commits"
    __table_args__ = (
        ForeignKeyConstraint(["tenant_id"], [f"{TENANCY_SCHEMA}.tenants.id"]),
        ForeignKeyConstraint(["batch_id"], [f"{SCHEMA}.batches.id"]),
        Index("commits_by_tenant", "tenant_id", "created_at"),
        {"schema": SCHEMA},
    )

    id: Mapped[CommitId] = mapped_column(IdColumn(CommitId), primary_key=True)
    tenant_id: Mapped[TenantId] = mapped_column(IdColumn(TenantId))
    batch_id: Mapped[BatchId | None] = mapped_column(IdColumn(BatchId), default=None)
    commit: Mapped[str] = mapped_column(Text)
    branch: Mapped[str] = mapped_column(Text)
    base: Mapped[str] = mapped_column(Text)
    start: Mapped[str] = mapped_column(Text)
    #: `[[batch id, path], ...]` a revert commit undoes; null for an authoring commit.
    reverts: Mapped[list[Any] | None] = mapped_column(JSONB, default=None)
    created_at: Mapped[_dt.datetime] = mapped_column(_TIME)


class CommitChangeRow(Base, kw_only=True):
    __tablename__ = "commit_changes"
    __table_args__ = (
        ForeignKeyConstraint(["tenant_id"], [f"{TENANCY_SCHEMA}.tenants.id"]),
        ForeignKeyConstraint(["commit_row"], [f"{SCHEMA}.commits.id"]),
        {"schema": SCHEMA},
    )

    commit_row: Mapped[CommitId] = mapped_column(IdColumn(CommitId), primary_key=True)
    ordinal: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[TenantId] = mapped_column(IdColumn(TenantId))
    path: Mapped[str] = mapped_column(Text)
    blob_base: Mapped[str | None] = mapped_column(Text, default=None)
    blob_left: Mapped[str | None] = mapped_column(Text, default=None)


class FeedbackIssueRow(Base, kw_only=True):
    """One run whose outcome the tenant's feedback setting lists (#1414 F1, A4): a request while `issue_number` is
    null, the run's issue once recorded. Lives as long as its issue."""

    __tablename__ = "feedback_issues"
    __table_args__ = (
        ForeignKeyConstraint(["tenant_id"], [f"{TENANCY_SCHEMA}.tenants.id"]),
        # One run per issue.
        Index("feedback_issues_one_run_per_issue", "tenant_id", "issue_number", unique=True,
              postgresql_where=text("issue_number IS NOT NULL")),
        {"schema": SCHEMA},
    )

    tenant_id: Mapped[TenantId] = mapped_column(IdColumn(TenantId), primary_key=True)
    run_id: Mapped[str] = mapped_column(Text, primary_key=True)
    case_id: Mapped[str] = mapped_column(Text)
    outcome: Mapped[str] = mapped_column(Text)
    #: The run's captured lookups, indexed by position (the decide answer names them by index).
    lookups: Mapped[list[Any]] = mapped_column(JSONB)
    issue_number: Mapped[int | None] = mapped_column(Integer, default=None)
    #: The issue's own comments were read whole once (a catch-up after it was recorded).
    listed: Mapped[bool] = mapped_column(Boolean)
    #: Every comment id judged on the issue, taken in or passed over (a passed-over comment is only its id).
    judged_comment_ids: Mapped[list[Any]] = mapped_column(JSONB)
    requested_at: Mapped[_dt.datetime] = mapped_column(_TIME)
    recorded_at: Mapped[_dt.datetime | None] = mapped_column(_TIME, default=None)


class FeedbackCommentRow(Base, kw_only=True):
    """One comment taken in (an eligible author, readable by D12), and its decision once made (A4)."""

    __tablename__ = "feedback_comments"
    __table_args__ = (
        ForeignKeyConstraint(["tenant_id"], [f"{TENANCY_SCHEMA}.tenants.id"]),
        ForeignKeyConstraint(["tenant_id", "run_id"], [f"{SCHEMA}.feedback_issues.tenant_id",
                                                       f"{SCHEMA}.feedback_issues.run_id"]),
        {"schema": SCHEMA},
    )

    tenant_id: Mapped[TenantId] = mapped_column(IdColumn(TenantId), primary_key=True)
    comment_id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    #: The framing run: the issue number is read through it (one owner).
    run_id: Mapped[str] = mapped_column(Text)
    author: Mapped[str] = mapped_column(Text)
    #: The forge's date of the comment.
    created: Mapped[str] = mapped_column(Text)
    body: Mapped[str] = mapped_column(Text)
    issue_url: Mapped[str] = mapped_column(Text)
    #: Counted failed answers (#1414 A4's ceiling).
    attempts: Mapped[int] = mapped_column(Integer)
    decision: Mapped[dict[str, Any] | None] = mapped_column(JSONB, default=None)
    #: The reply is on the issue, or the issue is gone: never read again.
    settled: Mapped[bool] = mapped_column(Boolean)


class FeedbackTickRow(Base, kw_only=True):
    """The tenant's feedback tick (A4): the comment cursor and the one-tick-per-tenant lease (O12)."""

    __tablename__ = "feedback_tick"
    __table_args__ = (
        ForeignKeyConstraint(["tenant_id"], [f"{TENANCY_SCHEMA}.tenants.id"]),
        {"schema": SCHEMA},
    )

    tenant_id: Mapped[TenantId] = mapped_column(IdColumn(TenantId), primary_key=True)
    #: The forge's time of the newest comment read; moves forward only.
    comments_since: Mapped[_dt.datetime | None] = mapped_column(_TIME, default=None)
    lease_owner: Mapped[str | None] = mapped_column(Text, default=None)
    lease_expiry: Mapped[_dt.datetime | None] = mapped_column(_TIME, default=None)
    fencing_token: Mapped[int] = mapped_column(Integer)
    cancel_requested: Mapped[bool] = mapped_column(Boolean)


# -- findings into the author lane's queue (#1487): the one insert the worker's end write and the operator lane share --

_logger = logging.getLogger(__name__)


class ItemRefused(Exception):
    """The database will never take this item (a NUL character jsonb refuses): waiting cannot cure it."""


def refuse_unholdable(value: Any) -> None:
    """Refuse, before anything is written, a value PostgreSQL could never hold (`postgres_cannot_hold`): every store
    verb screens all the text it was given."""
    why = postgres_cannot_hold(value)
    if why is not None:
        raise ItemRefused(why)


def refuse_unkeyed(row: Mapping[str, Any]) -> None:
    """A finding's key is its `finding_id` as the judge made it: a string with something in it. A missing, null,
    numeric or empty one would be keyed `'None'`, `'5'` or `''`, and a later row could collide with the made-up key."""
    key = row.get("finding_id")
    if not isinstance(key, str) or not key.strip():
        raise ItemRefused(f"a finding row carries no string finding_id (got {key!r})")


#: SQLSTATE classes an insert's own content causes, which waiting cannot cure: data (22), integrity (23) and limits
#: (54, which the driver reports as an operational error, so it is read before the outage test).
_CONTENT_CLASSES = frozenset({"22", "23", "54"})


@dataclasses.dataclass(frozen=True)
class FindingsInsert:
    """What `insert_findings` did: every row stored (`stored`, with `added` of them new; a finding id the store already
    holds stays as it is), or none of them (`refused`, the refusal's words in `why`)."""

    stored: bool
    added: int = 0
    why: str | None = None


async def insert_findings(s: AsyncSession, tenant: str, channels: Mapping[str, Sequence[Mapping[str, Any]]], *,
                          source_run: str) -> FindingsInsert:
    """Insert, in the transaction `s` is in, each channel's rows (`{kind: rows}`, author-lane kinds) as
    `waiting` items of `tenant` from `source_run`, all under one savepoint: every row is stored, or, refused, none of
    any channel (the savepoint rolled back, the transaction usable). The caller holds the tenant's state for the
    transaction. Refused: a row PostgreSQL could never hold or with no finding id (`refuse_unholdable`,
    `refuse_unkeyed`); an error of SQLSTATE class 22, 23 or 54; any other `Exception` that is not an outage (a
    deterministic database error such as a missing permission, or a fault in this code), logged. An outage
    (`jobs.is_outage`: a lost connection, deadlock, lock timeout, cancel, full disk) propagates, for the caller to
    retry whole. A `BaseException` (a cancellation) is never caught."""
    for kind in channels:
        if LANE_OF.get(kind) != AUTHOR_LANE:
            raise ValueError(f"not a findings kind: {kind}")
    try:
        for rows in channels.values():
            refuse_unholdable(list(rows))
            for row in rows:
                refuse_unkeyed(row)
    except ItemRefused as refused:
        return FindingsInsert(False, why=str(refused))
    except Exception as fault:  # noqa: BLE001 — rows the screens cannot even read are refused, never raised
        _logger.error("screening findings failed with %s; they are refused", type(fault).__name__, exc_info=fault)
        return FindingsInsert(False, why=f"screening the findings failed ({type(fault).__name__})")
    try:
        added = 0
        async with s.begin_nested():
            for kind, rows in channels.items():
                for row in rows:
                    added += len((await s.execute(_finding_insert(tenant, kind, row, source_run))).all())
    except Exception as fault:  # noqa: BLE001 — classified: content refuses, an outage is raised again
        return FindingsInsert(False, why=_refusal_of(fault))
    return FindingsInsert(True, added=added)


def _finding_insert(tenant: str, kind: str, row: Mapping[str, Any], source_run: str) -> Any:
    """One finding as a `waiting` item keyed by its `finding_id`, the conflict on an id held for good doing nothing."""
    table = cast(Table, WorkItemRow.__table__)
    return pg_insert(table).values(
        tenant_id=TenantId(tenant), kind=kind, item_key=row["finding_id"], payload=dict(row), source_run=source_run,
        status="waiting", reason=None, fault=None, batch_id=None, attempts=0, deferrals=0, offers_declined=0,
        coalesce_key=None, mistake_key=None, enqueued_at=func.now(), updated_at=func.now(),
    ).on_conflict_do_nothing(index_elements=["tenant_id", "kind", "item_key"]).returning(table.c.item_key)


def _refusal_of(fault: Exception) -> str:
    """The refusal `fault` makes of an insert, in P4's order; an outage is raised again."""
    from defender.jobs.store import is_outage

    code = _sqlstate(fault)
    if code is not None and code[:2] in _CONTENT_CLASSES:
        return f"the database refused a finding (SQLSTATE {code})"
    if is_outage(fault):
        raise fault
    _logger.error("storing findings failed with %s, which waiting cannot cure; they are refused", type(fault).__name__,
                  exc_info=fault)
    return f"storing the findings failed ({type(fault).__name__}" + (f", SQLSTATE {code})" if code else ")")


def _sqlstate(fault: BaseException) -> str | None:
    """The SQLSTATE a database error carries (the driver's error, or the one SQLAlchemy wraps), else `None`."""
    for candidate in (fault, getattr(fault, "orig", None)):
        code = getattr(candidate, "sqlstate", None)
        if isinstance(code, str) and len(code) == 5:
            return code
    return None
