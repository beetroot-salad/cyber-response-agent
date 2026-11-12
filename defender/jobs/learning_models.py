"""The learning store's tables (#1278): work items, batches and the commit-maker's record, and #1414's feedback
records (A4: the feedback issues, the comments taken in, the feedback tick's lease and cursor), in the
`learning` schema. Every value is set in Python (no server defaults); migration `0013_learning_store`
creates them. The rules the data holds on its own are constraints here, so #1339's catalog comparison
covers them: one item per (tenant, kind, key), one waiting request per case, at most one not-ended authoring
batch per lane and one working batch per lane, one run per feedback issue."""

from __future__ import annotations

import datetime as _dt
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKeyConstraint,
    Index,
    Integer,
    Text,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from defender.database import Base, IdColumn
from defender.records.formats import BatchId, CommitId, TenantId
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
        # One open authoring batch per lane (O3, H4): working, in review or waiting on a person.
        Index("batches_one_open_author_per_lane", "tenant_id", "lane", unique=True,
              postgresql_where=text(_in_list("kind", AUTHORING_KINDS) + " AND phase <> 'ended'")),
        # One working batch per lane, of any kind: the commit record and the lane's clone are one writer's.
        Index("batches_one_working_per_lane", "tenant_id", "lane", unique=True,
              postgresql_where=text("phase = 'working'")),
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
    created_at: Mapped[_dt.datetime] = mapped_column(_TIME)
    ended_at: Mapped[_dt.datetime | None] = mapped_column(_TIME, default=None)


class WorkItemRow(Base, kw_only=True):
    __tablename__ = "work_items"
    __table_args__ = (
        ForeignKeyConstraint(["tenant_id"], [f"{TENANCY_SCHEMA}.tenants.id"]),
        ForeignKeyConstraint(["batch_id"], [f"{SCHEMA}.batches.id"]),
        CheckConstraint(_in_list("kind", KINDS), name="kind"),
        CheckConstraint(_in_list("status", STATUSES), name="status"),
        # A request case is unique while waiting; the later run wins (r8 coalesce key).
        Index("work_items_one_waiting_request_per_case", "tenant_id", "kind", "coalesce_key", unique=True,
              postgresql_where=text("status = 'waiting' AND coalesce_key IS NOT NULL")),
        Index("work_items_by_status", "tenant_id", "status"),
        Index("work_items_by_batch", "batch_id"),
        {"schema": SCHEMA},
    )

    tenant_id: Mapped[TenantId] = mapped_column(IdColumn(TenantId), primary_key=True)
    kind: Mapped[str] = mapped_column(Text, primary_key=True)
    item_key: Mapped[str] = mapped_column(Text, primary_key=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB)
    #: The run the row came from, as text with no foreign key (a deleted investigation leaves it).
    source_run: Mapped[str | None] = mapped_column(Text, default=None)
    status: Mapped[str] = mapped_column(Text)
    reason: Mapped[str | None] = mapped_column(Text, default=None)
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
