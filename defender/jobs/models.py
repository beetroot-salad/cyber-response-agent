"""The job store's tables and the records it hands out. Every value is set in Python (no server
defaults). The alerts and investigations tables carry exactly the lean constraints of #1081's
design; the migration `0004_jobs` creates them and `0005_uuid_ids` makes their ids `uuid` (#1382).
The learning jobs and learning checks tables (#1344) are `0008_learning_jobs`'s; the host requests table (#1471) is
`0026_host_requests`'s. The claims, staged facts and uploads (#1546), and the owners' evidence columns, are
`0027_run_evidence`'s; the investigations' foreign key to their tenant's retention row is `0029_retention_required`'s."""

from __future__ import annotations

import dataclasses
import datetime as _dt
from typing import Any, Protocol

from sqlalchemy import BigInteger, Boolean, CheckConstraint, DateTime, Float, ForeignKeyConstraint, Index, Integer, LargeBinary, Text, UniqueConstraint, false, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.engine import Row
from sqlalchemy.orm import Mapped, mapped_column

from defender._model import model
from defender._vocab import DISPOSITION_VALUES, Disposition
from defender.database import Base, IdColumn
from defender.records.formats import AlertId, HostRequestId, InvestigationId, LearningJobId, TenantId
from defender.tenancy.models import SCHEMA as TENANCY_SCHEMA

SCHEMA = "jobs"

STAGES = ("queued", "running", "completed", "unparseable", "failed", "aborted")
#: Stages in which an investigation holds its alert: at most one per alert.
LIVE = ("queued", "running")
TERMINAL = tuple(stage for stage in STAGES if stage not in LIVE)

_TIME = DateTime(timezone=True)

#: An owner's evidence state (#1546 A-O4): written by the applier when the row ends, afterwards only to `expired` by the
#: retention sweep. Null exactly while the row is queued or running (a check).
EVIDENCE_STATES = ("complete", "partial", "none", "lost", "expired")
#: A run's scrub verdict (#1546 A-O10, D2): only `clean` is usable.
SCRUB_VERDICTS = ("clean", "tainted", "not_run")
#: An upload row's status (#1546 A-O3): inserted `pending` before its PUT, then `uploaded` or `refused`, once.
UPLOAD_STATUSES = ("pending", "uploaded", "refused")


def _quoted(values: tuple[str, ...]) -> str:
    return ", ".join(repr(v) for v in values)


#: The alert's outcome copy is all set or all null (#1581).
OUTCOME_COPY_WHOLE = ("(outcome IS NULL) = (outcome_investigation_id IS NULL) "
                      "AND (outcome IS NULL) = (outcome_created_at IS NULL)")


class AlertRow(Base, kw_only=True):
    __tablename__ = "alerts"
    __table_args__ = (
        ForeignKeyConstraint(["tenant_id"], [f"{TENANCY_SCHEMA}.tenants.id"]),
        # The target of investigations' composite key: an investigation cannot name another tenant's alert.
        UniqueConstraint("tenant_id", "id"),
        UniqueConstraint("tenant_id", "vendor", "vendor_ticket_id"),
        Index("alerts_newest_first", "tenant_id", text("fired_at DESC"), text("id DESC")),
        # #1581: the outcome filter is a range of this index; `outcome IS NULL` uses it too.
        Index("alerts_outcome_newest_first", "tenant_id", "outcome", text("fired_at DESC"), text("id DESC")),
        CheckConstraint(OUTCOME_COPY_WHOLE, name="outcome_copy_whole"),
        CheckConstraint(f"outcome IN ({_quoted(DISPOSITION_VALUES)})", name="outcome"),
        {"schema": SCHEMA},
    )

    id: Mapped[AlertId] = mapped_column(IdColumn(AlertId), primary_key=True)
    tenant_id: Mapped[TenantId] = mapped_column(IdColumn(TenantId))
    vendor: Mapped[str] = mapped_column(Text)
    vendor_ticket_id: Mapped[str] = mapped_column(Text)
    fired_at: Mapped[_dt.datetime] = mapped_column(_TIME)
    changed_at: Mapped[_dt.datetime] = mapped_column(_TIME)
    received_at: Mapped[_dt.datetime] = mapped_column(_TIME)
    #: Derived by the store from `raw` through the tenant's alert mapping when the alert is stored, and never rewritten
    #: by a later save of the mapping (#1345 O2, #1420); null when the tenant had no mapping then, or unmapped or unusable.
    title: Mapped[str | None] = mapped_column(Text)
    description: Mapped[str | None] = mapped_column(Text)
    raw: Mapped[bytes] = mapped_column(LargeBinary)
    #: A copy of O1's answer (#1581 AP1): the disposition of the alert's newest `completed` investigation by
    #: `(created_at, id)`, with that investigation's id and `created_at` (its source); all three null when none has
    #: completed. Only the store's `finish` and investigation delete write them (`store.py`), each with one conditional
    #: update judged against the stored source. The investigations own the facts; this exists so the list's outcome
    #: filter is an index range.
    outcome: Mapped[str | None] = mapped_column(Text, default=None)
    outcome_investigation_id: Mapped[InvestigationId | None] = mapped_column(IdColumn(InvestigationId), default=None)
    outcome_created_at: Mapped[_dt.datetime | None] = mapped_column(_TIME, default=None)


class InvestigationRow(Base, kw_only=True):
    __tablename__ = "investigations"
    __table_args__ = (
        ForeignKeyConstraint(["tenant_id", "alert_id"], [f"{SCHEMA}.alerts.tenant_id", f"{SCHEMA}.alerts.id"]),
        UniqueConstraint("tenant_id", "alert_id", "request_key", "attempt"),
        CheckConstraint(f"stage IN ({_quoted(STAGES)})", name="stage"),
        CheckConstraint("stage <> 'running' OR lease_expires_at IS NOT NULL", name="running_has_a_lease"),
        CheckConstraint("NOT cost_is_lower_limit OR cost_usd IS NOT NULL", name="lower_limit_has_a_cost"),
        # #1581 O10: a completed investigation always has a disposition, one of the vocabulary's.
        CheckConstraint("stage <> 'completed' OR disposition IS NOT NULL", name="completed_has_a_disposition"),
        CheckConstraint(f"disposition IN ({_quoted(DISPOSITION_VALUES)})", name="disposition"),
        # #1546 A-O4, A-O10: an ended row has an evidence state and a scrub verdict, a live one neither.
        CheckConstraint(f"evidence_state IN ({_quoted(EVIDENCE_STATES)})", name="evidence_state"),
        CheckConstraint(f"scrub IN ({_quoted(SCRUB_VERDICTS)})", name="scrub"),
        CheckConstraint(f"(stage IN ({_quoted(LIVE)})) = (evidence_state IS NULL) "
                        f"AND (stage IN ({_quoted(LIVE)})) = (scrub IS NULL)", name="ended_has_evidence"),
        # #1546 r9 (D16): every new investigation names its tenant's retention row, `NOT VALID` (an offboarded tenant may
        # keep investigations and have no row): `0029_retention_required`'s.
        ForeignKeyConstraint(["tenant_id"], [f"{TENANCY_SCHEMA}.evidence_retention.tenant_id"], use_alter=True,
                             postgresql_not_valid=True),
        Index("investigations_one_live_per_alert", "tenant_id", "alert_id", unique=True,
              postgresql_where=text(f"stage IN ({_quoted(LIVE)})")),
        Index("investigations_newest_first", "tenant_id", text("created_at DESC"), text("id DESC")),
        # #1581: the alert list's `latest_status`, one alert's newest investigation, is the first entry of this index.
        Index("investigations_alert_newest_first", "tenant_id", "alert_id", text("created_at DESC"), text("id DESC")),
        {"schema": SCHEMA},
    )

    id: Mapped[InvestigationId] = mapped_column(IdColumn(InvestigationId), primary_key=True)
    tenant_id: Mapped[TenantId] = mapped_column(IdColumn(TenantId))
    alert_id: Mapped[AlertId] = mapped_column(IdColumn(AlertId))
    request_key: Mapped[str] = mapped_column(Text)
    attempt: Mapped[int] = mapped_column(Integer)
    stage: Mapped[str] = mapped_column(Text)
    created_at: Mapped[_dt.datetime] = mapped_column(_TIME)
    started_at: Mapped[_dt.datetime | None] = mapped_column(_TIME, default=None)
    finished_at: Mapped[_dt.datetime | None] = mapped_column(_TIME, default=None)
    disposition: Mapped[str | None] = mapped_column(Text, default=None)
    #: Null only when unknown (a cost read that faulted); 0 until the end.
    cost_usd: Mapped[float | None] = mapped_column(Float, default=None)
    #: True when the cost is only a lower limit ("at least": spend may be missing from it, #1377 S2);
    #: never true beside a null cost (the table's check).
    cost_is_lower_limit: Mapped[bool] = mapped_column(Boolean, default=False)
    #: The API's mapped shape (`status`, `commit`, `stale_kind`), or null.
    knowledge: Mapped[dict[str, Any] | None] = mapped_column(JSONB(none_as_null=True), default=None)
    failure_reason: Mapped[str | None] = mapped_column(Text, default=None)
    failure_message: Mapped[str | None] = mapped_column(Text, default=None)
    #: When the holder's claim lapses (by the database's clock); a running row always has one (#1343 B1).
    lease_expires_at: Mapped[_dt.datetime | None] = mapped_column(_TIME, default=None)
    #: When the holder gave the running row back (`apply` of a hand-back), so no renewal covers it and its take-over says
    #: so; set on an ended row too, by the applier. Internal (#1343 B-P2).
    accounting_written_at: Mapped[_dt.datetime | None] = mapped_column(_TIME, default=None)
    #: Whether the investigation posts to its ticket (#1471 W1): set at create, copied by a retry.
    update_ticket: Mapped[bool] = mapped_column(Boolean)
    #: `EVIDENCE_STATES` once ended (#1546 A-O4), null while live.
    evidence_state: Mapped[str | None] = mapped_column(Text, default=None)
    #: The run's scrub verdict once ended (#1546 A-O10), null while live; `not_run` when no outcome said otherwise.
    scrub: Mapped[str | None] = mapped_column(Text, default=None)


_LEARNING_LIVE = ("queued", "running")
LEARNING_TERMINAL = ("completed", "failed", "skipped")
LEARNING_STATUSES = (*_LEARNING_LIVE, *LEARNING_TERMINAL)
LEARNING_TRIGGERS = ("auto", "explicit")
#: Whether a job's findings reached the queue (#1344, #1487): `none` for a job not ended `completed`; set by the
#: `completed` end write itself, `done` with its findings stored, or `refused` with none of them stored.
PUBLISH_STATES = ("none", "done", "refused")


class LearningJobRow(Base, kw_only=True):
    """One attempt of a learning job (#1344): attempts of one request share its request key and
    are numbered 1, 2, 3; a retry is a new row. The worker copies the job entry's progress record
    onto a running row and its end record onto the row it ends; nothing here is resumed from."""

    __tablename__ = "learning_jobs"
    __table_args__ = (
        ForeignKeyConstraint(["tenant_id", "alert_id"], [f"{SCHEMA}.alerts.tenant_id", f"{SCHEMA}.alerts.id"]),
        # No ON DELETE action: the investigation delete removes its jobs itself, under their row locks (O10).
        ForeignKeyConstraint(["investigation_id"], [f"{SCHEMA}.investigations.id"]),
        UniqueConstraint("tenant_id", "investigation_id", "request_key", "attempt"),
        CheckConstraint(f"status IN ({_quoted(LEARNING_STATUSES)})", name="status"),
        CheckConstraint(f"trigger IN ({_quoted(LEARNING_TRIGGERS)})", name="trigger"),
        CheckConstraint(f"publish_state IN ({_quoted(PUBLISH_STATES)})", name="publish_state"),
        CheckConstraint("status <> 'running' OR lease_expires_at IS NOT NULL", name="running_has_a_lease"),
        CheckConstraint(f"evidence_state IN ({_quoted(EVIDENCE_STATES)})", name="evidence_state"),
        CheckConstraint(f"(status IN ({_quoted(_LEARNING_LIVE)})) = (evidence_state IS NULL)", name="ended_has_evidence"),
        Index("learning_jobs_queued_by_age", "created_at", "id", postgresql_where=text("status = 'queued'")),
        Index("learning_jobs_running_by_lease", "lease_expires_at", "id", postgresql_where=text("status = 'running'")),
        Index("learning_jobs_by_investigation", "investigation_id"),
        Index("learning_jobs_newest_first", "tenant_id", text("created_at DESC"), text("id DESC")),
        {"schema": SCHEMA},
    )

    id: Mapped[LearningJobId] = mapped_column(IdColumn(LearningJobId), primary_key=True)
    tenant_id: Mapped[TenantId] = mapped_column(IdColumn(TenantId))
    alert_id: Mapped[AlertId] = mapped_column(IdColumn(AlertId))
    investigation_id: Mapped[InvestigationId] = mapped_column(IdColumn(InvestigationId))
    request_key: Mapped[str] = mapped_column(Text)
    attempt: Mapped[int] = mapped_column(Integer)
    trigger: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(Text)
    created_at: Mapped[_dt.datetime] = mapped_column(_TIME)
    #: The family step's progress, read-only (never resumed from).
    stage: Mapped[str | None] = mapped_column(Text, default=None)
    fork_message_id: Mapped[str | None] = mapped_column(Text, default=None)
    #: The siblings' own cost so far, then final: partial, without the questioner, oracle and judge (O13).
    sibling_cost_usd: Mapped[float] = mapped_column(Float, default=0.0)
    publish_state: Mapped[str] = mapped_column(Text, default="none")
    started_at: Mapped[_dt.datetime | None] = mapped_column(_TIME, default=None)
    #: Set at the end; on a `running` row, the mark of a hand-back, which no renewal covers.
    finished_at: Mapped[_dt.datetime | None] = mapped_column(_TIME, default=None)
    reason: Mapped[str | None] = mapped_column(Text, default=None)
    message: Mapped[str | None] = mapped_column(Text, default=None)
    lease_expires_at: Mapped[_dt.datetime | None] = mapped_column(_TIME, default=None)
    #: `EVIDENCE_STATES` once ended (#1546 A-O4), null while live.
    evidence_state: Mapped[str | None] = mapped_column(Text, default=None)
    #: The sibling cost is only a lower limit (#1546 D15): after an offboard or a take-over it is the last staged progress.
    #: The one column with a server default (false), which `0027_run_evidence` gave every existing row.
    sibling_cost_is_lower_limit: Mapped[bool] = mapped_column(Boolean, default=False, server_default=false())


class LearningCheckRow(Base, kw_only=True):
    """A tenant's family-less check clock (#1344 amendment 3): when its last post-step ended (or
    when a queued job armed it), whether that post-step found nothing waiting, and which
    post-step holds it now, and until when. Times are the database's clock, as a lease's are."""

    __tablename__ = "learning_checks"
    __table_args__ = (
        # No ON DELETE action, as every jobs table (M10).
        ForeignKeyConstraint(["tenant_id"], [f"{TENANCY_SCHEMA}.tenants.id"]),
        {"schema": SCHEMA},
    )

    tenant_id: Mapped[TenantId] = mapped_column(IdColumn(TenantId), primary_key=True)
    checked_at: Mapped[_dt.datetime] = mapped_column(_TIME)
    #: The last post-step found nothing waiting: no check is due until a job arms the row again.
    idle: Mapped[bool] = mapped_column(Boolean)
    #: A post-step of the tenant holds the row until then; renewed like a lease. NULL when none.
    checking_until: Mapped[_dt.datetime | None] = mapped_column(_TIME, default=None)
    #: The hold's token, minted by the worker that took it: only it renews or lets go of the hold.
    holder: Mapped[str | None] = mapped_column(Text, default=None)
    #: A job ended `completed` while a post-step held the row (live or lapsed, #1487 O7): set only by that end's arm,
    #: cleared by a new hold; the hold's end then makes the tenant due at once, whatever its own post-step found.
    armed_while_held: Mapped[bool] = mapped_column(Boolean, default=False)


#: A host request's stages (#1471 R2): it ends `completed` with its kind's result, or `failed` with a fixed reason.
HOST_REQUEST_STAGES = ("queued", "running", "completed", "failed")
HOST_REQUEST_LIVE = ("queued", "running")
#: The host-request kinds (#1471): the table's `kind`, the helper's `--kind` and the launch facts' `kind`. A drain (#1546
#: D7) is the lead-author lane's tick, queued by the operator command.
READINESS, ADOPTION, DRAIN = "readiness", "adoption", "drain"
HOST_REQUEST_KINDS = (READINESS, ADOPTION, DRAIN)


class HostRequestRow(Base, kw_only=True):
    """One short host request (#1471): a readiness check of a tenant, or an adoption of a system's base files. A request
    is never retried (B2): it runs once, and ends `completed` with its kind's result or `failed` with a fixed reason and
    the worker's own words. At most one row of a kind and dedupe key is queued (readiness: the tenant; adoption:
    `<tenant>/<system>`); a running or ended one dedupes nothing. `0026_host_requests` creates it."""

    __tablename__ = "host_requests"
    __table_args__ = (
        # No ON DELETE action, as every jobs table (M10): a tenant row is never deleted.
        ForeignKeyConstraint(["tenant_id"], [f"{TENANCY_SCHEMA}.tenants.id"]),
        CheckConstraint(f"stage IN ({_quoted(HOST_REQUEST_STAGES)})", name="stage"),
        CheckConstraint(f"kind IN ({_quoted(HOST_REQUEST_KINDS)})", name="kind"),
        CheckConstraint("stage <> 'running' OR lease_expires_at IS NOT NULL", name="running_has_a_lease"),
        Index("host_requests_one_queued_per_key", "kind", "dedupe_key", unique=True,
              postgresql_where=text("stage = 'queued'")),
        Index("host_requests_queued_by_age", "created_at", "id", postgresql_where=text("stage = 'queued'")),
        Index("host_requests_running_by_lease", "lease_expires_at", "id", postgresql_where=text("stage = 'running'")),
        Index("host_requests_live_by_tenant", "tenant_id", postgresql_where=text(f"stage IN ({_quoted(HOST_REQUEST_LIVE)})")),
        # #1546 D7: at most one drain queued or running per tenant, whatever its dedupe key.
        Index("host_requests_one_live_drain_per_tenant", "tenant_id", unique=True,
              postgresql_where=text(f"kind = '{DRAIN}' AND stage IN ({_quoted(HOST_REQUEST_LIVE)})")),
        {"schema": SCHEMA},
    )

    id: Mapped[HostRequestId] = mapped_column(IdColumn(HostRequestId), primary_key=True)
    tenant_id: Mapped[TenantId] = mapped_column(IdColumn(TenantId))
    kind: Mapped[str] = mapped_column(Text)
    dedupe_key: Mapped[str] = mapped_column(Text)
    #: The adopted system; null for a readiness check.
    system_id: Mapped[str | None] = mapped_column(Text, default=None)
    requester: Mapped[str] = mapped_column(Text)
    created_at: Mapped[_dt.datetime] = mapped_column(_TIME)
    started_at: Mapped[_dt.datetime | None] = mapped_column(_TIME, default=None)
    finished_at: Mapped[_dt.datetime | None] = mapped_column(_TIME, default=None)
    stage: Mapped[str] = mapped_column(Text)
    lease_expires_at: Mapped[_dt.datetime | None] = mapped_column(_TIME, default=None)
    #: The kind's result, validated by the worker: set exactly on a `completed` row (a drain's is its tick's exit status).
    result: Mapped[dict[str, Any] | int | None] = mapped_column(JSONB(none_as_null=True), default=None)
    failure_reason: Mapped[str | None] = mapped_column(Text, default=None)
    failure_message: Mapped[str | None] = mapped_column(Text, default=None)


#: A claim's kinds (#1546 PR7): every launched child's; the host-request kinds take their request row as reference.
INVESTIGATION_CLAIM, LEARNING_CLAIM, POST_STEP_CLAIM = "investigation", "learning", "post-step"
CLAIM_KINDS = (INVESTIGATION_CLAIM, LEARNING_CLAIM, *HOST_REQUEST_KINDS, POST_STEP_CLAIM)
#: Each claim kind's lease-reference column.
CLAIM_REFERENCE = {INVESTIGATION_CLAIM: "investigation_id", LEARNING_CLAIM: "learning_job_id",
                   **{kind: "host_request_id" for kind in HOST_REQUEST_KINDS}, POST_STEP_CLAIM: "hold_tenant_id"}
_REFERENCES = ("investigation_id", "learning_job_id", "host_request_id", "hold_tenant_id")


def _names_only(column: str) -> str:
    return " AND ".join(f"{c} IS {'NOT ' if c == column else ''}NULL" for c in _REFERENCES)


_KIND_REFERENCE = " OR ".join(
    f"(kind IN ({_quoted(tuple(k for k, c in CLAIM_REFERENCE.items() if c == column))}) AND {_names_only(column)})"
    for column in _REFERENCES)


class ClaimRow(Base, kw_only=True):
    """One launched child's claim (#1546 PR7): its token, minted by the store in the claim's own transaction (the folders,
    labels and every staged fact and upload name it), its tenant, its kind and exactly that kind's lease reference, the
    launch facts and the `(owner, object)` input set it may pull (never null; empty for every kind but a learning job and a
    drain). Only the claim names its reference: a row is claimed at most once (one claim per owner or request row, an
    index); a post-step hold is one reused row, its claims told apart by the hold's `holder`. `0027_run_evidence`."""

    __tablename__ = "claims"
    __table_args__ = (
        # No ON DELETE action, as every jobs table (M10): the investigation delete removes its claims itself.
        ForeignKeyConstraint(["tenant_id"], [f"{TENANCY_SCHEMA}.tenants.id"]),
        ForeignKeyConstraint(["investigation_id"], [f"{SCHEMA}.investigations.id"]),
        ForeignKeyConstraint(["learning_job_id"], [f"{SCHEMA}.learning_jobs.id"]),
        ForeignKeyConstraint(["host_request_id"], [f"{SCHEMA}.host_requests.id"]),
        ForeignKeyConstraint(["hold_tenant_id"], [f"{SCHEMA}.learning_checks.tenant_id"]),
        CheckConstraint(f"kind IN ({_quoted(CLAIM_KINDS)})", name="kind"),
        CheckConstraint(_KIND_REFERENCE, name="kind_names_its_reference"),
        *(Index(f"claims_one_per_{column}", column, unique=True, postgresql_where=text(f"{column} IS NOT NULL"))
          for column in ("investigation_id", "learning_job_id", "host_request_id")),
        Index("claims_by_tenant", "tenant_id"),
        {"schema": SCHEMA},
    )

    token: Mapped[str] = mapped_column(Text, primary_key=True)
    tenant_id: Mapped[TenantId] = mapped_column(IdColumn(TenantId))
    kind: Mapped[str] = mapped_column(Text)
    inputs: Mapped[list[dict[str, Any]]] = mapped_column(JSONB)
    investigation_id: Mapped[InvestigationId | None] = mapped_column(IdColumn(InvestigationId), default=None)
    learning_job_id: Mapped[LearningJobId | None] = mapped_column(IdColumn(LearningJobId), default=None)
    host_request_id: Mapped[HostRequestId | None] = mapped_column(IdColumn(HostRequestId), default=None)
    hold_tenant_id: Mapped[TenantId | None] = mapped_column(IdColumn(TenantId), default=None)
    #: The claim's launch facts (the alert reference, the knowledge pin); nulled by the offboarding pass.
    launch: Mapped[dict[str, Any] | None] = mapped_column(JSONB(none_as_null=True), default=None)
    #: Set by the store at the claim; null only on a row planted without it.
    created_at: Mapped[_dt.datetime | None] = mapped_column(_TIME, default=None)


class StagedFactRow(Base, kw_only=True):
    """One fact the claim's helper staged (#1546), a closed typed value it parsed and screened on receipt (PR2): create-once
    by `(token, name)` except `progress`, the one replaced fact. Written only while the claim is live (PR7)."""

    __tablename__ = "staged_facts"
    __table_args__ = (
        ForeignKeyConstraint(["token"], [f"{SCHEMA}.claims.token"]),
        {"schema": SCHEMA},
    )

    token: Mapped[str] = mapped_column(Text, primary_key=True)
    name: Mapped[str] = mapped_column(Text, primary_key=True)
    body: Mapped[Any] = mapped_column(JSONB)
    staged_at: Mapped[_dt.datetime] = mapped_column(_TIME)


class UploadRow(Base, kw_only=True):
    """One object the claim's helper put in the evidence store (#1546 A-O3): create-once by `(token, object)`, inserted
    `pending` before its PUT and moved once to `uploaded` or `refused` (or made `refused` at once, with nothing computed, for
    an object the helper could not put at all), each only while the claim is live; `accepted_at` is
    set by the applier alone, when the owner's ending promotes it, and an accepted row never changes. An arm page's row
    copies its arm's `scrub`."""

    __tablename__ = "uploads"
    __table_args__ = (
        ForeignKeyConstraint(["token"], [f"{SCHEMA}.claims.token"]),
        CheckConstraint(f"status IN ({_quoted(UPLOAD_STATUSES)})", name="status"),
        CheckConstraint(f"scrub IN ({_quoted(SCRUB_VERDICTS)})", name="scrub"),
        CheckConstraint("size >= 0", name="size"),
        CheckConstraint("status = 'refused' OR (size IS NOT NULL AND sha256 IS NOT NULL AND wrapped_key IS NOT NULL)",
                        name="computed_unless_refused"),
        CheckConstraint("accepted_at IS NULL OR status = 'uploaded'", name="only_uploaded_is_accepted"),
        Index("uploads_unaccepted_by_age", "created_at", postgresql_where=text("accepted_at IS NULL")),
        Index("uploads_accepted_by_age", "accepted_at", postgresql_where=text("accepted_at IS NOT NULL")),
        {"schema": SCHEMA},
    )

    token: Mapped[str] = mapped_column(Text, primary_key=True)
    object: Mapped[str] = mapped_column(Text, primary_key=True)
    #: Size, digest and wrapped data key, computed by the helper before the PUT; null only on a row refused before any
    #: was (`refuse_upload`).
    size: Mapped[int | None] = mapped_column(BigInteger)
    sha256: Mapped[str | None] = mapped_column(Text)
    wrapped_key: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(Text)
    created_at: Mapped[_dt.datetime] = mapped_column(_TIME)
    scrub: Mapped[str | None] = mapped_column(Text, default=None)
    accepted_at: Mapped[_dt.datetime | None] = mapped_column(_TIME, default=None)


class _Token:
    """A claim's token (#1546 PR7), minted by the store in the claim's own transaction: kept beside the claim's fields,
    not among them, so the claim's dataclass fields stay its record and state."""

    @property
    def token(self) -> str:
        return self.__dict__["_token"]


def with_token(claim: Any, token: str) -> Any:
    """`claim` carrying `token` (the store's one way to set it on a frozen claim)."""
    object.__setattr__(claim, "_token", token)
    return claim


@dataclasses.dataclass(frozen=True)
class LearningCheckClaim:
    """A tenant's family-less check clock, held for its post-step (#1344 amendment 3): the tenant and the hold's token,
    which is the post-step's claim token (#1546 PR7)."""

    tenant_id: TenantId
    token: str


@model(frozen=True)
class HostRequestRecord:
    """A host request as read (#1471): the row's fields, in the store's words; `request_id` is the row's id."""

    request_id: HostRequestId
    tenant_id: TenantId
    kind: str
    system_id: str | None
    stage: str
    requester: str
    created_at: _dt.datetime
    started_at: _dt.datetime | None
    finished_at: _dt.datetime | None
    #: A readiness or adoption result's record; a drain's tick exit status (#1546 amendment r9 "Drain").
    result: dict[str, Any] | int | None
    failure_reason: str | None
    failure_message: str | None


@dataclasses.dataclass(frozen=True)
class HostRequestClaim(_Token):
    """A claimed host request. No tenant state is read with it: the worker starts the request's helper whatever the
    state, and the helper's own tenant admission refuses a tenant that is not active."""

    record: HostRequestRecord


#: Evidence states whose accepted objects may be read (#1546 A-O6): an owner `none` or `expired` has none.
READABLE_EVIDENCE = ("complete", "partial", "lost")


@dataclasses.dataclass(frozen=True)
class ClaimView:
    """A claim row as its helper reads it (#1546 PR7): its token, tenant, kind, fixed input set `(owner, object)`, launch
    facts and the id of the row (or hold tenant) it references."""

    token: str
    tenant_id: str
    kind: str
    inputs: tuple[tuple[str, str], ...]
    launch: dict[str, Any]
    reference: str | None


@dataclasses.dataclass(frozen=True)
class AcceptedObject:
    """One accepted object of an owner (#1546 A-O6): the owner's kind (`investigation` or `learning`), the claim it was
    uploaded under, its recorded size and digest, and its wrapped data key."""

    owner_kind: str
    claim: str
    size: int
    sha256: str
    wrapped_key: str


def claim_view(row: ClaimRow) -> ClaimView:
    reference = row.investigation_id or row.learning_job_id or row.host_request_id or row.hold_tenant_id
    raw = row.inputs if isinstance(row.inputs, list) else []
    inputs = tuple((str(i["owner"]), str(i["object"])) for i in raw
                   if isinstance(i, dict) and isinstance(i.get("owner"), str) and isinstance(i.get("object"), str))
    return ClaimView(token=row.token, tenant_id=str(row.tenant_id), kind=row.kind, inputs=inputs,
                     launch=dict(row.launch) if isinstance(row.launch, dict) else {},
                     reference=None if reference is None else str(reference))


def host_request_record(row: HostRequestRow) -> HostRequestRecord:
    return HostRequestRecord(
        request_id=row.id, tenant_id=row.tenant_id, kind=row.kind, system_id=row.system_id, stage=row.stage,
        requester=row.requester, created_at=row.created_at, started_at=row.started_at, finished_at=row.finished_at,
        result=row.result, failure_reason=row.failure_reason, failure_message=row.failure_message)


@model(frozen=True)
class AlertListing:
    """An alert as a list shows it: every stored field but `raw`, which a list never reads (#1507), and what its
    investigations concluded (#1581). `outcome` is the stored copy of the newest completed investigation's disposition;
    `latest_status` the newest investigation's stage; each None when there is no such investigation."""

    alert_id: AlertId
    tenant_id: TenantId
    vendor: str
    vendor_ticket_id: str
    fired_at: _dt.datetime
    changed_at: _dt.datetime
    received_at: _dt.datetime
    title: str | None
    description: str | None
    outcome: Disposition | None
    latest_status: str | None


@model(frozen=True)
class StoredAlert:
    """An alert as read. `raw` is the exact bytes inserted."""

    alert_id: AlertId
    tenant_id: TenantId
    vendor: str
    vendor_ticket_id: str
    fired_at: _dt.datetime
    changed_at: _dt.datetime
    received_at: _dt.datetime
    title: str | None
    description: str | None
    raw: bytes


@model(frozen=True)
class InvestigationRecord:
    """An investigation as read: the wire model's fields, in the store's words."""

    investigation_id: InvestigationId
    tenant_id: TenantId
    alert_id: AlertId
    request_key: str
    attempt: int
    stage: str
    created_at: _dt.datetime
    started_at: _dt.datetime | None
    finished_at: _dt.datetime | None
    disposition: str | None
    cost_usd: float | None
    cost_is_lower_limit: bool
    knowledge: dict[str, Any] | None
    failure_reason: str | None
    failure_message: str | None
    update_ticket: bool


@dataclasses.dataclass(frozen=True)
class Claim(_Token):
    """A claimed investigation and its tenant's state, read in the claim's own transaction
    (#1342 r7 R7-1): the worker starts a job only for an `active` tenant."""

    record: InvestigationRecord
    tenant_state: str


@model(frozen=True)
class LearningJobRecord:
    """A learning job attempt as read."""

    learning_job_id: LearningJobId
    tenant_id: TenantId
    alert_id: AlertId
    investigation_id: InvestigationId
    request_key: str
    attempt: int
    trigger: str
    status: str
    stage: str | None
    fork_message_id: str | None
    sibling_cost_usd: float
    publish_state: str
    created_at: _dt.datetime
    started_at: _dt.datetime | None
    finished_at: _dt.datetime | None
    reason: str | None
    message: str | None
    #: The sibling cost is only a lower limit (#1546 D15).
    sibling_cost_is_lower_limit: bool = False


class LearningProgress(Protocol):
    """What the job entry's records say of a family step (its progress or end record, as
    `records.job_lane` reads them): the fork pick, the stage and the siblings' cost. The worker
    copies it onto the running row, and onto the row it ends."""

    @property
    def fork_message_id(self) -> str | None: ...

    @property
    def stage(self) -> str | None: ...

    @property
    def sibling_cost_usd(self) -> float: ...


@dataclasses.dataclass(frozen=True)
class LearningClaim(_Token):
    """A claimed learning job and its tenant's state, read in the claim's own transaction."""

    record: LearningJobRecord
    tenant_state: str


def learning_job_record(row: LearningJobRow) -> LearningJobRecord:
    return LearningJobRecord(
        learning_job_id=row.id, tenant_id=row.tenant_id, alert_id=row.alert_id, investigation_id=row.investigation_id,
        request_key=row.request_key, attempt=row.attempt, trigger=row.trigger, status=row.status, stage=row.stage,
        fork_message_id=row.fork_message_id, sibling_cost_usd=row.sibling_cost_usd,
        publish_state=row.publish_state, created_at=row.created_at,
        started_at=row.started_at, finished_at=row.finished_at, reason=row.reason, message=row.message,
        sibling_cost_is_lower_limit=row.sibling_cost_is_lower_limit)


#: The columns an alert list selects: every column but `raw` (#1507).
#: Every alert column a list reads: all but `raw` (#1507) and the two that only keep the stored outcome in step with its
#: source investigation (#1581), which no read shows. The list's query adds `latest_status` beside them.
ALERT_LISTING_COLUMNS = tuple(column for column in AlertRow.__table__.columns
                              if column.key not in ("raw", "outcome_investigation_id", "outcome_created_at"))


def alert_listing(row: Row[Any]) -> AlertListing:
    """An `AlertListing` from a row of `ALERT_LISTING_COLUMNS` and `latest_status`, each field the column of its name
    (`alert_id` is `id`): a column the record lacks, or a field no column fills, is a `TypeError`, never a field left at
    a default."""
    values = dict(row._mapping)
    values["alert_id"] = values.pop("id")
    return AlertListing(**values)


def stored_alert(row: AlertRow) -> StoredAlert:
    return StoredAlert(
        alert_id=row.id, tenant_id=row.tenant_id, vendor=row.vendor, vendor_ticket_id=row.vendor_ticket_id,
        fired_at=row.fired_at, changed_at=row.changed_at, received_at=row.received_at, title=row.title,
        description=row.description, raw=bytes(row.raw))


def is_terminal(stage: str) -> bool:
    """Whether `stage` is one a row ends in (the one place that tests membership of `TERMINAL`)."""
    return stage in TERMINAL


def investigation_record(row: InvestigationRow) -> InvestigationRecord:
    return InvestigationRecord(
        investigation_id=row.id, tenant_id=row.tenant_id, alert_id=row.alert_id, request_key=row.request_key,
        attempt=row.attempt, stage=row.stage, created_at=row.created_at, started_at=row.started_at,
        finished_at=row.finished_at, disposition=row.disposition, cost_usd=row.cost_usd,
        cost_is_lower_limit=row.cost_is_lower_limit,  # stored by the applier, never derived on read (#1546 D15)
        knowledge=row.knowledge, failure_reason=row.failure_reason, failure_message=row.failure_message,
        update_ticket=row.update_ticket)
