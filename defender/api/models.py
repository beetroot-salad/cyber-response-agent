"""The API's wire shapes: what a request may carry and what a response says."""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import (
    AfterValidator, AwareDatetime, BaseModel, BeforeValidator, ConfigDict, Field, field_validator,
    model_validator,
)

from defender._clock import as_utc
from defender._text import postgres_can_hold
from defender.kit.access import secret_fields
from defender._vocab import DISPOSITION_VALUES, normalized_disposition
from defender.identity.models import Email
from defender.records.formats import (
    AlertId, AlertMappingFault, InvestigationId, LearningJobId, MembershipId, TenantId, UserId, check_mapping,
)

InvestigationStatus = Literal["queued", "running", "completed", "unparseable", "failed", "aborted"]

LearningJobStatus = Literal["queued", "running", "completed", "failed", "skipped"]

#: What a tenant-chosen name may be (a system id), and the lesson id and page cursor: the same
#: grammar in a path segment and in a request body, and ASCII only, so it is always safe to put back
#: into a URL or a header. An id the system mints is not one of these: it is its family's type
#: (`TenantId`, `AlertId`, ...), whose grammar is canonical UUID text (#1382).
RECORD_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"
RecordId = Annotated[str, Field(pattern=RECORD_ID_PATTERN)]

def _refuse_unstorable_id(value: str) -> str:
    """Refuse text PostgreSQL cannot hold, here rather than at the store (#1379 O1a)."""
    if not postgres_can_hold(value):
        raise ValueError("it holds a NUL or a lone surrogate, which cannot be stored")
    return value


#: The id a caller mints once per user action, so a retried or double-clicked create
#: returns the record the first attempt made.
ClientRequestId = Annotated[str, Field(
    min_length=1, max_length=200,
    description="Minted once per user action. Repeating the request with it answers the latest "
                "attempt of the request this id started; a request answered with an investigation "
                "already live started nothing, so repeating it is a new request.",
), AfterValidator(_refuse_unstorable_id)]


def _not_a_number(value: object) -> object:
    """Refuse a number where a moment is due: pydantic's lax datetime reads one as seconds since
    1970, so a compact date like `20260928` would silently become a time in 1970."""
    if isinstance(value, bool | int | float):
        raise ValueError("a moment is an RFC 3339 date-time, not a number")
    if isinstance(value, str):
        try:
            float(value)
        except ValueError:
            return value
        raise ValueError("a moment is an RFC 3339 date-time, not a number")
    return value


#: A moment, as every channel carries it: aware, never a bare number, and in UTC.
Instant = Annotated[AwareDatetime, BeforeValidator(_not_a_number), AfterValidator(as_utc)]

#: A credential's field name: it reaches the audit detail, so it is plain ASCII that any audit
#: store accepts — never a NUL or a lone surrogate that would fail the audit write.
CredentialKey = Annotated[str, Field(pattern=r"^[A-Za-z][A-Za-z0-9_.-]{0,63}$")]


class _Request(BaseModel):
    model_config = ConfigDict(extra="forbid")


class AlertSummary(BaseModel):
    """An alert as listed. The raw alert is left out of lists; `GET /alerts/{id}` carries it."""

    alert_id: AlertId
    vendor: str = Field(description="The ticket system the alert was pulled from.")
    vendor_ticket_id: str = Field(description="The vendor's own id; unique per tenant and vendor.")
    title: str | None = Field(description="Derived from the raw alert through the tenant's alert mapping; null when unmapped or unusable.")
    description: str | None = Field(description="As `title`.")
    fired_at: Instant = Field(description="When the vendor says the alert fired.")
    changed_at: Instant = Field(description="When the vendor last changed the ticket.")
    received_at: Instant = Field(description="When we pulled it; our own clock.")


class Alert(AlertSummary):
    raw: str = Field(description="The alert's text exactly as the vendor sent it: not parsed, not re-serialized.")


KnowledgeStatus = Literal["current", "stale", "pinned"]
StaleKind = Literal["transient", "operator"]


class InvestigationKnowledge(BaseModel):
    """Which revision of the tenant's knowledge the investigation's run read (#1108 P4, O-WARN):
    the latest approved one (`current`), an earlier one because the newer could not be loaded
    (`stale`, with why in two words), or one named at launch (`pinned`)."""

    status: KnowledgeStatus
    commit: str | None = Field(
        description="The knowledge commit the run read; null only when its record is unreadable.")
    stale_kind: StaleKind | None = Field(
        default=None,
        description="Set iff `status` is `stale`: `transient` (a temporary outage) or `operator` "
                    "(awaiting operator action).")


class Investigation(BaseModel):
    investigation_id: InvestigationId
    alert_id: AlertId
    status: InvestigationStatus
    request_key: str = Field(
        description="The `client_request_id` of the request this investigation answers.")
    attempt: int = Field(description="Which attempt of the request this is; the first is 1.")
    disposition: str | None = Field(
        default=None,
        description="Set once the investigation completes with a readable report.",
        json_schema_extra={"enum": [*DISPOSITION_VALUES, None]},
    )
    cost_usd: float | None = Field(
        description="Model cost so far while the investigation is live (0 until its first update), "
                    "final once the status is terminal and its worker has written its last figure; "
                    "null when the run ended but its cost could not be read (unknown).")
    created_at: Instant
    started_at: Instant | None = None
    finished_at: Instant | None = None
    failure_reason: str | None = Field(
        default=None,
        description="Set when the investigation failed or was aborted: a fixed reason such as "
                    "`setup_refused`, `no_report`, `worker_error`, `cancelled`, `lease_lapsed` (its worker "
                    "was lost; a retry follows) or `retry_cap` (lost on the last of its attempts).")
    failure_message: str | None = Field(
        default=None, description="Our own words on why it failed; never model or run output.")
    artifacts: list[str] = Field(
        default_factory=list,
        description="Keys readable at `/investigations/{id}/artifacts/{key}`; empty until upload.",
    )
    knowledge: InvestigationKnowledge | None = Field(
        default=None,
        description="The tenant knowledge the run read; null when there is no run record to say "
                    "(no run yet, or a run from before knowledge was recorded).",
    )

    @field_validator("disposition")
    @classmethod
    def _known_disposition(cls, value: str | None) -> str | None:
        if value is not None and normalized_disposition(value) != value:
            raise ValueError(f"not a disposition: {value!r}")
        return value


class InvestigationCreate(_Request):
    alert_id: AlertId
    client_request_id: ClientRequestId


class LearningJob(BaseModel):
    learning_job_id: LearningJobId
    investigation_id: InvestigationId
    alert_id: AlertId
    status: LearningJobStatus
    trigger: Literal["auto", "explicit"] = Field(
        description="`auto` when the investigation's completion queued it; `explicit` for a re-learn."
    )
    stage: str | None = None
    reason: str | None = Field(default=None, description=(
        "Why a `skipped` or `failed` job ended, one fixed word: `no_fork_point`, `history_unreadable`, "
        "`expired`, `family_unusable`, `control_failed`, `launch_refused`, `verify_refused`, "
        "`source_unavailable`, `judge_failed`, `entry_error`, `exited_without_result`, `worker_error`, "
        "`lease_lapsed` or `retry_cap`; null otherwise."))
    message: str | None = Field(default=None, description=(
        "A sentence of our own code's about the ending (never run or launcher text); a `completed` job "
        "with no findings carries the judge's verdict word here."))
    created_at: Instant
    finished_at: Instant | None = None


class LearningJobCreate(_Request):
    investigation_id: InvestigationId
    client_request_id: ClientRequestId


class Lesson(BaseModel):
    lesson_id: RecordId
    title: str
    description: str
    status: str


SettingValue = str | int | bool


class SystemSettings(BaseModel):
    """A connected system of the tenant's, as the systems repository stores it: a data source,
    or the ticket system alerts come from."""

    system_id: RecordId
    kind: str
    display_name: str
    enabled: bool
    settings: dict[str, SettingValue]


class System(SystemSettings):
    """A system as the API serves it. `has_credentials` is the secret store's answer, asked at
    read time, so it cannot disagree with where credentials are written."""

    has_credentials: bool = Field(description="Credentials are write-only; this is all a read says.")


class SystemPut(_Request):
    """The whole record: a PUT replaces it, so NO field has a default — a default would silently
    reset whatever the caller left out (re-enable a disabled system, erase its settings)."""

    kind: str = Field(min_length=1)
    display_name: str = Field(min_length=1)
    enabled: bool
    settings: dict[str, SettingValue]


class AlertMapping(_Request):
    """The tenant's alert mapping, as a PUT names it and a GET answers it (#1345): the dotted path in the raw alert
    where each fact lives, or null for an entry the tenant leaves unmapped. A PUT replaces the whole mapping, so NO
    entry has a default (D4): it names all six. The entries and the path rule are `records`' (`check_mapping`)."""

    signature: str | None
    event_time: str | None
    summary: str | None
    case_key: str | None
    title: str | None
    description: str | None

    @model_validator(mode="after")
    def _paths_are_valid(self) -> AlertMapping:
        try:
            check_mapping(self.model_dump())
        except AlertMappingFault as fault:
            raise ValueError(str(fault)) from None
        return self


#: The shortest a secret credential value may be (#1163 A4): a typed-in placeholder is refused
#: at write time, not found out at the first call.
SECRET_MIN_LENGTH = 16


class CredentialsPut(_Request):
    """The whole credential set, replaced; no field has a default. `kind` says which fields are
    secret, by the rule `secret_fields` states (r7 A19): all but `username` in a
    `static` set, all but `client_id` in an `oauth-client-credentials` set."""

    kind: Literal["static", "oauth-client-credentials"]
    credentials: dict[CredentialKey, str] = Field(min_length=1)

    @model_validator(mode="after")
    def _secrets_are_long_enough(self) -> CredentialsPut:
        secret = secret_fields(self.kind, self.credentials)
        short = sorted(k for k in secret if len(self.credentials[k]) < SECRET_MIN_LENGTH)
        if short:
            raise ValueError(
                f"secret field(s) {short} are shorter than {SECRET_MIN_LENGTH} characters")
        return self




class SystemCheck(BaseModel):
    ok: bool
    detail: str


class FieldError(BaseModel):
    """One part of a request that failed validation. The refused value is never echoed."""

    loc: list[str | int] = Field(description="Where: `body`, `query`, `path` or `header`, then the field's path.")
    msg: str
    type: str = Field(description="The validation rule that failed, e.g. `string_pattern_mismatch`.")


class Problem(BaseModel):
    """An error, as RFC 9457 problem details, served as `application/problem+json`."""

    type: str = Field(default="about:blank", description="`about:blank`: the status says what kind of problem it is.")
    title: str = Field(description="The status's phrase.")
    status: int
    detail: str | None = Field(default=None, description="What happened to this request.")
    errors: list[FieldError] | None = Field(
        default=None, description="On a 422 from validation: each failing part of the request.")


# --- people, memberships and sign-in (#1306) ---------------------------------------------------

#: An email as typed: the shape is checked, deliverability is not. The identity rule then normalizes
#: it, and its refusal is a 422 like the pattern's; the pattern stays plain because the OpenAPI schema
#: hands it to clients' own regex engines.
EMAIL_PATTERN = r"^[^@\s]+@[^@\s]+$"


class InviteCreate(BaseModel):
    """Invite a person by email."""

    model_config = ConfigDict(extra="forbid")

    email: Email = Field(pattern=EMAIL_PATTERN, max_length=254)


class Invitation(BaseModel):
    """An invitation as its inviters see it: only what they typed, its status and its date."""

    id: MembershipId
    email: str
    status: Literal["invited"]
    created_at: Instant


class Member(BaseModel):
    user_id: UserId
    email: str
    display_name: str


class MeUser(BaseModel):
    id: UserId
    email: str
    display_name: str


class TenantRef(BaseModel):
    tenant_id: TenantId


class TenantItem(BaseModel):
    """A tenant and its one job, as an administrator sees it (#1214): the state, the pending action,
    the current step and whose it is, and the last failure (which names the step and the external
    answer, never a secret). Nothing pending means `pending_action`, `step` and `step_actor` are null."""

    tenant_id: TenantId
    state: Literal["creating", "active", "offboarding", "offboarded"]
    pending_action: Literal["create", "rotate", "offboard", "delete_repo"] | None
    step: str | None
    step_actor: Literal["service", "host"] | None
    failure: str | None
    created_at: Instant


class InvitationRef(BaseModel):
    id: MembershipId
    tenant_id: TenantId


class Me(BaseModel):
    user: MeUser
    tenants: list[TenantRef]
    administrator: bool = Field(description="Whether this session holds platform administrator powers.")
    invitations: list[InvitationRef] = Field(description="Open invitations addressed to this user.")
