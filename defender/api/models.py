"""The API's wire shapes: what a request may carry and what a response says."""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import (
    AfterValidator, AwareDatetime, BaseModel, BeforeValidator, ConfigDict, Field, field_validator,
    model_validator,
)
from pydantic.json_schema import SkipJsonSchema

from defender._clock import as_utc
from defender._text import postgres_can_hold
from defender._vocab import DISPOSITION_VALUES, normalized_disposition
from defender.identity.models import Email
from defender.records.learning_causes import BatchCause, ItemCause
from defender.records.formats import (
    AlertId, AlertMappingFault, BatchId, CredentialId, InvestigationId, LearningJobId, MembershipId, ProgramId, TenantId, UserId, WorkItemId,
    check_mapping,
)

InvestigationStatus = Literal["queued", "running", "completed", "unparseable", "failed", "aborted"]

LearningJobStatus = Literal["queued", "running", "completed", "failed", "skipped"]

#: What a tenant-chosen name may be (a system id), and the lesson id and page cursor: the same
#: grammar in a path segment and in a request body, and ASCII only, so it is always safe to put back
#: into a URL or a header. An id the system mints is not one of these: it is its family's type
#: (`TenantId`, `AlertId`, ...), whose grammar is canonical UUID text (#1382).
RECORD_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"
RecordId = Annotated[str, Field(pattern=RECORD_ID_PATTERN)]

def _must_be_storable(value: str) -> str:
    """Refuse text PostgreSQL cannot hold, here rather than at the store (#1379 O1a; a program's name and a
    credential's, #1307 A2)."""
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
), AfterValidator(_must_be_storable)]


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
    title: str | None = Field(description="Derived from the raw alert through the tenant's alert mapping as it stood when the alert was stored; null when the tenant had no mapping then, or the entry is unmapped or unusable.")
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
    cost_is_lower_limit: bool = Field(
        description="True when `cost_usd` is a lower limit: the run's cost is at least that much, because "
                    "spend recorded for the run may be missing from it (a spend write failed, the run was "
                    "killed before it reported, or its row was ended without its final figure). False when "
                    "the figure is exact, and always false beside a null `cost_usd`.")
    created_at: Instant
    started_at: Instant | None = None
    finished_at: Instant | None = None
    failure_reason: str | None = Field(
        default=None,
        description="Set when the investigation failed or was aborted: a fixed reason such as "
                    "`setup_refused`, `no_report`, `worker_error`, `cancelled`, `tenant_offboarded` (its tenant was offboarded), `lease_lapsed` (its worker "
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
        "`lease_lapsed`, `retry_cap` or `tenant_offboarded` (its tenant was offboarded); null otherwise."))
    message: str | None = Field(default=None, description=(
        "A sentence of our own code's about the ending (never run or launcher text); a `completed` job "
        "with no findings carries the judge's verdict word here."))
    created_at: Instant
    finished_at: Instant | None = None


#: The kinds of learning work item; equal to `learning_models.KINDS` (a test ties the two).
ItemKind = Literal["finding", "questioner_finding", "pitfall", "curation_request", "feedback_instruction"]


class SetAsideItem(BaseModel):
    """A learning item the loop stopped working on (#1485): held for a person, or dead. `reason` can be model-written
    or forge text: plain text, rendered as text."""

    item_id: WorkItemId
    kind: ItemKind
    key: str
    status: Literal["held", "dead"]
    reason: str | None
    #: Why it is set aside: a cause from the closed item list (`reason` is the detail text beside it).
    cause: ItemCause | None
    source_run: str | None
    batch_id: BatchId | None
    pr_number: int | None
    updated_at: Instant


class ParkedItemRef(BaseModel):
    kind: ItemKind
    key: str


class ParkedBatch(BaseModel):
    """A batch the loop will not touch again (#1485). `blocks_lane`: it holds its lane, so that lane's work stops."""

    batch_id: BatchId
    batch_kind: Literal["author", "revert", "registry"]
    lane: str
    blocks_lane: bool
    branch: str
    pr_number: int | None
    reason: str | None
    #: Why it is parked: a cause from the closed batch list (`reason` is the detail text beside it).
    cause: BatchCause | None
    parked_at: Instant | None
    #: A person may release it: parked for a credential refusal (a release withdraws a pending abandon request).
    releasable: bool
    #: Set once a person asked to abandon it and until the loop carries it out.
    abandon_requested_at: Instant | None
    #: When the loop last looked at it (for a requested batch, only a look at or after the request).
    last_checked: Instant | None
    created_at: Instant
    items: list[ParkedItemRef]


class ItemReleased(BaseModel):
    """A held item released (#1537 O1): `status` is `waiting`, or `skipped` when a fresher request for its case waits."""

    id: WorkItemId
    status: Literal["waiting", "skipped"]


class BatchReleased(BaseModel):
    """A parked batch released (#1537 O2): `in_review` (it had a PR) or `working` (it had none)."""

    id: BatchId
    phase: Literal["in_review", "working"]


class AbandonRequested(BaseModel):
    """An abandon request recorded (#1537 O3); the loop carries it out on its next pass over the batch."""

    id: BatchId
    abandon_requested_at: Instant


class LearningJobCreate(_Request):
    investigation_id: InvestigationId
    client_request_id: ClientRequestId


class Lesson(BaseModel):
    lesson_id: RecordId
    title: str
    description: str
    status: str


#: Text a record stores as it was sent (a setting, the access declaration, the case comment body): any text PostgreSQL can
#: hold. What it must say is the record judgement's (#1470 P6), not the wire's.
StoredText = Annotated[str, AfterValidator(_must_be_storable)]


class CatalogAdapter(BaseModel):
    """One adapter a system record may name (#1470 O2): the catalog's own declarations, read from the adapter's module.
    A catalog record's system id is its adapter id (P4)."""

    adapter_id: str
    display_name: str | None = Field(description="Null when the adapter declares none.")
    settings_keys: list[str] = Field(description="The keys a record of this adapter stores, prefixed, as stored.")
    sample_settings: dict[str, str] | None = Field(description="An example value for each stored key; null when the "
                                                               "adapter declares none.")
    lab_example: bool = Field(description="A lab example adapter, not a product integration (D6).")


class SavedSystem(BaseModel):
    """A tenant system's version as a save stored it (#1470 O4): the record, without `has_credentials`, since a save asks
    the secret store nothing (r8 Am-2); a read (`System`) answers it. `system_id` is held to the system-id grammar, so a
    hand-edited row outside it cannot be served (D13)."""

    system_id: RecordId
    version: int = Field(description="The version a write names as `replaces` to replace this one.")
    display_name: str | None = Field(description="The catalog's name for the system's adapter; null when the catalog "
                                                 "has no entry for it (an upgrade removed it).")
    enabled: bool
    settings: dict[str, str] = Field(description="The prefixed settings keys and their text, as stored.")
    access: str = Field(description="The access declaration's text, as stored.")


class System(SavedSystem):
    """A tenant system as its current version stands (#1470 O3). `has_credentials` is the secret store's answer, asked at
    read time, for the current version's credential generation: a set entered for an earlier destination does not count
    (D-D)."""

    has_credentials: bool = Field(description="Credentials are write-only; this is all a read says.")


class SystemPut(_Request):
    """A system's next version, whole: NO field has a default — a default would silently reset whatever the caller left
    out. `replaces` is the version a read showed, or 0 when a read showed none (P2). The adapter is the system id (P4);
    what the record must say is the judgement's, answered as `faults`."""

    replaces: int
    enabled: bool
    settings: dict[StoredText, StoredText]
    access: StoredText


class CaseRecord(BaseModel):
    """The tenant's case write-back record as its current version stands (#1470 O6)."""

    version: int
    system_id: str
    comment_body: str


class CaseRecordPut(_Request):
    """The case record's next version, whole; `replaces` as a system write's (P2)."""

    replaces: int
    system_id: StoredText
    comment_body: StoredText


class CredentialsPut(_Request):
    """A system's whole credential set, replaced, for the version `for_version` names (#1470 O7): accepted exactly when
    that version's credential generation is the current version's (P3). The fields are exactly those of the current
    version's auth scheme, and its kind is the scheme's (P4); both are the credential schema's (`kit.access`), answered
    as `faults`."""

    for_version: int
    credentials: dict[CredentialKey, str]


class AlertMapping(_Request):
    """The tenant's alert mapping, as a PUT names it and a GET answers it (#1345): the dotted path in the raw alert
    where each fact lives, or null for an entry the tenant leaves unmapped. A path reads nested keys, keys holding dots
    (`alert.rule.id` as one key), or a mix; where both hold a value, the nested key wins (#1481). A PUT replaces the whole
    mapping, so NO entry has a default (D4): it names all six. The entries and the path rule are `records`' (`check_mapping`)."""

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
    # Absent, never null, on the wire (the body is dumped without None), so the schema names only the present shape.
    faults: list[str] | SkipJsonSchema[None] = Field(
        default=None, description=("On a 422 from the record judgement or the credential schema: every fault, each a "
                                   "sentence naming the system and the key or part. A 422 carries `errors` or `faults`, "
                                   "never both."))
    current_version: int | SkipJsonSchema[None] = Field(
        default=None, description=("On a 409 for a stale write or a moved credential generation: the version a read "
                                   "now shows (0 when none)."))


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
    """A person's view of themselves."""

    kind: Literal["person"] = "person"
    user: MeUser
    tenants: list[TenantRef]
    administrator: bool = Field(description="Whether this session holds platform administrator powers.")
    invitations: list[InvitationRef] = Field(description="Open invitations addressed to this user.")


class ProgramRef(BaseModel):
    id: ProgramId
    display_name: str


class CredentialRef(BaseModel):
    """The credential a program's request came in on: never its secret."""

    id: CredentialId
    expires_at: Instant


class ProgramMe(BaseModel):
    """A program's view of itself: who it is, the one tenant it belongs to, and the credential it used."""

    kind: Literal["program"] = "program"
    program: ProgramRef
    tenant: TenantRef
    credential: CredentialRef


class ProgramCreate(BaseModel):
    """Make a program: a non-human caller of the tenant (a SOAR, a script)."""

    model_config = ConfigDict(extra="forbid")

    display_name: Annotated[str, Field(min_length=1, max_length=200), AfterValidator(_must_be_storable)]


class Program(BaseModel):
    id: ProgramId
    display_name: str
    created_by: UserId = Field(description="The administrator who made it.")
    created_at: Instant


class CredentialCreate(BaseModel):
    """Issue a credential for a program: an API key, or an OAuth client of the programs realm."""

    model_config = ConfigDict(extra="forbid")

    kind: Literal["key", "oauth_client"]
    name: Annotated[str, Field(min_length=1, max_length=200), AfterValidator(_must_be_storable)]
    expires_at: Instant | None = Field(default=None, description="Between 7 and 365 days from now; 90 days when absent.")


class Credential(BaseModel):
    """A credential as its administrators see it: facts only, never a secret or a hash."""

    id: CredentialId
    kind: Literal["key", "oauth_client"]
    name: str
    state: Literal["pending", "live", "revoked"]
    created_by: UserId | None
    created_at: Instant
    expires_at: Instant
    last_used_at: Instant | None


class CredentialIssued(Credential):
    """The create answer: the only time the secret is shown."""

    secret: str
