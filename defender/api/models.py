"""The API's wire shapes: what a request may carry and what a response says.

These are the contract, so they change only with the API's version, never because a store
changed. Request bodies forbid unknown fields; in particular a body cannot name a tenant, which
comes from the login alone (#1131 "Tenancy").

Vocabulary follows #1131: "investigation" in the public API ("run" stays the internal name), and
`status` is the execution lifecycle, distinct from `disposition`, the outcome
(`docs/platform-design.md` §2.3).

Two shapes are closed by one type each, used on EVERY way data crosses the boundary — a path,
a query, a body, a cursor (`pages.py`), and a record the store answers — so nothing past it has
to handle them:

- every moment is an `Instant`: timezone-aware (a time without an offset is refused, never a
  naive value compared against an aware one), never a bare number (`20260928` is not read as
  seconds since 1970), and normalized to UTC, so one instant has one spelling wherever it is
  compared, digested or served;
- every record id is a `RecordId`, matching `RECORD_ID_PATTERN`.

On the way in a violation is the caller's 422. On the way out the record cannot even be built: a
store that reads a row breaking its promise (`ports.py`) fails as it builds the record, a 500,
rather than serving an id the API could not address again or put safely into a `Location`.
(The framework does not re-check a record a route returns; the check is the record's own, at
construction.)
"""

from __future__ import annotations

from typing import Annotated, Any, Literal

from pydantic import AfterValidator, AwareDatetime, BaseModel, BeforeValidator, ConfigDict, Field, field_validator

from defender._clock import as_utc
from defender._vocab import DISPOSITION_VALUES, normalized_disposition

InvestigationStatus = Literal["queued", "running", "completed", "unparseable", "failed", "aborted"]

LearningJobStatus = Literal["queued", "running", "completed", "failed", "skipped"]

#: What a record id may be: the same grammar in a path segment and in a request body, and ASCII
#: only, so an id is always safe to put back into a URL or a header.
RECORD_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"
RecordId = Annotated[str, Field(pattern=RECORD_ID_PATTERN)]

#: The id a caller mints once per user action, so a retried or double-clicked create
#: returns the record the first attempt made.
ClientRequestId = Annotated[str, Field(
    min_length=1, max_length=200,
    description="Minted once per user action. Repeating the request with it answers the record "
                "that request created; a request answered with an investigation already live "
                "created nothing, so repeating it is a new request.",
)]


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

    alert_id: RecordId
    vendor: str = Field(description="The ticket system the alert was pulled from.")
    vendor_ticket_id: str = Field(description="The vendor's own id; unique per tenant and vendor.")
    title: str
    severity: str | None
    rule: str | None
    fired_at: Instant = Field(description="When the vendor says the alert fired.")
    changed_at: Instant = Field(description="When the vendor last changed the ticket.")
    received_at: Instant = Field(description="When we pulled it; our own clock.")


class Alert(AlertSummary):
    raw: dict[str, Any] = Field(description="The alert exactly as the vendor sent it.")


class Investigation(BaseModel):
    investigation_id: RecordId
    alert_id: RecordId
    status: InvestigationStatus
    disposition: str | None = Field(
        default=None,
        description="Set once the investigation completes with a readable report.",
        json_schema_extra={"enum": [*DISPOSITION_VALUES, None]},
    )
    cost_usd: float = Field(description="Model cost so far; final once the status is terminal.")
    created_at: Instant
    started_at: Instant | None = None
    finished_at: Instant | None = None
    artifacts: list[str] = Field(
        default_factory=list,
        description="Keys readable at `/investigations/{id}/artifacts/{key}`; empty until upload.",
    )

    @field_validator("disposition")
    @classmethod
    def _known_disposition(cls, value: str | None) -> str | None:
        if value is not None and normalized_disposition(value) != value:
            raise ValueError(f"not a disposition: {value!r}")
        return value


class InvestigationCreate(_Request):
    alert_id: RecordId
    client_request_id: ClientRequestId


class LearningJob(BaseModel):
    learning_job_id: RecordId
    investigation_id: RecordId
    alert_id: RecordId
    status: LearningJobStatus
    trigger: Literal["auto", "explicit"] = Field(
        description="`auto` when the investigation's completion queued it; `explicit` for a re-learn."
    )
    stage: str | None = None
    status_detail: str | None = Field(default=None, description="A skip reason or error summary.")
    created_at: Instant
    finished_at: Instant | None = None


class LearningJobCreate(_Request):
    investigation_id: RecordId
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


class CredentialsPut(_Request):
    """The whole credential set, replaced; no field has a default."""

    credentials: dict[CredentialKey, str] = Field(min_length=1)


class SystemCheck(BaseModel):
    ok: bool
    detail: str
