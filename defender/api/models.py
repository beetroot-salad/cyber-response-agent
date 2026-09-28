"""The API's wire shapes: what a request may carry and what a response says.

These are the contract, so they change only with the API's version, never because a store
changed. Request bodies forbid unknown fields; in particular a body cannot name a tenant, which
comes from the login alone (#1131 "Tenancy").

Vocabulary follows #1131: "investigation" in the public API ("run" stays the internal name), and
`status` is the execution lifecycle, distinct from `disposition`, the outcome
(`docs/platform-design.md` §2.3).
"""

from __future__ import annotations

import datetime as _dt
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from defender._vocab import DISPOSITION_VALUES, normalized_disposition

InvestigationStatus = Literal["queued", "running", "completed", "unparseable", "failed", "aborted"]

#: The statuses in which an investigation is still executing. At most one per alert
#: (`docs/platform-design.md` §4.1); cancel applies only to these, delete never does.
LIVE_STATUSES: frozenset[str] = frozenset({"queued", "running"})

LearningJobStatus = Literal["queued", "running", "completed", "failed", "skipped"]

#: The id a caller mints once per user action, so a retried or double-clicked create
#: returns the record the first attempt made.
ClientRequestId = Annotated[str, Field(min_length=1, max_length=200)]


class _Request(BaseModel):
    model_config = ConfigDict(extra="forbid")


class AlertSummary(BaseModel):
    """An alert as listed. The raw alert is left out of lists; `GET /alerts/{id}` carries it."""

    alert_id: str
    vendor: str = Field(description="The ticket system the alert was pulled from.")
    vendor_ticket_id: str = Field(description="The vendor's own id; unique per tenant and vendor.")
    title: str
    severity: str | None
    rule: str | None
    fired_at: _dt.datetime = Field(description="When the vendor says the alert fired.")
    changed_at: _dt.datetime = Field(description="When the vendor last changed the ticket.")
    received_at: _dt.datetime = Field(description="When we pulled it; our own clock.")


class Alert(AlertSummary):
    raw: dict[str, Any] = Field(description="The alert exactly as the vendor sent it.")


class Investigation(BaseModel):
    investigation_id: str
    alert_id: str
    status: InvestigationStatus
    disposition: str | None = Field(
        default=None,
        description="Set once the investigation completes with a readable report.",
        json_schema_extra={"enum": [*DISPOSITION_VALUES, None]},
    )
    cost_usd: float = Field(description="Model cost so far; final once the status is terminal.")
    created_at: _dt.datetime
    started_at: _dt.datetime | None = None
    finished_at: _dt.datetime | None = None
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
    alert_id: str
    client_request_id: ClientRequestId


class LearningJob(BaseModel):
    learning_job_id: str
    investigation_id: str
    alert_id: str
    status: LearningJobStatus
    trigger: Literal["auto", "explicit"] = Field(
        description="`auto` when the investigation's completion queued it; `explicit` for a re-learn."
    )
    stage: str | None = None
    status_detail: str | None = Field(default=None, description="A skip reason or error summary.")
    created_at: _dt.datetime
    finished_at: _dt.datetime | None = None


class LearningJobCreate(_Request):
    investigation_id: str
    client_request_id: ClientRequestId


class Lesson(BaseModel):
    lesson_id: str
    title: str
    description: str
    status: str


SettingValue = str | int | bool


class System(BaseModel):
    """A connected system of the tenant's: a data source, or the ticket system alerts come from."""

    system_id: str
    kind: str
    display_name: str
    enabled: bool
    settings: dict[str, SettingValue]
    has_credentials: bool = Field(description="Credentials are write-only; this is all a read says.")


class SystemPut(_Request):
    kind: str = Field(min_length=1)
    display_name: str = Field(min_length=1)
    enabled: bool = True
    settings: dict[str, SettingValue] = Field(default_factory=dict)


class CredentialsPut(_Request):
    credentials: dict[str, str] = Field(min_length=1)


class SystemCheck(BaseModel):
    ok: bool
    detail: str
