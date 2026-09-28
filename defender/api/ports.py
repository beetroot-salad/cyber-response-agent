"""What the routes need from the rest of the platform, as interfaces.

The stub wires these to in-memory fakes (`fakes.py`); the store (#1082), the job model (#1081),
the secret store and the login provider implement them later without the routes changing. Every
repository method takes the tenant first: a record of another tenant's answers `None` or raises
`NotFound`, exactly as a missing one does, so the API never tells a caller that an id exists
elsewhere.

The rules the design puts in the data layer live behind these methods, not in the routes: at
most one live investigation per alert, the `client_request_id` replay, the learning job's
refusal of an investigation that did not complete (`docs/platform-design.md` §2.5, §4.1).
"""

from __future__ import annotations

import datetime as _dt
from collections.abc import Callable
from typing import Literal, Protocol, runtime_checkable

from defender._model import model

from .models import (
    Alert,
    AlertSummary,
    Investigation,
    LearningJob,
    Lesson,
    System,
    SystemCheck,
    SystemPut,
)


@model(frozen=True)
class Principal:
    """Who is calling. The tenant scopes every read and write; the user id reaches only the
    audit log (#1131 "Tenancy")."""

    tenant_id: str
    user_id: str


class Unauthenticated(Exception):
    """No usable login on the request."""


class NotFound(Exception):
    """The addressed record does not exist for this tenant."""


class Conflict(Exception):
    """The record exists but its state refuses the request."""


class UnknownReference(Exception):
    """A request body names a record that does not exist for this tenant."""


@runtime_checkable
class Authenticator(Protocol):
    def authenticate(self, bearer_token: str | None) -> Principal:
        """The caller behind `bearer_token`, or raise `Unauthenticated`."""
        ...


@runtime_checkable
class AlertsRepository(Protocol):
    def list_alerts(
        self,
        tenant_id: str,
        *,
        fired_after: _dt.datetime | None,
        fired_before: _dt.datetime | None,
        severity: str | None,
        limit: int,
    ) -> list[AlertSummary]:
        """Newest `fired_at` first."""
        ...

    def get_alert(self, tenant_id: str, alert_id: str) -> Alert | None: ...


@runtime_checkable
class InvestigationsRepository(Protocol):
    def create_investigation(
        self, tenant_id: str, alert_id: str, client_request_id: str
    ) -> tuple[Investigation, bool]:
        """Start an investigation of `alert_id`, or return the one that answers this request.

        Returns `(investigation, created)`. `created` is False when `client_request_id` was
        already used for this alert, or when the alert already has a live investigation, which
        is then returned. A terminal prior never blocks: a new one is a rerun. Raises
        `UnknownReference` for an alert this tenant does not have.
        """
        ...

    def list_investigations(
        self, tenant_id: str, *, alert_id: str | None, limit: int
    ) -> list[Investigation]:
        """Newest first; deleted investigations are left out."""
        ...

    def get_investigation(self, tenant_id: str, investigation_id: str) -> Investigation | None:
        """`None` for a deleted investigation too."""
        ...

    def cancel_investigation(self, tenant_id: str, investigation_id: str) -> Investigation:
        """Stop a live investigation. `NotFound`, or `Conflict` if it already ended."""
        ...

    def delete_investigation(self, tenant_id: str, investigation_id: str) -> None:
        """Soft delete: hidden from reads, kept because lessons cite it. `NotFound`, or
        `Conflict` while it is live."""
        ...


@runtime_checkable
class LearningJobsRepository(Protocol):
    def create_learning_job(
        self, tenant_id: str, investigation_id: str, client_request_id: str
    ) -> tuple[LearningJob, bool]:
        """Queue an explicit re-learn of a completed investigation.

        Returns `(job, created)`; `created` is False when `client_request_id` was already used
        for this investigation, and that job is returned. `UnknownReference` for an
        investigation this tenant does not have; `Conflict` for one that did not complete, or
        for a `client_request_id` already used for another investigation.
        """
        ...

    def list_learning_jobs(
        self, tenant_id: str, *, investigation_id: str | None, limit: int
    ) -> list[LearningJob]:
        """Newest first."""
        ...

    def get_learning_job(self, tenant_id: str, learning_job_id: str) -> LearningJob | None: ...


@runtime_checkable
class LessonsRepository(Protocol):
    def list_lessons(self, tenant_id: str) -> list[Lesson]: ...


@runtime_checkable
class SystemsRepository(Protocol):
    def list_systems(self, tenant_id: str) -> list[System]: ...

    def get_system(self, tenant_id: str, system_id: str) -> System | None: ...

    def put_system(self, tenant_id: str, system_id: str, body: SystemPut) -> tuple[System, bool]:
        """Create or replace a system's settings. Returns `(system, created)`."""
        ...


@runtime_checkable
class SecretStore(Protocol):
    """Write-only from the API's side: nothing here can read a credential back. The credential
    proxy, which adds credentials to outgoing calls, reads them through its own port."""

    def put_credentials(self, tenant_id: str, system_id: str, credentials: dict[str, str]) -> None: ...

    def has_credentials(self, tenant_id: str, system_id: str) -> bool: ...


@runtime_checkable
class SystemChecker(Protocol):
    def check(self, tenant_id: str, system: System) -> SystemCheck:
        """Test the connection and a first query."""
        ...


@runtime_checkable
class ArtifactLinks(Protocol):
    def signed_url(self, tenant_id: str, investigation_id: str, key: str) -> str:
        """A short-lived link on the blob store's own origin, never the app's: a run page renders
        attacker-influenced text and must not run beside the logged-in session (#1131 "API")."""
        ...


AuditAction = Literal[
    "investigation.start",
    "investigation.cancel",
    "investigation.delete",
    "artifact.read",
    "learning_job.start",
    "system.update",
    "system.credentials",
]


@model(frozen=True)
class AuditEvent:
    """One audited action. `detail` never carries a credential value."""

    tenant_id: str
    user_id: str
    action: str
    target: str
    at: _dt.datetime
    detail: str = ""


@runtime_checkable
class AuditLog(Protocol):
    def record(self, event: AuditEvent) -> None: ...


@model(frozen=True)
class ApiDeps:
    """Everything `create_app` wires the routes to. The ports are `@runtime_checkable` because
    pydantic validates each field here with `isinstance`, which a plain `Protocol` refuses."""

    authenticator: Authenticator
    alerts: AlertsRepository
    investigations: InvestigationsRepository
    learning_jobs: LearningJobsRepository
    lessons: LessonsRepository
    systems: SystemsRepository
    secrets: SecretStore
    checker: SystemChecker
    artifact_links: ArtifactLinks
    audit: AuditLog
    clock: Callable[[], _dt.datetime]

