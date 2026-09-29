"""What the routes need from the rest of the platform, as interfaces.

The store (#1082), the job model (#1081), the secret store and the login provider implement
these; `fakes.py` holds rule-free stand-ins for the demo server. Every repository method takes
the tenant first: a record of another tenant's answers `None` or raises `NotFound`, exactly as a
missing one does, so the API never tells a caller that an id exists elsewhere.

The data rules (`docs/platform-design.md` §2.5, §4.1) are written here as each method's
contract, and they are the STORE's to enforce — with constraints and one transaction per write,
not in the routes. The API only maps what a method answers onto HTTP. The rules' own tests
belong with the store's implementation (#1082), run against these ports; the API's tests
(`tests/test_api_stub.py`) script the answers and check the mapping.
"""

from __future__ import annotations

import dataclasses
import datetime as _dt
from collections.abc import Callable
from typing import Literal, Protocol

from pydantic import AwareDatetime

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
    SystemSettings,
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


class Authenticator(Protocol):
    def authenticate(self, bearer_token: str | None) -> Principal:
        """The caller behind `bearer_token`, or raise `Unauthenticated`."""
        ...


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


class InvestigationsRepository(Protocol):
    def create_investigation(
        self, tenant_id: str, alert_id: str, client_request_id: str
    ) -> tuple[Investigation, bool]:
        """Start an investigation of `alert_id`, or return the one that answers this request.

        Returns `(investigation, created)`. The store's rules (§4.1):

        - `client_request_id` is bound, per `(tenant_id, alert_id)`, to whatever this call
          returns — a created investigation or an existing live one — so the same request
          always answers the same investigation, `created=False` on every replay, whatever
          happened to it since.
        - At most one live (`queued`/`running`) investigation per alert: when one exists it is
          returned, `created=False`. A terminal prior never blocks; a new one is a rerun.
        - The check and the write are one transaction: concurrent calls with one request id
          create at most one investigation.

        Raises `UnknownReference` for an alert this tenant does not have.
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
        """Soft delete: hidden from every read, kept because lessons cite it. `NotFound`, or
        `Conflict` while it is live."""
        ...


class LearningJobsRepository(Protocol):
    def create_learning_job(
        self, tenant_id: str, investigation_id: str, client_request_id: str
    ) -> tuple[LearningJob, bool]:
        """Queue an explicit re-learn of an investigation.

        Returns `(job, created)`. The store's rules (§2.5, §2.6): a `client_request_id` already
        used by this tenant answers its job, `created=False`, checked before anything else;
        explicit re-learns are otherwise unlimited. `UnknownReference` for an investigation
        this tenant does not have; `Conflict` for one that cannot be learned from — the design
        names `unparseable`.
        """
        ...

    def list_learning_jobs(
        self, tenant_id: str, *, investigation_id: str | None, limit: int
    ) -> list[LearningJob]:
        """Newest first."""
        ...

    def get_learning_job(self, tenant_id: str, learning_job_id: str) -> LearningJob | None: ...


class LessonsRepository(Protocol):
    def list_lessons(self, tenant_id: str) -> list[Lesson]: ...


class SystemsRepository(Protocol):
    """Settings only. Whether a system has credentials is the secret store's answer."""

    def list_systems(self, tenant_id: str) -> list[SystemSettings]: ...

    def get_system(self, tenant_id: str, system_id: str) -> SystemSettings | None: ...

    def put_system(
        self, tenant_id: str, system_id: str, body: SystemPut
    ) -> tuple[SystemSettings, bool]:
        """Create or replace a system's settings. Returns `(settings, created)`."""
        ...


class SecretStore(Protocol):
    """Write-only from the API's side: nothing here can read a credential back. The credential
    proxy, which adds credentials to outgoing calls, reads them through its own port."""

    def put_credentials(self, tenant_id: str, system_id: str, credentials: dict[str, str]) -> None: ...

    def has_credentials(self, tenant_id: str, system_id: str) -> bool: ...


class SystemChecker(Protocol):
    def check(self, tenant_id: str, system: System) -> SystemCheck:
        """Test the connection and a first query."""
        ...


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
    at: AwareDatetime
    detail: str = ""


class AuditLog(Protocol):
    def record(self, event: AuditEvent) -> None: ...


@dataclasses.dataclass(frozen=True)
class ApiDeps:
    """Everything `create_app` wires the routes to. Plain wiring, not a boundary type: the
    ports are structural, checked by mypy at the composition root, and a test may hand in any
    object that answers the calls it scripts."""

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
