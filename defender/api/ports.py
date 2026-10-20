"""What the routes need from the rest of the platform, as interfaces."""

from __future__ import annotations

import dataclasses
import datetime as _dt
from contextlib import AbstractContextManager
from typing import Literal, Protocol

from defender._model import model
from defender.tenancy._tenant import TenantId

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


#: A position in a newest-first list: the last row served's timestamp and id. A list answers
#: only rows strictly after it in its order (`api/pages.py`).
TimePosition = tuple[_dt.datetime, str]


@model(frozen=True)
class Principal:
    """Who is calling. The tenant scopes every read and write; the user id reaches only the
    audit log (#1131 "Tenancy"). The tenant is checked against its grammar here, where the login
    provider's answer becomes a caller, so no port ever sees an unchecked one; a login answer
    that fails it is a 401 (`app._principal`)."""

    tenant_id: TenantId
    user_id: str


class Unauthenticated(Exception):
    """No usable login on the request."""


class NotFound(Exception):
    """The addressed record does not exist for this tenant."""


class Conflict(Exception):
    """The record exists but its state refuses the request."""


class UnknownReference(Exception):
    """A request body names a record that does not exist for this tenant."""


class StoreBrokePromise(Exception):
    """A port answered something its contract rules out. A 500: the store has a bug, and serving
    the answer would hand the client a wrong one."""


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
        after: TimePosition | None,
        limit: int,
    ) -> list[AlertSummary]:
        """Up to `limit` alerts strictly after `after`, newest first by `(fired_at, alert_id)`.
        The window is `fired_after <= fired_at < fired_before`, so adjacent windows meet without
        a gap or an overlap."""
        ...

    def get_alert(self, tenant_id: str, alert_id: str) -> Alert | None: ...


class InvestigationsRepository(Protocol):
    def list_investigations(
        self, tenant_id: str, *, alert_id: str | None, after: TimePosition | None, limit: int
    ) -> list[Investigation]:
        """Up to `limit` strictly after `after`, newest first by `(created_at,
        investigation_id)`; deleted investigations are left out, and never make a page short."""
        ...

    def get_investigation(self, tenant_id: str, investigation_id: str) -> Investigation | None:
        """`None` for a deleted investigation too."""
        ...


class LearningJobsRepository(Protocol):
    def list_learning_jobs(
        self, tenant_id: str, *, investigation_id: str | None, after: TimePosition | None,
        limit: int,
    ) -> list[LearningJob]:
        """Up to `limit` strictly after `after`, newest first by `(created_at,
        learning_job_id)`."""
        ...

    def get_learning_job(self, tenant_id: str, learning_job_id: str) -> LearningJob | None: ...


class LessonsRepository(Protocol):
    def list_lessons(self, tenant_id: str, *, after: str | None, limit: int) -> list[Lesson]:
        """Up to `limit` lessons with a `lesson_id` greater than `after`, by `lesson_id`."""
        ...


class SystemsRepository(Protocol):
    """Settings only. Whether a system has credentials is the secret store's answer."""

    def list_systems(
        self, tenant_id: str, *, after: str | None, limit: int
    ) -> list[SystemSettings]:
        """Up to `limit` systems with a `system_id` greater than `after`, by `system_id`."""
        ...

    def get_system(self, tenant_id: str, system_id: str) -> SystemSettings | None: ...


AuditAction = Literal[
    "investigation.start",
    "investigation.cancel",
    "investigation.delete",
    "artifact.read",
    "learning_job.start",
    "system.update",
    "system.credentials",
]


class WriteTransaction(Protocol):
    """One store transaction, opened for one tenant and one acting user. Everything written
    through it — records and audit events — commits together when the `with` block exits
    normally, and none of it when the block raises."""

    def create_investigation(
        self, alert_id: str, client_request_id: str
    ) -> tuple[Investigation, bool]:
        """Start an investigation of `alert_id`, or answer the one this request already has —
        the rules are §4.1's (request-id replay, one live investigation per alert). Returns
        `(investigation, created)`, `created` only when this call inserted the row.
        `UnknownReference` for an alert this tenant does not have; `Conflict` for a repeated
        request whose investigation was deleted since."""
        ...

    def cancel_investigation(self, investigation_id: str) -> Investigation:
        """Stop a live investigation. `NotFound`, or `Conflict` if it already ended."""
        ...

    def delete_investigation(self, investigation_id: str) -> None:
        """Soft delete: hidden from every read, kept because lessons cite it. `NotFound`, or
        `Conflict` while it is live."""
        ...

    def create_learning_job(
        self, investigation_id: str, client_request_id: str
    ) -> tuple[LearningJob, bool]:
        """Queue an explicit re-learn of an investigation, or answer the job this request
        already queued — the rules are §2.5's. Returns `(job, created)`. `UnknownReference` for
        an investigation this tenant does not have; `Conflict` for one that cannot be learned
        from — the design names `unparseable`."""
        ...

    def put_system(self, system_id: str, body: SystemPut) -> tuple[SystemSettings, bool]:
        """Create or replace a system's settings. Returns `(settings, created)`."""
        ...

    def audit(self, action: AuditAction, target: str, detail: str = "") -> None:
        """Record an audit event for the transaction's tenant and user, stamped by the store's
        clock. `detail` never carries a credential value."""
        ...


class Writes(Protocol):
    def transaction(
        self, tenant_id: TenantId, actor: str
    ) -> AbstractContextManager[WriteTransaction]:
        """A transaction for `tenant_id`, acting as `actor` (the user id the audit names)."""
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
    writes: Writes
    secrets: SecretStore
    checker: SystemChecker
    artifact_links: ArtifactLinks
