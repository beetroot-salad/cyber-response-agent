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

What the API relies on is written here too, as the store's promise, never assumed:

- **Every record answered fits the wire models' types** (`models.py`): its ids match
  `RECORD_ID_PATTERN`, its moments carry an offset, and a disposition is stored already
  normalized. The store checks this when it writes, so a read never meets a row it cannot serve;
  a row that breaks it is the store's bug, and fails as the store builds the record — a 500.
- **A list answers fewer than `limit` rows only when no more follow.** The route asks for
  `limit + 1` and reads a short answer as the end of the list (`pages.py`).
- **A write records its own audit event, in its own transaction.** Each write method takes the
  acting user (`actor`) and inserts the event with the record, so a write is audited exactly when
  it commits, and a retry that replays it neither repeats nor loses it
  (`docs/platform-design.md` §2.10). The API's own `AuditLog` is only for what happens outside
  the store.
"""

from __future__ import annotations

import dataclasses
import datetime as _dt
from collections.abc import Callable
from typing import Literal, Protocol

from pydantic import AwareDatetime

from defender._model import model
from defender._tenant import TenantId

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
    provider's answer becomes a caller, so no port ever sees an unchecked one."""

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
    def create_investigation(
        self, tenant_id: str, alert_id: str, client_request_id: str, *, actor: str
    ) -> tuple[Investigation, bool]:
        """Start an investigation of `alert_id`, or return the one that answers this request.

        Returns `(investigation, created)`. The store's rules (§4.1):

        - `client_request_id` is unique per `(tenant_id, alert_id)` and bound only to the
          investigation it created: a repeat answers that one, `created=False`, whatever
          happened to it since.
        - At most one live (`queued`/`running`) investigation per alert: when one exists it is
          returned, `created=False`, and the request id is not bound to it — a repeat after it
          ended starts a rerun. A terminal prior never blocks; a new one is a rerun.
        - The check, the write and its `investigation.start` audit event are one transaction:
          concurrent calls with one request id create at most one investigation, and only a
          creation is audited.

        Raises `UnknownReference` for an alert this tenant does not have.
        """
        ...

    def list_investigations(
        self, tenant_id: str, *, alert_id: str | None, after: TimePosition | None, limit: int
    ) -> list[Investigation]:
        """Up to `limit` strictly after `after`, newest first by `(created_at,
        investigation_id)`; deleted investigations are left out, and never make a page short."""
        ...

    def get_investigation(self, tenant_id: str, investigation_id: str) -> Investigation | None:
        """`None` for a deleted investigation too."""
        ...

    def cancel_investigation(
        self, tenant_id: str, investigation_id: str, *, actor: str
    ) -> Investigation:
        """Stop a live investigation, audited `investigation.cancel` with the write. `NotFound`,
        or `Conflict` if it already ended."""
        ...

    def delete_investigation(self, tenant_id: str, investigation_id: str, *, actor: str) -> None:
        """Soft delete: hidden from every read, kept because lessons cite it; audited
        `investigation.delete` with the write. `NotFound`, or `Conflict` while it is live."""
        ...


class LearningJobsRepository(Protocol):
    def create_learning_job(
        self, tenant_id: str, investigation_id: str, client_request_id: str, *, actor: str
    ) -> tuple[LearningJob, bool]:
        """Queue an explicit re-learn of an investigation.

        Returns `(job, created)`. The store's rules (§2.5, §2.6): `client_request_id` is unique
        per `(tenant_id, investigation_id)`, so a repeat answers the job it created,
        `created=False`, checked before anything else — and the same id sent for another
        investigation is another request. Explicit re-learns are otherwise unlimited. A creation
        is audited `learning_job.start` in the same transaction. `UnknownReference` for an
        investigation this tenant does not have; `Conflict` for one that cannot be learned
        from — the design names `unparseable`.
        """
        ...

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

    def put_system(
        self, tenant_id: str, system_id: str, body: SystemPut, *, actor: str
    ) -> tuple[SystemSettings, bool]:
        """Create or replace a system's settings, audited `system.update` with the write.
        Returns `(settings, created)`."""
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
    """The API's own audit, for the two actions that happen outside the store's transactions:
    an artifact read (recorded once the signed link is issued) and a credentials write to the
    secret store (a `PUT` that repeats safely, so a retry records it again). Every other action is
    audited by the store write that performs it."""

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
