"""What the routes need from the rest of the platform, as interfaces."""

from __future__ import annotations

import dataclasses
import datetime as _dt
from contextlib import AbstractAsyncContextManager
from typing import Literal, Protocol

from defender._model import model
from defender.tenancy import TenantRepository
from defender.identity import IdentityService
# The store's refusals are the API's: one class each, so the store's raise is the API's answer
# with no mapping between them (#1342).
from defender.jobs.errors import Conflict, NotFound, UnknownReference  # noqa: F401 — re-exported: the API's refusals
from defender.records.formats import TenantId

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
    audit log (#1131 "Tenancy"). The tenant is the request path's, checked against its grammar
    here so no port ever sees an unchecked one, and against the caller's membership before a
    `Principal` exists (`app._principal`)."""

    tenant_id: TenantId
    user_id: str


class StoreBrokePromise(Exception):
    """A port answered something its contract rules out. A 500: the store has a bug, and serving
    the answer would hand the client a wrong one."""


class AlertsRepository(Protocol):
    async def list_alerts(
        self,
        tenant_id: str,
        *,
        fired_after: _dt.datetime | None,
        fired_before: _dt.datetime | None,
        after: TimePosition | None,
        limit: int,
    ) -> list[AlertSummary]:
        """Up to `limit` alerts strictly after `after`, newest first by `(fired_at, alert_id)`.
        The window is `fired_after <= fired_at < fired_before`, so adjacent windows meet without
        a gap or an overlap."""
        ...

    async def get_alert(self, tenant_id: str, alert_id: str) -> Alert | None: ...


class InvestigationsRepository(Protocol):
    """An investigation's `knowledge` is stored on its row from its run's HOST-held knowledge
    record (beside the run dir, never anything the box can write), mapped `fresh` ->
    `current`, `stale` -> `stale` with its kind, `pinned` -> `pinned`, the commit carried and the
    publish's raw reason dropped. Null when the run never started: setup was refused before the
    run existed. A run that started but whose record is missing or does not parse is
    `{status: stale, stale_kind: operator, commit: null}` — never claimed current (#1108 P4,
    OD22')."""

    async def list_investigations(
        self, tenant_id: str, *, alert_id: str | None, after: TimePosition | None, limit: int
    ) -> list[Investigation]:
        """Up to `limit` strictly after `after`, newest first by `(created_at,
        investigation_id)`."""
        ...

    async def get_investigation(self, tenant_id: str, investigation_id: str) -> Investigation | None:
        """`None` for an investigation this tenant does not have."""
        ...


class LearningJobsRepository(Protocol):
    async def list_learning_jobs(
        self, tenant_id: str, *, investigation_id: str | None, after: TimePosition | None,
        limit: int,
    ) -> list[LearningJob]:
        """Up to `limit` strictly after `after`, newest first by `(created_at,
        learning_job_id)`."""
        ...

    async def get_learning_job(self, tenant_id: str, learning_job_id: str) -> LearningJob | None: ...


class LessonsRepository(Protocol):
    async def list_lessons(self, tenant_id: str, *, after: str | None, limit: int) -> list[Lesson]:
        """Up to `limit` lessons with a `lesson_id` greater than `after`, by `lesson_id`."""
        ...


class SystemsRepository(Protocol):
    """Settings only. Whether a system has credentials is the secret store's answer."""

    async def list_systems(
        self, tenant_id: str, *, after: str | None, limit: int
    ) -> list[SystemSettings]:
        """Up to `limit` systems with a `system_id` greater than `after`, by `system_id`."""
        ...

    async def get_system(self, tenant_id: str, system_id: str) -> SystemSettings | None: ...


AuditAction = Literal[
    "investigation.start",
    "investigation.cancel",
    "investigation.delete",
    "investigation.claim",
    "investigation.finish",
    "investigation.takeover",
    "investigation.retry",
    "artifact.read",
    "learning_job.start",
    "system.update",
    "system.credentials",
]


class WriteTransaction(Protocol):
    """One store transaction, opened for one tenant and one acting user. Everything written
    through it — the records — commits together when the `async with` block exits normally, and
    none of it when the block raises. Audit events are emitted after commit, so a rolled-back
    block emits none and an event can be lost in a crash between the commit and its emission."""

    async def create_investigation(
        self, alert_id: str, client_request_id: str
    ) -> tuple[Investigation, bool]:
        """Start an investigation of `alert_id`, or answer the one this request already has —
        the rules are §4.1's (the latest attempt of a repeated request, one live investigation
        per alert). Returns `(investigation, created)`, `created` only when this call inserted
        the row. `UnknownReference` for an alert this tenant does not have."""
        ...

    async def cancel_investigation(self, investigation_id: str) -> Investigation:
        """Abort an investigation that is queued or running (`aborted`, reason `cancelled`); a
        running one's worker stops its run within about a second. `NotFound`; `Conflict` if it
        already ended — and when it ended because its worker was lost and a retry of it is live,
        the message names that retry's id."""
        ...

    async def delete_investigation(self, investigation_id: str) -> None:
        """Remove every attempt of the request the investigation belongs to (its run folders
        stay). `NotFound`, or `Conflict` while any attempt is live. A replay of the request
        afterwards starts a new investigation."""
        ...

    async def create_learning_job(
        self, investigation_id: str, client_request_id: str
    ) -> tuple[LearningJob, bool]:
        """Queue an explicit re-learn of an investigation, or answer the job this request
        already queued — the rules are §2.5's. Returns `(job, created)`. `UnknownReference` for
        an investigation this tenant does not have; `Conflict` for one that cannot be learned
        from — the design names `unparseable`."""
        ...

    async def put_system(self, system_id: str, body: SystemPut) -> tuple[SystemSettings, bool]:
        """Create or replace a system's settings. Returns `(settings, created)`."""
        ...

    async def audit(self, action: AuditAction, target: str, detail: str = "") -> None:
        """Record an audit event for the transaction's tenant and user, stamped by the store's
        clock. `detail` never carries a credential value."""
        ...


class Writes(Protocol):
    def transaction(
        self, tenant_id: TenantId, actor: str
    ) -> AbstractAsyncContextManager[WriteTransaction]:
        """A transaction for `tenant_id`, acting as `actor` (the user id the audit names)."""
        ...


class SecretStore(Protocol):
    """Write-only from the API's side: nothing here can read a credential back. The credential
    proxy, which adds credentials to outgoing calls, reads them through its own port."""

    async def put_credentials(
        self, tenant_id: str, system_id: str, kind: str, credentials: dict[str, str],
    ) -> None:
        """Replace the whole set, stored with its `kind` (`static` or `oauth-client-credentials`)."""
        ...

    async def has_credentials(self, tenant_id: str, system_id: str) -> bool: ...


class SystemChecker(Protocol):
    async def check(self, tenant_id: str, system: System) -> SystemCheck:
        """Test the connection and a first query."""
        ...


class ArtifactLinks(Protocol):
    async def signed_url(self, tenant_id: str, investigation_id: str, key: str) -> str:
        """A short-lived link on the blob store's own origin, never the app's: a run page renders
        attacker-influenced text and must not run beside the logged-in session (#1131 "API")."""
        ...


@dataclasses.dataclass(frozen=True)
class ApiDeps:
    """Everything `create_app` wires the routes to. Plain wiring, not a boundary type: the
    ports are structural, checked by mypy at the composition root, and a test may hand in any
    object that answers the calls it scripts."""

    identity: IdentityService
    #: The tenant rows: read for the administrator's list and progress, written by the request
    #: methods only (#1214). The same store `identity` reads tenants from.
    tenants: TenantRepository
    #: The one `Origin` a state-changing request may carry (O6).
    frontend_origin: str
    alerts: AlertsRepository
    investigations: InvestigationsRepository
    learning_jobs: LearningJobsRepository
    lessons: LessonsRepository
    systems: SystemsRepository
    writes: Writes
    secrets: SecretStore
    checker: SystemChecker
    artifact_links: ArtifactLinks
