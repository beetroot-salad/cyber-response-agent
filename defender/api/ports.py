"""What the routes need from the rest of the platform, as interfaces."""

from __future__ import annotations

import dataclasses
import datetime as _dt
from typing import Literal, Protocol

from defender._model import model
from defender.tenancy import TenantRecord, TenantRepository
from defender.identity import IdentityService
# The store's refusals are the API's: one class each, so the store's raise is the API's answer
# with no mapping between them (#1342).
from defender.jobs.errors import Conflict, NotFound, OffboardNotSettled, UnknownReference  # noqa: F401 — re-exported: the API's refusals
from defender.records.formats import AlertId, CredentialId, InvestigationId, LearningJobId, ProgramId, TenantId, UserId

from .models import (
    Alert,
    AlertMapping,
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
    #: A person's user id or a program's id (both UUID text); audit actors are free text in the log.
    actor_id: UserId | ProgramId
    #: The credential a program's request came in on; None for a person (#1307 D6).
    credential_id: CredentialId | None = None


class StoreBrokePromise(Exception):
    """A port answered something its contract rules out. A 500: the store has a bug, and serving
    the answer would hand the client a wrong one."""


class AlertsRepository(Protocol):
    async def list_alerts(
        self,
        tenant_id: TenantId,
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

    async def get_alert(self, tenant_id: TenantId, alert_id: AlertId) -> Alert | None: ...


class InvestigationsRepository(Protocol):
    """An investigation's `knowledge` is stored on its row from its run's HOST-held knowledge
    record (beside the run dir, never anything the box can write), mapped `fresh` ->
    `current`, `stale` -> `stale` with its kind, `pinned` -> `pinned`, the commit carried and the
    publish's raw reason dropped. Null when the run never started: setup was refused before the
    run existed. A run that started but whose record is missing or does not parse is
    `{status: stale, stale_kind: operator, commit: null}` — never claimed current (#1108 P4,
    OD22')."""

    async def list_investigations(
        self, tenant_id: TenantId, *, alert_id: AlertId | None, after: TimePosition | None, limit: int
    ) -> list[Investigation]:
        """Up to `limit` strictly after `after`, newest first by `(created_at,
        investigation_id)`."""
        ...

    async def get_investigation(self, tenant_id: TenantId, investigation_id: InvestigationId) -> Investigation | None:
        """`None` for an investigation this tenant does not have."""
        ...


class LearningJobsRepository(Protocol):
    async def list_learning_jobs(
        self, tenant_id: TenantId, *, investigation_id: InvestigationId | None, after: TimePosition | None,
        limit: int,
    ) -> list[LearningJob]:
        """Up to `limit` strictly after `after`, newest first by `(created_at,
        learning_job_id)`."""
        ...

    async def get_learning_job(self, tenant_id: TenantId, learning_job_id: LearningJobId) -> LearningJob | None: ...


class LessonsRepository(Protocol):
    async def list_lessons(self, tenant_id: TenantId, *, after: str | None, limit: int) -> list[Lesson]:
        """Up to `limit` lessons with a `lesson_id` greater than `after`, by `lesson_id`."""
        ...


class SystemsRepository(Protocol):
    """Settings only. Whether a system has credentials is the secret store's answer."""

    async def list_systems(
        self, tenant_id: TenantId, *, after: str | None, limit: int
    ) -> list[SystemSettings]:
        """Up to `limit` systems with a `system_id` greater than `after`, by `system_id`."""
        ...

    async def get_system(self, tenant_id: TenantId, system_id: str) -> SystemSettings | None: ...

    async def put_system(
        self, principal: Principal, system_id: str, body: SystemPut
    ) -> tuple[SystemSettings, bool]:
        """Create or replace a system's settings. Returns `(settings, created)`. The port commits, then
        announces `system.update` (P2: one announcer per audited action, after its commit)."""
        ...


class AlertMappingRepository(Protocol):
    async def get_alert_mapping(self, tenant_id: TenantId) -> AlertMapping | None:
        """The tenant's alert mapping (#1345), `None` until one is saved."""
        ...


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
    "learning_job.claim",
    "learning_job.finish",
    "learning_job.takeover",
    "learning_job.retry",
    "learning_post_step",
    "system.update",
    "system.credentials",
    "alert_mapping.update",
]


class Writes(Protocol):
    """The store-backed writes, each one call that names the acting `principal` (its tenant is
    `principal.tenant_id`, already checked against membership), commits before it returns and
    then announces its audit event: one announcer per audited action (P2). Audit events are
    emitted after commit, so a failed write announces nothing and an event can be lost in a crash
    between the commit and its emission."""

    async def create_investigation(
        self, principal: Principal, alert_id: AlertId, client_request_id: str
    ) -> tuple[Investigation, bool]:
        """Start an investigation of `alert_id`, or answer the one this request already has —
        the rules are §4.1's (the latest attempt of a repeated request, one live investigation
        per alert). Returns `(investigation, created)`, `created` only when this call inserted
        the row. `UnknownReference` for an alert this tenant does not have; `Conflict` naming the
        missing mapping when a new investigation is due and the tenant has saved no alert mapping
        (#1345 O4)."""
        ...

    async def cancel_investigation(self, principal: Principal, investigation_id: InvestigationId) -> Investigation:
        """Abort an investigation that is queued or running (`aborted`, reason `cancelled`); a
        running one's worker tells its run to stop within about a second, and the run has ended within
        the worker's stop grace (30 s) of that. `NotFound`; `Conflict` if it
        already ended — and when it ended because its worker was lost and a retry of it is live,
        the message names that retry's id."""
        ...

    async def delete_investigation(self, principal: Principal, investigation_id: InvestigationId) -> None:
        """Remove every attempt of the request the investigation belongs to, and every learning
        job of those attempts, queued or ended (their run and episode folders stay). `NotFound`, or
        `Conflict` while any attempt is live or any of their learning jobs is running (#1344 O10). A
        replay of the request afterwards starts a new investigation."""
        ...

    async def create_learning_job(
        self, principal: Principal, investigation_id: InvestigationId, client_request_id: str
    ) -> tuple[LearningJob, bool]:
        """Queue an explicit re-learn of an investigation, or answer the job this request
        already queued: a replay by `(investigation, client request id)` answers the latest
        attempt (#1344 O11). Returns `(job, created)`. `UnknownReference` for an investigation
        this tenant does not have; `Conflict` for one that did not end `completed`."""
        ...

    async def put_alert_mapping(self, principal: Principal, body: AlertMapping) -> tuple[AlertMapping, bool]:
        """Replace the tenant's alert mapping whole (#1345); it applies to alerts stored from now on, and stored
        alerts keep their title and description (#1420). Returns what the store holds and whether it was created:
        `(mapping, created)`, `created` only for the tenant's first save."""
        ...


class AuditPort(Protocol):
    """Actions with no store write of their own (`artifact.read`). Demo only: on the real server
    every caller of it is unreachable, so it refuses."""

    async def announce(self, principal: Principal, action: AuditAction, target: str, detail: str = "") -> None:
        """Record an audit event for the principal's tenant and caller, stamped by the store's
        clock. `detail` never carries a credential value."""
        ...


class SecretStore(Protocol):
    """Write-only from the API's side: nothing here can read a credential back. The credential
    proxy, which adds credentials to outgoing calls, reads them through its own port."""

    async def put_credentials(
        self, principal: Principal, system_id: str, kind: str, credentials: dict[str, str],
    ) -> None:
        """Replace the whole set, stored with its `kind` (`static` or `oauth-client-credentials`). The
        port announces `system.credentials` after its write (P2)."""
        ...

    async def has_credentials(self, tenant_id: TenantId, system_id: str) -> bool: ...


class SystemChecker(Protocol):
    async def check(self, tenant_id: TenantId, system: System) -> SystemCheck:
        """Test the connection and a first query."""
        ...


class ArtifactLinks(Protocol):
    async def signed_url(self, tenant_id: TenantId, investigation_id: InvestigationId, key: str) -> str:
        """A short-lived link on the blob store's own origin, never the app's: a run page renders
        attacker-influenced text and must not run beside the logged-in session (#1131 "API")."""
        ...


class Offboarding(Protocol):
    """The one operation behind the administrator's offboard request (#1360 D6): the tenant moves to `offboarding` and
    every queued or running job of it ends, as one change. `NotFound` for an absent tenant, `Conflict` for one that
    is not `creating` or `active` (tenancy's refusals; the routes answer both); `OffboardNotSettled` when jobs kept
    appearing behind it (rolled back, the request can be repeated; the route answers 503); a failure leaves tenant
    and jobs as they were. Not `Writes`: that is a per-tenant transaction acting as a user."""

    async def offboard_tenant(self, tenant_id: TenantId, *, actor: UserId) -> TenantRecord:
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
    #: The alert mapping's read, its own port so the systems port can refuse whole (#1083 G2).
    alert_mapping: AlertMappingRepository
    writes: Writes
    secrets: SecretStore
    checker: SystemChecker
    artifact_links: ArtifactLinks
    #: Actions with no store write of their own: the artifact read (#1083 P2).
    audit: AuditPort
    #: The offboard request's one write: the tenant transition and the ending of its jobs (#1360 D6).
    offboarding: Offboarding
