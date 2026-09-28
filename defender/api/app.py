"""The routes: #1131's public API, each a thin translation onto a port.

Every route resolves the caller through the one login dependency (`_principal`) and passes its
tenant to the ports; no route reads a tenant from the request. Status codes:

- `POST` creates answer 201 with a `Location` header, or 200 with the existing record when the
  request replays an earlier one (same `client_request_id`) or, for an investigation, when the
  alert already has a live one.
- A record another tenant owns is a 404, the same as a missing one.
- A body naming a missing record is a 422; a state that refuses the request is a 409.
"""

from __future__ import annotations

import datetime as _dt
from collections.abc import Awaitable, Callable
from typing import Annotated

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Query, Request, Response, status
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from .models import (
    Alert,
    AlertSummary,
    CredentialsPut,
    Investigation,
    InvestigationCreate,
    LearningJob,
    LearningJobCreate,
    Lesson,
    System,
    SystemCheck,
    SystemPut,
)
from .ports import (
    ApiDeps,
    AuditAction,
    AuditEvent,
    Conflict,
    NotFound,
    Principal,
    Unauthenticated,
    UnknownReference,
)

API_VERSION = "0.1.0-stub"

#: The largest page any list returns; `limit` defaults to `DEFAULT_PAGE`.
MAX_PAGE = 200
DEFAULT_PAGE = 50

_bearer = HTTPBearer(auto_error=False, description="A token from the login provider.")


def _deps(request: Request) -> ApiDeps:
    deps: ApiDeps = request.app.state.deps
    return deps


def _principal(
    deps: Annotated[ApiDeps, Depends(_deps)],
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
) -> Principal:
    token = None if credentials is None else credentials.credentials
    try:
        return deps.authenticator.authenticate(token)
    except Unauthenticated as e:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, str(e), headers={"WWW-Authenticate": "Bearer"}
        ) from e


Deps = Annotated[ApiDeps, Depends(_deps)]
Caller = Annotated[Principal, Depends(_principal)]
Limit = Annotated[int, Query(ge=1, le=MAX_PAGE)]


def _audit(deps: ApiDeps, caller: Principal, action: AuditAction, target: str, detail: str = "") -> None:
    deps.audit.record(AuditEvent(
        tenant_id=caller.tenant_id, user_id=caller.user_id, action=action, target=target,
        at=deps.clock(), detail=detail,
    ))


def _not_found(what: str, record_id: str) -> HTTPException:
    return HTTPException(status.HTTP_404_NOT_FOUND, f"no {what} {record_id!r}")


def _created_or_replayed(response: Response, created: bool, location: str) -> None:
    if created:
        response.status_code = status.HTTP_201_CREATED
        response.headers["Location"] = location


alerts = APIRouter(prefix="/alerts", tags=["alerts"])


@alerts.get("")
def list_alerts(
    deps: Deps,
    caller: Caller,
    fired_after: _dt.datetime | None = None,
    fired_before: _dt.datetime | None = None,
    severity: str | None = None,
    limit: Limit = DEFAULT_PAGE,
) -> list[AlertSummary]:
    return deps.alerts.list_alerts(
        caller.tenant_id, fired_after=fired_after, fired_before=fired_before,
        severity=severity, limit=limit,
    )


@alerts.get("/{alert_id}")
def get_alert(deps: Deps, caller: Caller, alert_id: str) -> Alert:
    alert = deps.alerts.get_alert(caller.tenant_id, alert_id)
    if alert is None:
        raise _not_found("alert", alert_id)
    return alert


investigations = APIRouter(prefix="/investigations", tags=["investigations"])


@investigations.post("", responses={201: {"model": Investigation}})
def start_investigation(
    deps: Deps, caller: Caller, body: InvestigationCreate, response: Response
) -> Investigation:
    """Start an investigation of an alert. Calling it again for the same alert is a rerun,
    unless an investigation of that alert is still live, which is then returned."""
    investigation, created = deps.investigations.create_investigation(
        caller.tenant_id, body.alert_id, body.client_request_id
    )
    if created:
        _audit(deps, caller, "investigation.start", investigation.investigation_id,
               detail=f"alert {body.alert_id}")
    _created_or_replayed(response, created, f"/investigations/{investigation.investigation_id}")
    return investigation


@investigations.get("")
def list_investigations(
    deps: Deps, caller: Caller, alert_id: str | None = None, limit: Limit = DEFAULT_PAGE
) -> list[Investigation]:
    return deps.investigations.list_investigations(caller.tenant_id, alert_id=alert_id, limit=limit)


@investigations.get("/{investigation_id}")
def get_investigation(deps: Deps, caller: Caller, investigation_id: str) -> Investigation:
    investigation = deps.investigations.get_investigation(caller.tenant_id, investigation_id)
    if investigation is None:
        raise _not_found("investigation", investigation_id)
    return investigation


@investigations.post("/{investigation_id}/cancel")
def cancel_investigation(deps: Deps, caller: Caller, investigation_id: str) -> Investigation:
    investigation = deps.investigations.cancel_investigation(caller.tenant_id, investigation_id)
    _audit(deps, caller, "investigation.cancel", investigation_id)
    return investigation


@investigations.delete("/{investigation_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_investigation(deps: Deps, caller: Caller, investigation_id: str) -> None:
    """Hide an investigation from every read. Its records are kept: lessons cite runs."""
    deps.investigations.delete_investigation(caller.tenant_id, investigation_id)
    _audit(deps, caller, "investigation.delete", investigation_id)


@investigations.get(
    "/{investigation_id}/artifacts/{key:path}",
    status_code=status.HTTP_307_TEMPORARY_REDIRECT,
    response_class=RedirectResponse,
)
def read_artifact(deps: Deps, caller: Caller, investigation_id: str, key: str) -> RedirectResponse:
    """Redirect to a short-lived signed link on the blob store's own origin. The bytes never
    pass through the API, and a run page never renders on the app's origin.

    `key` may hold `/` (a file inside the run folder's bundle); only keys the investigation's
    own artifact list names are answered."""
    investigation = get_investigation(deps, caller, investigation_id)
    if key not in investigation.artifacts:
        raise _not_found("artifact", key)
    _audit(deps, caller, "artifact.read", investigation_id, detail=key)
    url = deps.artifact_links.signed_url(caller.tenant_id, investigation_id, key)
    return RedirectResponse(url, headers={"Cache-Control": "no-store"})


learning_jobs = APIRouter(prefix="/learning-jobs", tags=["learning"])


@learning_jobs.post("", responses={201: {"model": LearningJob}})
def start_learning_job(
    deps: Deps, caller: Caller, body: LearningJobCreate, response: Response
) -> LearningJob:
    """Learn again from a completed investigation. Completion already queued one
    automatically; this adds another."""
    job, created = deps.learning_jobs.create_learning_job(
        caller.tenant_id, body.investigation_id, body.client_request_id
    )
    if created:
        _audit(deps, caller, "learning_job.start", job.learning_job_id,
               detail=f"investigation {body.investigation_id}")
    _created_or_replayed(response, created, f"/learning-jobs/{job.learning_job_id}")
    return job


@learning_jobs.get("")
def list_learning_jobs(
    deps: Deps, caller: Caller, investigation_id: str | None = None, limit: Limit = DEFAULT_PAGE
) -> list[LearningJob]:
    return deps.learning_jobs.list_learning_jobs(
        caller.tenant_id, investigation_id=investigation_id, limit=limit
    )


@learning_jobs.get("/{learning_job_id}")
def get_learning_job(deps: Deps, caller: Caller, learning_job_id: str) -> LearningJob:
    job = deps.learning_jobs.get_learning_job(caller.tenant_id, learning_job_id)
    if job is None:
        raise _not_found("learning job", learning_job_id)
    return job


lessons = APIRouter(prefix="/lessons", tags=["learning"])


@lessons.get("")
def list_lessons(deps: Deps, caller: Caller) -> list[Lesson]:
    return deps.lessons.list_lessons(caller.tenant_id)


systems = APIRouter(prefix="/systems", tags=["systems"])


@systems.get("")
def list_systems(deps: Deps, caller: Caller) -> list[System]:
    return deps.systems.list_systems(caller.tenant_id)


def _system(deps: ApiDeps, caller: Principal, system_id: str) -> System:
    system = deps.systems.get_system(caller.tenant_id, system_id)
    if system is None:
        raise _not_found("system", system_id)
    return system


@systems.put("/{system_id}", responses={201: {"model": System}})
def put_system(deps: Deps, caller: Caller, system_id: str, body: SystemPut, response: Response) -> System:
    """Create or replace a connected system's settings. Credentials are set separately."""
    system, created = deps.systems.put_system(caller.tenant_id, system_id, body)
    _audit(deps, caller, "system.update", system_id)
    _created_or_replayed(response, created, f"/systems/{system_id}")
    return system


@systems.put("/{system_id}/credentials", status_code=status.HTTP_204_NO_CONTENT)
def put_credentials(deps: Deps, caller: Caller, system_id: str, body: CredentialsPut) -> None:
    """Replace the system's credentials. Write-only: no endpoint returns them."""
    _system(deps, caller, system_id)
    deps.secrets.put_credentials(caller.tenant_id, system_id, body.credentials)
    _audit(deps, caller, "system.credentials", system_id,
           detail="fields: " + ", ".join(sorted(body.credentials)))


@systems.post("/{system_id}/check")
def check_system(deps: Deps, caller: Caller, system_id: str) -> SystemCheck:
    """Test the connection and a first query."""
    return deps.checker.check(caller.tenant_id, _system(deps, caller, system_id))


def _refusal(code: int) -> Callable[[Request, Exception], Awaitable[JSONResponse]]:
    async def handle(_request: Request, exc: Exception) -> JSONResponse:
        return JSONResponse({"detail": str(exc)}, status_code=code)
    return handle


def create_app(deps: ApiDeps) -> FastAPI:
    app = FastAPI(
        title="Defender platform API",
        version=API_VERSION,
        summary="Stub: the routes and shapes are the contract; the records are in-memory fakes.",
    )
    app.state.deps = deps
    for router in (alerts, investigations, learning_jobs, lessons, systems):
        app.include_router(router)
    app.add_exception_handler(NotFound, _refusal(status.HTTP_404_NOT_FOUND))
    app.add_exception_handler(Conflict, _refusal(status.HTTP_409_CONFLICT))
    app.add_exception_handler(UnknownReference, _refusal(status.HTTP_422_UNPROCESSABLE_CONTENT))
    return app
