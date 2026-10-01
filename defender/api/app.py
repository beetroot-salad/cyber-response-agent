"""The routes: #1131's public API, each a thin translation onto a port.

Every route resolves the caller through the one login dependency (`_principal`) and passes its
tenant to the ports; no route reads a tenant from the request. Every write — and every audited
read — runs in one store transaction opened for the caller: the route writes the record and its
audit event through it, so the two commit together or not at all. Which actions are audited, and
with what, is decided here; that they commit together is the store's (`ports.py`). The routes
decide no data rule — which request replays which record, what may be cancelled, deleted or
learned from is the store's (`ports.py`). What they own is the mapping onto HTTP:

- A create answers 201 with a `Location` header when the port says it created, else 200 with
  the record the port returned.
- `None` from a read, or `NotFound`, is a 404; a record another tenant owns reads the same.
- `UnknownReference` (a body naming a missing record) is a 422; `Conflict` is a 409.
- Malformed input never reaches a port, whichever way it comes in (path, query, body or
  cursor): ids outside `RECORD_ID_PATTERN`, times without an offset and bare numbers where a
  time is due are 422s at the boundary.
- An answer a port's contract rules out is a 500 (`StoreBrokePromise`), never served.
"""

from __future__ import annotations

import datetime as _dt
import json
from collections.abc import Awaitable, Callable
from contextlib import AbstractContextManager
from typing import Annotated, Any

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Path, Query, Request, Response, status
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import ValidationError

from defender._tenant import TenantRefused

from .models import (
    RECORD_ID_PATTERN,
    Alert,
    AlertSummary,
    CredentialsPut,
    Instant,
    Investigation,
    InvestigationCreate,
    LearningJob,
    LearningJobCreate,
    Lesson,
    System,
    SystemCheck,
    SystemPut,
    SystemSettings,
)
from .pages import Order, Page, newest_first, ordered_by_id, paginate
from .ports import (
    ApiDeps,
    Conflict,
    NotFound,
    Principal,
    StoreBrokePromise,
    TimePosition,
    Unauthenticated,
    UnknownReference,
    WriteTransaction,
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
    # A login answer that cannot become a caller — a tenant outside its grammar, a malformed
    # user — is no login at all: a 401, like a missing token, never a 500.
    except (Unauthenticated, TenantRefused, ValidationError) as e:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, str(e), headers={"WWW-Authenticate": "Bearer"}
        ) from e


Deps = Annotated[ApiDeps, Depends(_deps)]
Caller = Annotated[Principal, Depends(_principal)]
Limit = Annotated[int, Query(ge=1, le=MAX_PAGE)]
Cursor = Annotated[str | None, Query(max_length=2048, description="`next_cursor` from the previous page.")]
Id = Annotated[str, Path(pattern=RECORD_ID_PATTERN)]


#: Each list's total order, as its port states it (`ports.py`).
_ALERT_ORDER: Order[AlertSummary, TimePosition] = newest_first(lambda a: a.fired_at, lambda a: a.alert_id)
_INVESTIGATION_ORDER: Order[Investigation, TimePosition] = newest_first(lambda i: i.created_at, lambda i: i.investigation_id)
_LEARNING_JOB_ORDER: Order[LearningJob, TimePosition] = newest_first(lambda j: j.created_at, lambda j: j.learning_job_id)
_LESSON_ORDER: Order[Lesson, str] = ordered_by_id(lambda le: le.lesson_id)
_SYSTEM_ORDER: Order[SystemSettings, str] = ordered_by_id(lambda s: s.system_id)


def _filter_moment(moment: _dt.datetime | None) -> str | None:
    """A filter moment's cursor spelling. It is an `Instant`, already UTC, so one instant has
    one spelling whatever offset the caller wrote it with."""
    return None if moment is None else moment.isoformat()


def _transaction(deps: ApiDeps, caller: Principal) -> AbstractContextManager[WriteTransaction]:
    return deps.writes.transaction(caller.tenant_id, caller.user_id)


def _answered_for(what: str, named: str, answered: str) -> None:
    """The store's answer to a create is for what the request named (`ports.py`)."""
    if answered != named:
        raise StoreBrokePromise(f"asked about {what} {named!r}, the store answered for {answered!r}")


def _not_found(what: str, record_id: str) -> HTTPException:
    return HTTPException(status.HTTP_404_NOT_FOUND, f"no {what} {record_id!r}")


def _created_at(request: Request, response: Response, route: str, **path: str) -> None:
    """201 and a `Location` the router builds from `route`'s path. Only a creation calls it: a
    replay answers the default 200 and needs no URL. Every path value is a `RecordId`, whose
    grammar is URL-safe, so the router never has to encode or refuse one."""
    response.status_code = status.HTTP_201_CREATED
    response.headers["Location"] = str(request.url_for(route, **path))


alerts = APIRouter(prefix="/alerts", tags=["alerts"])


@alerts.get("")
def list_alerts(
    deps: Deps,
    caller: Caller,
    fired_after: Instant | None = None,
    fired_before: Instant | None = None,
    severity: str | None = None,
    cursor: Cursor = None,
    limit: Limit = DEFAULT_PAGE,
) -> Page[AlertSummary]:
    return paginate(
        lambda after, n: deps.alerts.list_alerts(
            caller.tenant_id, fired_after=fired_after, fired_before=fired_before,
            severity=severity, after=after, limit=n,
        ),
        _ALERT_ORDER, list_name="alerts", tenant_id=caller.tenant_id, cursor=cursor, limit=limit,
        filters={"fired_after": _filter_moment(fired_after), "fired_before": _filter_moment(fired_before),
                 "severity": severity},
    )


@alerts.get("/{alert_id}")
def get_alert(deps: Deps, caller: Caller, alert_id: Id) -> Alert:
    alert = deps.alerts.get_alert(caller.tenant_id, alert_id)
    if alert is None:
        raise _not_found("alert", alert_id)
    return alert


investigations = APIRouter(prefix="/investigations", tags=["investigations"])


@investigations.post("", responses={201: {"model": Investigation}})
def start_investigation(
    deps: Deps, caller: Caller, body: InvestigationCreate, request: Request, response: Response
) -> Investigation:
    """Start an investigation of an alert. While one of the alert's investigations is live, it
    is returned and nothing starts; otherwise a new one starts (a rerun, if an earlier one ended).

    Repeating a request with its `client_request_id` returns the investigation that request
    started (200). A request answered with an investigation that was already live started
    nothing, so repeating it later is a new request."""
    with _transaction(deps, caller) as tx:
        investigation, created = tx.create_investigation(body.alert_id, body.client_request_id)
        _answered_for("alert", body.alert_id, investigation.alert_id)
        if created:
            tx.audit("investigation.start", investigation.investigation_id,
                     detail=f"alert {body.alert_id}")
    if created:
        _created_at(request, response, "get_investigation",
                    investigation_id=investigation.investigation_id)
    return investigation


@investigations.get("")
def list_investigations(
    deps: Deps, caller: Caller, alert_id: Annotated[str | None, Query(pattern=RECORD_ID_PATTERN)] = None,
    cursor: Cursor = None,
    limit: Limit = DEFAULT_PAGE,
) -> Page[Investigation]:
    return paginate(
        lambda after, n: deps.investigations.list_investigations(
            caller.tenant_id, alert_id=alert_id, after=after, limit=n),
        _INVESTIGATION_ORDER, list_name="investigations", tenant_id=caller.tenant_id,
        cursor=cursor, limit=limit, filters={"alert_id": alert_id},
    )


@investigations.get("/{investigation_id}")
def get_investigation(deps: Deps, caller: Caller, investigation_id: Id) -> Investigation:
    investigation = deps.investigations.get_investigation(caller.tenant_id, investigation_id)
    if investigation is None:
        raise _not_found("investigation", investigation_id)
    return investigation


@investigations.post("/{investigation_id}/cancel")
def cancel_investigation(deps: Deps, caller: Caller, investigation_id: Id) -> Investigation:
    with _transaction(deps, caller) as tx:
        investigation = tx.cancel_investigation(investigation_id)
        tx.audit("investigation.cancel", investigation_id)
    return investigation


@investigations.delete("/{investigation_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_investigation(deps: Deps, caller: Caller, investigation_id: Id) -> None:
    """Hide an investigation from every read. Its records are kept: lessons cite runs."""
    with _transaction(deps, caller) as tx:
        tx.delete_investigation(investigation_id)
        tx.audit("investigation.delete", investigation_id)


@investigations.get(
    "/{investigation_id}/artifacts/{key:path}",
    status_code=status.HTTP_307_TEMPORARY_REDIRECT,
    response_class=RedirectResponse,
)
def read_artifact(deps: Deps, caller: Caller, investigation_id: Id, key: str) -> RedirectResponse:
    """Redirect to a short-lived signed link on the blob store's own origin. The bytes never
    pass through the API, and a run page never renders on the app's origin.

    `key` may hold `/` (a file inside the run folder's bundle); only keys the investigation's
    own artifact list names are answered."""
    investigation = get_investigation(deps, caller, investigation_id)
    if key not in investigation.artifacts:
        raise _not_found("artifact", key)
    url = deps.artifact_links.signed_url(caller.tenant_id, investigation_id, key)
    # Audited once the link exists, and committed before it is handed out.
    with _transaction(deps, caller) as tx:
        tx.audit("artifact.read", investigation_id, detail=key)
    return RedirectResponse(url, headers={"Cache-Control": "no-store"})


learning_jobs = APIRouter(prefix="/learning-jobs", tags=["learning"])


@learning_jobs.post("", responses={201: {"model": LearningJob}})
def start_learning_job(
    deps: Deps, caller: Caller, body: LearningJobCreate, request: Request, response: Response
) -> LearningJob:
    """Learn again from an investigation: queue an explicit re-learn. A completed
    investigation is learned from automatically; this adds another, and re-learns are unlimited.
    Repeating a request with its `client_request_id` returns the job that request queued (200)."""
    with _transaction(deps, caller) as tx:
        job, created = tx.create_learning_job(body.investigation_id, body.client_request_id)
        _answered_for("investigation", body.investigation_id, job.investigation_id)
        if created:
            tx.audit("learning_job.start", job.learning_job_id,
                     detail=f"investigation {body.investigation_id}")
    if created:
        _created_at(request, response, "get_learning_job", learning_job_id=job.learning_job_id)
    return job


@learning_jobs.get("")
def list_learning_jobs(
    deps: Deps, caller: Caller,
    investigation_id: Annotated[str | None, Query(pattern=RECORD_ID_PATTERN)] = None,
    cursor: Cursor = None,
    limit: Limit = DEFAULT_PAGE,
) -> Page[LearningJob]:
    return paginate(
        lambda after, n: deps.learning_jobs.list_learning_jobs(
            caller.tenant_id, investigation_id=investigation_id, after=after, limit=n),
        _LEARNING_JOB_ORDER, list_name="learning-jobs", tenant_id=caller.tenant_id,
        cursor=cursor, limit=limit, filters={"investigation_id": investigation_id},
    )


@learning_jobs.get("/{learning_job_id}")
def get_learning_job(deps: Deps, caller: Caller, learning_job_id: Id) -> LearningJob:
    job = deps.learning_jobs.get_learning_job(caller.tenant_id, learning_job_id)
    if job is None:
        raise _not_found("learning job", learning_job_id)
    return job


lessons = APIRouter(prefix="/lessons", tags=["learning"])


@lessons.get("")
def list_lessons(
    deps: Deps, caller: Caller, cursor: Cursor = None, limit: Limit = DEFAULT_PAGE
) -> Page[Lesson]:
    return paginate(
        lambda after, n: deps.lessons.list_lessons(caller.tenant_id, after=after, limit=n),
        _LESSON_ORDER, list_name="lessons", tenant_id=caller.tenant_id, cursor=cursor,
        limit=limit, filters={},
    )


systems = APIRouter(prefix="/systems", tags=["systems"])


def _served(deps: ApiDeps, caller: Principal, settings: SystemSettings) -> System:
    """The system as served: its settings plus the secret store's own answer, so the flag can
    never disagree with where credentials were written."""
    has = deps.secrets.has_credentials(caller.tenant_id, settings.system_id)
    # Only the settings' own fields: a store answering a richer record cannot collide with ours.
    return System(**settings.model_dump(include=set(SystemSettings.model_fields)), has_credentials=has)


@systems.get("")
def list_systems(
    deps: Deps, caller: Caller, cursor: Cursor = None, limit: Limit = DEFAULT_PAGE
) -> Page[System]:
    page = paginate(
        lambda after, n: deps.systems.list_systems(caller.tenant_id, after=after, limit=n),
        _SYSTEM_ORDER, list_name="systems", tenant_id=caller.tenant_id, cursor=cursor,
        limit=limit, filters={},
    )
    # Served after the page is cut, so the secret store is asked only about rows that are sent.
    return Page(items=[_served(deps, caller, s) for s in page.items], next_cursor=page.next_cursor)


def _settings(deps: ApiDeps, caller: Principal, system_id: str) -> SystemSettings:
    settings = deps.systems.get_system(caller.tenant_id, system_id)
    if settings is None:
        raise _not_found("system", system_id)
    return settings


@systems.put("/{system_id}", responses={201: {"model": System}})
def put_system(
    deps: Deps, caller: Caller, system_id: Id, body: SystemPut, request: Request, response: Response
) -> System:
    """Create or replace a connected system's settings. Credentials are set separately."""
    with _transaction(deps, caller) as tx:
        settings, created = tx.put_system(system_id, body)
        _answered_for("system", system_id, settings.system_id)
        tx.audit("system.update", system_id)
    if created:
        # A PUT creates the resource at its own URL; built by the router, so no query rides along.
        _created_at(request, response, "put_system", system_id=system_id)
    return _served(deps, caller, settings)


@systems.put("/{system_id}/credentials", status_code=status.HTTP_204_NO_CONTENT)
def put_credentials(deps: Deps, caller: Caller, system_id: Id, body: CredentialsPut) -> None:
    """Replace the system's credentials. Write-only: no endpoint returns them."""
    _settings(deps, caller, system_id)
    # The secret store is outside the transaction, so the audit event is written first and the
    # secret inside the block: a failed audit write stops the secret write, and only a commit
    # failing after the secret is stored can leave it unaudited.
    with _transaction(deps, caller) as tx:
        tx.audit("system.credentials", system_id,
                 detail="fields: " + ", ".join(sorted(body.credentials)))
        deps.secrets.put_credentials(caller.tenant_id, system_id, body.credentials)


@systems.post("/{system_id}/check")
def check_system(deps: Deps, caller: Caller, system_id: Id) -> SystemCheck:
    """Test the connection and a first query."""
    return deps.checker.check(caller.tenant_id, _served(deps, caller, _settings(deps, caller, system_id)))


def _refusal(code: int) -> Callable[[Request, Exception], Awaitable[JSONResponse]]:
    async def handle(_request: Request, exc: Exception) -> JSONResponse:
        return JSONResponse({"detail": str(exc)}, status_code=code)
    return handle


class _AsciiJSONResponse(JSONResponse):
    """JSON with every non-ASCII character escaped. A 422 echoes the refused input, and a lone
    surrogate in it cannot be encoded as UTF-8: rendered raw, the refusal itself would be a 500."""

    def render(self, content: Any) -> bytes:
        return json.dumps(content, ensure_ascii=True, allow_nan=False, separators=(",", ":")).encode("ascii")


async def _invalid_request(_request: Request, exc: Exception) -> JSONResponse:
    """FastAPI's own 422 shape, rendered so any refused input can be echoed."""
    if not isinstance(exc, RequestValidationError):
        raise exc
    return _AsciiJSONResponse({"detail": jsonable_encoder(exc.errors())}, status_code=422)


def create_app(deps: ApiDeps) -> FastAPI:
    app = FastAPI(
        title="Defender platform API",
        version=API_VERSION,
        summary="Stub: the routes and shapes are the contract; the records behind them are not yet real.",
    )
    app.state.deps = deps
    for router in (alerts, investigations, learning_jobs, lessons, systems):
        app.include_router(router)
    app.add_exception_handler(NotFound, _refusal(status.HTTP_404_NOT_FOUND))
    app.add_exception_handler(Conflict, _refusal(status.HTTP_409_CONFLICT))
    # The literal, not starlette's constant: it was renamed across starlette releases.
    app.add_exception_handler(UnknownReference, _refusal(422))
    app.add_exception_handler(RequestValidationError, _invalid_request)
    return app
