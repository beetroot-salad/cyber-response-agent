"""The routes: #1131's public API, each a thin translation onto a port."""

from __future__ import annotations

import asyncio
import datetime as _dt
import logging
import threading
from collections.abc import AsyncIterator
from contextlib import AbstractContextManager, asynccontextmanager
from typing import Annotated, NamedTuple

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Path, Query, Request, Response, status
from fastapi.responses import RedirectResponse

from defender import identity as _identity
from defender.identity import Authenticated, IdentityService
from defender.identity.service import SESSION_LIFETIME
from defender.tenancy._tenant import TenantId

from .models import (
    RECORD_ID_PATTERN,
    Alert,
    AlertSummary,
    CredentialsPut,
    Instant,
    Invitation,
    InvitationRef,
    InviteCreate,
    Investigation,
    InvestigationCreate,
    LearningJob,
    LearningJobCreate,
    Lesson,
    Me,
    Member,
    MeUser,
    System,
    SystemCheck,
    SystemPut,
    SystemSettings,
    TenantRef,
)
from .pages import Order, Page, newest_first, ordered_by_id, paginate
from .problems import install as install_problems
from .problems import problem, refusal, responses
from .ports import (
    ApiDeps,
    Conflict,
    NotFound,
    Principal,
    StoreBrokePromise,
    TimePosition,
    UnknownReference,
    WriteTransaction,
)

API_VERSION = "0.1.0-stub"

#: The largest page any list returns; `limit` defaults to `DEFAULT_PAGE`.
MAX_PAGE = 200
DEFAULT_PAGE = 50

#: DC-6: `__Host-` cookies are Secure, Path=/ and carry no Domain.
SESSION_COOKIE = "__Host-defender_session"
PRELOGIN_COOKIE = "__Host-defender_prelogin"
_PRELOGIN_MAX_AGE = 600
_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
#: How long the sender loop may take to stop when the app shuts down.
_SENDER_STOP_WAIT = 2.0

_logger = logging.getLogger(__name__)


def _deps(request: Request) -> ApiDeps:
    deps: ApiDeps = request.app.state.deps
    return deps


def _check_origin(request: Request, deps: Annotated[ApiDeps, Depends(_deps)]) -> None:
    """A request that changes state must come from the configured frontend (O6). Checked first,
    before the session and before the body is read, so a forged request learns nothing."""
    if request.method not in _SAFE_METHODS and request.headers.get("origin") != deps.frontend_origin:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "this request does not come from the frontend")


def _authenticated(request: Request, deps: Annotated[ApiDeps, Depends(_deps)]) -> Authenticated:
    return deps.identity.authenticate(request.cookies.get(SESSION_COOKIE))


Authed = Annotated[Authenticated, Depends(_authenticated)]


class _Membered(NamedTuple):
    auth: Authenticated
    tenant_id: TenantId


def _membered(
    tenant_id: Annotated[str, Path(description="The tenant the request acts in.")],
    auth: Authed, deps: Annotated[ApiDeps, Depends(_deps)],
) -> _Membered:
    """The tenant is the path's and is checked against the caller's membership on every request;
    a non-member, an unknown tenant and a malformed id are all the same 404 (P-D)."""
    return _Membered(auth, TenantId(deps.identity.member_of(auth, tenant_id)))


Membered = Annotated[_Membered, Depends(_membered)]


def _principal(member: Membered) -> Principal:
    return Principal(tenant_id=member.tenant_id, user_id=member.auth.user.id)


def _administrator(auth: Authed, deps: Annotated[ApiDeps, Depends(_deps)]) -> Authenticated:
    deps.identity.require_administrator(auth)
    return auth


Deps = Annotated[ApiDeps, Depends(_deps)]
Admin = Annotated[Authenticated, Depends(_administrator)]
Caller = Annotated[Principal, Depends(_principal)]
Limit = Annotated[int, Query(ge=1, le=MAX_PAGE)]
Cursor = Annotated[str | None, Query(max_length=2048, description="`next_cursor` from the previous page.")]
Id = Annotated[str, Path(pattern=RECORD_ID_PATTERN)]


#: The problems any route can answer: no login, a request that fails validation (every route
#: takes an id, a body, a cursor or a page size), an unexpected failure.
_EVERY_ROUTE = responses(401, 422, 500)


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


def _created_at(request: Request, response: Response, route: str, tenant_id: str, **path: str) -> None:
    """201 and a `Location` the router builds from `route`'s path. Only a creation calls it: a
    replay answers the default 200 and needs no URL. Every path value is a `RecordId`, whose
    grammar is URL-safe, so the router never has to encode or refuse one."""
    response.status_code = status.HTTP_201_CREATED
    response.headers["Location"] = str(request.url_for(route, tenant_id=tenant_id, **path))


alerts = APIRouter(prefix="/alerts", tags=["alerts"], responses=_EVERY_ROUTE)


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


@alerts.get("/{alert_id}", responses=responses(404))
def get_alert(deps: Deps, caller: Caller, alert_id: Id) -> Alert:
    alert = deps.alerts.get_alert(caller.tenant_id, alert_id)
    if alert is None:
        raise _not_found("alert", alert_id)
    return alert


investigations = APIRouter(prefix="/investigations", tags=["investigations"], responses=_EVERY_ROUTE)


@investigations.post("", responses={201: {"model": Investigation}, **responses(409)})
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
        _created_at(request, response, "get_investigation", caller.tenant_id,
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


@investigations.get("/{investigation_id}", responses=responses(404))
def get_investigation(deps: Deps, caller: Caller, investigation_id: Id) -> Investigation:
    investigation = deps.investigations.get_investigation(caller.tenant_id, investigation_id)
    if investigation is None:
        raise _not_found("investigation", investigation_id)
    return investigation


@investigations.post("/{investigation_id}/cancel", responses=responses(404, 409))
def cancel_investigation(deps: Deps, caller: Caller, investigation_id: Id) -> Investigation:
    with _transaction(deps, caller) as tx:
        investigation = tx.cancel_investigation(investigation_id)
        tx.audit("investigation.cancel", investigation_id)
    return investigation


@investigations.delete("/{investigation_id}", status_code=status.HTTP_204_NO_CONTENT,
                        responses=responses(404, 409))
def delete_investigation(deps: Deps, caller: Caller, investigation_id: Id) -> None:
    """Hide an investigation from every read. Its records are kept: lessons cite runs."""
    with _transaction(deps, caller) as tx:
        tx.delete_investigation(investigation_id)
        tx.audit("investigation.delete", investigation_id)


@investigations.get(
    "/{investigation_id}/artifacts/{key:path}",
    status_code=status.HTTP_307_TEMPORARY_REDIRECT,
    response_class=RedirectResponse,
    responses=responses(404),
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


learning_jobs = APIRouter(prefix="/learning-jobs", tags=["learning"], responses=_EVERY_ROUTE)


@learning_jobs.post("", responses={201: {"model": LearningJob}, **responses(409)})
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
        _created_at(request, response, "get_learning_job", caller.tenant_id, learning_job_id=job.learning_job_id)
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


@learning_jobs.get("/{learning_job_id}", responses=responses(404))
def get_learning_job(deps: Deps, caller: Caller, learning_job_id: Id) -> LearningJob:
    job = deps.learning_jobs.get_learning_job(caller.tenant_id, learning_job_id)
    if job is None:
        raise _not_found("learning job", learning_job_id)
    return job


lessons = APIRouter(prefix="/lessons", tags=["learning"], responses=_EVERY_ROUTE)


@lessons.get("")
def list_lessons(
    deps: Deps, caller: Caller, cursor: Cursor = None, limit: Limit = DEFAULT_PAGE
) -> Page[Lesson]:
    return paginate(
        lambda after, n: deps.lessons.list_lessons(caller.tenant_id, after=after, limit=n),
        _LESSON_ORDER, list_name="lessons", tenant_id=caller.tenant_id, cursor=cursor,
        limit=limit, filters={},
    )


systems = APIRouter(prefix="/systems", tags=["systems"], responses=_EVERY_ROUTE)


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
        _created_at(request, response, "put_system", caller.tenant_id, system_id=system_id)
    return _served(deps, caller, settings)


@systems.put("/{system_id}/credentials", status_code=status.HTTP_204_NO_CONTENT,
             responses=responses(404))
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


@systems.post("/{system_id}/check", responses=responses(404))
def check_system(deps: Deps, caller: Caller, system_id: Id) -> SystemCheck:
    """Test the connection and a first query."""
    return deps.checker.check(caller.tenant_id, _served(deps, caller, _settings(deps, caller, system_id)))


# --- people, memberships and sign-in (#1306) ---------------------------------------------------

#: What every identity route can answer: no session, a refused request, a malformed one.
_IDENTITY = responses(401, 403, 422, 500)


def _cookie_options() -> dict[str, object]:
    return {"path": "/", "secure": True, "httponly": True, "samesite": "lax"}


auth = APIRouter(tags=["auth"])


@auth.get("/auth/login", status_code=status.HTTP_302_FOUND, response_class=RedirectResponse,
          responses=responses(503, 500))
def login(deps: Deps) -> RedirectResponse:
    """Send the person to the sign-in page. The state, nonce and PKCE verifier travel back in a
    short-lived cookie."""
    start = deps.identity.begin_signin()
    response = RedirectResponse(start.url, status_code=status.HTTP_302_FOUND)
    response.set_cookie(PRELOGIN_COOKIE, start.prelogin, max_age=_PRELOGIN_MAX_AGE, **_cookie_options())  # type: ignore[arg-type]
    return response


@auth.get("/auth/callback", status_code=status.HTTP_303_SEE_OTHER, response_class=RedirectResponse,
          responses=responses(403, 503, 422, 500))
def callback(request: Request, deps: Deps, code: str = "", state: str = "") -> Response:
    """Finish a sign-in: a session cookie and a redirect to the frontend, or a 403 problem of one
    of four types. The pre-login cookie is cleared whatever the outcome."""
    try:
        value = deps.identity.complete_signin(
            code=code, state=state, prelogin=request.cookies.get(PRELOGIN_COOKIE))
    except _identity.CallbackRefused as e:
        response: Response = problem(403, str(e), type_=f"urn:defender:problem:{e.reason}")
    except _identity.SignInUnavailable:
        response = problem(503, "sign-in is unavailable")
    else:
        response = RedirectResponse(deps.frontend_origin, status_code=status.HTTP_303_SEE_OTHER)
        response.set_cookie(SESSION_COOKIE, value, max_age=int(SESSION_LIFETIME.total_seconds()),
                            **_cookie_options())  # type: ignore[arg-type]
    response.delete_cookie(PRELOGIN_COOKIE, **_cookie_options())  # type: ignore[arg-type]
    return response


@auth.post("/auth/logout", status_code=status.HTTP_204_NO_CONTENT, responses=_IDENTITY)
def logout(request: Request, deps: Deps, caller: Authed) -> Response:
    """End this session only; other devices stay signed in."""
    deps.identity.logout(caller, request.cookies.get(SESSION_COOKIE, ""))
    response = Response(status_code=status.HTTP_204_NO_CONTENT)
    response.delete_cookie(SESSION_COOKIE, **_cookie_options())  # type: ignore[arg-type]
    return response


@auth.get("/me", responses=_IDENTITY)
def read_me(deps: Deps, caller: Authed) -> Me:
    view = deps.identity.me(caller)
    return Me(
        user=MeUser(id=view.user.id, email=view.user.email, display_name=view.user.display_name),
        tenants=[TenantRef(tenant_id=t) for t in view.tenants],
        administrator=view.administrator,
        invitations=[InvitationRef(id=i.id, tenant_id=i.tenant_id) for i in view.invitations])


@auth.post("/invitations/{invitation_id}/accept", responses={**_IDENTITY, **responses(404)})
def accept_invitation(deps: Deps, caller: Authed, invitation_id: str = Path(max_length=64)) -> TenantRef:
    """Accept an invitation addressed to you, while signed in."""
    return TenantRef(tenant_id=deps.identity.accept(caller, invitation_id))


people = APIRouter(tags=["people"], responses=_EVERY_ROUTE)


def _invitation(view: _identity.InvitationView) -> Invitation:
    return Invitation(id=view.id, email=view.email, status=view.status, created_at=view.created_at)


@people.get("/members")
def list_members(deps: Deps, member: Membered) -> Page[Member]:
    rows = deps.identity.members(member.tenant_id)
    return Page(items=[Member(user_id=m.user_id, email=m.email, display_name=m.display_name) for m in rows],
                next_cursor=None)


@people.delete("/members/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def remove_member(deps: Deps, member: Membered, user_id: str = Path(max_length=64)) -> None:
    """End a membership: yours, or another member's. Nothing else of that person changes."""
    deps.identity.remove(member.auth, member.tenant_id, user_id)


@people.get("/invitations")
def list_invitations(deps: Deps, member: Membered) -> Page[Invitation]:
    return Page(items=[_invitation(v) for v in deps.identity.invitations(member.tenant_id)],
                next_cursor=None)


@people.post("/invitations", status_code=status.HTTP_202_ACCEPTED, responses=responses(409))
def invite(deps: Deps, member: Membered, body: InviteCreate) -> Invitation:
    """Invite a person by email. The answer is the same whoever the email belongs to; the
    email itself goes out afterwards."""
    return _invitation(deps.identity.invite(member.auth, member.tenant_id, body.email))


@people.delete("/invitations/{invitation_id}", status_code=status.HTTP_204_NO_CONTENT)
def revoke_invitation(deps: Deps, member: Membered, invitation_id: str = Path(max_length=64)) -> None:
    deps.identity.revoke(member.auth, member.tenant_id, invitation_id)


admin = APIRouter(prefix="/admin", tags=["admin"], responses={**_IDENTITY, **responses(404)})


@admin.get("/tenants")
def list_all_tenants(deps: Deps, caller: Admin) -> Page[TenantRef]:
    return Page(items=[TenantRef(tenant_id=t) for t in deps.identity.all_tenants(caller)], next_cursor=None)


@admin.post("/tenants/{tenant_id}/invitations", status_code=status.HTTP_202_ACCEPTED,
            responses=responses(409))
def admin_invite(deps: Deps, caller: Admin, body: InviteCreate,
                 tenant_id: str = Path(max_length=64)) -> Invitation:
    """Invite the first member into a tenant that has no active members."""
    return _invitation(deps.identity.admin_invite(caller, tenant_id, body.email))


def _send_loop(identity: IdentityService, stop: threading.Event) -> None:
    """Run the sender now and then every `send_interval` until told to stop. A failing pass
    never stops the loop."""
    while True:
        try:
            identity.send_pending()
        except Exception:
            _logger.exception("a sender pass failed; the next pass tries again")
        if stop.wait(identity.send_interval.total_seconds()):
            return


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    identity: IdentityService = app.state.deps.identity
    await asyncio.to_thread(identity.start)
    stop = threading.Event()
    sender = threading.Thread(target=_send_loop, args=(identity, stop), name="identity-sender", daemon=True)
    sender.start()
    try:
        yield
    finally:
        stop.set()
        await asyncio.to_thread(sender.join, _SENDER_STOP_WAIT)


def create_app(deps: ApiDeps) -> FastAPI:
    app = FastAPI(
        title="Defender platform API",
        version=API_VERSION,
        summary="Stub: the routes and shapes are the contract; the records behind them are not yet real.",
        dependencies=[Depends(_check_origin)],
        lifespan=_lifespan,
    )
    app.state.deps = deps
    in_tenant = APIRouter(prefix="/tenants/{tenant_id}", responses=responses(404))
    for router in (alerts, investigations, learning_jobs, lessons, systems, people):
        in_tenant.include_router(router)
    for router in (auth, in_tenant, admin):
        app.include_router(router)
    install_problems(app)
    app.add_exception_handler(NotFound, refusal(status.HTTP_404_NOT_FOUND))
    app.add_exception_handler(Conflict, refusal(status.HTTP_409_CONFLICT))
    # The literal, not starlette's constant: it was renamed across starlette releases.
    app.add_exception_handler(UnknownReference, refusal(422))
    # Unlike the data ports' refusals, none of these answers carries a `WWW-Authenticate`: a
    # session cookie has no challenge to offer.
    app.add_exception_handler(_identity.NotAuthenticated, refusal(status.HTTP_401_UNAUTHORIZED))
    app.add_exception_handler(_identity.Forbidden, refusal(status.HTTP_403_FORBIDDEN))
    app.add_exception_handler(_identity.NotFound, refusal(status.HTTP_404_NOT_FOUND))
    app.add_exception_handler(_identity.Conflict, refusal(status.HTTP_409_CONFLICT))
    app.add_exception_handler(_identity.SignInUnavailable, refusal(status.HTTP_503_SERVICE_UNAVAILABLE))
    return app
