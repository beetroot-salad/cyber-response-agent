"""The routes: #1131's public API, each a thin translation onto a port."""

from __future__ import annotations

import asyncio
import datetime as _dt
import logging
from collections.abc import AsyncIterator, Callable
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from typing import Annotated, Any, NamedTuple

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Path, Query, Request, Response, status
from fastapi.exceptions import RequestValidationError
from fastapi.routing import APIRoute
from fastapi.responses import RedirectResponse
from starlette.datastructures import Headers, MutableHeaders
from starlette.types import ASGIApp, Receive, Scope, Send

from defender import identity as _identity
from defender import tenancy as _tenancy
from defender.identity import Authenticated, IdentityService, audit
from defender.identity.service import SESSION_LIFETIME
from defender.identity.roles import Permission
from defender.records.formats import (
    AlertId, CredentialId, InvestigationId, LearningJobId, MembershipId, TenantId, UserId,
)

from .models import (
    AlertMapping,
    RECORD_ID_PATTERN,
    Alert,
    AlertSummary,
    Credential,
    CredentialCreate,
    CredentialIssued,
    CredentialRef,
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
    Program,
    ProgramCreate,
    ProgramMe,
    ProgramRef,
    System,
    SystemCheck,
    SystemPut,
    SystemSettings,
    TenantItem,
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

_logger = logging.getLogger(__name__)


async def _deps(request: Request) -> ApiDeps:
    deps: ApiDeps = request.app.state.deps
    return deps


#: The scope key under which a verified program's credential expiry travels to the response.
_EXPIRY_SCOPE_KEY = "defender.credential_expires_at"
#: Every response to a verified program carries when the credential it used expires (#1307 D9).
EXPIRY_HEADER = "Defender-Credential-Expires"


class _FrontendOriginOnly:
    """A request that changes state must come from the configured frontend (O6), unless it carries an
    `Authorization` header and no `Cookie` header at all: a browser attaches cookies by itself, so only
    a request with a cookie can be forged from another site (#1307 D2, O9). A layer in front of routing,
    so it answers before the session is looked at or the body is read: a forged request learns
    nothing, not even whether its body would have parsed."""

    def __init__(self, app: ASGIApp, *, origin: str) -> None:
        self._app = app
        self._origin = origin

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http" and scope["method"] not in _SAFE_METHODS:
            headers = Headers(scope=scope)
            bearer_only = "authorization" in headers and "cookie" not in headers
            if not bearer_only and headers.get("origin") != self._origin:
                refused = problem(status.HTTP_403_FORBIDDEN, "this request does not come from the frontend")
                await refused(scope, receive, send)
                return
        await self._app(scope, receive, send)


class _ExpiryHeader:
    """Put the used credential's expiry on the response, whatever its status (D9). The route's
    authentication leaves it in the scope once the credential has verified; a request refused before
    that carries none."""

    def __init__(self, app: ASGIApp) -> None:
        self._app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return

        async def with_header(message: Any) -> None:
            if message["type"] == "http.response.start" and _EXPIRY_SCOPE_KEY in scope:
                MutableHeaders(scope=message)[EXPIRY_HEADER] = scope[_EXPIRY_SCOPE_KEY]
            await send(message)

        await self._app(scope, receive, with_header)


def _declares(what: str) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Mark a dependency as the declaration a route owes (P-H): a permission, or a category outside the
    tenant (`public`, `person`, `any`, `platform`). `undeclared_routes` finds the routes without one."""
    def mark(dependency: Callable[..., Any]) -> Callable[..., Any]:
        dependency.__dict__["declares"] = what
        return dependency
    return mark


async def _credentialed(request: Request, deps: ApiDeps) -> Authenticated:
    """The caller, by exactly one way in: a session cookie (a person) or `Authorization: Bearer` (a
    program). Both together, or an unusable header, is not authenticated: no precedence between them."""
    header = request.headers.get("authorization")
    if header is None:
        return await deps.identity.authenticate(request.cookies.get(SESSION_COOKIE))
    scheme, _, value = header.partition(" ")
    if "cookie" in request.headers or scheme.lower() != "bearer" or not value.strip():
        raise _identity.NotAuthenticated("sign in")
    caller = await deps.identity.authenticate_bearer(value.strip())
    assert caller.credential is not None
    request.scope[_EXPIRY_SCOPE_KEY] = caller.credential.expires_at.astimezone(_dt.UTC).isoformat()
    return caller


async def _authenticated(request: Request, deps: Annotated[ApiDeps, Depends(_deps)]) -> Authenticated:
    return await _credentialed(request, deps)


Authed = Annotated[Authenticated, Depends(_authenticated)]


@_declares("public")
async def _public() -> None:
    """The sign-in routes: nobody is authenticated yet."""


@_declares("person")
async def _person(auth: Authed) -> Authenticated:
    if auth.credential is not None:
        raise _identity.Forbidden("only a person may do that")
    return auth


@_declares("any")
async def _any_caller(auth: Authed) -> Authenticated:
    return auth


Person = Annotated[Authenticated, Depends(_person)]
AnyCaller = Annotated[Authenticated, Depends(_any_caller)]


class _Membered(NamedTuple):
    auth: Authenticated
    tenant_id: TenantId
    membership: _identity.Membership


async def _membered(
    tenant_id: Annotated[TenantId, Path(description="The tenant the request acts in.")],
    auth: Authed, deps: Annotated[ApiDeps, Depends(_deps)],
) -> _Membered:
    """The tenant is the path's and is checked against the caller's membership on every request;
    a non-member and an unknown tenant are the same 404 (P-D). A malformed id is a 422, after the
    sign-in check (#1382): it says nothing of any tenant. Membership comes before permission (D1)."""
    return _Membered(auth, tenant_id, await deps.identity.member_of(auth, tenant_id))


Membered = Annotated[_Membered, Depends(_membered)]


def _permitted(permission: Permission) -> Callable[..., Any]:
    """The dependency of a route that needs `permission`: the caller is a member of the path's tenant
    and its role grants it, else 404 or 403 before anything else in the path is looked at (D1, D4)."""
    @_declares(permission)
    async def dependency(member: Membered, deps: Annotated[ApiDeps, Depends(_deps)]) -> _Membered:
        deps.identity.require(member.membership, permission)
        return member
    return dependency


async def _principal(member: _Membered) -> Principal:
    credential = member.auth.credential
    return Principal(tenant_id=member.tenant_id, user_id=member.auth.user.id,
                     credential_id=None if credential is None else credential.id)


def _caller_with(permission: Permission) -> Callable[..., Any]:
    check = _permitted(permission)

    @_declares(permission)
    async def dependency(member: _Membered = Depends(check)) -> Principal:  # noqa: B008
        return await _principal(member)
    return dependency


@_declares("platform")
async def _administrator(auth: Authed, deps: Annotated[ApiDeps, Depends(_deps)]) -> Authenticated:
    deps.identity.require_administrator(auth)
    return auth


Deps = Annotated[ApiDeps, Depends(_deps)]
Admin = Annotated[Authenticated, Depends(_administrator)]
#: A tenant route's caller, by the one permission the route needs (O3).
WorkReader = Annotated[Principal, Depends(_caller_with("work.read"))]
InvestigationRunner = Annotated[Principal, Depends(_caller_with("investigations.run"))]
InvestigationDeleter = Annotated[Principal, Depends(_caller_with("investigations.delete"))]
LearningRunner = Annotated[Principal, Depends(_caller_with("learning.run"))]
ConfigReader = Annotated[Principal, Depends(_caller_with("config.read"))]
ConfigWriter = Annotated[Principal, Depends(_caller_with("config.write"))]
PeopleManager = Annotated[_Membered, Depends(_permitted("people.manage"))]
def _declared_query(dependant: Any) -> set[str]:
    """The query parameter names a route reads, its dependencies' included."""
    names = {param.alias for param in dependant.query_params}
    for sub in dependant.dependencies:
        names |= _declared_query(sub)
    return names


def _any_query(endpoint: Callable[..., Any]) -> Callable[..., Any]:
    """Mark a route whose caller is not an API client and may add parameters of its own (the
    identity provider's redirect to the sign-in callback adds `session_state`, `iss`, ...)."""
    endpoint.__dict__["_any_query"] = True
    return endpoint


async def _no_unknown_query(request: Request) -> None:
    """Refuse a query parameter the matched route does not read (#1342 r7 R7-2), so a client
    sending a filter the API dropped or never had learns it instead of getting everything."""
    route = request.scope.get("route")
    dependant = getattr(route, "dependant", None)
    if dependant is None or getattr(getattr(route, "endpoint", None), "_any_query", False):
        return
    declared = _declared_query(dependant)
    unknown = [name for name in dict.fromkeys(request.query_params.keys()) if name not in declared]
    if unknown:
        raise RequestValidationError([
            {"type": "extra_forbidden", "loc": ("query", name), "msg": "Extra inputs are not permitted",
             "input": request.query_params.get(name)} for name in unknown])


Limit = Annotated[int, Query(ge=1, le=MAX_PAGE)]
Cursor = Annotated[str | None, Query(max_length=2048, description="`next_cursor` from the previous page.")]
#: A system id: a name the tenant chose, not a minted id.
SystemPath = Annotated[str, Path(pattern=RECORD_ID_PATTERN)]


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


def _transaction(deps: ApiDeps, caller: Principal) -> AbstractAsyncContextManager[WriteTransaction]:
    return deps.writes.transaction(caller.tenant_id, caller)


def _answered_for(what: str, named: str, answered: str) -> None:
    """The store's answer to a create is for what the request named (`ports.py`)."""
    if answered != named:
        raise StoreBrokePromise(f"asked about {what} {named!r}, the store answered for {answered!r}")


def _not_found(what: str, record_id: str) -> HTTPException:
    return HTTPException(status.HTTP_404_NOT_FOUND, f"no {what} {record_id!r}")


def _created_at(request: Request, response: Response, route: str, tenant_id: str, **path: str) -> None:
    """201 and a `Location` the router builds from `route`'s path. Only a creation calls it: a
    replay answers the default 200 and needs no URL. Every path value is a record id or a `RecordId`,
    whose grammar is URL-safe, so the router never has to encode or refuse one."""
    response.status_code = status.HTTP_201_CREATED
    response.headers["Location"] = str(request.url_for(route, tenant_id=tenant_id, **path))


alerts = APIRouter(prefix="/alerts", tags=["alerts"], responses=_EVERY_ROUTE)


@alerts.get("")
async def list_alerts(
    deps: Deps,
    caller: WorkReader,
    fired_after: Instant | None = None,
    fired_before: Instant | None = None,
    cursor: Cursor = None,
    limit: Limit = DEFAULT_PAGE,
) -> Page[AlertSummary]:
    return await paginate(
        lambda after, n: deps.alerts.list_alerts(
            caller.tenant_id, fired_after=fired_after, fired_before=fired_before,
            after=after, limit=n,
        ),
        _ALERT_ORDER, list_name="alerts", tenant_id=caller.tenant_id, cursor=cursor, limit=limit,
        filters={"fired_after": _filter_moment(fired_after), "fired_before": _filter_moment(fired_before)},
    )


@alerts.get("/{alert_id}", responses=responses(404))
async def get_alert(deps: Deps, caller: WorkReader, alert_id: AlertId) -> Alert:
    alert = await deps.alerts.get_alert(caller.tenant_id, alert_id)
    if alert is None:
        raise _not_found("alert", alert_id)
    return alert


investigations = APIRouter(prefix="/investigations", tags=["investigations"], responses=_EVERY_ROUTE)


@investigations.post("", responses={201: {"model": Investigation}, **responses(409)})
async def start_investigation(
    deps: Deps, caller: InvestigationRunner, body: InvestigationCreate, request: Request, response: Response
) -> Investigation:
    """Start an investigation of an alert. While one of the alert's investigations is live, it
    is returned and nothing starts; otherwise a new one starts (a rerun, if an earlier one ended).

    Repeating a request with its `client_request_id` returns the investigation that request
    started (200). A request answered with an investigation that was already live started
    nothing, so repeating it later is a new request. A new investigation for a tenant with no
    saved alert mapping is refused (409), naming how to save one."""
    async with _transaction(deps, caller) as tx:
        investigation, created = await tx.create_investigation(body.alert_id, body.client_request_id)
        _answered_for("alert", body.alert_id, investigation.alert_id)
        if created:
            await tx.audit("investigation.start", investigation.investigation_id,
                     detail=f"alert {body.alert_id}")
    if created:
        _created_at(request, response, "get_investigation", caller.tenant_id,
                    investigation_id=investigation.investigation_id)
    return investigation


@investigations.get("")
async def list_investigations(
    deps: Deps, caller: WorkReader, alert_id: Annotated[AlertId | None, Query()] = None,
    cursor: Cursor = None,
    limit: Limit = DEFAULT_PAGE,
) -> Page[Investigation]:
    return await paginate(
        lambda after, n: deps.investigations.list_investigations(
            caller.tenant_id, alert_id=alert_id, after=after, limit=n),
        _INVESTIGATION_ORDER, list_name="investigations", tenant_id=caller.tenant_id,
        cursor=cursor, limit=limit, filters={"alert_id": alert_id},
    )


@investigations.get("/{investigation_id}", responses=responses(404))
async def get_investigation(deps: Deps, caller: WorkReader, investigation_id: InvestigationId) -> Investigation:
    investigation = await deps.investigations.get_investigation(caller.tenant_id, investigation_id)
    if investigation is None:
        raise _not_found("investigation", investigation_id)
    return investigation


@investigations.post("/{investigation_id}/cancel", responses=responses(404, 409))
async def cancel_investigation(deps: Deps, caller: InvestigationRunner, investigation_id: InvestigationId) -> Investigation:
    async with _transaction(deps, caller) as tx:
        investigation = await tx.cancel_investigation(investigation_id)
        await tx.audit("investigation.cancel", investigation_id)
    return investigation


@investigations.delete("/{investigation_id}", status_code=status.HTTP_204_NO_CONTENT,
                        responses=responses(404, 409))
async def delete_investigation(deps: Deps, caller: InvestigationDeleter, investigation_id: InvestigationId) -> None:
    """Delete an investigation and every attempt of the request it belongs to. Its run folders
    stay: lessons cite runs. Refused while any attempt is queued or running."""
    async with _transaction(deps, caller) as tx:
        await tx.delete_investigation(investigation_id)
        await tx.audit("investigation.delete", investigation_id)


@investigations.get(
    "/{investigation_id}/artifacts/{key:path}",
    status_code=status.HTTP_307_TEMPORARY_REDIRECT,
    response_class=RedirectResponse,
    responses=responses(404),
)
async def read_artifact(deps: Deps, caller: WorkReader, investigation_id: InvestigationId, key: str) -> RedirectResponse:
    """Redirect to a short-lived signed link on the blob store's own origin. The bytes never
    pass through the API, and a run page never renders on the app's origin.

    `key` may hold `/` (a file inside the run folder's bundle); only keys the investigation's
    own artifact list names are answered."""
    investigation = await get_investigation(deps, caller, investigation_id)
    if key not in investigation.artifacts:
        raise _not_found("artifact", key)
    url = await deps.artifact_links.signed_url(caller.tenant_id, investigation_id, key)
    # Audited once the link exists, and committed before it is handed out.
    async with _transaction(deps, caller) as tx:
        await tx.audit("artifact.read", investigation_id, detail=key)
    return RedirectResponse(url, headers={"Cache-Control": "no-store"})


learning_jobs = APIRouter(prefix="/learning-jobs", tags=["learning"], responses=_EVERY_ROUTE)


@learning_jobs.post("", responses={201: {"model": LearningJob}, **responses(409)})
async def start_learning_job(
    deps: Deps, caller: LearningRunner, body: LearningJobCreate, request: Request, response: Response
) -> LearningJob:
    """Learn again from an investigation: queue an explicit re-learn. A completed
    investigation is learned from automatically; this adds another, and re-learns are unlimited.
    Repeating a request with its `client_request_id` returns the job that request queued (200)."""
    async with _transaction(deps, caller) as tx:
        job, created = await tx.create_learning_job(body.investigation_id, body.client_request_id)
        _answered_for("investigation", body.investigation_id, job.investigation_id)
        if created:
            await tx.audit("learning_job.start", job.learning_job_id,
                     detail=f"investigation {body.investigation_id}")
    if created:
        _created_at(request, response, "get_learning_job", caller.tenant_id, learning_job_id=job.learning_job_id)
    return job


@learning_jobs.get("")
async def list_learning_jobs(
    deps: Deps, caller: WorkReader,
    investigation_id: Annotated[InvestigationId | None, Query()] = None,
    cursor: Cursor = None,
    limit: Limit = DEFAULT_PAGE,
) -> Page[LearningJob]:
    return await paginate(
        lambda after, n: deps.learning_jobs.list_learning_jobs(
            caller.tenant_id, investigation_id=investigation_id, after=after, limit=n),
        _LEARNING_JOB_ORDER, list_name="learning-jobs", tenant_id=caller.tenant_id,
        cursor=cursor, limit=limit, filters={"investigation_id": investigation_id},
    )


@learning_jobs.get("/{learning_job_id}", responses=responses(404))
async def get_learning_job(deps: Deps, caller: WorkReader, learning_job_id: LearningJobId) -> LearningJob:
    job = await deps.learning_jobs.get_learning_job(caller.tenant_id, learning_job_id)
    if job is None:
        raise _not_found("learning job", learning_job_id)
    return job


lessons = APIRouter(prefix="/lessons", tags=["learning"], responses=_EVERY_ROUTE)


@lessons.get("")
async def list_lessons(
    deps: Deps, caller: WorkReader, cursor: Cursor = None, limit: Limit = DEFAULT_PAGE
) -> Page[Lesson]:
    return await paginate(
        lambda after, n: deps.lessons.list_lessons(caller.tenant_id, after=after, limit=n),
        _LESSON_ORDER, list_name="lessons", tenant_id=caller.tenant_id, cursor=cursor,
        limit=limit, filters={},
    )


systems = APIRouter(prefix="/systems", tags=["systems"], responses=_EVERY_ROUTE)


async def _served(deps: ApiDeps, caller: Principal, settings: SystemSettings) -> System:
    """The system as served: its settings plus the secret store's own answer, so the flag can
    never disagree with where credentials were written."""
    has = await deps.secrets.has_credentials(caller.tenant_id, settings.system_id)
    # Only the settings' own fields: a store answering a richer record cannot collide with ours.
    return System(**settings.model_dump(include=set(SystemSettings.model_fields)), has_credentials=has)


@systems.get("")
async def list_systems(
    deps: Deps, caller: ConfigReader, cursor: Cursor = None, limit: Limit = DEFAULT_PAGE
) -> Page[System]:
    page = await paginate(
        lambda after, n: deps.systems.list_systems(caller.tenant_id, after=after, limit=n),
        _SYSTEM_ORDER, list_name="systems", tenant_id=caller.tenant_id, cursor=cursor,
        limit=limit, filters={},
    )
    # Served after the page is cut, so the secret store is asked only about rows that are sent.
    return Page(items=[await _served(deps, caller, s) for s in page.items], next_cursor=page.next_cursor)


async def _settings(deps: ApiDeps, caller: Principal, system_id: str) -> SystemSettings:
    settings = await deps.systems.get_system(caller.tenant_id, system_id)
    if settings is None:
        raise _not_found("system", system_id)
    return settings


@systems.put("/{system_id}", responses={201: {"model": System}})
async def put_system(
    deps: Deps, caller: ConfigWriter, system_id: SystemPath, body: SystemPut, request: Request, response: Response
) -> System:
    """Create or replace a connected system's settings. Credentials are set separately."""
    async with _transaction(deps, caller) as tx:
        settings, created = await tx.put_system(system_id, body)
        _answered_for("system", system_id, settings.system_id)
        await tx.audit("system.update", system_id)
    if created:
        # A PUT creates the resource at its own URL; built by the router, so no query rides along.
        _created_at(request, response, "put_system", caller.tenant_id, system_id=system_id)
    return await _served(deps, caller, settings)


@systems.put("/{system_id}/credentials", status_code=status.HTTP_204_NO_CONTENT,
             responses=responses(404))
async def put_credentials(deps: Deps, caller: ConfigWriter, system_id: SystemPath, body: CredentialsPut) -> None:
    """Replace the system's credentials. Write-only: no endpoint returns them."""
    await _settings(deps, caller, system_id)
    # The secret store is outside the transaction, so the audit event is written first and the
    # secret inside the block: a failed audit write stops the secret write, and only a commit
    # failing after the secret is stored can leave it unaudited.
    async with _transaction(deps, caller) as tx:
        await tx.audit("system.credentials", system_id,
                 detail="fields: " + ", ".join(sorted(body.credentials)))
        await deps.secrets.put_credentials(
            caller.tenant_id, system_id, body.kind, body.credentials)


@systems.post("/{system_id}/check", responses=responses(404))
async def check_system(deps: Deps, caller: ConfigWriter, system_id: SystemPath) -> SystemCheck:
    """Test the connection and a first query."""
    return await deps.checker.check(caller.tenant_id, await _served(deps, caller, await _settings(deps, caller, system_id)))


# --- people, memberships and sign-in (#1306) ---------------------------------------------------

#: What every identity route can answer: no session, a refused request, a malformed one.
_IDENTITY = responses(401, 403, 422, 500)


def _cookie_options() -> dict[str, object]:
    return {"path": "/", "secure": True, "httponly": True, "samesite": "lax"}


auth = APIRouter(tags=["auth"])


@auth.get("/auth/login", status_code=status.HTTP_302_FOUND, response_class=RedirectResponse,
          responses=responses(503, 500), dependencies=[Depends(_public)])
async def login(deps: Deps) -> RedirectResponse:
    """Send the person to the sign-in page. The state, nonce and PKCE verifier travel back in a
    short-lived cookie."""
    start = await deps.identity.begin_signin()
    response = RedirectResponse(start.url, status_code=status.HTTP_302_FOUND)
    response.set_cookie(PRELOGIN_COOKIE, start.prelogin, max_age=_PRELOGIN_MAX_AGE, **_cookie_options())  # type: ignore[arg-type]
    return response


@auth.get("/auth/callback", status_code=status.HTTP_303_SEE_OTHER, response_class=RedirectResponse,
          responses=responses(403, 503, 422, 500), dependencies=[Depends(_public)])
@_any_query
async def callback(request: Request, deps: Deps, code: str = "", state: str = "") -> Response:
    """Finish a sign-in: a session cookie and a redirect to the frontend, or a 403 problem of one
    of four types. The pre-login cookie is cleared whatever the outcome."""
    try:
        value = await deps.identity.complete_signin(
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
async def logout(request: Request, deps: Deps, caller: Person) -> Response:
    """End this session only; other devices stay signed in."""
    await deps.identity.logout(caller, request.cookies.get(SESSION_COOKIE, ""))
    response = Response(status_code=status.HTTP_204_NO_CONTENT)
    response.delete_cookie(SESSION_COOKIE, **_cookie_options())  # type: ignore[arg-type]
    return response


@auth.get("/me", responses=_IDENTITY)
async def read_me(deps: Deps, caller: AnyCaller) -> Me | ProgramMe:
    """Who the caller is: a person with their tenants and invitations, or a program with its one tenant
    and the credential it used."""
    view = await deps.identity.me(caller)
    if view.credential is not None:
        if not view.tenants:  # a program's tenant is gone with its membership: fail closed
            raise _identity.NotAuthenticated("sign in")
        return ProgramMe(
            program=ProgramRef(id=view.user.id, display_name=view.user.display_name),
            tenant=TenantRef(tenant_id=view.tenants[0]),
            credential=CredentialRef(id=view.credential.id, expires_at=view.credential.expires_at))
    assert view.user.email is not None  # a person always has one
    return Me(
        user=MeUser(id=view.user.id, email=view.user.email, display_name=view.user.display_name),
        tenants=[TenantRef(tenant_id=t) for t in view.tenants],
        administrator=view.administrator,
        invitations=[InvitationRef(id=i.id, tenant_id=i.tenant_id) for i in view.invitations])


@auth.post("/invitations/{invitation_id}/accept", responses={**_IDENTITY, **responses(404)})
async def accept_invitation(deps: Deps, caller: Person, invitation_id: MembershipId) -> TenantRef:
    """Accept an invitation addressed to you, while signed in."""
    return TenantRef(tenant_id=await deps.identity.accept(caller, invitation_id))


people = APIRouter(tags=["people"], responses=_EVERY_ROUTE)


def _invitation(view: _identity.InvitationView) -> Invitation:
    return Invitation(id=view.id, email=view.email, status=view.status, created_at=view.created_at)


@people.get("/members")
async def list_members(deps: Deps, member: PeopleManager) -> Page[Member]:
    rows = await deps.identity.members(member.tenant_id)
    return Page(items=[Member(user_id=m.user_id, email=m.email, display_name=m.display_name) for m in rows],
                next_cursor=None)


@people.delete("/members/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_member(deps: Deps, member: PeopleManager, user_id: UserId) -> None:
    """End a membership: yours, or another member's. Nothing else of that person changes."""
    await deps.identity.remove(member.auth, member.tenant_id, user_id)


@people.get("/invitations")
async def list_invitations(deps: Deps, member: PeopleManager) -> Page[Invitation]:
    return Page(items=[_invitation(v) for v in await deps.identity.invitations(member.tenant_id)],
                next_cursor=None)


@people.post("/invitations", status_code=status.HTTP_202_ACCEPTED, responses=responses(409))
async def invite(deps: Deps, member: PeopleManager, body: InviteCreate) -> Invitation:
    """Invite a person by email. The answer is the same whoever the email belongs to; the
    email itself goes out afterwards."""
    return _invitation(await deps.identity.invite(member.auth, member.tenant_id, body.email))


@people.delete("/invitations/{invitation_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_invitation(deps: Deps, member: PeopleManager, invitation_id: MembershipId) -> None:
    await deps.identity.revoke(member.auth, member.tenant_id, invitation_id)


programs = APIRouter(tags=["programs"], responses=_EVERY_ROUTE)

#: A program id in a path: a person's id is as well-formed as one, and is found to be no program.
ProgramPath = Annotated[UserId, Path(description="A program of the tenant.")]


def _program(user: Any) -> Program:
    return Program(id=user.id, display_name=user.display_name, created_by=user.created_by, created_at=user.created_at)


def _credential(row: Any) -> Credential:
    return Credential(id=row.id, kind=row.kind, name=row.name, state=row.state, created_by=row.created_by,
                      created_at=row.created_at, expires_at=row.expires_at, last_used_at=row.last_used_at)


@programs.post("/programs", status_code=status.HTTP_201_CREATED)
async def create_program(deps: Deps, member: PeopleManager, body: ProgramCreate) -> Program:
    """Make a program, a non-human caller that belongs to this tenant and outlives whoever made it."""
    return _program(await deps.identity.create_program(member.auth, member.tenant_id, body.display_name))


@programs.get("/programs")
async def list_programs(deps: Deps, member: PeopleManager) -> Page[Program]:
    return Page(items=[_program(u) for u in await deps.identity.programs(member.tenant_id)], next_cursor=None)


@programs.delete("/programs/{program_id}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_program(deps: Deps, member: PeopleManager, program_id: ProgramPath) -> None:
    """Cut a program off at once: its membership ends and every credential is revoked."""
    await deps.identity.remove_program(member.auth, member.tenant_id, program_id)


@programs.post("/programs/{program_id}/credentials", status_code=status.HTTP_201_CREATED,
               responses=responses(409, 503))
async def issue_credential(
    deps: Deps, member: PeopleManager, program_id: ProgramPath, body: CredentialCreate,
) -> CredentialIssued:
    """Issue a key or an OAuth client. The secret is in this answer and nowhere else, ever."""
    row, secret = await deps.identity.issue_credential(
        member.auth, member.tenant_id, program_id, kind=body.kind, name=body.name, expires_at=body.expires_at)
    return CredentialIssued(**_credential(row).model_dump(), secret=secret)


@programs.get("/programs/{program_id}/credentials")
async def list_credentials(deps: Deps, member: PeopleManager, program_id: ProgramPath) -> Page[Credential]:
    rows = await deps.identity.credentials(member.tenant_id, program_id)
    return Page(items=[_credential(r) for r in rows], next_cursor=None)


@programs.delete("/programs/{program_id}/credentials/{credential_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_credential(
    deps: Deps, member: PeopleManager, program_id: ProgramPath, credential_id: CredentialId,
) -> None:
    await deps.identity.revoke_credential(member.auth, member.tenant_id, program_id, credential_id)


admin = APIRouter(prefix="/admin", tags=["admin"], responses={**_IDENTITY, **responses(404)})


#: An administrator's tenant path. A malformed id is a 422, after the administrator check (#1382).
AdminTenant = Annotated[TenantId, Path(description="The tenant the request acts on.")]


def _tenant_item(record: _tenancy.TenantRecord) -> TenantItem:
    return TenantItem(
        tenant_id=record.id, state=record.state, pending_action=record.pending_action,  # type: ignore[arg-type]
        step=record.step, step_actor=record.step_actor, failure=record.failure,  # type: ignore[arg-type]
        created_at=record.created_at)


@admin.get("/tenants")
async def list_all_tenants(deps: Deps, caller: Admin) -> Page[TenantItem]:
    items = [_tenant_item(r) for r in await deps.tenants.tenants()]
    audit.emit("admin.tenants.list", actor=caller.user.id, tenant_id=None, target=None)
    return Page(items=items, next_cursor=None)


@admin.post("/tenants", status_code=status.HTTP_202_ACCEPTED)
async def create_tenant(deps: Deps, caller: Admin, request: Request, response: Response) -> TenantItem:
    """Mint a tenant and record it `creating`; the management service does the rest. No members."""
    record = await deps.tenants.request_create(now=deps.identity.now())
    audit.emit("tenant.create", actor=caller.user.id, tenant_id=record.id, target=record.id)
    response.headers["Location"] = str(request.app.url_path_for("get_tenant", tenant_id=record.id))
    return _tenant_item(record)


@admin.get("/tenants/{tenant_id}")
async def get_tenant(deps: Deps, caller: Admin, tenant_id: AdminTenant) -> TenantItem:
    record = await deps.tenants.tenant(tenant_id)
    if record is None:
        raise _tenancy.NotFound(f"no tenant {tenant_id}")
    return _tenant_item(record)


@admin.post("/tenants/{tenant_id}/resume", status_code=status.HTTP_202_ACCEPTED, responses=responses(409))
async def resume_tenant(deps: Deps, caller: Admin, tenant_id: AdminTenant) -> TenantItem:
    """Clear the failure of a stopped job so the next pass retries its step."""
    record = await deps.tenants.request_resume(tenant_id)
    audit.emit("tenant.resume", actor=caller.user.id, tenant_id=record.id, target=record.id)
    return _tenant_item(record)


@admin.post("/tenants/{tenant_id}/offboard", status_code=status.HTTP_202_ACCEPTED, responses=responses(409))
async def offboard_tenant(deps: Deps, caller: Admin, tenant_id: AdminTenant) -> TenantItem:
    """End access at once and queue the teardown, replacing any pending action."""
    record = await deps.tenants.request_offboard(tenant_id, now=deps.identity.now())
    audit.emit("tenant.offboard", actor=caller.user.id, tenant_id=record.id, target=record.id)
    return _tenant_item(record)


@admin.post("/tenants/{tenant_id}/rotate-forge-credential", status_code=status.HTTP_202_ACCEPTED,
            responses=responses(409))
async def rotate_tenant_credential(deps: Deps, caller: Admin, tenant_id: AdminTenant) -> TenantItem:
    """Queue a new credential generation for an active tenant with nothing pending."""
    record = await deps.tenants.request_rotate(tenant_id)
    audit.emit("tenant.rotate", actor=caller.user.id, tenant_id=record.id, target=record.id)
    return _tenant_item(record)


@admin.post("/tenants/{tenant_id}/invitations", status_code=status.HTTP_202_ACCEPTED,
            responses=responses(409))
async def admin_invite(deps: Deps, caller: Admin, body: InviteCreate,
                       tenant_id: AdminTenant) -> Invitation:
    """Invite the first member into a tenant that has no active members."""
    return _invitation(await deps.identity.admin_invite(caller, tenant_id, body.email))


async def _run_then_close(identity: IdentityService, stop: asyncio.Event) -> None:
    """The background loop (sender and session purge) until `stop`, then the service's close: in one
    task, so nothing closes what the loop uses while it runs, even when the lifespan waiting on it is
    itself cancelled."""
    try:
        await identity.run_background(stop)
    finally:
        await identity.close()


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Apply the bootstrap before serving and run the background loop as a task on this loop. On
    shutdown the loop finishes the email or session purge it is on (a purge is cut off at its
    deadline), then the service closes, then the tenant repository (its own connections; the store
    outlives both)."""
    deps: ApiDeps = app.state.deps
    identity = deps.identity
    try:
        await _start_identity(identity)
        stop = asyncio.Event()
        background = asyncio.create_task(_run_then_close(identity, stop), name="identity-background")
        try:
            yield
        finally:
            stop.set()
            await asyncio.shield(background)
    finally:
        await deps.tenants.close()


async def _start_identity(identity: IdentityService) -> None:
    try:
        await identity.start()
    except BaseException:
        await identity.close()
        raise


alert_mapping = APIRouter(prefix="/alert-mapping", tags=["alert mapping"], responses=_EVERY_ROUTE)


@alert_mapping.get("")
async def get_alert_mapping(deps: Deps, caller: ConfigReader) -> AlertMapping:
    """The tenant's alert mapping: all six entries, unmapped ones null. Not found until one is saved."""
    mapping = await deps.systems.get_alert_mapping(caller.tenant_id)
    if mapping is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "this tenant has no alert mapping yet")
    return mapping


@alert_mapping.put("", responses={201: {"model": AlertMapping}})
async def put_alert_mapping(
    deps: Deps, caller: ConfigWriter, body: AlertMapping, request: Request, response: Response
) -> AlertMapping:
    """Replace the tenant's alert mapping whole: all six entries, each a dotted path or null. Its alerts' title
    and description are re-derived through it before this answers."""
    async with _transaction(deps, caller) as tx:
        mapping, created = await tx.put_alert_mapping(body)
        await tx.audit("alert_mapping.update", caller.tenant_id)
    if created:
        _created_at(request, response, "put_alert_mapping", caller.tenant_id)
    return mapping


def create_app(deps: ApiDeps) -> FastAPI:
    app = FastAPI(
        title="Defender platform API",
        version=API_VERSION,
        summary="Stub: the routes and shapes are the contract; the records behind them are not yet real.",
        lifespan=_lifespan,
        dependencies=[Depends(_no_unknown_query)],
    )
    app.state.deps = deps
    app.add_middleware(_ExpiryHeader)
    app.add_middleware(_FrontendOriginOnly, origin=deps.frontend_origin)
    in_tenant = APIRouter(prefix="/tenants/{tenant_id}", responses=responses(404))
    for router in (alerts, investigations, learning_jobs, lessons, systems, alert_mapping, people, programs):
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
    app.add_exception_handler(_identity.Invalid, refusal(422))
    app.add_exception_handler(_tenancy.NotFound, refusal(status.HTTP_404_NOT_FOUND))
    app.add_exception_handler(_tenancy.Conflict, refusal(status.HTTP_409_CONFLICT))
    app.add_exception_handler(_identity.SignInUnavailable, refusal(status.HTTP_503_SERVICE_UNAVAILABLE))
    return app


def _served_routes(routes: Any) -> Any:
    """Every route as served: FastAPI includes routers lazily, so an included router yields its effective routes."""
    for route in routes:
        if isinstance(route, APIRoute):
            yield route
        elif hasattr(route, "effective_candidates"):
            yield from _served_routes(route.effective_candidates())
        elif hasattr(route, "dependant"):
            yield route


def _has_declaration(dependant: Any) -> bool:
    return any(getattr(sub.call, "declares", None) is not None or _has_declaration(sub) for sub in dependant.dependencies)


def undeclared_routes(app: FastAPI) -> list[tuple[str, str]]:
    """The (method, path) of every route of `app` that declares neither a permission nor a category
    outside the tenant (P-H): a route added without either is found by a test, not by a review."""
    return sorted({
        (method, route.path)
        for route in _served_routes(app.routes) if not _has_declaration(route.dependant)
        for method in route.methods if method not in {"HEAD", "OPTIONS"}})
