"""The routes: #1131's public API, each a thin translation onto a port."""

from __future__ import annotations

import asyncio
import datetime as _dt
import logging
from collections.abc import AsyncIterator, Callable, Coroutine
from contextlib import asynccontextmanager
from typing import Annotated, Any, Generic, Literal, NamedTuple, TypeVar

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Path, Query, Request, Response, status
from fastapi.exceptions import RequestValidationError
from fastapi.routing import APIRoute
from fastapi.responses import RedirectResponse
from starlette.datastructures import Headers, MutableHeaders
from starlette.types import ASGIApp, Receive, Scope, Send

from defender import identity as _identity
from defender import tenancy as _tenancy
from defender.identity import Authenticated, IdentityService, PersonCaller, ProgramCaller, audit
from defender.identity.service import SESSION_LIFETIME
from defender.identity.roles import Permission
from defender.identity.models import Role
from defender.records.formats import (
    AlertId, CredentialId, InvestigationId, LearningJobId, MembershipId, ProgramId, TenantId, UserId,
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
from .problems import HANDLERS, problem, refusal, responses
from .ports import (
    ApiDeps,
    Conflict,
    NotFound,
    Principal,
    StoreBrokePromise,
    TimePosition,
    UnknownReference,
)
from .refusing import NotImplementedYet

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
#: The scope key under which the authenticated caller travels from `_AuthenticatingRoute` to the route's dependencies.
_CALLER_SCOPE_KEY = "defender.caller"
#: Every response to a verified program carries when the credential it used expires (#1307 D9).
EXPIRY_HEADER = "Defender-Credential-Expires"


def _way_in(headers: Headers) -> Literal["session", "bearer"]:
    """How a request offers to be authenticated (P-F): an `Authorization` header of the `Bearer` scheme (with a value
    or not) is `bearer`, and the cookie is then never read; anything else is the session cookie's way, an
    `Authorization` header of another scheme included, which is not ours to read (a staging proxy's or a browser's
    cached Basic login must not lock every person out; #1450 review). The origin layer and the authentication both
    ask it, so they cannot disagree (#1307 A4). A cookie beside a Bearer header changes nothing: a load balancer's
    or a cookie jar's cookie must not lock a program out, and a browser cannot be made to send a Bearer header to
    another site, so such a request is not forged (#1450 review, amending P-F's "both is refused")."""
    return "bearer" if _scheme_and_value(headers)[0].lower() == "bearer" else "session"


def _scheme_and_value(headers: Headers) -> tuple[str, str]:
    """The `Authorization` header's scheme and value, split at the first whitespace; empty strings for no header."""
    parts = headers.get("authorization", "").split(None, 1)
    return (parts[0] if parts else "", parts[1].strip() if len(parts) > 1 else "")


class _FrontendOriginOnly:
    """A request that changes state must come from the configured frontend (O6), unless it is a `bearer`
    request (see `_way_in`): a browser attaches cookies by itself but never an `Authorization` header it was
    not told to (a cached Basic login is the one it adds, and that is the cookie's way), so only a request
    authenticated by its cookie can be forged from another site (#1307 O9). A layer in front of routing,
    so it answers before the session is looked at or the body is read: a forged request learns
    nothing, not even whether its body would have parsed."""

    def __init__(self, app: ASGIApp, *, origin: str) -> None:
        self._app = app
        self._origin = origin

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http" and scope["method"] not in _SAFE_METHODS:
            headers = Headers(scope=scope)
            if _way_in(headers) != "bearer" and headers.get("origin") != self._origin:
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
            if message["type"] == "http.response.start":
                _stamp_expiry(scope, MutableHeaders(scope=message))
            await send(message)

        await self._app(scope, receive, with_header)


def _stamp_expiry(scope: Scope, headers: MutableHeaders) -> None:
    if _EXPIRY_SCOPE_KEY in scope:
        headers[EXPIRY_HEADER] = scope[_EXPIRY_SCOPE_KEY]


async def _server_error(request: Request, exc: Exception) -> Response:
    """The 500 for an unhandled failure. Starlette renders it outside every middleware of the app, so the
    expiry header cannot be added on the way out like the others: it is put on here (D9, A6). The server still
    logs the failure: the handler answers, then the server re-raises it."""
    response = await HANDLERS[Exception](request, exc)
    _stamp_expiry(request.scope, response.headers)
    return response


async def _not_authenticated(request: Request, exc: Exception) -> Response:
    """The 401. A request that came the bearer way (see `_way_in`) is challenged as RFC 6750 says, so an OAuth
    client knows to fetch a new token; one that came with the session cookie, or with nothing, is not: a session
    has no challenge to offer, and a browser must not be invited to try Bearer."""
    response = problem(status.HTTP_401_UNAUTHORIZED, str(exc))
    if _way_in(request.headers) == "bearer":
        presented = _scheme_and_value(request.headers)[1]
        response.headers["WWW-Authenticate"] = 'Bearer error="invalid_token"' if presented else "Bearer"
    return response


def _declares(what: str) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Mark a dependency as the declaration a route owes (P-H): a permission, or a category outside the
    tenant (`public`, `person`, `any`, `platform`). `undeclared_routes` finds the routes without one."""
    def mark(dependency: Callable[..., Any]) -> Callable[..., Any]:
        dependency.__dict__["declares"] = what
        return dependency
    return mark


async def _credentialed(request: Request, deps: ApiDeps) -> Authenticated:
    """The caller, by exactly one way in (`_way_in`): a session cookie (a person) or `Authorization: Bearer` (a
    program). A Bearer header without a value is not authenticated, and the cookie is not tried instead."""
    if _way_in(request.headers) == "session":
        return await deps.identity.authenticate(request.cookies.get(SESSION_COOKIE))
    value = _scheme_and_value(request.headers)[1]
    if not value:
        raise _identity.NotAuthenticated("sign in")
    caller = await deps.identity.authenticate_bearer(value)
    request.scope[_EXPIRY_SCOPE_KEY] = caller.credential.expires_at.astimezone(_dt.UTC).isoformat()
    return caller


async def _authenticated(request: Request) -> Authenticated:
    """The caller `_AuthenticatingRoute` authenticated before the request's body was read (A7)."""
    caller: Authenticated = request.scope[_CALLER_SCOPE_KEY]
    return caller


def _authenticates(dependant: Any) -> bool:
    return any(sub.call is _authenticated or _authenticates(sub) for sub in dependant.dependencies)


class _AuthenticatingRoute(APIRoute):
    """A route whose caller is known before FastAPI reads the request: authentication first, so an invalid or
    missing credential is a 401 whatever the body holds, a malformed body included (#1307 A7). FastAPI parses
    the body before it resolves dependencies, so a dependency alone cannot be first; every router of this
    module is made with this class."""

    def get_route_handler(self) -> Callable[[Request], Coroutine[Any, Any, Response]]:
        handler = super().get_route_handler()
        authenticates = _authenticates(self.dependant)

        async def authenticate_first(request: Request) -> Response:
            if authenticates:
                request.scope[_CALLER_SCOPE_KEY] = await _credentialed(request, request.app.state.deps)
            return await handler(request)
        return authenticate_first


def _router(**options: Any) -> APIRouter:
    return APIRouter(route_class=_AuthenticatingRoute, **options)


Authed = Annotated[Authenticated, Depends(_authenticated)]


@_declares("public")
async def _public() -> None:
    """The sign-in routes: nobody is authenticated yet."""


@_declares("person")
async def _person(auth: Authed) -> PersonCaller:
    if isinstance(auth, ProgramCaller):
        raise _identity.Forbidden("only a person may do that")
    return auth


@_declares("any")
async def _any_caller(auth: Authed) -> Authenticated:
    return auth


Person = Annotated[PersonCaller, Depends(_person)]
AnyCaller = Annotated[Authenticated, Depends(_any_caller)]


#: The caller a tenant route holds: either kind, or a person once a people route has narrowed it.
_Caller = TypeVar("_Caller", bound=Authenticated)


class _Membered(NamedTuple, Generic[_Caller]):
    auth: _Caller
    tenant_id: TenantId
    #: The caller's role in the tenant: what `member_of` answered, the one producer of a role.
    role: Role


async def _membered(
    tenant_id: Annotated[TenantId, Path(description="The tenant the request acts in.")],
    auth: Authed, deps: Annotated[ApiDeps, Depends(_deps)],
) -> _Membered[Authenticated]:
    """The tenant is the path's and is checked against the caller's membership on every request;
    a non-member and an unknown tenant are the same 404 (P-D). A malformed id is a 422, after the
    sign-in check (#1382): it says nothing of any tenant. Membership comes before permission (D1)."""
    return _Membered(auth, tenant_id, await deps.identity.member_of(auth, tenant_id))


Membered = Annotated[_Membered[Authenticated], Depends(_membered)]


def _permitted(permission: Permission) -> Callable[..., Any]:
    """The dependency of a route that needs `permission`: the caller is a member of the path's tenant
    and its role grants it, else 404 or 403 before anything else in the path is looked at (D1, D4)."""
    @_declares(permission)
    async def dependency(member: Membered, deps: Annotated[ApiDeps, Depends(_deps)]) -> _Membered[Authenticated]:
        deps.identity.require(member.role, permission)
        return member
    return dependency


def _principal(member: _Membered[Authenticated]) -> Principal:
    """The audit's caller, built here and nowhere else: the user and, for a program, the credential it used.
    Every tenant route takes its `Principal` from `_caller_with`, so none can leave the credential out."""
    auth = member.auth
    return Principal(tenant_id=member.tenant_id, actor_id=auth.actor_id,
                     credential_id=auth.credential.id if isinstance(auth, ProgramCaller) else None)


def _caller_with(permission: Permission) -> Callable[..., Any]:
    check = _permitted(permission)

    @_declares(permission)
    async def dependency(member: _Membered[Authenticated] = Depends(check)) -> Principal:  # noqa: B008
        return _principal(member)
    return dependency


@_declares("platform")
async def _administrator(
    auth: Annotated[PersonCaller, Depends(_person)], deps: Annotated[ApiDeps, Depends(_deps)],
) -> PersonCaller:
    """A platform administrator: a person (a program is refused before the flag is looked at) whose flag is set."""
    deps.identity.require_administrator(auth)
    return auth


Deps = Annotated[ApiDeps, Depends(_deps)]
Admin = Annotated[PersonCaller, Depends(_administrator)]
#: A tenant route's caller, by the one permission the route needs (O3).
WorkReader = Annotated[Principal, Depends(_caller_with("work.read"))]
InvestigationRunner = Annotated[Principal, Depends(_caller_with("investigations.run"))]
InvestigationDeleter = Annotated[Principal, Depends(_caller_with("investigations.delete"))]
LearningRunner = Annotated[Principal, Depends(_caller_with("learning.run"))]
ConfigReader = Annotated[Principal, Depends(_caller_with("config.read"))]
ConfigWriter = Annotated[Principal, Depends(_caller_with("config.write"))]


async def _people_manager(
    member: Annotated[_Membered[Authenticated], Depends(_permitted("people.manage"))],
) -> _Membered[PersonCaller]:
    """The caller of a people route, narrowed once to a person. Membership is checked first (a program of another
    tenant gets the same 404 as anyone), then the permission; `automation` does not grant `people.manage`, and a
    program is refused here as well should a role ever change that."""
    auth = member.auth
    if isinstance(auth, ProgramCaller):
        raise _identity.Forbidden("only a person may do that")
    return _Membered(auth, member.tenant_id, member.role)


PeopleManager = Annotated[_Membered[PersonCaller], Depends(_people_manager)]
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
#: The families nothing real backs yet answer 501 when their ports refuse (`refusing.py`); the document says so on
#: every server, whichever ports are passed.
_UNBACKED = {**_EVERY_ROUTE, **responses(501)}


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


alerts = _router(prefix="/alerts", tags=["alerts"], responses=_EVERY_ROUTE)


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


investigations = _router(prefix="/investigations", tags=["investigations"], responses=_EVERY_ROUTE)


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
    investigation, created = await deps.writes.create_investigation(caller, body.alert_id, body.client_request_id)
    _answered_for("alert", body.alert_id, investigation.alert_id)
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
    return await deps.writes.cancel_investigation(caller, investigation_id)


@investigations.delete("/{investigation_id}", status_code=status.HTTP_204_NO_CONTENT,
                        responses=responses(404, 409))
async def delete_investigation(deps: Deps, caller: InvestigationDeleter, investigation_id: InvestigationId) -> None:
    """Delete an investigation and every attempt of the request it belongs to. Its run folders
    stay: lessons cite runs. Refused while any attempt is queued or running."""
    await deps.writes.delete_investigation(caller, investigation_id)


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
    # Audited once the link exists, before it is handed out.
    await deps.audit.announce(caller, "artifact.read", investigation_id, key)
    return RedirectResponse(url, headers={"Cache-Control": "no-store"})


learning_jobs = _router(prefix="/learning-jobs", tags=["learning"], responses=_EVERY_ROUTE)


@learning_jobs.post("", responses={201: {"model": LearningJob}, **responses(409)})
async def start_learning_job(
    deps: Deps, caller: LearningRunner, body: LearningJobCreate, request: Request, response: Response
) -> LearningJob:
    """Learn again from an investigation: queue an explicit re-learn. A completed
    investigation is learned from automatically; this adds another, and re-learns are unlimited.
    Repeating a request with its `client_request_id` returns the job that request queued (200)."""
    job, created = await deps.writes.create_learning_job(caller, body.investigation_id, body.client_request_id)
    _answered_for("investigation", body.investigation_id, job.investigation_id)
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


lessons = _router(prefix="/lessons", tags=["learning"], responses=_UNBACKED)


@lessons.get("")
async def list_lessons(
    deps: Deps, caller: WorkReader, cursor: Cursor = None, limit: Limit = DEFAULT_PAGE
) -> Page[Lesson]:
    return await paginate(
        lambda after, n: deps.lessons.list_lessons(caller.tenant_id, after=after, limit=n),
        _LESSON_ORDER, list_name="lessons", tenant_id=caller.tenant_id, cursor=cursor,
        limit=limit, filters={},
    )


systems = _router(prefix="/systems", tags=["systems"], responses=_UNBACKED)


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
    settings, created = await deps.systems.put_system(caller, system_id, body)
    _answered_for("system", system_id, settings.system_id)
    if created:
        # A PUT creates the resource at its own URL; built by the router, so no query rides along.
        _created_at(request, response, "put_system", caller.tenant_id, system_id=system_id)
    return await _served(deps, caller, settings)


@systems.put("/{system_id}/credentials", status_code=status.HTTP_204_NO_CONTENT,
             responses=responses(404))
async def put_credentials(deps: Deps, caller: ConfigWriter, system_id: SystemPath, body: CredentialsPut) -> None:
    """Replace the system's credentials. Write-only: no endpoint returns them."""
    await _settings(deps, caller, system_id)
    await deps.secrets.put_credentials(caller, system_id, body.kind, body.credentials)


@systems.post("/{system_id}/check", responses=responses(404))
async def check_system(deps: Deps, caller: ConfigWriter, system_id: SystemPath) -> SystemCheck:
    """Test the connection and a first query."""
    return await deps.checker.check(caller.tenant_id, await _served(deps, caller, await _settings(deps, caller, system_id)))


# --- people, memberships and sign-in (#1306) ---------------------------------------------------

#: What every identity route can answer: no session, a refused request, a malformed one.
_IDENTITY = responses(401, 403, 422, 500)


def _cookie_options() -> dict[str, object]:
    return {"path": "/", "secure": True, "httponly": True, "samesite": "lax"}


auth = _router(tags=["auth"])


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
    if isinstance(view, ProgramCaller):  # a program, let in only while its one tenant is active
        return ProgramMe(
            program=ProgramRef(id=view.program.id, display_name=view.program.display_name),
            tenant=TenantRef(tenant_id=view.program.tenant_id),
            credential=CredentialRef(id=view.credential.id, expires_at=view.credential.expires_at))
    return Me(
        user=MeUser(id=view.user.id, email=view.user.email, display_name=view.user.display_name),
        tenants=[TenantRef(tenant_id=t) for t in view.tenants],
        administrator=view.administrator,
        invitations=[InvitationRef(id=i.id, tenant_id=i.tenant_id) for i in view.invitations])


@auth.post("/invitations/{invitation_id}/accept", responses={**_IDENTITY, **responses(404)})
async def accept_invitation(deps: Deps, caller: Person, invitation_id: MembershipId) -> TenantRef:
    """Accept an invitation addressed to you, while signed in."""
    return TenantRef(tenant_id=await deps.identity.accept(caller, invitation_id))


people = _router(tags=["people"], responses=_EVERY_ROUTE)


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


programs = _router(tags=["programs"], responses=_EVERY_ROUTE)

#: A program id in a path: a person's id is as well-formed as one, and is found to be no program.
ProgramPath = Annotated[ProgramId, Path(description="A program of the tenant.")]


def _program(program: Any) -> Program:
    return Program(id=program.id, display_name=program.display_name, created_by=program.created_by,
                   created_at=program.created_at)


def _credential(row: Any) -> Credential:
    return Credential(id=row.id, kind=row.kind, name=row.name, state=row.state, created_by=row.created_by,
                      created_at=row.created_at, expires_at=row.expires_at, last_used_at=row.last_used_at)


@programs.post("/programs", status_code=status.HTTP_201_CREATED)
async def create_program(deps: Deps, member: PeopleManager, body: ProgramCreate) -> Program:
    """Make a program, a non-human caller that belongs to this tenant and outlives whoever made it."""
    return _program(await deps.identity.create_program(member.auth, member.tenant_id, body.display_name))


@programs.get("/programs")
async def list_programs(deps: Deps, member: PeopleManager) -> Page[Program]:
    return Page(items=[_program(p) for p in await deps.identity.programs(member.tenant_id)], next_cursor=None)


@programs.delete("/programs/{program_id}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_program(deps: Deps, member: PeopleManager, program_id: ProgramPath) -> None:
    """Cut a program off at once: it is removed and every credential is revoked."""
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


admin = _router(prefix="/admin", tags=["admin"], responses={**_IDENTITY, **responses(404)})


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
    """End access at once, end the tenant's queued and running jobs, and queue the teardown, replacing any pending
    action: one change through the offboarding port."""
    record = await deps.offboarding.offboard_tenant(tenant_id, actor=caller.user.id)
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


alert_mapping = _router(prefix="/alert-mapping", tags=["alert mapping"], responses=_EVERY_ROUTE)


@alert_mapping.get("")
async def get_alert_mapping(deps: Deps, caller: ConfigReader) -> AlertMapping:
    """The tenant's alert mapping: all six entries, unmapped ones null. Not found until one is saved."""
    mapping = await deps.alert_mapping.get_alert_mapping(caller.tenant_id)
    if mapping is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "this tenant has no alert mapping yet")
    return mapping


@alert_mapping.put("", responses={201: {"model": AlertMapping}})
async def put_alert_mapping(
    deps: Deps, caller: ConfigWriter, body: AlertMapping, request: Request, response: Response
) -> AlertMapping:
    """Replace the tenant's alert mapping whole: all six entries, each a dotted path or null. A path reads nested keys, keys
    holding dots, or a mix; where both hold a value, the nested key wins (#1481). It applies to alerts
    stored from now on; alerts already stored keep their title and description."""
    mapping, created = await deps.writes.put_alert_mapping(caller, body)
    if created:
        _created_at(request, response, "put_alert_mapping", caller.tenant_id)
    return mapping


def create_app(deps: ApiDeps) -> FastAPI:
    app = FastAPI(
        title="Defender platform API",
        version=API_VERSION,
        summary="The routes and shapes of the platform API; a route whose records are not yet served answers 501.",
        lifespan=_lifespan,
        dependencies=[Depends(_no_unknown_query)],
    )
    app.state.deps = deps
    app.add_middleware(_ExpiryHeader)
    app.add_middleware(_FrontendOriginOnly, origin=deps.frontend_origin)
    in_tenant = _router(prefix="/tenants/{tenant_id}", responses=responses(404))
    for router in (alerts, investigations, learning_jobs, lessons, systems, alert_mapping, people, programs):
        in_tenant.include_router(router)
    for router in (auth, in_tenant, admin):
        app.include_router(router)
    install_problems(app)
    app.add_exception_handler(NotFound, refusal(status.HTTP_404_NOT_FOUND))
    app.add_exception_handler(Conflict, refusal(status.HTTP_409_CONFLICT))
    # The literal, not starlette's constant: it was renamed across starlette releases.
    app.add_exception_handler(UnknownReference, refusal(422))
    app.add_exception_handler(NotImplementedYet, refusal(status.HTTP_501_NOT_IMPLEMENTED))
    app.add_exception_handler(_identity.NotAuthenticated, _not_authenticated)
    app.add_exception_handler(_identity.Forbidden, refusal(status.HTTP_403_FORBIDDEN))
    app.add_exception_handler(_identity.NotFound, refusal(status.HTTP_404_NOT_FOUND))
    app.add_exception_handler(_identity.Conflict, refusal(status.HTTP_409_CONFLICT))
    app.add_exception_handler(_identity.Invalid, refusal(422))
    app.add_exception_handler(_tenancy.NotFound, refusal(status.HTTP_404_NOT_FOUND))
    app.add_exception_handler(_tenancy.Conflict, refusal(status.HTTP_409_CONFLICT))
    app.add_exception_handler(_identity.SignInUnavailable, refusal(status.HTTP_503_SERVICE_UNAVAILABLE))
    app.add_exception_handler(Exception, _server_error)
    if undeclared := undeclared_routes(app):
        raise RuntimeError(f"routes declare neither a permission nor a category (P-H): {undeclared}")
    if unauthenticated := unauthenticated_routes(app):
        raise RuntimeError(f"routes ask for the caller but are not made by `_router` (A7): {unauthenticated}")
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


def unauthenticated_routes(app: FastAPI) -> list[tuple[str, str]]:
    """The (method, path) of every route of `app` that asks for its caller but is not an `_AuthenticatingRoute`: only
    that class puts the caller where the route's dependencies read it, so such a route would answer every request
    with a server error. A router made by `_router` cannot hold one; a plain `APIRouter` or the app's own can."""
    return sorted({
        (method, route.path)
        for route in _served_routes(app.routes)
        if isinstance(route, APIRoute) and _authenticates(route.dependant) and not isinstance(route, _AuthenticatingRoute)
        for method in route.methods or () if method not in {"HEAD", "OPTIONS"}})
