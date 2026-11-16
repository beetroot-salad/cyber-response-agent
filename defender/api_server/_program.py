"""The program's start and stop (#1083 Am-3). One exit stack owns every step: each step that opens something
registers its close, so a refusal or a stop at any point closes, in reverse, exactly what was opened. What the app's
lifespan closes (the identity service with its sign-in adapters and people repository, the tenant rows) is held on
a start-only stack and handed to the lifespan as it is entered: one owner for each close."""

from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import datetime as _dt
import logging
import signal
import socket
import sys
import threading
from collections.abc import AsyncIterator, Callable, Iterator, Mapping
from contextlib import AsyncExitStack, asynccontextmanager

import httpx
import uvicorn
from fastapi import FastAPI
import uvicorn.server

from defender.api.app import create_app
from defender.api.config_records import ConfigCredentials, ConfigRecords
from defender.api.ports import ApiDeps, LearningWorkRepository, SecretStore, SystemsRepository
from defender.api.job_store import JobStorePorts
from defender.api.learning_work import StoreLearningWork
from defender.api.refusing import Refusing
from defender.configuration.issuer import DEPLOYMENT_ISSUER
from defender.credential_proxy import OpenBaoSecrets
from defender.identity import BootstrapRefused, IdentityService, SignInUnavailable
from defender.identity.keycloak import KeycloakPrograms, KeycloakSignIn  # lint-shippable: ok — the program wires the one sign-in vendor the platform supports (#1083).
from defender.identity.logged_mail import LoggedMail
from defender.identity.postgres import PostgresIdentityRepository
from defender.jobs.store import JobStore
from defender.kit.faults import AdapterFault
from defender.kit.internal_http import internal_async_client, tls_trust
from defender.learning_store import LearningStore
from defender.migrations import DatabaseUnreachable, RevisionMismatch, check_version
from defender.system_records import RecordStore
from defender.system_rules import Catalog, judge_records
from defender.tenancy import TenantRepository
from defender.tenancy.models import TenantRecords
from defender.tenancy.postgres import PostgresTenantRepository

from ._settings import OPENBAO_SETTINGS, Settings, StartRefused

#: What each family nothing real backs yet names as its owner (P1, #1470 O15).
_CHECK = "#1460 (the connection check)"
_BLOB_STORE = "#1082 (the blob store)"
_LESSONS = "#1082"
#: The learning store's pool: the two learning reads only, so small beside the job store's.
_LEARNING_POOL = 3
_LEARNING_WORK = "a learning store (#1485)"

#: How long the secret store's start checks may take, each (the writer's own calls use the writer's timeout).
_OPENBAO_START_SECONDS = 10.0
#: The secret path the start's login check reads the metadata of: a tenant and system no record can name, so the
#: answer is "nothing there" for a token whose policy covers the mount (#1532 K2).
_PROBE_TENANT, _PROBE_SYSTEM = "00000000-0000-4000-8000-000000000000", "api-login-probe"


@dataclasses.dataclass(frozen=True)
class Running:
    """What `serving` yields: the ASGI app (its lifespan entered) and the bound listening sockets."""

    app: FastAPI
    sockets: list[socket.socket]


def _wall_clock() -> _dt.datetime:
    return _dt.datetime.now(_dt.UTC)


_log = logging.getLogger(__name__)

#: The refusals whose own message already names the step and the cause: they are the operator's line as they are.
_OWN_MESSAGE = (RevisionMismatch, DatabaseUnreachable, SignInUnavailable, BootstrapRefused)


#: How long any start step may take before it refuses naming itself: well past a healthy step (a probe's four
#: requests time out at 10 s each), so a dependency that accepts and then never answers ends the start in words.
STEP_SECONDS = 60.0


class _Stopped(Exception):
    """A stop signal arrived during start: the start ends, closing what it opened, and the program exits 0."""


class _Server(uvicorn.Server):
    """uvicorn serving the bound socket. Its own signal capture is off: the program's stop is the one signal owner,
    start and serve alike, so no signal can land between two mechanisms and be lost."""

    @contextlib.contextmanager
    def capture_signals(self) -> Iterator[None]:
        yield


class _Steps:
    """The program's life, one step at a time, and the one owner of its stop. Every failure inside a start step is
    that step's refusal (`StartRefused`, one line naming it), and so is a step that outlives `STEP_SECONDS`; a stop
    cancels only the step in flight, so the closes after a refusal or a stop always run whole. Serving is the last
    step: a stop there tells uvicorn to exit, and a second stop forces it."""

    def __init__(self, *, within: float = STEP_SECONDS) -> None:
        self.stop = asyncio.Event()
        self._within = within
        self._running: asyncio.Task[object] | None = None
        self._server: uvicorn.Server | None = None

    def request_stop(self, sig: int = signal.SIGTERM) -> None:
        if self._server is not None:
            self._server.handle_exit(sig, None)  # uvicorn's own answer to a signal: exit, and a second SIGINT forces it
        self.stop.set()
        if self._running is not None:
            self._running.cancel()

    @asynccontextmanager
    async def step(self, name: str) -> AsyncIterator[None]:
        if self.stop.is_set():
            raise _Stopped
        self._running = asyncio.current_task()
        within = self._within
        deadline = asyncio.timeout(within)
        try:
            async with deadline:
                yield
        except asyncio.CancelledError:
            if not self.stop.is_set():
                raise
            task = asyncio.current_task()
            if task is not None:
                task.uncancel()
            raise _Stopped from None
        except StartRefused:
            raise
        except _OWN_MESSAGE as why:
            raise StartRefused(str(why)) from why
        except TimeoutError as why:
            if deadline.expired():
                raise StartRefused(f"{name} did not finish within {within:g} s") from None
            raise _unforeseen(name, why) from why
        except Exception as why:
            raise _unforeseen(name, why) from why
        finally:
            self._running = None

    async def serve(self, server: uvicorn.Server, sockets: list[socket.socket]) -> None:
        self._server = server
        if self.stop.is_set():  # a stop that landed as the start finished
            return
        await server.serve(sockets=sockets)


def _unforeseen(name: str, why: Exception) -> StartRefused:
    """The refusal for a failure the step has no refusal of its own for: one line naming the step and the error."""
    _log.debug("start step %s failed", name, exc_info=why)  # the whole error, for whoever turns on debug
    first = next(iter(str(why).splitlines()), "")  # a driver's error carries its SQL and a link after
    return StartRefused(f"{name} failed: {type(why).__name__}: {first}".rstrip(": "))


async def _abandonable(call: Callable[[], None]) -> None:
    """Run a blocking call off the loop in a daemon thread that a stop may abandon: `asyncio.to_thread` cannot be
    cancelled, so a database that accepts and never answers would hold a stop signal (and exit) forever."""
    loop = asyncio.get_running_loop()
    done: asyncio.Future[None] = loop.create_future()

    def settle(error: BaseException | None) -> None:
        if done.cancelled():
            return
        if error is None:
            done.set_result(None)
        else:
            done.set_exception(error)

    def work() -> None:
        try:
            call()
        except BaseException as failed:  # noqa: BLE001 — handed to the awaiting coroutine whole
            outcome: BaseException | None = failed
        else:
            outcome = None
        with contextlib.suppress(RuntimeError):  # a stop abandoned this thread and the loop has since closed
            loop.call_soon_threadsafe(settle, outcome)

    threading.Thread(target=work, name="version-check", daemon=True).start()
    await done


def _bind(settings: Settings) -> socket.socket:
    sock = socket.socket(socket.AF_INET6 if ":" in settings.host else socket.AF_INET)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((settings.host, settings.port))
    except OSError as why:
        sock.close()
        raise StartRefused(f"DEFENDER_API_HOST / DEFENDER_API_PORT: cannot listen on {settings.host}:{settings.port}: {why.strerror or why}") from why
    return sock


def api_deps(*, identity: IdentityService, tenants: TenantRepository, ports: JobStorePorts, frontend_origin: str,
             systems: SystemsRepository, secrets: SecretStore,
             learning_work: LearningWorkRepository | None = None) -> ApiDeps:
    """The app's ports as the program composes them: the job store's ports back every family the store serves, the
    tenant's records and their credentials are `systems` and `secrets` (the program's are over the record store and
    OpenBao, #1470), the learning loop's set-aside reads (#1485) are the real adapter's over the learning store the
    program opened (a world that passes none gets a refusal, as for any family it does not back), and the rest refuse
    (the connection check, the blob store, lessons). The API test worlds compose through this too (#1496), so they
    cannot drift."""
    return ApiDeps(
        identity=identity, tenants=tenants, frontend_origin=frontend_origin,
        alerts=ports, investigations=ports, learning_jobs=ports, alert_mapping=ports, writes=ports,
        learning_work=learning_work if learning_work is not None else Refusing(_LEARNING_WORK),
        offboarding=ports, lessons=Refusing(_LESSONS), systems=systems, secrets=secrets,
        checker=Refusing(_CHECK), artifact_links=Refusing(_BLOB_STORE), audit=Refusing(_BLOB_STORE))


async def _seal_status(settings: Settings, transport: httpx.AsyncBaseTransport | None) -> bool:
    """OpenBao's unauthenticated seal status (D9): whether it is sealed, or `StartRefused` naming its address when it
    cannot be read or is not `{"sealed": <bool>}`. Only this is asked at start of a sealed store."""
    where = f"DEFENDER_OPENBAO_ADDR: the secret store at {settings.openbao_addr}"
    try:
        async with internal_async_client(trust=tls_trust(DEPLOYMENT_ISSUER.ca_cert), transport=transport,
                                         timeout=_OPENBAO_START_SECONDS) as client:
            reply = await client.get(f"{settings.openbao_addr}/v1/sys/seal-status")
    except httpx.HTTPError as why:
        raise StartRefused(f"{where} cannot be reached for its seal status ({type(why).__name__})") from None
    if reply.status_code != 200:
        raise StartRefused(f"{where} answered its seal status with {reply.status_code}")
    try:
        answer = reply.json()
    except ValueError:
        answer = None
    sealed = answer.get("sealed") if isinstance(answer, dict) else None
    if not isinstance(sealed, bool):
        raise StartRefused(f"{where} answered its seal status without a `sealed` true or false")
    return sealed


async def _login_check(secrets: OpenBaoSecrets) -> None:
    """The API's token works at this address and may read under the mount (G4; #1532): its lookup-self, then a metadata
    read of a path no record names. A refusal is the secret store's own fault, which states what OpenBao did and the
    settings that answer can come from, never which one is wrong (#1532 P1). The token is never shown."""
    try:
        await secrets.look_up_self()
        await secrets.has_credentials(_PROBE_TENANT, _PROBE_SYSTEM, generation=1)
    except AdapterFault as fault:
        raise StartRefused(f"the API's secret-store check failed: {fault}") from None


def _whole_catalog() -> Catalog:
    """The catalog built whole (every entry and every adapter module), once, so the judgement inside the record store's
    row lock reads no files. An unreadable adapters directory refuses start; an adapter that fails to load is kept as
    data (D8): the judgement names it as a fault on each ask."""
    return Catalog.of_checkout().load_all()


@asynccontextmanager
async def serving(settings: Settings, *, transport: httpx.AsyncBaseTransport | None,
                  openbao_transport: httpx.AsyncBaseTransport | None,
                  steps: _Steps | None = None) -> AsyncIterator[Running]:
    """Start every step in order and yield the running app; leaving closes what was opened, in reverse. A start
    step that fails raises `StartRefused` with its message, after closing what the earlier steps opened. `steps`
    lets the caller stop the start (`run` passes its own); without it nothing can. `transport` reaches the sign-in provider and
    `openbao_transport` the secret store (None: the network; a test passes fakes)."""
    steps = steps if steps is not None else _Steps()  # lint-default: ok — a fresh _Steps per call: a shared default would carry one start's stop into the next
    async with AsyncExitStack() as stack:
        async with steps.step("the database version check"):
            await _abandonable(lambda: check_version(settings.database_dsn))
        async with steps.step("the secret store's seal status"):
            sealed = await _seal_status(settings, openbao_transport)
        secrets = OpenBaoSecrets(addr=settings.openbao_addr, token=settings.openbao_token.get_secret_value(),
                                 mount=settings.openbao_kv_mount, transport=openbao_transport,
                                 settings=OPENBAO_SETTINGS)
        await stack.enter_async_context(secrets.pooled())  # one pooled client for the login check and every request
        if not sealed:  # sealed: the API starts, and each request needing the store answers 503 until it is unsealed
            async with steps.step("the secret store's login check"):
                await _login_check(secrets)
        async with steps.step("reading the adapter catalog"):
            catalog = await asyncio.to_thread(_whole_catalog)
        async with AsyncExitStack() as until_lifespan:  # closes what the lifespan will own, if start ends before it
            async with steps.step("building the sign-in adapters"):
                signin = KeycloakSignIn(
                    issuer=settings.signin_issuer, client_id=settings.signin_client_id,
                    client_secret=settings.signin_client_secret.get_secret_value(),
                    redirect_uri=settings.signin_redirect_uri, admin_client_id=settings.signin_admin_client_id,
                    admin_client_secret=settings.signin_admin_client_secret.get_secret_value(),
                    server_url=settings.keycloak_server_url, transport=transport)
                until_lifespan.push_async_callback(signin.close)
                programs = KeycloakPrograms(
                    issuer=settings.programs_issuer, audience=settings.programs_audience,
                    admin_client_id=settings.programs_admin_client_id,
                    admin_client_secret=settings.programs_admin_client_secret.get_secret_value(),
                    server_url=settings.keycloak_server_url, transport=transport)
                until_lifespan.push_async_callback(programs.close)
            async with steps.step("the sign-in realm probe"):
                await signin.probe()
            async with steps.step("the programs realm probe"):
                await programs.probe()
            async with steps.step("building the stores and the app"):
                store = JobStore(settings.database_dsn, clock=_wall_clock)
                stack.push_async_callback(store.close)  # the lifespan does not close it: it outlives the lifespan
                learning = LearningStore(settings.database_dsn, max_connections=_LEARNING_POOL)
                stack.push_async_callback(learning.close)  # outlives the lifespan, as the job store does
                people = PostgresIdentityRepository(settings.database_dsn)
                until_lifespan.push_async_callback(people.close)
                tenants = PostgresTenantRepository(settings.database_dsn)
                until_lifespan.push_async_callback(tenants.close)
                records = record_store(settings.database_dsn, catalog, clock=_wall_clock)
                stack.push_async_callback(records.close)  # like the job store, it outlives the lifespan
                identity = IdentityService(people, signin=signin, mail=LoggedMail(), clock=_wall_clock,
                                           bootstrap=settings.administrators, programs=programs)
                app = create_app(api_deps(
                    identity=identity, tenants=tenants, ports=JobStorePorts(store), frontend_origin=settings.frontend_origin,
                    systems=ConfigRecords(records, tenants, catalog, secrets), secrets=ConfigCredentials(records, secrets),
                    learning_work=StoreLearningWork(learning)))
            async with steps.step("binding the listening socket"):
                sock = _bind(settings)
                stack.callback(sock.close)
            async with steps.step("the bootstrap"):
                # Handed over as the lifespan is entered, nothing awaited between: from here it closes the service and
                # the tenant rows, its start's failure too. A stop before this step leaves them on `until_lifespan`.
                until_lifespan.pop_all()
                await stack.enter_async_context(app.router.lifespan_context(app))
        yield Running(app=app, sockets=[sock])


def record_store(dsn: str, catalog: Catalog, *, clock: Callable[[], _dt.datetime]) -> RecordStore:
    """The record store as the API serves it: each write judged over `catalog` (the one built whole at start, so the
    judgement inside the row lock reads no files), only what the write changes (#1366 C4)."""
    return RecordStore(dsn, clock=clock, judge=_catalog_judge(catalog))


def _catalog_judge(catalog: Catalog) -> Callable[[TenantRecords, TenantRecords], list[str]]:
    """The record judgement over the catalog built at start, as the record store takes it."""
    def judge(after: TenantRecords, before: TenantRecords) -> list[str]:
        return list(judge_records(after, before, catalog=catalog))
    return judge


async def _serve_on_sockets(settings: Settings, transport: httpx.AsyncBaseTransport | None,
                            openbao_transport: httpx.AsyncBaseTransport | None, steps: _Steps) -> None:
    async with serving(settings, transport=transport, openbao_transport=openbao_transport, steps=steps) as running:
        await steps.serve(_Server(uvicorn.Config(running.app, lifespan="off", log_config=None)), running.sockets)


async def _run(settings: Settings, transport: httpx.AsyncBaseTransport | None,
               openbao_transport: httpx.AsyncBaseTransport | None) -> int:
    loop = asyncio.get_running_loop()
    steps = _Steps()
    for sig in uvicorn.server.HANDLED_SIGNALS:
        loop.add_signal_handler(sig, steps.request_stop, sig)
    try:
        await _serve_on_sockets(settings, transport, openbao_transport, steps)
    except _Stopped:
        return 0
    except StartRefused as refused:
        print(refused, file=sys.stderr)
        return 1
    finally:
        for sig in uvicorn.server.HANDLED_SIGNALS:
            with contextlib.suppress(ValueError, RuntimeError):
                loop.remove_signal_handler(sig)
    return 0


def run(environ: Mapping[str, str], *, transport: httpx.AsyncBaseTransport | None,
        openbao_transport: httpx.AsyncBaseTransport | None) -> int:
    """The whole program: settings, then `serving`, then uvicorn on its sockets until a handled signal. A refusal
    prints its message to stderr and returns 1; a handled signal returns 0 after everything is closed."""
    try:
        settings = Settings.from_environ(environ)
    except StartRefused as refused:
        print(refused, file=sys.stderr)
        return 1
    return asyncio.run(_run(settings, transport, openbao_transport))
