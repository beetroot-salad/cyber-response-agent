"""The program's start and stop (#1083 Am-3). One exit stack owns every step: each step that opens something
registers its close, so a refusal or a stop at any point closes, in reverse, exactly what was opened."""

from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import datetime as _dt
import socket
import sys
from collections.abc import AsyncIterator, Mapping
from contextlib import AsyncExitStack, asynccontextmanager

import httpx
import uvicorn
from fastapi import FastAPI
import uvicorn.server

from defender.api.app import create_app
from defender.api.ports import ApiDeps
from defender.api.job_store import JobStorePorts
from defender.api.refusing import Refusing
from defender.identity import BootstrapRefused, IdentityService, SignInUnavailable
from defender.identity.keycloak import KeycloakPrograms, KeycloakSignIn
from defender.identity.logged_mail import LoggedMail
from defender.identity.postgres import PostgresIdentityRepository
from defender.jobs.store import JobStore
from defender.migrations import DatabaseUnreachable, RevisionMismatch, check_version
from defender.tenancy.postgres import PostgresTenantRepository

from ._settings import Settings, StartRefused

#: What each unbacked family's refusal names (P1; piece 2 is #1470).
_PIECE_2 = "piece 2 of #1083 (#1470)"
_LESSONS = "#1082"


@dataclasses.dataclass(frozen=True)
class Running:
    """What `serving` yields: the ASGI app (its lifespan entered) and the bound listening sockets."""

    app: FastAPI
    sockets: list[socket.socket]


def _now() -> _dt.datetime:
    return _dt.datetime.now(_dt.UTC)


async def _probe(adapter: KeycloakSignIn | KeycloakPrograms) -> None:
    try:
        await adapter.probe()
    except SignInUnavailable as why:
        raise StartRefused(str(why)) from why


def _bind(settings: Settings) -> socket.socket:
    sock = socket.socket(socket.AF_INET6 if ":" in settings.host else socket.AF_INET)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((settings.host, settings.port))
    except OSError as why:
        sock.close()
        raise StartRefused(f"cannot listen on {settings.host}:{settings.port}: {why.strerror or why}") from why
    sock.set_inheritable(True)
    return sock


def _deps(settings: Settings, identity: IdentityService, tenants: PostgresTenantRepository,
          ports: JobStorePorts) -> ApiDeps:
    piece_2, lessons = Refusing(_PIECE_2), Refusing(_LESSONS)
    return ApiDeps(
        identity=identity, tenants=tenants, frontend_origin=settings.frontend_origin,
        alerts=ports, investigations=ports, learning_jobs=ports, alert_mapping=ports, writes=ports,
        offboarding=ports, lessons=lessons, systems=piece_2, secrets=piece_2, checker=piece_2,
        artifact_links=piece_2, audit=piece_2)


@asynccontextmanager
async def serving(settings: Settings, *, transport: httpx.AsyncBaseTransport | None) -> AsyncIterator[Running]:
    """Start every step in order and yield the running app; leaving closes what was opened, in reverse. A start
    step that refuses raises `StartRefused` with its message, after closing what the earlier steps opened."""
    async with AsyncExitStack() as stack:
        try:
            await asyncio.to_thread(check_version, settings.database_dsn)
        except (RevisionMismatch, DatabaseUnreachable) as why:
            raise StartRefused(str(why)) from why
        signin = KeycloakSignIn(
            issuer=settings.signin_issuer, client_id=settings.signin_client_id,
            client_secret=settings.signin_client_secret, redirect_uri=settings.signin_redirect_uri,
            admin_client_id=settings.signin_admin_client_id, admin_client_secret=settings.signin_admin_client_secret,
            server_url=settings.keycloak_server_url, transport=transport)
        stack.push_async_callback(signin.close)
        programs = KeycloakPrograms(
            issuer=settings.programs_issuer, audience=settings.programs_audience,
            admin_client_id=settings.programs_admin_client_id,
            admin_client_secret=settings.programs_admin_client_secret,
            server_url=settings.keycloak_server_url, transport=transport)
        stack.push_async_callback(programs.close)
        await _probe(signin)
        await _probe(programs)
        store = JobStore(settings.database_dsn, clock=_now)
        stack.push_async_callback(store.close)
        people = PostgresIdentityRepository(settings.database_dsn)
        stack.push_async_callback(people.close)
        tenants = PostgresTenantRepository(settings.database_dsn)
        stack.push_async_callback(tenants.close)
        identity = IdentityService(people, signin=signin, mail=LoggedMail(), clock=_now,
                                   bootstrap=settings.administrators, programs=programs)
        app = create_app(_deps(settings, identity, tenants, JobStorePorts(store)))
        sock = _bind(settings)
        stack.callback(sock.close)
        try:
            await stack.enter_async_context(app.router.lifespan_context(app))
        except BootstrapRefused as why:
            raise StartRefused(str(why)) from why
        yield Running(app=app, sockets=[sock])


async def _serve(settings: Settings, transport: httpx.AsyncBaseTransport | None, stop: asyncio.Event,
                 started: list[bool]) -> None:
    async with serving(settings, transport=transport) as running:
        started.append(True)
        if stop.is_set():
            return
        config = uvicorn.Config(running.app, lifespan="off", log_config=None)
        await uvicorn.Server(config).serve(sockets=running.sockets)


async def _run(settings: Settings, transport: httpx.AsyncBaseTransport | None) -> int:
    loop = asyncio.get_running_loop()
    stop = asyncio.Event()
    started: list[bool] = []
    task = asyncio.ensure_future(_serve(settings, transport, stop, started))

    def request_stop() -> None:
        stop.set()
        if not started:
            task.cancel()

    for sig in uvicorn.server.HANDLED_SIGNALS:
        loop.add_signal_handler(sig, request_stop)
    try:
        await task
    except asyncio.CancelledError:
        if not stop.is_set():
            raise
    except StartRefused as refused:
        print(refused, file=sys.stderr)
        return 1
    finally:
        for sig in uvicorn.server.HANDLED_SIGNALS:
            with contextlib.suppress(ValueError, RuntimeError):
                loop.remove_signal_handler(sig)
    return 0


def run(environ: Mapping[str, str], *, transport: httpx.AsyncBaseTransport | None) -> int:
    """The whole program: settings, then `serving`, then uvicorn on its sockets until a handled signal. A refusal
    prints its message to stderr and returns 1; a handled signal returns 0 after everything is closed."""
    try:
        settings = Settings.from_environ(environ)
    except StartRefused as refused:
        print(refused, file=sys.stderr)
        return 1
    return asyncio.run(_run(settings, transport))
