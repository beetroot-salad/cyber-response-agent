"""#1307 slice A: the real app's routes as a class — no test functions. A test over "every route" takes its
inputs from the app's own route table, so a route added later falls into the class without an edit."""
from __future__ import annotations

import functools
import re
from typing import Any

from fastapi.routing import APIRoute

from defender.api.app import create_app
from defender.api.refusing import Refusing
from defender.api.ports import ApiDeps
from defender.tests.support.api._identity1306 import FRONTEND_ORIGIN, T1
from defender.tests.support.api._server1083 import FORGE_DOMAIN  # #1592 r15.2: `ApiDeps.forge_domain` is required
from defender.tests.support.api._mount1161 import API
from defender.tests.support.shared._fixture_uuid import fixture_uuid

PATH_ID = fixture_uuid("1307:a:path-id")
#: The two sign-in routes: they never authenticate (O1, O2).
PUBLIC = {("GET", API + "/auth/login"), ("GET", API + "/auth/callback")}
_PARAM = re.compile(r"\{(\w+)(?::\w+)?\}")
_FILL = {"tenant_id": T1, "key": "report.md", "system_id": "tix"}


def concrete(template: str) -> str:
    """The template with every path parameter filled by a well-formed value (ids a valid UUID that names nothing)."""
    return _PARAM.sub(lambda m: _FILL.get(m.group(1), PATH_ID), template)


def normal(template: str) -> str:
    """The template with parameter names erased: `/tenants/{}/members/{}`."""
    return _PARAM.sub("{}", template)


def _served(routes: Any) -> Any:
    """Every route as served: FastAPI includes routers lazily, so an included router yields its effective routes."""
    for route in routes:
        if isinstance(route, APIRoute):
            yield route
        elif hasattr(route, "effective_candidates"):
            yield from _served(route.effective_candidates())
        elif hasattr(route, "dependant"):  # an effective route context: carries path and methods
            yield route


#: A route table smaller than this means the walk missed routes (the app serves 35 at base, C11); an empty class must fail.
ROUTE_FLOOR = 20


def route_table_deps() -> ApiDeps:
    """Dependencies enough to build the app and read its route table: no identity service is needed to list routes."""
    import dataclasses

    store = Refusing("route table only (#1496)")
    ports = {name: store for name in ("alerts", "investigations", "learning_jobs", "learning_work", "lessons", "systems",
                                      "writes", "secrets", "checker", "artifact_links", "offboarding", "alert_mapping",
                                      "audit", "host_requests")}  # #1471: the host-requests port, once ApiDeps has it
    known = {f.name for f in dataclasses.fields(ApiDeps)}
    return ApiDeps(**{k: v for k, v in ports.items() if k in known},  # type: ignore[arg-type]
                   identity=None, frontend_origin=FRONTEND_ORIGIN, forge_domain=FORGE_DOMAIN, tenants=None)


@functools.lru_cache(maxsize=1)
def app_routes() -> tuple[tuple[str, str], ...]:
    """(METHOD, path template) for every route the real app serves, sorted."""
    app: Any = create_app(route_table_deps())
    found = {(method, route.path) for route in _served(app.routes)
             for method in route.methods if method not in {"HEAD", "OPTIONS"}}
    assert len(found) > ROUTE_FLOOR, f"the route walk found {len(found)} routes"
    return tuple(sorted(found))


def authenticating_routes() -> list[tuple[str, str]]:
    return [r for r in app_routes() if r not in PUBLIC]


def route_id(route: tuple[str, str]) -> str:
    return f"{route[0]} {route[1]}"


#: #1471 R1/A1: a host-request start answers 201 when it queues and 200 when it replays the one already queued, so a test
#: that compares two answers of one route primes such a start first; every later call then replays.
REPLAYING_STARTS = frozenset({("POST", API + "/tenants/{tenant_id}/readiness"),
                              ("POST", API + "/tenants/{tenant_id}/systems/{system_id}/adoptions")})


def prime_start(client: Any, route: tuple[str, str]) -> None:
    """Send `route` once as `client` when it is a replaying start (else nothing), so its answer is the same each time."""
    if route in REPLAYING_STARTS:
        got = client.request(route[0], concrete(route[1]))
        assert got.status_code not in (401, 403, 500), (route, got.status_code, got.text)
