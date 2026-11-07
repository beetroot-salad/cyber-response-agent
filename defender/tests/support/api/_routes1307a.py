"""#1307 slice A: the real app's routes as a class — no test functions. A test over "every route" takes its
inputs from the app's own route table, so a route added later falls into the class without an edit."""
from __future__ import annotations

import functools
import re
from typing import Any

from fastapi.routing import APIRoute

from defender.api.app import create_app
from defender.api.fakes import InMemorySecrets, InMemoryStore, StubArtifactLinks, StubSystemChecker
from defender.api.ports import ApiDeps
from defender.tests.support.api._identity1306 import FRONTEND_ORIGIN, T1
from defender.tests.support.shared._fixture_uuid import fixture_uuid

PATH_ID = fixture_uuid("1307:a:path-id")
#: The two sign-in routes: they never authenticate (O1, O2).
PUBLIC = {("GET", "/auth/login"), ("GET", "/auth/callback")}
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


@functools.lru_cache(maxsize=1)
def app_routes() -> tuple[tuple[str, str], ...]:
    """(METHOD, path template) for every route the real app serves, sorted."""
    store = InMemoryStore(lambda: None)  # type: ignore[arg-type]
    app: Any = create_app(ApiDeps(  # building the route table needs no identity service
        alerts=store, investigations=store, learning_jobs=store, lessons=store, systems=store, writes=store,
        secrets=InMemorySecrets(), checker=StubSystemChecker(), artifact_links=StubArtifactLinks(),
        identity=None, frontend_origin=FRONTEND_ORIGIN, tenants=None))  # type: ignore[arg-type]
    found = {(method, route.path) for route in _served(app.routes)
             for method in route.methods if method not in {"HEAD", "OPTIONS"}}
    assert len(found) > ROUTE_FLOOR, f"the route walk found {len(found)} routes"
    return tuple(sorted(found))


def authenticating_routes() -> list[tuple[str, str]]:
    return [r for r in app_routes() if r not in PUBLIC]


def route_id(route: tuple[str, str]) -> str:
    return f"{route[0]} {route[1]}"
