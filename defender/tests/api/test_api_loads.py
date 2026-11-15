"""The API program loads no runtime or `learning` module (#1080; the set is `_spec1080.API_FORBIDDEN`).

Asked of Python rather than the source: each `api` module is imported in a fresh interpreter and
the modules left loaded are read back, so a conditional import counts as it executes at import time. An import
inside a function runs only when it is called: the last test serves every route in a child process (#1495)."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from defender.tests.tooling.layout_contracts._spec1080 import api_forbidden

DEFENDER = Path(__file__).resolve().parents[2]
REPO = DEFENDER.parent

_PROBE = """
import importlib, json, sys
importlib.import_module(sys.argv[1])
print(json.dumps(sorted(sys.modules)))
"""


def _loaded(module: str) -> list[str]:
    env = {**os.environ, "PYTHONPATH": os.pathsep.join(
        p for p in (str(REPO), os.environ.get("PYTHONPATH", "")) if p)}
    proc = subprocess.run([sys.executable, "-c", _PROBE, module], capture_output=True, text=True,
                          check=False, cwd=str(REPO), env=env, timeout=180)
    assert proc.returncode == 0, f"importing {module} failed:\n{proc.stderr}"
    return json.loads(proc.stdout.splitlines()[-1])


API_MODULES = sorted(
    "defender.api" + ("" if p.stem == "__init__" else f".{p.stem}")
    for p in (DEFENDER / "api").glob("*.py"))


@pytest.mark.parametrize("module", API_MODULES)
def test_an_api_module_loads_no_runtime_or_learning(module):
    found = api_forbidden(_loaded(module))
    assert not found, f"{module} loads {found}"


def test_the_probe_sees_a_runtime_load():
    """Positive control: a module that does load the runtime is reported."""
    assert "defender.investigation.run_state" in api_forbidden(_loaded("defender.investigation.run_state"))
    # runtime code placed outside `investigation` counts too
    assert "defender.systems.verbs" in api_forbidden(_loaded("defender.systems.verbs"))


#: #1214 r9: what the API's import of `defender.api.app` may not load beyond #1339's allowance (identity's models
#: and SQLAlchemy ORM): the lifecycle node, the database repositories of identity and tenancy, the driver.
_NOT_BY_THE_API = ("defender.lifecycle", "defender.tenancy.postgres", "defender.identity.postgres", "psycopg")


def _found(modules: list[str], name: str) -> list[str]:
    return [m for m in modules if m == name or m.startswith(name + ".")]


@pytest.mark.parametrize("module", API_MODULES)
def test_an_api_module_loads_no_lifecycle_and_no_database_repository_or_driver(module):
    """The API reaches tenancy only through its in-memory twin or an injected repository; `lifecycle` is never loaded (#1214 r9, DC-6)."""
    modules = _loaded(module)
    found = [m for name in _NOT_BY_THE_API for m in _found(modules, name)]
    assert not found, f"{module} loads {found}"


def test_the_not_loaded_probe_sees_a_load():
    """Positive control: the identity database repository and the lifecycle node are reported when imported."""
    assert _found(_loaded("defender.identity.postgres"), "defender.identity.postgres")
    assert _found(_loaded("defender.lifecycle"), "defender.lifecycle")


#: #1083 Am-1: the real server program is a package of its own, `defender/api_server/`, under the same #1080 guard.
API_SERVER_MODULES = sorted(
    "defender.api_server" + ("" if p.stem == "__init__" else f".{p.stem}")
    for p in (DEFENDER / "api_server").rglob("*.py"))


def test_the_program_glob_finds_the_entry_module():
    """Positive control: the recursive glob over `defender/api_server/` finds `__main__`. (Am-1)"""
    assert "defender.api_server.__main__" in API_SERVER_MODULES
    assert "defender.api_server" in API_SERVER_MODULES


@pytest.mark.parametrize("module", API_SERVER_MODULES)
def test_a_program_module_loads_no_runtime_or_learning(module):
    """Every module of the real server program loads nothing in `API_FORBIDDEN`. (Am-1)"""
    found = api_forbidden(_loaded(module))
    assert not found, f"{module} loads {found}"


# --- #1495: what a serving process loads -----------------------------------------------------------
# The guards above import each module; a function-level import (inside a route's handler, a port's method, or
# `serving`) runs only while the program serves, so they never see it. This one runs the real program in a child
# process, sends every route of the app one request that gets past sign-in and validation to its handler, and reads
# what the process loaded. Only `API_FORBIDDEN` applies: the program composes the database repositories and the
# driver by design, so `_NOT_BY_THE_API` (the `defender.api.app` import's rule) does not, beyond `defender.lifecycle`,
# which `API_FORBIDDEN` names too.

def _stopped_before_the_handler(response: Any) -> bool:
    """Refused at sign-in, method, validation (a 422 naming field errors) or permission (a 403 of no reason). A store's
    refusal (an unknown reference's 422, the sign-in service's 403 naming its reason) came from the handler."""
    if response.status_code in (401, 405):
        return True
    if response.status_code == 422:
        return bool(response.json().get("errors"))
    if response.status_code == 403:
        return response.json().get("type", "about:blank") == "about:blank"
    return False


#: The calls that end what later calls stand on (Ann's session, tenant A's service) go last, in this order.
_LAST = (("POST", "/admin/tenants/{tenant_id}/offboard"), ("POST", "/auth/logout"))


def _serving_requests(seeded: Any) -> list[tuple[tuple[str, str], str, dict[str, Any]]]:
    """One request per served route, (route, path, httpx keyword arguments): an administrator's route as Ops, every
    other as Ann (tenant A's admin, the write origin sent), on tenant A, with the route's body where it takes one."""
    from defender.tests.api.test_programs_1307_roles import BODIES
    from defender.tests.support.api._routes1307a import _PARAM, PATH_ID, app_routes, normal
    from defender.tests.support.api._server1083 import A, person

    fill = {"tenant_id": A, "key": "report.md", "system_id": "tix"}
    bodies = {**BODIES, ("POST", "/admin/tenants/{}/invitations"): {"email": "new@a.example"}}
    query = {("GET", "/auth/callback"): {"code": "c", "state": "s"}}
    routes = sorted(app_routes(), key=lambda r: (_LAST.index(r) if r in _LAST else -1, r))
    requests = []
    for route in routes:
        method, template = route
        session = seeded.ops_session if template.startswith("/admin/") else seeded.ann_session
        kwargs: dict[str, Any] = {"headers": person(session, write=True)}
        if (method, normal(template)) in bodies:
            kwargs["json"] = bodies[method, normal(template)]
        if route in query:
            kwargs["params"] = query[route]
        requests.append((route, _PARAM.sub(lambda m: fill.get(m.group(1), PATH_ID), template), kwargs))
    return requests


@pytest.mark.postgres
def test_a_serving_program_that_answered_every_route_loads_no_runtime_or_learning(tmp_path, migrated_database):
    """The real program, serving over the real ports, loads nothing in `API_FORBIDDEN` while it answers one request
    per route; each request reached its handler. (#1495)"""
    import asyncio

    import httpx

    from defender.tests.support.api._server1083 import B, LOADED_ENV, A, Child, environment, seed_identity
    from defender.tests.support.jobs._jobs1342 import register_tenant

    register_tenant(migrated_database, A)
    register_tenant(migrated_database, B)
    seeded = asyncio.run(seed_identity(migrated_database))
    child = Child.faked({**environment(tmp_path, dsn=migrated_database), LOADED_ENV: "1"})
    try:
        assert child.ready(), "the program did not come up"
        with httpx.Client(base_url=child.base_url, timeout=30, follow_redirects=False) as client:
            answered = {f"{route[0]} {route[1]}": client.request(route[0], path, **kwargs)
                        for route, path, kwargs in _serving_requests(seeded)}
    finally:
        ended = child.stop()
    assert ended.returncode == 0, ended.stderr
    unreached = {route: (r.status_code, r.text) for route, r in answered.items() if _stopped_before_the_handler(r)}
    assert not unreached, f"these requests never reached their handler: {unreached}"
    # controls: Ann passed tenant A's member gate (its 404 would read as reached), and the offboard met an active tenant
    assert answered["GET /tenants/{tenant_id}/alert-mapping"].status_code == 200
    assert answered["POST /admin/tenants/{tenant_id}/offboard"].status_code == 202
    [line] = [line for line in ended.stdout.splitlines() if line.startswith("loaded ")]
    found = api_forbidden(json.loads(line.removeprefix("loaded ")))
    assert not found, f"the serving program loads {found}"
