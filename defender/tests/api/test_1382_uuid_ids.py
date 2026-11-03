"""#1382 O3: every id the system mints enters the API as its family's type, and a value that is not canonical
lowercase UUID text is a 422 naming that parameter, on every route that takes one. The routes are read off the
app's own route table, so a new route that takes an id is covered without being listed here. Sign-in and the
administrator check still answer first; a well-formed id that names nothing keeps its 404."""
from __future__ import annotations

import typing
from typing import Any

import pytest

pytest.importorskip("fastapi")

from fastapi.routing import APIRoute  # noqa: E402
from pydantic import BaseModel  # noqa: E402

from defender.records.formats import TenantId, UuidId  # noqa: E402
from defender.tests.api.test_api_stub import _api_routes  # noqa: E402
from defender.tests.support.api._identity1306 import ANN, OPS, T1, UNKNOWN, World  # noqa: E402
from defender.tests.support.shared._fixture_uuid import fixture_uuid  # noqa: E402

GOOD = fixture_uuid("1382:some-id")
MALFORMED = {"api-style": "al-1", "upper-case": GOOD.upper(), "braced": "{" + GOOD + "}"}


def _id_family(annotation: Any) -> type[UuidId] | None:
    """The id family an annotation names, through `X | None`."""
    for candidate in (annotation, *typing.get_args(annotation)):
        if isinstance(candidate, type) and issubclass(candidate, UuidId):
            return candidate
    return None


def _params(dependant: Any) -> list[tuple[str, str, Any]]:
    """(where, name, annotation) of every path and query parameter a route reads, its dependencies' included."""
    found = [("path", p.alias, p.field_info.annotation) for p in dependant.path_params]
    found += [("query", p.alias, p.field_info.annotation) for p in dependant.query_params]
    for sub in dependant.dependencies:
        found += _params(sub)
    return found


def _id_inputs(app: Any) -> list[tuple[APIRoute, str, str, set[str]]]:
    """(route, where, name, the route's path parameters) for every id the route takes in its path, query or body."""
    out = []
    for route in _api_routes(app.routes):
        params = _params(route.dependant)
        path_names = {name for where, name, _ in params if where == "path"}
        seen = set()
        for where, name, annotation in params:
            if _id_family(annotation) is not None and (where, name) not in seen:
                seen.add((where, name))
                out.append((route, where, name, path_names))
        body = route.body_field.field_info.annotation if route.body_field is not None else None
        if isinstance(body, type) and issubclass(body, BaseModel):
            out += [(route, "body", name, path_names) for name, field in body.model_fields.items()
                    if _id_family(field.annotation) is not None]
    return out


@pytest.fixture(scope="module")
def world() -> tuple[World, Any, Any]:
    world = World(administrators=[OPS], tenants={T1: [ANN]})
    return world, world.sign_in(ANN), world.sign_in_admin()


def _request(world: tuple[World, Any, Any], route: APIRoute, where: str, name: str, path_names: set[str],
             bad: str) -> Any:
    _, member, admin = world
    values = {p: (T1 if p == "tenant_id" else GOOD) for p in path_names}
    if where == "path":
        values[name] = bad
    path = route.path_format.format(**values)
    browser = admin if route.path.startswith("/admin") else member
    method = sorted(route.methods)[0]
    return browser.request(method, path, params={name: bad} if where == "query" else None,
                           json={name: bad} if where == "body" else ({} if method in ("POST", "PUT") else None))


def test_the_route_table_takes_every_id_family_somewhere(world):
    """Control on the sweep: tenant, alert, investigation, learning job, membership and user ids all reach a route."""
    app = world[0].app
    families = set()
    for route, where, name, _ in _id_inputs(app):
        annotation = dict(((w, n), a) for w, n, a in _params(route.dependant)).get((where, name))
        if annotation is None:  # a body field
            annotation = route.body_field.field_info.annotation.model_fields[name].annotation
        families.add(_id_family(annotation).__name__)
    assert families >= {"TenantId", "AlertId", "InvestigationId", "LearningJobId", "MembershipId", "UserId"}, families


@pytest.mark.parametrize("bad", sorted(MALFORMED))
def test_a_malformed_id_is_a_422_naming_it_on_every_route_that_takes_one(world, bad):
    """Path, query and body ids alike: 422, and the error's location is that parameter (O3)."""
    inputs = _id_inputs(world[0].app)
    assert inputs
    for route, where, name, path_names in inputs:
        response = _request(world, route, where, name, path_names, MALFORMED[bad])
        where_ = f"{sorted(route.methods)[0]} {route.path} ({where} {name})"
        assert response.status_code == 422, (where_, response.status_code, response.text)
        assert [where, name] in [e["loc"] for e in response.json()["errors"]], (where_, response.text)


def test_sign_in_and_the_administrator_check_answer_before_the_id_grammar(world):
    """No session: 401 whatever the tenant looks like; a member on an admin route: 403 (O3)."""
    w, member, _ = world
    stranger = w.client()
    assert stranger.get(f"/tenants/{MALFORMED['api-style']}/alerts").status_code == 401
    assert member.get(f"/admin/tenants/{MALFORMED['api-style']}").status_code == 403


def test_a_well_formed_id_that_names_nothing_keeps_its_404(world):
    """The existence answers are unchanged: an unknown tenant and an unknown alert are 404, not 422."""
    _, member, admin = world
    assert member.get(f"/tenants/{UNKNOWN}/alerts").status_code == 404
    assert member.get(f"/tenants/{T1}/alerts/{GOOD}").status_code == 404
    assert admin.get(f"/admin/tenants/{TenantId(UNKNOWN)}").status_code == 404
