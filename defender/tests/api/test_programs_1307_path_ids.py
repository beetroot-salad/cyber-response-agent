"""#1307 contract repair (B5): every id in a path is its family's type (#1382 O3), the program routes' included. The #1382 sweep reads
which parameters are ids from the route table's own annotations, so a route whose id was retyped as `Any` leaves the sweep with
nothing to ask about. This sweep takes its inputs from the `{name}` placeholders of each route's path instead, with an explicit
allow-list for the placeholders that are not minted ids; a placeholder neither listed nor typed as an id is a failure of its own."""
from __future__ import annotations

import re
from typing import Any

import pytest

pytest.importorskip("fastapi")

from defender.tests.api.test_1382_uuid_ids import GOOD, MALFORMED, _id_family, _params  # noqa: E402
from defender.tests.api.test_api_stub import _api_routes  # noqa: E402
from defender.tests.support.api._identity1306 import ANN, OPS, T1  # noqa: E402
from defender.tests.support.api._programs1307 import ProgramsWorld, create_program, issue_key  # noqa: E402

_PLACEHOLDER = re.compile(r"\{(\w+)(?::\w+)?\}")
#: Path placeholders that are not minted ids: an artifact's key inside its run folder, and a system id the tenant chose.
NOT_IDS = {"key", "system_id"}


@pytest.fixture(scope="module")
def world() -> tuple[ProgramsWorld, Any, Any]:
    world = ProgramsWorld(administrators=[OPS], tenants={T1: [ANN]})
    return world, world.sign_in(ANN), world.sign_in_admin()


def _placeholder_routes(app: Any) -> list[tuple[Any, str, list[str]]]:
    """(route, method, the route's path placeholders in order) for every route served that has a placeholder."""
    out = []
    for route in _api_routes(app.routes):
        names = _PLACEHOLDER.findall(route.path)
        out += [(route, method, names) for method in sorted(route.methods - {"HEAD", "OPTIONS"})] if names else []
    return out


def test_every_path_placeholder_outside_the_allow_list_is_typed_as_an_id_family(world) -> None:
    """The placeholders and the annotations agree: each placeholder not on the allow-list is a path parameter of the route
    with an id family, and the families the program routes need (program, credential, tenant) are among them (B5)."""
    families: set[str] = set()
    placeholders: set[str] = set()
    for route, _, names in _placeholder_routes(world[0].app):
        annotated = {name: annotation for where, name, annotation in _params(route.dependant) if where == "path"}
        assert set(names) <= set(annotated), (route.path, names, sorted(annotated))
        for name in set(names) - NOT_IDS:
            family = _id_family(annotated[name])
            assert family is not None, f"{route.path}: {{{name}}} is not typed as an id family"
            families.add(family.__name__)
            placeholders.add(name)
    assert {"program_id", "credential_id", "tenant_id", "investigation_id"} <= placeholders, sorted(placeholders)
    assert families >= {"TenantId", "AlertId", "InvestigationId", "LearningJobId", "MembershipId", "UserId", "CredentialId"}, families


@pytest.mark.parametrize("bad", sorted(MALFORMED))
def test_a_malformed_id_in_any_path_placeholder_is_a_422_naming_it(world, bad) -> None:
    """For every route, every placeholder outside the allow-list, set to a malformed id while the others are well-formed: 422
    naming that path parameter. Program and credential routes included: not a 404 that says the id names nothing (B5, #1382 O3)."""
    _, member, admin = world
    swept: set[str] = set()
    for route, method, names in _placeholder_routes(world[0].app):
        for name in sorted(set(names) - NOT_IDS):
            values = {p: (T1 if p == "tenant_id" else GOOD) for p in names}
            values[name] = MALFORMED[bad]
            path = route.path_format.format(**values)
            browser = admin if route.path.startswith("/admin") else member
            response = browser.request(method, path, json={} if method in ("POST", "PUT") else None)
            where = f"{method} {route.path} ({name})"
            assert response.status_code == 422, (where, response.status_code, response.text)
            assert ["path", name] in [e["loc"] for e in response.json()["errors"]], (where, response.text)
            swept.add(name)
    assert {"program_id", "credential_id"} <= swept  # control: the program routes were part of the sweep


def test_well_formed_program_and_credential_ids_that_name_nothing_are_404s(world) -> None:
    """Control: the same routes with well-formed ids that name nothing keep their 404, so the 422 above is the grammar's (O2)."""
    w, member, _ = world
    program = str(create_program(member, T1)["id"])
    issue_key(member, T1, program)
    assert member.get(f"/tenants/{T1}/programs/{GOOD}/credentials").status_code == 404
    assert member.delete(f"/tenants/{T1}/programs/{program}/credentials/{GOOD}").status_code == 404
