"""#1307 contract repair (code-stage attack batch, cross-surface): what every route does for a program as the same caller as a person
(P-F, O2, O8, D9, A5, A6). The inputs are the route census and the permission table, not the routes the attackers happened to try."""
from __future__ import annotations

from typing import Any

import pytest

pytest.importorskip("fastapi")

pytestmark = [
    pytest.mark.filterwarnings("error:coroutine .* was never awaited:RuntimeWarning"),
    pytest.mark.filterwarnings("error::pytest.PytestUnraisableExceptionWarning"),
]

from defender.tests.api.test_programs_1307_roles import (  # noqa: E402
    AUTOMATION,
    PERMISSION_OF,
    TENANT_ROUTES,
    _call,
)
from defender.tests.support.api._identity1306 import ALERT, ANN, T1, user_id  # noqa: E402
from defender.tests.support.api._programs1307 import (  # noqa: E402
    EXPIRY_HEADER,
    Soar,
    issue_oauth,
    parse_time,
    soar,
    start_investigation,
)
from defender.tests.support.api._routes1307a import PATH_ID, app_routes, normal, route_id  # noqa: E402

KINDS = ("key", "oauth_client")
#: Every tenant route the automation role is granted (the permission table of the roles tests, written out there once).
AUTOMATION_ROUTES = [r for r in TENANT_ROUTES if PERMISSION_OF[r] in AUTOMATION]


def _credential_of(s: Soar, kind: str) -> tuple[str, str]:
    """(the bearer value to present, the id of the credential it names) for a credential of `kind`."""
    if kind == "key":
        return s.key, s.key_id
    credential = issue_oauth(s.ann, T1, s.program_id)
    return s.world.realm.issue(credential), credential


def _as_program(s: Soar, kind: str, *, raise_errors: bool = True) -> tuple[Any, str]:
    """(a client authenticated as the program by a credential of `kind`, that credential's id)."""
    value, credential = _credential_of(s, kind)
    return s.world.bearer(value, raise_errors=raise_errors), credential


# --- F9: the audit names the program and the credential on every route ------------------------------------------------

class _Ids:
    def __init__(self, investigation_id: str) -> None:
        self.values = {"tenant_id": T1, "investigation_id": investigation_id, "alert_id": ALERT.alert_id, "key": "report.md"}

    def fill(self, template: str) -> str:
        import re
        return re.sub(r"\{(\w+)(?::\w+)?\}", lambda m: self.values.get(m.group(1), PATH_ID), template)


def _seeded(s: Soar) -> _Ids:
    """An investigation of the tenant's alert, queued, with one artifact: every id an automation route names exists."""
    investigation_id = start_investigation(s.ann, T1, "seed").json()["investigation_id"]
    store = s.world.store
    found = s.world.call(store.get_investigation, T1, investigation_id)
    store.add_investigation(T1, found.model_copy(update={"artifacts": ["report.md"]}))
    return _Ids(investigation_id)


def _route(s: Soar, ids: _Ids, route: tuple[str, str]) -> tuple[str, str]:
    (template,) = [p for m, p in app_routes() if (m, normal(p)) == route]
    return route[0], ids.fill(template)


def _new_events(s: Soar, mark: int) -> list[Any]:
    return s.world.store.audit_events[mark:]


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("route", AUTOMATION_ROUTES, ids=route_id)
def test_every_audit_event_a_program_causes_names_the_program_and_the_credential_it_used(
        route: tuple[str, str], kind: str) -> None:
    """Called as a program, every route the automation role is granted emits the same audited actions a person's call does
    (parity with an admin), and each carries actor = the program and credential = the one used, never none and never the
    program's other credential (O8, D6). Ids in the path name real records, so the handler is reached and its audit runs."""
    s = soar()
    ids = _seeded(s)
    method, path = _route(s, ids, route)
    program, credential = _as_program(s, kind)
    mark = len(s.world.store.audit_events)
    response = program.request(method, path, json=_body(route, ids))
    assert response.status_code < 400 or PATH_ID in path, (route, response.status_code, response.text)  # a learning job has no fixture
    events = _new_events(s, mark)
    for event in events:
        assert (event.user_id, event.credential_id) == (s.program_id, credential), (route, event)
    # parity: the same call by a person is audited the same number of times (a program is not audited less, or more)
    person = soar()
    person_ids = _seeded(person)
    person_method, person_path = _route(person, person_ids, route)
    person_mark = len(person.world.store.audit_events)
    person_response = person.ann.request(person_method, person_path, json=_body(route, person_ids))
    assert person_response.status_code == response.status_code, route
    person_events = _new_events(person, person_mark)
    assert [e.action for e in events] == [e.action for e in person_events], route
    assert all(e.credential_id is None and e.user_id == user_id(person.ann) for e in person_events)


def _body(route: tuple[str, str], ids: _Ids) -> Any:
    from defender.tests.api.test_programs_1307_roles import BODIES
    body = BODIES.get(route)
    return None if body is None else {**body, **({"client_request_id": "from-program"} if "client_request_id" in body else {})}


def test_the_audited_routes_of_the_class_are_the_ones_that_matter() -> None:
    """Control on the sweep above: the class holds more than reads, so a route that drops the credential has something to drop."""
    audited = [r for r in AUTOMATION_ROUTES if r[0] != "GET"]
    assert len(audited) >= 2, audited
    assert any(r[1].endswith("/artifacts/{}") for r in AUTOMATION_ROUTES)  # the artifact read audits though it is a GET


# --- F10: the expiry header on every response after verification, errors included (D9, A6) --------------------------------

class StoreDown(Exception):
    """What the broken store raises: a failure in a route's handler that the API did not foresee."""


def _break_the_store(s: Soar) -> None:
    def down(*args: Any, **kwargs: Any) -> Any:
        raise StoreDown("the store is down")

    store = s.world.store
    for name in dir(store):
        if not name.startswith(("_", "add_")) and name != "audit_events" and callable(getattr(store, name)):
            setattr(store, name, down)


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("route", AUTOMATION_ROUTES, ids=route_id)
def test_a_500_to_a_verified_program_carries_the_expiry_header(route: tuple[str, str], kind: str) -> None:
    """A handler that raises something unforeseen: the server error is a response to a program whose credential verified, so
    it carries the credential's expiry like every other (D9, A6)."""
    s = soar()
    ids = _seeded(s)
    method, path = _route(s, ids, route)
    program, credential = _as_program(s, kind, raise_errors=False)
    expires = {r.id: r for r in s.world.credentials(s.program_id)}[credential].expires_at
    _break_the_store(s)
    response = program.request(method, path, json=_body(route, ids))
    assert response.status_code == 500, (route, response.status_code, response.text)
    assert parse_time(response.headers[EXPIRY_HEADER]) == expires
    assert EXPIRY_HEADER not in s.world.bearer("not-a-key", raise_errors=False).get(f"/tenants/{T1}/alerts").headers  # control


def test_a_500_to_a_person_has_no_expiry_header() -> None:
    """Control: the header is the program's alone (D9)."""
    s = soar()
    person = s.world.sign_in(ANN, browser=s.world.client(raise_errors=False))
    _break_the_store(s)
    response = person.get(f"/tenants/{T1}/alerts")
    assert response.status_code == 500
    assert EXPIRY_HEADER not in response.headers


@pytest.mark.parametrize("kind", KINDS)
def test_the_expiry_header_is_on_a_409_and_on_a_401_after_verification(kind: str) -> None:
    """Statuses the contract's table lacked: cancelling an investigation that already ended (409), and `/me` of a program whose
    tenant stopped being active (401, after the credential verified). Both carry the credential's expiry (D9)."""
    s = soar(failing_writes=True)
    program, credential = _as_program(s, kind)
    expires = {r.id: r for r in s.world.credentials(s.program_id)}[credential].expires_at
    investigation = start_investigation(program, T1).json()["investigation_id"]
    assert program.post(f"/tenants/{T1}/investigations/{investigation}/cancel").status_code == 200
    again = program.post(f"/tenants/{T1}/investigations/{investigation}/cancel")
    assert again.status_code == 409, again.text
    assert parse_time(again.headers[EXPIRY_HEADER]) == expires
    assert parse_time(program.get("/me").headers[EXPIRY_HEADER]) == expires  # control: the 200
    s.world.repo.missing_tenants.add(T1)  # the tenant left `active` (#1214) and the program's membership is still active
    refused = program.get("/me")
    assert refused.status_code == 401, refused.text
    assert parse_time(refused.headers[EXPIRY_HEADER]) == expires


# --- F11: a tenant that is not active ends access for every caller kind (A5, #1214) ----------------------------------------

def test_a_tenant_that_is_not_active_is_404_on_every_tenant_route_for_a_person_and_for_a_program() -> None:
    """The tenant leaves `active` while every membership stays active: a person admin, a program by key and a program by token
    are all told what an unknown tenant is told, on every tenant route, and neither `/me` lists the tenant (A5, O2, P-F)."""
    s = soar(failing_writes=True)
    credential = issue_oauth(s.ann, T1, s.program_id)
    callers = {"person": s.ann, "key": s.program(), "token": s.world.bearer(s.world.realm.issue(credential))}
    for name, caller in callers.items():  # control: before the flip each caller reaches the tenant
        assert caller.get(f"/tenants/{T1}/alerts").status_code == 200, name
        assert T1 in caller.get("/me").text, name
    s.world.repo.missing_tenants.add(T1)
    failures = []
    for name, caller in callers.items():
        for route in TENANT_ROUTES:
            got = _call(caller, route).status_code
            if got != 404:
                failures.append(f"{name} {route_id(route)}: {got}")
        me = caller.get("/me")
        if T1 in me.text:
            failures.append(f"{name} /me lists the tenant: {me.status_code} {me.text}")
    assert failures == []
