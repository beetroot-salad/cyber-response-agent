"""#1342 r7 R7-2 (attack round, candidate 33): an undeclared query parameter is refused API-wide, by name and exactly.

The rule: a request whose query string names a parameter the matched route does not declare is a 422
problem (`application/problem+json`) with one `errors[]` entry per unknown name, `type: "extra_forbidden"`,
`loc: ["query", <name>]`, before the handler runs. The one exception is `GET /auth/callback` (D-ai).
These cases pin its edges over the identity world (real routes, a real session): spelling, emptiness,
path names, another route's names, duplicates and many names, the routes outside `/tenants/{T}`, and that
a refused identity write changes nothing.

Equivalent today, no case: a parameter declared only by a dependency counts as declared (r7-b/12) — every
dependency of the routes here declares nothing of its own, so no observable request tells the two apart."""
from __future__ import annotations

from typing import Any

import pytest

pytest.importorskip("fastapi")

# A forgotten `world.call` leaves a never-awaited coroutine; pytest reports its RuntimeWarning as an unraisable exception, so both are errors.
pytestmark = [
    pytest.mark.filterwarnings("error:coroutine .* was never awaited:RuntimeWarning"),
    pytest.mark.filterwarnings("error::pytest.PytestUnraisableExceptionWarning"),
]

from defender.tests.support.api._identity1306 import (  # noqa: E402
    ALERT,
    ANN,
    BOB,
    EMPTY,
    NEW,
    NINA,
    OPS,
    T1,
    T2,
    AuditLog,
    World,
    invitation_rows,
    items,
    me,
    tenants_of,
    two_tenants,
    user_id,
)

ALERTS = f"/tenants/{T1}/alerts"


def _refused(response: Any, *names: str) -> None:
    """A 422 problem whose `errors[]` is exactly one `extra_forbidden` entry at `["query", name]` per name (in any order)."""
    assert response.status_code == 422, response.text
    assert response.headers["content-type"] == "application/problem+json"
    entries = sorted((e["type"], tuple(e["loc"])) for e in response.json()["errors"])
    assert entries == sorted(("extra_forbidden", ("query", name)) for name in names), response.text


@pytest.mark.parametrize(("name", "value"), [
    ("Limit", "5"),                                  # case is part of the name
    ("LIMIT", "5"),
    ("limitx", "1"),                                 # a declared name is not a prefix match
    ("lim", "1"),
    ("bogus", ""),                                   # an empty value still names the parameter
    ("fired-after", "2026-09-28T08:00:00Z"),         # a different spelling of a declared name
    ("firedafter", "2026-09-28T08:00:00Z"),
    ("limit[]", "1"),
    ("limit ", "1"),
], ids=repr)
def test_r7_2_a_parameter_that_is_not_a_declared_name_exactly_is_refused_with_its_own_entry(name: str, value: str) -> None:
    """On `GET /alerts` (which declares `limit`, `cursor`, `fired_after`, `fired_before`): a near miss of any kind is refused under its own name. (R7-2)"""
    _, ann, _ = two_tenants()
    _refused(ann.get(ALERTS, params={name: value}), name)


@pytest.mark.parametrize("name", ["alert_id", "tenant_id"])
def test_r7_2_a_path_parameters_name_is_not_a_query_name(name: str) -> None:
    """`GET /tenants/{T}/alerts/{alert_id}?alert_id=x` (and `?tenant_id=...`): the path's names are not query names, so the parameter is refused. (R7-2)"""
    _, ann, _ = two_tenants()
    _refused(ann.get(f"{ALERTS}/{ALERT.alert_id}", params={name: "x"}), name)


@pytest.mark.parametrize(("path", "name", "value"), [
    ("/systems", "alert_id", "al-1"),                # `/systems` declares `cursor` and `limit` only
    ("/systems", "fired_after", "2026-09-28T08:00:00Z"),
    (f"/alerts/{ALERT.alert_id}", "limit", "5"),     # one alert: the list's names are not its own
    ("/lessons", "alert_id", "al-1"),                # another route's filter
    ("/alerts", "alert_id", "al-1"),
    ("/alerts", "investigation_id", "inv-1"),
    ("/investigations", "fired_after", "2026-09-28T08:00:00Z"),
    ("/learning-jobs", "fired_before", "2026-09-28T08:00:00Z"),
    ("/members", "cursor", "x"),
    ("/members", "limit", "5"),
    ("/invitations", "limit", "5"),
])
def test_r7_2_a_name_another_route_declares_is_refused_here(path: str, name: str, value: str) -> None:
    """The declared names are the matched route's own: a name some other route reads is unknown to this one. (R7-2)"""
    _, ann, _ = two_tenants()
    _refused(ann.get(f"/tenants/{T1}{path}", params={name: value}), name)


def test_r7_2_an_admin_list_refuses_a_name_the_tenant_lists_declare() -> None:
    """`GET /admin/tenants?cursor=x`: the admin list declares no query name at all. (R7-2)"""
    world = World(administrators=[OPS], tenants={T1: [ANN]})
    ops = world.sign_in_admin()
    _refused(ops.get("/admin/tenants", params={"cursor": "x"}), "cursor")
    _refused(ops.get("/admin/tenants", params={"limit": "5"}), "limit")


def test_r7_2_a_name_given_twice_has_one_entry() -> None:
    """`?x=1&x=2` names one unknown parameter: exactly one `errors[]` entry. (R7-2)"""
    _, ann, _ = two_tenants()
    _refused(ann.get(f"{ALERTS}?x=1&x=2"), "x")


def test_r7_2_every_one_of_many_unknown_names_has_its_own_entry() -> None:
    """Seven distinct unknown names (and a declared one beside them): seven entries, none dropped, none for the declared name. (R7-2)"""
    _, ann, _ = two_tenants()
    names = [f"unknown{n}" for n in range(7)]
    _refused(ann.get(ALERTS + "?limit=5&" + "&".join(f"{n}=1" for n in names)), *names)


def test_r7_2_control_declared_names_beside_no_unknown_one_are_served() -> None:
    """Control: `GET /alerts?limit=5&fired_after=...` answers 200. (R7-2)"""
    _, ann, _ = two_tenants()
    assert ann.get(ALERTS, params={"limit": "5", "fired_after": "2026-09-28T08:00:00Z"}).status_code == 200


# --- the rule is app-wide: every route but the sign-in callback (D-ai) -------------------------------------

def test_r7_2_a_delete_route_refuses_an_undeclared_parameter() -> None:
    """`DELETE /tenants/{T}/investigations/{id}?x=1` is refused like any other method's request. (R7-2)"""
    _, ann, _ = two_tenants()
    _refused(ann.delete(f"/tenants/{T1}/investigations/inv-1", params={"x": "1"}), "x")


def test_r7_2_sign_in_start_refuses_an_undeclared_parameter() -> None:
    """`GET /auth/login?x=1` is refused (it is not the identity provider's redirect target; only `/auth/callback` is exempt, D-ai). (R7-2, D-ai)"""
    world = World(tenants={T1: [ANN]})
    _refused(world.client().get("/auth/login", params={"x": "1"}), "x")


def test_r7_2_sign_out_refuses_an_undeclared_parameter_and_does_not_sign_out() -> None:
    """`POST /auth/logout?x=1` is refused and the session is still good. (R7-2)"""
    _, ann, _ = two_tenants()
    _refused(ann.post("/auth/logout", params={"x": "1"}), "x")
    assert ann.get("/me").status_code == 200, "a refused logout signed the person out"


def test_r7_2_me_refuses_an_undeclared_parameter() -> None:
    """`GET /me?x=1` is refused. (R7-2)"""
    _, ann, _ = two_tenants()
    _refused(ann.get("/me", params={"x": "1"}), "x")


def test_r7_2_accepting_an_invitation_with_an_undeclared_parameter_is_refused_and_accepts_nothing() -> None:
    """`POST /invitations/{id}/accept?x=1` is refused; the invitation is still open and the person joined nothing. (R7-2)"""
    world, ann, bob = two_tenants()
    world.invite(ann, T1, BOB)
    world.send_pending()
    [open_invitation] = [r for r in me(bob)["invitations"] if r["tenant_id"] == T1]
    _refused(bob.post(f"/invitations/{open_invitation['id']}/accept", params={"x": "1"}), "x")
    assert tenants_of(bob) == {T2}
    assert [r["id"] for r in me(bob)["invitations"]] == [open_invitation["id"]]


def test_r7_2_control_the_callback_alone_accepts_any_query() -> None:
    """Control (D-ai): `GET /auth/callback` with a parameter of the provider's own is not refused for it (the sign-in completes). (R7-2, D-ai)"""
    world = World(tenants={T1: [ANN]})
    browser = world.client()
    response = world.sign_in_response(browser, ANN, extra={"session_state": "s", "iss": "https://idp.example"})
    assert response.status_code == 303, response.text


# --- before the handler runs, on the identity routes -------------------------------------------------------

def test_r7_2_an_invitation_with_an_undeclared_parameter_is_refused_before_anything_is_recorded_or_sent(caplog: Any) -> None:
    """`POST /tenants/{T}/invitations?x=1`: 422, no invitation row, nothing sent, no audit event. (R7-2: before the handler runs)"""
    audit = AuditLog(caplog)
    world, ann, _ = two_tenants()
    mark, rows = audit.mark(), invitation_rows(ann, T1)
    mails = list(world.mail.attempts)

    refused = ann.post(f"/tenants/{T1}/invitations", params={"x": "1"}, json={"email": NEW})

    _refused(refused, "x")
    world.send_pending()
    assert invitation_rows(ann, T1) == rows, "an invitation was recorded for a refused request"
    assert list(world.mail.attempts) == mails, "an invitation was sent for a refused request"
    assert audit.since(mark) == []


def test_r7_2_removing_a_member_with_an_undeclared_parameter_is_refused_and_removes_nobody(caplog: Any) -> None:
    """`DELETE /tenants/{T}/members/{id}?x=1`: 422, the member is still a member, no audit event. (R7-2: before the handler runs)"""
    audit = AuditLog(caplog)
    world, ann, _ = two_tenants()
    nina = world.member(ann, T1, NINA)
    mark = audit.mark()

    refused = ann.delete(f"/tenants/{T1}/members/{user_id(nina)}", params={"x": "1"})

    _refused(refused, "x")
    assert NINA in {m["email"] for m in items(ann.get(f"/tenants/{T1}/members"))}, "the member was removed by a refused request"
    assert tenants_of(nina) == {T1}
    assert audit.since(mark) == []


def test_r7_2_revoking_an_invitation_with_an_undeclared_parameter_is_refused_and_revokes_nothing(caplog: Any) -> None:
    """`DELETE /tenants/{T}/invitations/{id}?x=1`: 422, the invitation stays, no audit event. (R7-2: before the handler runs)"""
    audit = AuditLog(caplog)
    world, ann, _ = two_tenants()
    row = world.invite(ann, T1, NEW).json()["id"]
    rows, mark = invitation_rows(ann, T1), audit.mark()

    refused = ann.delete(f"/tenants/{T1}/invitations/{row}", params={"x": "1"})

    _refused(refused, "x")
    assert invitation_rows(ann, T1) == rows
    assert audit.since(mark) == []


def test_r7_2_an_administrators_invitation_with_an_undeclared_parameter_is_refused_before_anything_is_recorded(caplog: Any) -> None:
    """`POST /admin/tenants/{T}/invitations?x=1`: 422, no membership or invitation made, no audit event. (R7-2: before the handler runs)"""
    audit = AuditLog(caplog)
    world = World(administrators=[OPS], tenants={EMPTY: []})
    ops = world.sign_in_admin()
    mark, held = audit.mark(), world.call(world.repo.memberships_of_tenant, EMPTY)

    refused = ops.post(f"/admin/tenants/{EMPTY}/invitations", params={"x": "1"}, json={"email": NEW})

    _refused(refused, "x")
    assert world.call(world.repo.memberships_of_tenant, EMPTY) == held, "a refused request recorded a membership"
    assert audit.since(mark) == []
