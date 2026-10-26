"""#1306: the browser session — limits, storage, Origin, no Bearer (O6, DC-6)."""
from __future__ import annotations

import datetime as _dt
from collections.abc import Callable
from typing import Any

import pytest

pytest.importorskip("fastapi")

from defender.tests.support.api._identity1306 import OPS as OPS_EMAIL  # noqa: E402
from defender.tests.support.api._identity1306 import (  # noqa: E402
    ANN,
    BOB,
    EMPTY,
    FRONTEND_ORIGIN,
    HOUR,
    NEW,
    NINA,
    SECOND,
    SEVEN_DAYS,
    SESSION_COOKIE,
    T0,
    T1,
    T2,
    World,
    invitation_id,
    invitation_rows,
    items,
    me,
    repo_holds,
    tenants_of,
    two_tenants,
    user_id,
)

MINUTE = _dt.timedelta(minutes=1)


def test_idle_expiry_is_twelve_hours_from_a_last_seen_written_only_when_over_five_minutes_old() -> None:
    """Idle when `now - last_seen > 12h`; a request moves last-seen only if it is over 5 minutes old (O6)."""
    world = World(tenants={T1: [ANN]})
    a, b, c, d, e = (world.sign_in(ANN) for _ in range(5))
    world.clock.now = T0 + 5 * MINUTE
    assert c.get("/me").status_code == 200  # exactly 5 minutes: not written
    world.clock.now = T0 + 5 * MINUTE + SECOND
    assert d.get("/me").status_code == 200  # over 5 minutes: written
    world.clock.now = T0 + 6 * MINUTE
    assert b.get("/me").status_code == 200  # written
    world.clock.now = T0 + 12 * HOUR
    assert e.get("/me").status_code == 200  # exactly 12 hours idle is not over the limit
    world.clock.now = T0 + 12 * HOUR + SECOND
    assert [x.get("/me").status_code for x in (a, c, b, d, e)] == [401, 401, 200, 200, 200]


@pytest.mark.parametrize("limit", ["idle", "absolute"])
def test_an_expired_session_stays_expired_however_often_it_is_sent(limit: str) -> None:
    """A refused request does not revive the session it refused (O6: 12 hours idle, 7 days at most)."""
    world = World(tenants={T1: [ANN]})
    ann = world.sign_in(ANN)
    if limit == "idle":
        world.clock.now = T0 + 12 * HOUR + SECOND
    else:
        for _ in range(28):
            world.clock.advance(6 * HOUR)
            ann.get("/me")
        world.clock.now = T0 + SEVEN_DAYS + SECOND
    assert ann.get("/me").status_code == 401
    world.clock.advance(MINUTE)
    assert ann.get("/me").status_code == 401
    assert ann.get(f"/tenants/{T1}/alerts").status_code == 401


def test_a_session_ends_seven_days_after_sign_in_however_busy() -> None:
    """Absolute 7-day limit (O6)."""
    world = World(tenants={T1: [ANN]})
    ann = world.sign_in(ANN)
    for _ in range(27):
        world.clock.advance(6 * HOUR)
        assert ann.get("/me").status_code == 200
    world.clock.now = T0 + SEVEN_DAYS - SECOND
    assert ann.get("/me").status_code == 200
    world.clock.now = T0 + SEVEN_DAYS + SECOND
    assert ann.get("/me").status_code == 401


def test_the_session_value_is_random_and_only_a_hash_of_it_is_stored() -> None:
    """Random values; neither the repository nor the service keeps a cookie value (O6, DC-8)."""
    world = World(tenants={T1: [ANN, BOB]})
    browsers = [world.sign_in(ANN), world.sign_in(ANN), world.sign_in(BOB), world.sign_in(BOB)]
    values = [b.cookies[SESSION_COOKIE] for b in browsers]
    assert len(set(values)) == len(values)
    assert all(len(v) >= 32 for v in values)
    people = {ANN: user_id(browsers[0]), BOB: user_id(browsers[2])}
    for value in values:  # nothing about the person is in the value, and no two share a stem
        for email, uid in people.items():
            assert uid not in value
            assert email not in value
    assert len({v[:8] for v in values}) == len(values)
    for i, v in enumerate(values):  # random: two values agree in few positions, not a shared clock or host part
        for w in values[i + 1:]:
            same = sum(1 for x, y in zip(v, w, strict=False) if x == y)
            assert same < min(len(v), len(w)) // 2, (v, w)
    assert repo_holds(world.repo, ANN)  # control: the walk reaches what the repository holds
    assert repo_holds(world.service, ANN)  # control: and what the service holds
    assert not any(repo_holds(world.repo, v) or repo_holds(world.service, v) for v in values)
    assert all(b.get("/me").status_code == 200 for b in browsers)


def test_a_bearer_header_is_not_a_session_and_a_401_offers_no_bearer_challenge() -> None:
    """The value works only as the cookie; the refusal does not invite Bearer (O6)."""
    world = World(tenants={T1: [ANN]})
    value = world.sign_in(ANN).cookies[SESSION_COOKIE]
    bearer = world.client()
    refused = bearer.get("/me", headers={"Authorization": f"Bearer {value}"})
    assert refused.status_code == 401
    assert "bearer" not in refused.headers.get("www-authenticate", "").lower()
    for name in ("defender_session", "__Secure-defender_session", "session"):  # DC-6: only the __Host- name
        assert world.client_with_cookie(value, name=name).get("/me").status_code == 401, name
    assert world.client_with_cookie(value).get("/me").status_code == 200


def test_a_session_of_a_user_who_is_not_active_is_not_a_caller() -> None:
    """Each request reads the user: a session row of an `invited` user is 401 (flow 4, P-A)."""
    world = World(tenants={T1: [ANN]})
    world.invite(world.sign_in(ANN), T1, NEW)
    invited = world.repo.user_by_email(NEW)
    assert invited.status == "invited"
    world.repo.add_session("seeded-session-of-an-invited-user-0123", invited.id, now=T0, expires_at=T0 + SEVEN_DAYS)
    assert world.client_with_cookie("seeded-session-of-an-invited-user-0123").get("/me").status_code == 401
    ann = world.repo.user_by_email(ANN)  # control: the same seeding for an active user is a caller
    world.repo.add_session("seeded-session-of-an-active-user-01234", ann.id, now=T0, expires_at=T0 + SEVEN_DAYS)
    assert world.client_with_cookie("seeded-session-of-an-active-user-01234").get("/me").status_code == 200


class _Scene:
    def __init__(self) -> None:
        self.world = World(administrators=[OPS_EMAIL], tenants={T1: [ANN], T2: [BOB]})
        self.world.register(EMPTY)
        self.ann, self.bob = self.world.sign_in(ANN), self.world.sign_in(BOB)
        self.ops = self.world.sign_in_admin(OPS_EMAIL)
        self.nina = self.world.member(self.ann, T1, NINA)
        self.world.invite(self.ann, T1, NEW)
        self.world.invite(self.ann, T1, BOB)
        self.world.send_pending()
        self.revoke_id = invitation_id(self.ann, T1, NEW)
        self.accept_id = me(self.bob)["invitations"][0]["id"]
        self.nina_id = user_id(self.nina)


Op = tuple[str, Callable[[Any, _Scene], Any], int, Callable[[_Scene], bool]]
OPS: dict[str, Op] = {
    "invite": ("ann", lambda c, s: c.post(f"/tenants/{T1}/invitations", json={"email": "zed@z.example"}), 202,
               lambda s: "zed@z.example" not in {r["email"] for r in invitation_rows(s.ann, T1)}),
    "revoke": ("ann", lambda c, s: c.delete(f"/tenants/{T1}/invitations/{s.revoke_id}"), 204,
               lambda s: any(r["id"] == s.revoke_id for r in invitation_rows(s.ann, T1))),
    "remove": ("ann", lambda c, s: c.delete(f"/tenants/{T1}/members/{s.nina_id}"), 204,
               lambda s: NINA in {m["email"] for m in items(s.ann.get(f"/tenants/{T1}/members"))}),
    "accept": ("bob", lambda c, s: c.post(f"/invitations/{s.accept_id}/accept"), 200,
               lambda s: tenants_of(s.bob) == {T2}),
    "logout": ("ann", lambda c, s: c.post("/auth/logout"), 204,
               lambda s: s.ann.get("/me").status_code == 200),
    "admin-invite": ("ops", lambda c, s: c.post(f"/admin/tenants/{EMPTY}/invitations", json={"email": "zed@z.example"}),
                     202, lambda s: not s.world.repo.memberships_of_tenant(EMPTY)),
}


FORGED_ORIGINS = [
    "https://evil.example", FRONTEND_ORIGIN + ".evil.example", "null", None,
    FRONTEND_ORIGIN.replace("https://", "http://"),  # a scheme downgrade is another origin
    "https://evil.example/" + FRONTEND_ORIGIN,  # ends with the configured origin
    FRONTEND_ORIGIN + ":8443",  # another port is another origin
]


@pytest.mark.parametrize("name", sorted(OPS))
@pytest.mark.parametrize("origin", FORGED_ORIGINS)
def test_a_state_changing_request_without_the_frontend_origin_is_refused_and_changes_nothing(
        name: str, origin: str | None) -> None:
    """Missing or foreign Origin -> 403, nothing changes; the right Origin works (O6, incl. logout, accept and the platform route)."""
    scene = _Scene()
    who, request, success, untouched = OPS[name]
    actor = {"ann": scene.ann, "bob": scene.bob, "ops": scene.ops}[who]
    cookie = actor.cookies[SESSION_COOKIE]
    refused = request(scene.world.client_with_cookie(cookie, origin=origin), scene)
    assert refused.status_code == 403
    assert untouched(scene)
    allowed = request(scene.world.client_with_cookie(cookie, origin=FRONTEND_ORIGIN), scene)
    assert allowed.status_code == success


def test_the_origin_is_checked_before_the_session_and_only_for_state_changing_methods() -> None:
    """Check order Origin, session, tenant; GET needs no Origin (O6)."""
    world, _, _ = two_tenants()
    path = f"/tenants/{T1}/invitations"
    assert world.client(origin=None).post(path, json={"email": NEW}).status_code == 403
    assert world.client().post(path, json={"email": NEW}).status_code == 401
    assert world.client(origin=None).get("/me").status_code == 401
    ann = world.sign_in(ANN)
    no_origin = world.client_with_cookie(ann.cookies[SESSION_COOKIE], origin=None)
    assert no_origin.get("/me").status_code == 200
    assert no_origin.post(f"/tenants/{T2}/invitations", json={"email": NEW}).status_code == 403  # not 404
