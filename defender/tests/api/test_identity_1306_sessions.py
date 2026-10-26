"""#1306: the browser session — limits, storage, Origin, no Bearer (O6, DC-6)."""
from __future__ import annotations

import datetime as _dt
from collections.abc import Callable
from typing import Any

import pytest

pytest.importorskip("fastapi")

from defender.tests.support.api._identity1306 import (  # noqa: E402
    ANN,
    BOB,
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
    """The repository never holds the cookie value (O6, DC-8)."""
    world = World(tenants={T1: [ANN]})
    first, second = world.sign_in(ANN), world.sign_in(ANN)
    values = [first.cookies[SESSION_COOKIE], second.cookies[SESSION_COOKIE]]
    assert values[0] != values[1]
    assert all(len(v) >= 32 for v in values)
    assert repo_holds(world.repo, ANN)  # control: the walk reaches what the repository holds
    assert not any(repo_holds(world.repo, v) for v in values)
    assert first.get("/me").status_code == second.get("/me").status_code == 200


def test_a_bearer_header_is_not_a_session_and_a_401_offers_no_bearer_challenge() -> None:
    """The value works only as the cookie; the refusal does not invite Bearer (O6)."""
    world = World(tenants={T1: [ANN]})
    value = world.sign_in(ANN).cookies[SESSION_COOKIE]
    bearer = world.client()
    refused = bearer.get("/me", headers={"Authorization": f"Bearer {value}"})
    assert refused.status_code == 401
    assert "bearer" not in refused.headers.get("www-authenticate", "").lower()
    assert world.client_with_cookie(value).get("/me").status_code == 200


class _Scene:
    def __init__(self) -> None:
        self.world, self.ann, self.bob = two_tenants()
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
}


@pytest.mark.parametrize("name", sorted(OPS))
@pytest.mark.parametrize("origin", ["https://evil.example", FRONTEND_ORIGIN + ".evil.example", "null", None])
def test_a_state_changing_request_without_the_frontend_origin_is_refused_and_changes_nothing(
        name: str, origin: str | None) -> None:
    """Missing or foreign Origin -> 403, nothing changes; the right Origin works (O6, incl. logout and accept)."""
    scene = _Scene()
    who, request, success, untouched = OPS[name]
    actor = scene.ann if who == "ann" else scene.bob
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
