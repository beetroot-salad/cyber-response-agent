"""#1307: how a program signs in and where it may act (O1, O2, O9, P-F, P-I) — sketch."""
from __future__ import annotations

import pytest

pytest.importorskip("fastapi")

pytestmark = [
    pytest.mark.filterwarnings("error:coroutine .* was never awaited:RuntimeWarning"),
    pytest.mark.filterwarnings("error::pytest.PytestUnraisableExceptionWarning"),
]

from defender.tests.support.api._identity1306 import (  # noqa: E402
    ANN,
    LAB,
    ME,
    NEW,
    OPS,
    SESSION_COOKIE,
    T1,
    T2,
    UNKNOWN,
    masked,
    user_id,
)
from defender.tests.support.api._programs1307 import (  # noqa: E402
    EXPIRY_HEADER,
    ProgramsWorld,
    create_program,
    issue_key,
    issue_oauth,
    parse_time,
    soar,
    start_investigation,
)


# --- O1: three ways in, one caller ------------------------------------------------------------

def test_a_live_key_of_an_active_program_reaches_its_tenant() -> None:
    """`Authorization: Bearer dfk_…` naming a live key -> the program, in its tenant (O1)."""
    s = soar()
    assert s.key.startswith(f"dfk_{s.key_id}_")
    assert s.program().get(f"/tenants/{T1}/alerts").status_code == 200
    assert s.world.bearer(s.key[:-2] + "xx").get(f"/tenants/{T1}/alerts").status_code == 401


def test_a_programs_realm_token_naming_a_live_oauth_credential_reaches_its_tenant() -> None:
    """A verified JWT whose client id and `sub` name a live OAuth credential -> the program (O1)."""
    s = soar()
    credential = issue_oauth(s.ann, T1, s.program_id)
    assert credential in s.world.realm.clients
    token = s.world.realm.issue(credential)
    assert s.world.bearer(token).get(f"/tenants/{T1}/alerts").status_code == 200
    assert s.world.bearer("eyJ.not-issued.sig").get(f"/tenants/{T1}/alerts").status_code == 401


def test_a_token_whose_sub_is_not_the_recorded_service_account_is_refused() -> None:
    """Client id alone is a name: a token for a recreated client (other `sub`) -> 401 (O1, P-B)."""
    s = soar()
    credential = issue_oauth(s.ann, T1, s.program_id)
    recorded = s.world.realm.clients[credential].service_account_id
    assert s.world.bearer(s.world.realm.forge(credential, recorded)).get(f"/tenants/{T1}/alerts").status_code == 200
    other = "00000000-5a00-4000-8000-999999999999"
    assert s.world.bearer(s.world.realm.forge(credential, other)).get(f"/tenants/{T1}/alerts").status_code == 401


def test_a_cookie_and_an_authorization_header_together_are_refused() -> None:
    """Cookie + `Authorization` -> 401, never resolved by precedence (O1, P-F)."""
    s = soar()
    cookie = s.ann.cookies.get(SESSION_COOKIE)
    assert s.ann.get(f"/tenants/{T1}/alerts").status_code == 200
    both = s.world.bearer(s.key)
    both.cookies.set(SESSION_COOKIE, cookie)
    assert both.get(f"/tenants/{T1}/alerts").status_code == 401
    assert both.get("/me").status_code == 401


def test_a_non_bearer_authorization_scheme_is_refused_even_beside_nothing_else() -> None:
    """`Authorization: Basic …` -> 401; the cookie path is not consulted for it (O1)."""
    s = soar()
    assert s.world.bearer(s.key, scheme="Basic").get(f"/tenants/{T1}/alerts").status_code == 401
    assert s.world.bearer(s.key, scheme="Bearer").get(f"/tenants/{T1}/alerts").status_code == 200


# --- O2: one authorization path ---------------------------------------------------------------

def test_a_program_gets_404_in_another_tenant_alike_an_unknown_tenant() -> None:
    """A program outside its tenant gets the non-member 404 (O2, P-D)."""
    s = soar()
    program = s.program()
    reference = program.get(f"/tenants/{UNKNOWN}/alerts")
    probed = program.get(f"/tenants/{T2}/alerts")
    assert probed.status_code == reference.status_code == 404
    assert masked(probed, T2) == masked(reference, UNKNOWN)


def test_a_program_gets_403_for_a_permission_its_role_lacks() -> None:
    """Membership holds, permission does not -> 403 (O2): automation cannot invite."""
    s = soar()
    assert s.program().post(f"/tenants/{T1}/invitations", json={"email": NEW}).status_code == 403
    assert s.ann.post(f"/tenants/{T1}/invitations", json={"email": NEW}).status_code == 202


def test_a_program_or_credential_id_of_another_tenant_is_404_under_the_path_tenant() -> None:
    """Ids below T must belong to T: another tenant's program, another program's credential -> 404 (O2, A3)."""
    s = soar()
    theirs = str(create_program(s.bob, T2, "B's SOAR")["id"])
    their_key, _ = issue_key(s.bob, T2, theirs)
    assert s.ann.post(f"/tenants/{T1}/programs/{theirs}/credentials",
                      json={"kind": "key", "name": "x"}).status_code == 404
    assert s.ann.get(f"/tenants/{T1}/programs/{theirs}/credentials").status_code == 404
    second = str(create_program(s.ann, T1, "second")["id"])
    assert s.ann.delete(f"/tenants/{T1}/programs/{second}/credentials/{s.key_id}").status_code == 404
    assert s.ann.delete(f"/tenants/{T1}/programs/{theirs}/credentials/{their_key}").status_code == 404
    assert s.program().get(f"/tenants/{T1}/alerts").status_code == 200  # nothing was revoked


def test_a_program_sees_itself_its_tenant_and_its_credential_expiry_at_me() -> None:
    """`/me` for a program: itself, its tenant, the expiry of the credential it used (O2, FC-4)."""
    s = soar()
    response = s.program().get("/me")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["program"]["id"] == s.program_id
    assert body["tenant"]["tenant_id"] == T1
    assert body["credential"]["id"] == s.key_id
    assert parse_time(body["credential"]["expires_at"]) == parse_time(response.headers[EXPIRY_HEADER])


@pytest.mark.parametrize(("method", "path"), [
    pytest.param("post", "/auth/logout", id="sign-out"),
    pytest.param("post", "/invitations/00000000-0000-4000-8000-000000000000/accept", id="accept-invitation"),
    pytest.param("get", "/admin/tenants", id="platform"),
])
def test_person_only_and_platform_routes_refuse_a_program(method: str, path: str) -> None:
    """Outside `/tenants/`: person-only and platform routes -> 403 for a program (O2)."""
    s = soar()
    assert getattr(s.program(), method)(path).status_code == 403


# --- O9: the frontend-origin rule is for cookies ---------------------------------------------

def test_a_bearer_write_without_origin_is_accepted_and_a_cookie_write_without_origin_is_not() -> None:
    """Origin rule applies to cookie requests only (O9)."""
    s = soar()
    assert start_investigation(s.world.bearer(s.key, origin=None), T1).status_code == 201
    no_origin = s.world.client_with_cookie(s.ann.cookies.get(SESSION_COOKIE), origin=None)
    assert start_investigation(no_origin, T1, "r2").status_code == 403


# --- P-I: "member" means a person --------------------------------------------------------------

def test_platform_rescue_still_works_when_only_a_program_remains() -> None:
    """The last person leaves; a program is no member in the people sense, so the rescue invitation goes (P-I)."""
    world = ProgramsWorld(administrators=[OPS], tenants={LAB: [ME]})
    me = world.sign_in(ME)
    program_id = str(create_program(me, LAB)["id"])
    _, key = issue_key(me, LAB, program_id)
    ops = world.sign_in_admin()
    assert ops.post(f"/admin/tenants/{LAB}/invitations", json={"email": NEW}).status_code == 409
    assert me.delete(f"/tenants/{LAB}/members/{user_id(me)}").status_code == 204
    assert world.bearer(key).get(f"/tenants/{LAB}/alerts").status_code == 200
    assert ops.post(f"/admin/tenants/{LAB}/invitations", json={"email": NEW}).status_code == 202


def test_a_program_is_not_listed_or_removable_as_a_member() -> None:
    """Members listing and member removal are about people; a program id there -> absent / 404 (P-I)."""
    s = soar()
    listed = s.ann.get(f"/tenants/{T1}/members").json()["items"]
    assert [m["email"] for m in listed] == [ANN]
    assert s.ann.delete(f"/tenants/{T1}/members/{s.program_id}").status_code == 404
    assert s.program().get(f"/tenants/{T1}/alerts").status_code == 200
