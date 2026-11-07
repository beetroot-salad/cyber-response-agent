"""#1307 live: the Keycloak facts the design rests on (C21, C22, C26, C27, listing pages, secret read-back), against the
dev compose Keycloak with realm `defender-programs` imported (`live`; CI skips it, `-m "not live and not gate"`).

CANNOT RUN YET: the programs realm export (`.devcontainer/keycloak/realm-defender-programs.json`) and its compose mount are
committed by the code stage (the offline checks in `test_1307_programs_realm_export.py` are red until then). Owner: code stage
runs this file once the compose imports the realm, and records the answers (a failure here is the probe answering).

Inputs (test-only environment; the tests skip cleanly when the first two are unset):

    DEFENDER_LIVE_KEYCLOAK_URL             base URL, e.g. http://keycloak:8080 (from the dev container)
    DEFENDER_LIVE_PROGRAMS_ADMIN_SECRET    the dev secret of the API's programs-realm admin client in the export
    DEFENDER_LIVE_PROGRAMS_REALM           default defender-programs
    DEFENDER_LIVE_PROGRAMS_ADMIN_CLIENT    default defender-api-programs-admin
    DEFENDER_LIVE_PROGRAMS_AUDIENCE        default defender-api-programs

    PYTHONPATH="$PWD" defender/.venv/bin/python -m pytest -m live defender/tests/identity/test_1307_keycloak_live.py

Every client a test creates is deleted afterwards; the realm is otherwise left as found.
"""
from __future__ import annotations

import base64
import json
import os
import uuid
from collections.abc import Iterator

import httpx
import pytest

pytestmark = pytest.mark.live

URL = os.environ.get("DEFENDER_LIVE_KEYCLOAK_URL", "").rstrip("/")
ADMIN_SECRET = os.environ.get("DEFENDER_LIVE_PROGRAMS_ADMIN_SECRET", "")
REALM = os.environ.get("DEFENDER_LIVE_PROGRAMS_REALM", "defender-programs")
ADMIN_CLIENT = os.environ.get("DEFENDER_LIVE_PROGRAMS_ADMIN_CLIENT", "defender-api-programs-admin")
AUDIENCE = os.environ.get("DEFENDER_LIVE_PROGRAMS_AUDIENCE", "defender-api-programs")
PEOPLE_REALM = "defender"
LIFESPAN = 300


@pytest.fixture(scope="module")
def kc() -> Iterator[httpx.Client]:
    if not (URL and ADMIN_SECRET):
        pytest.skip("DEFENDER_LIVE_KEYCLOAK_URL and DEFENDER_LIVE_PROGRAMS_ADMIN_SECRET are not set (no live Keycloak)")
    with httpx.Client(base_url=URL, timeout=10) as client:
        try:
            client.get(f"/realms/{REALM}/.well-known/openid-configuration").raise_for_status()
        except httpx.TransportError:
            pytest.skip(f"no Keycloak answers at {URL}")
        yield client


def _token_url(realm: str = REALM) -> str:
    return f"/realms/{realm}/protocol/openid-connect/token"


def _grant(kc: httpx.Client, client_id: str, secret: str, realm: str = REALM) -> httpx.Response:
    return kc.post(_token_url(realm), data={"grant_type": "client_credentials", "client_id": client_id, "client_secret": secret})


def _claims(token: str) -> dict:
    body = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))


@pytest.fixture
def admin(kc: httpx.Client) -> httpx.Client:
    """The API's own programs-realm admin client, as the adapter will use it."""
    response = _grant(kc, ADMIN_CLIENT, ADMIN_SECRET)
    assert response.status_code == 200, response.text
    kc.headers["Authorization"] = f"Bearer {response.json()['access_token']}"
    yield kc
    kc.headers.pop("Authorization", None)


@pytest.fixture
def made(admin: httpx.Client) -> Iterator[list[str]]:
    ids: list[str] = []
    yield ids
    for client_id in ids:
        admin.delete(f"/admin/realms/{REALM}/clients/{client_id}")


def _body(client_id: str, *, audience: bool, lifespan: int = LIFESPAN) -> dict:
    mappers = [{"name": "audience", "protocol": "openid-connect", "protocolMapper": "oidc-audience-mapper",
                "config": {"included.custom.audience": AUDIENCE, "access.token.claim": "true", "id.token.claim": "false"}}]
    return {"id": client_id, "clientId": client_id, "enabled": True, "publicClient": False, "serviceAccountsEnabled": True,
            "standardFlowEnabled": False, "implicitFlowEnabled": False, "directAccessGrantsEnabled": False,
            "attributes": {"access.token.lifespan": str(lifespan)}, "protocolMappers": mappers if audience else []}


def _create(admin: httpx.Client, made: list[str], *, audience: bool = True) -> str:
    client_id = str(uuid.uuid4())
    response = admin.post(f"/admin/realms/{REALM}/clients", json=_body(client_id, audience=audience))
    assert response.status_code == 201, response.text
    made.append(client_id)
    return client_id


def _secret(admin: httpx.Client, client_id: str) -> str:
    response = admin.get(f"/admin/realms/{REALM}/clients/{client_id}/client-secret")
    assert response.status_code == 200, response.text
    return str(response.json()["value"])


def test_c27_a_uuid_client_id_with_our_internal_id_is_accepted_and_a_duplicate_is_refused(admin, made) -> None:
    """The caller may choose both the client id and the internal id; a second client under the same client id is 409 (C27)."""
    client_id = _create(admin, made)
    fetched = admin.get(f"/admin/realms/{REALM}/clients/{client_id}")
    assert fetched.status_code == 200
    assert (fetched.json()["id"], fetched.json()["clientId"]) == (client_id, client_id)
    again = admin.post(f"/admin/realms/{REALM}/clients", json={**_body(client_id, audience=True), "id": str(uuid.uuid4())})
    assert again.status_code == 409


def test_c21_client_credentials_gives_a_five_minute_bearer_token_naming_the_client_and_its_service_account(admin, made) -> None:
    """azp = client id, sub = the service-account user (stable across tokens), typ Bearer, 300 s, no refresh token (C21, C23)."""
    client_id = _create(admin, made)
    secret = _secret(admin, client_id)
    account = admin.get(f"/admin/realms/{REALM}/clients/{client_id}/service-account-user")
    assert account.status_code == 200, account.text
    first, second = _grant(admin, client_id, secret), _grant(admin, client_id, secret)
    assert first.status_code == second.status_code == 200, first.text
    assert "refresh_token" not in first.json()
    claims = _claims(first.json()["access_token"])
    assert (claims["azp"], claims["typ"], claims["sub"]) == (client_id, "Bearer", account.json()["id"])
    assert claims["exp"] - claims["iat"] == LIFESPAN
    assert claims["iss"].endswith(f"/realms/{REALM}")
    assert _claims(second.json()["access_token"])["sub"] == claims["sub"]


def test_c22_the_audience_mapper_adds_the_programs_audience_and_a_client_without_it_lacks_it(admin, made) -> None:
    """With the mapper the token's `aud` has the programs audience; without it (control, same realm) it does not (C22)."""
    mapped, bare = _create(admin, made), _create(admin, made, audience=False)
    for client_id, expected in ((mapped, True), (bare, False)):
        response = _grant(admin, client_id, _secret(admin, client_id))
        assert response.status_code == 200, response.text
        aud = _claims(response.json()["access_token"]).get("aud", [])
        assert (AUDIENCE in ([aud] if isinstance(aud, str) else aud)) is expected, aud


def test_the_clients_secret_can_be_read_back_and_is_the_one_that_signs_in(admin, made) -> None:
    """`GET .../client-secret` returns the generated secret, and the token endpoint accepts it and refuses another (create step 3)."""
    client_id = _create(admin, made)
    secret = _secret(admin, client_id)
    assert secret
    assert _grant(admin, client_id, secret).status_code == 200
    assert _grant(admin, client_id, secret + "x").status_code == 401


def test_the_client_list_without_a_page_size_is_cut_short_and_pages_reach_every_client(admin, made) -> None:
    """The adapter must page: with more than 100 clients an unpaged list is incomplete, `first`/`max` pages cover all (listing)."""
    for _ in range(105):
        _create(admin, made, audience=False)
    everything: list[str] = []
    first = 0
    while True:
        page = admin.get(f"/admin/realms/{REALM}/clients", params={"first": first, "max": 50}).json()
        everything += [c["clientId"] for c in page]
        if len(page) < 50:
            break
        first += 50
    assert set(made) <= set(everything)
    assert len(everything) == len(set(everything))
    unpaged = admin.get(f"/admin/realms/{REALM}/clients").json()
    assert len(unpaged) < len(everything)


def test_c26_the_programs_admin_client_manages_clients_here_and_has_no_rights_in_master_or_the_people_realm(admin) -> None:
    """Its token lists this realm's clients; the same token is refused (401/403) by `master` and by the people realm (C26)."""
    assert admin.get(f"/admin/realms/{REALM}/clients", params={"max": 5}).status_code == 200
    for realm in ("master", PEOPLE_REALM):
        for path in ("clients", "users"):
            status = admin.get(f"/admin/realms/{realm}/{path}", params={"max": 1}).status_code
            assert status in (401, 403), (realm, path, status)
    assert admin.get(f"/admin/realms/{REALM}/users", params={"max": 1}).status_code in (401, 403)  # manage-clients, not users
