# ruff: noqa: PT018 — each compound assert states one fact about one answer
"""#1161 B8 machinery self-test: the provider's front channel and `FakeKeycloak`'s code grant, with no code under test."""
from __future__ import annotations

import base64
import hashlib
import threading
import urllib.parse

import httpx
import pytest

from defender.tests.support.api._server1083 import FakeKeycloak, SIGNIN_CLIENT, SIGNIN_REALM, BACK
from defender.tests.support.api._signin1161 import AUTH_PATH, Choice, FrontChannel

VERIFIER = "v" * 43
CHALLENGE = base64.urlsafe_b64encode(hashlib.sha256(VERIFIER.encode()).digest()).rstrip(b"=").decode()
CALLBACK = "http://localhost:4000/api/auth/callback"


def _authorize(front: FrontChannel, state: str = "S1", **override: str) -> str:
    query = {"response_type": "code", "client_id": "defender-api", "redirect_uri": CALLBACK, "scope": "openid profile",
             "state": state, "nonce": "N1", "prompt": "login", "code_challenge": CHALLENGE,
             "code_challenge_method": "S256", **override}
    return f"{front.origin}{AUTH_PATH}?{urllib.parse.urlencode(query)}"


def _follow(url: str) -> dict[str, list[str]]:
    r = httpx.get(url, follow_redirects=False, timeout=10)
    assert r.status_code == 302, r.status_code
    location = urllib.parse.urlsplit(r.headers["location"])
    assert f"{location.scheme}://{location.netloc}{location.path}" == CALLBACK
    return urllib.parse.parse_qs(location.query)


def _exchange(keycloak: FakeKeycloak, code: str, verifier: str = VERIFIER) -> httpx.Response:
    import anyio

    async def go() -> httpx.Response:
        async with httpx.AsyncClient(transport=keycloak) as client:
            return await client.post(f"{BACK}/realms/{SIGNIN_REALM}/protocol/openid-connect/token", auth=SIGNIN_CLIENT,
                                     data={"grant_type": "authorization_code", "code": code, "code_verifier": verifier,
                                           "redirect_uri": CALLBACK})
    return anyio.run(go)


@pytest.fixture
def front():
    f = FrontChannel()
    f.sign_in_as("acct-1", amr=("pwd",))
    yield f
    f.close()


def test_the_success_redirect_has_c42s_parameters_in_c42s_order_and_its_code_exchanges_once(front):
    """State echoed, `session_state`, `iss`, `code`; the code exchanges for an ID token once (C42, B8)."""
    q = _follow(_authorize(front))
    assert list(q) == ["state", "session_state", "iss", "code"] and q["state"] == ["S1"]
    assert q["iss"] == [f"{front.origin}/realms/{SIGNIN_REALM}"]
    keycloak = FakeKeycloak(front=front.origin)
    first = _exchange(keycloak, q["code"][0])
    assert first.status_code == 200 and "id_token" in first.json()
    again = _exchange(keycloak, q["code"][0])
    assert (again.status_code, again.json()) == (400, {"error": "invalid_grant", "error_description": "Code not valid"})


def test_the_error_redirect_has_c42s_parameters_in_c42s_order(front):
    """`error`, optional `error_description`, `state`, `iss` (C42)."""
    front.queue(Choice(error="invalid_request", error_description="Missing parameter: x"), Choice(error="access_denied"))
    assert list(_follow(_authorize(front))) == ["error", "error_description", "state", "iss"]
    assert list(_follow(_authorize(front))) == ["error", "state", "iss"]


def test_a_request_the_provider_would_refuse_is_answered_with_its_observed_error(front):
    """Unsupported response_type and a missing PKCE method are the observed error redirects (Q4b)."""
    assert _follow(_authorize(front, response_type="bogus"))["error"] == ["unsupported_response_type"]
    url = _authorize(front).replace("&code_challenge_method=S256", "")
    assert _follow(url)["error_description"] == ["Missing parameter: code_challenge_method"]


def test_each_code_binds_its_requests_challenge_and_redirect_and_the_wrong_verifier_burns_it(front):
    """The exchange verifies the binding from the code alone (B8)."""
    keycloak = FakeKeycloak(front=front.origin)
    code = _follow(_authorize(front))["code"][0]
    wrong = _exchange(keycloak, code, verifier="w" * 43)
    assert wrong.json()["error_description"] == "PKCE verification failed: Code mismatch"
    assert _exchange(keycloak, code).json()["error_description"] == "Code not valid"
    assert _exchange(keycloak, "not-a-code").status_code == 400


def test_a_codes_fault_is_honoured_by_the_exchange(front):
    """`invalid_grant` "Code not valid", or a refused connection for `unavailable` (B8)."""
    keycloak = FakeKeycloak(front=front.origin)
    front.queue(Choice(account="a", fault="invalid_grant"), Choice(account="a", fault="unavailable"))
    assert _exchange(keycloak, _follow(_authorize(front))["code"][0]).json()["error_description"] == "Code not valid"
    with pytest.raises(httpx.ConnectError):
        _exchange(keycloak, _follow(_authorize(front))["code"][0])


def test_held_requests_are_released_in_any_order_each_with_its_own_choice(front):
    """Parked unanswered until released; the account is bound at release (B8: two tabs, both orders)."""
    front.hold = True
    answers: dict[int, dict[str, list[str]]] = {}

    def go(i: int) -> None:
        answers[i] = _follow(_authorize(front, state=f"S{i}"))

    threads = [threading.Thread(target=go, args=(i,)) for i in (0, 1)]
    threads[0].start()
    front.wait_held(1)
    threads[1].start()
    front.wait_held(2)
    assert answers == {}
    by_state = {r.query["state"]: r.index for r in front.seen}
    front.release(by_state["S1"], Choice(account="second"))
    threads[1].join(10)
    assert set(answers) == {1} and threads[0].is_alive()
    front.release(by_state["S0"], Choice(account="first"))
    threads[0].join(10)
    keycloak = FakeKeycloak(front=front.origin)
    for i, account in ((0, "first"), (1, "second")):
        token = _exchange(keycloak, answers[i]["code"][0]).json()["id_token"]
        import jwt
        assert jwt.decode(token, options={"verify_signature": False})["sub"] == account


def test_the_form_mode_serves_a_committed_page_that_continues_to_the_redirect(front):
    """`go_back()` needs a committed authorize page (probe, advisor point 3): a 200 whose button continues (B8)."""
    front.form = True
    page = httpx.get(_authorize(front), timeout=10)
    assert page.status_code == 200 and "<button" in page.text
    assert urllib.parse.urlsplit(front.complete(0)).path == "/api/auth/callback"
    r = httpx.get(f"{front.origin}/continue?i=0", follow_redirects=False)
    assert r.status_code == 302 and r.headers["location"].startswith(CALLBACK)


def test_a_front_channel_fault_is_raised_at_close_not_swallowed():
    """No default choice: the browser would hang; the test fails at close (B8 machinery)."""
    f = FrontChannel()
    assert httpx.get(_authorize(f), timeout=10).status_code == 500
    with pytest.raises(AssertionError, match="no Choice"):
        f.close()
