"""#1163 the proxy's fault table (O7, A9): every outcome is classified, a refused request is
never sent, and a breaker or transport outcome is told apart from a plain refusal."""
from __future__ import annotations

import json

import pytest

from defender.tests.integrations.credential_proxy_1163 import _harness as H
from defender.tests.integrations.credential_proxy_1163 import _tenant as T

BASE = T.BASE_PATH
PATH = f"{BASE}/users/x"


@pytest.mark.parametrize(("status", "headers", "fault"), [
    pytest.param(200, {}, None, id="200-control"),
    pytest.param(404, {}, "UpstreamFault", id="404"),
    pytest.param(400, {}, "UpstreamFault", id="400"),
    pytest.param(403, {}, "UpstreamFault", id="403-is-not-a-breaker"),
    pytest.param(429, {}, "UpstreamFault", id="429"),
    pytest.param(401, {}, "ConfigFault", id="401-with-a-credential"),
    pytest.param(302, {"Location": "/elsewhere"}, "UpstreamFault", id="302"),
    pytest.param(500, {}, "TransportFault", id="500"),
    pytest.param(502, {}, "TransportFault", id="502"),
    pytest.param(503, {}, "TransportFault", id="503"),
])
def test_f1_an_upstream_reply_is_classified(tmp_path, data_root, status, headers, fault):
    """The upstream's status maps to its fault class; 2xx is no fault. O7, A9."""
    with T.rig(tmp_path / "forge", data_root) as r:
        r.up.replies[PATH] = (status, headers, b"{}")
        answer = r.ask()

    assert answer["fault"] == fault, answer
    assert r.up.paths() == [PATH]


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
def test_f1_a_redirect_is_not_followed_and_the_credential_goes_nowhere_else(
        tmp_path, data_root, status):
    """A 3xx is an `UpstreamFault`; its Location, even on another host, is never fetched.
    O2, O7."""
    with H.upstream() as elsewhere, T.rig(tmp_path / "forge", data_root) as r:
        r.up.replies[PATH] = (status, {"Location": f"{elsewhere.url}/landing"}, b"")
        answer = r.ask()

    assert answer["fault"] == "UpstreamFault"
    assert (elsewhere.seen, r.up.paths()) == ([], [PATH])


def test_f1_an_unreachable_upstream_is_a_transport_fault(tmp_path, data_root):
    """Nothing listening at the declared base: `TransportFault`; after a merged change to the
    live upstream the same token is sent. O7, A9."""
    port = H.free_port()
    with T.rig(tmp_path / "forge", data_root,
               lambda u: H.declaration(f"http://127.0.0.1:{port}{BASE}")) as r:
        answer = r.ask(url=f"http://127.0.0.1:{port}{PATH}")
        assert (answer["fault"], r.up.seen) == ("TransportFault", [])
        r.t.merge({"settings/systems/identity/access.yaml": H.declaration(r.up.url + BASE)},
                  "point at the live upstream")
        r.t.publish()
        control = r.ask()

    assert control["fault"] is None
    assert r.up.paths() == [PATH]


@pytest.mark.parametrize(("size", "fault"), [(1024, None), (1025, "UpstreamFault")])
def test_f1_a_response_over_the_cap_is_an_upstream_fault(tmp_path, data_root, size, fault):
    """With a 1024-byte cap, 1024 bytes pass and 1025 are an `UpstreamFault`. O7."""
    with T.rig(tmp_path / "forge", data_root, max_response_bytes=1024) as r:
        r.up.replies[PATH] = (200, {"Content-Type": "text/plain"}, b"a" * size)
        answer = r.ask()

    assert answer["fault"] == fault, answer["fault"]
    if fault is None:
        assert len(answer["body"]) == 1024


def test_f2_no_credential_set_is_a_config_fault_unsent(tmp_path, data_root):
    """A system with a merged declaration and no stored set is refused unsent; after the set
    is written the same token works. O7."""
    with T.rig(tmp_path / "forge", data_root, creds=None) as r:
        refused = r.ask()
        assert (refused["fault"], r.up.seen, r.store.reads) == (
            "ConfigFault", [], [(r.t.tenant_id, "identity")])
        r.store.sets[(r.t.tenant_id, "identity")] = T.static_set()
        control = r.ask()

    assert control["fault"] is None


def test_f2_a_system_without_a_merged_declaration_is_a_config_fault_unsent(
        tmp_path, data_root):
    """`cmdb` is granted but has no http-proxy declaration: refused, no store read. O7."""
    with T.rig(tmp_path / "forge", data_root) as r:
        refused = r.ask(system="cmdb", grant={("cmdb", "r")}, url=f"{r.up.url}{BASE}/hosts")

    assert (refused["fault"], r.up.seen, r.store.reads) == ("ConfigFault", [], [])


def test_f2_a_system_outside_the_token_grant_is_a_config_fault_unsent(tmp_path, data_root):
    """A declared system the token does not grant is refused unsent and unread. O7, A9."""
    with T.rig(tmp_path / "forge", data_root) as r:
        refused = r.ask(grant={("cmdb", "r")})

    assert (refused["fault"], r.up.seen, r.store.reads) == ("ConfigFault", [], [])


def _oauth_rig(tmp_path, data_root, token_url):
    return T.rig(tmp_path / "forge", data_root, lambda u: H.declaration(
        u + BASE, scheme=H.oauth_scheme(token_url)), creds=T.oauth_set())


@pytest.mark.parametrize(("status", "body", "fault"), [
    pytest.param(400, b'{"error":"invalid_client"}', "ConfigFault", id="400"),
    pytest.param(401, b'{"error":"invalid_client"}', "ConfigFault", id="401"),
    pytest.param(500, b"{}", "TransportFault", id="500"),
    pytest.param(503, b"{}", "TransportFault", id="503"),
    pytest.param(200, b"{}", "ConfigFault", id="200-without-access-token"),
    pytest.param(200, b'{"access_token": ""}', "ConfigFault", id="200-empty-access-token"),
    pytest.param(200, b"not json", "ConfigFault", id="200-not-json"),
])
def test_f3_a_failed_oauth_exchange_is_classified_and_nothing_is_sent(
        tmp_path, data_root, status, body, fault):
    """A 4xx or an unusable 200 from the token endpoint is ConfigFault, a 5xx TransportFault;
    one attempt, the API request never sent. O7, A12."""
    with H.upstream() as auth:
        auth.replies["/token"] = (status, {}, body)
        with _oauth_rig(tmp_path, data_root, auth.url + "/token") as r:
            answer = r.ask()

    assert answer["fault"] == fault, answer
    assert (len(auth.seen), r.up.seen) == (1, [])
    assert H.CANARY_SECRET not in json.dumps(answer)


def test_f3_an_unreachable_token_endpoint_is_a_transport_fault_and_nothing_is_sent(
        tmp_path, data_root):
    """A token URL nothing listens at is TransportFault, the API request never sent; control:
    a working token endpoint on the same rig shape sends. O7, A12."""
    issued: list[str] = []
    with _oauth_rig(tmp_path, data_root, f"http://127.0.0.1:{H.free_port()}/token") as r:
        answer = r.ask()
    assert answer["fault"] == "TransportFault", answer
    assert r.up.seen == []

    with H.upstream() as auth:
        auth.replies["/token"] = H.token_endpoint(issued)
        with _oauth_rig(tmp_path / "ok", data_root, auth.url + "/token") as control:
            assert control.ask()["fault"] is None
    assert len(issued) == 1


def test_f3_a_401_on_the_access_token_evicts_it_without_a_retry(tmp_path, data_root):
    """The upstream refusing the cached token is a `ConfigFault` after one exchange and one
    send; the next request exchanges afresh and succeeds. O7, A8."""
    issued: list[str] = []
    with H.upstream() as auth:
        auth.replies["/token"] = H.token_endpoint(issued)
        with T.rig(tmp_path / "forge", data_root, lambda u: H.declaration(
                u + BASE, scheme=H.oauth_scheme(auth.url + "/token")),
                creds=T.oauth_set()) as r:
            r.up.replies[PATH] = lambda s: (
                (401, {}, b'{"detail":"token rejected"}') if len(r.up.seen) == 1
                else (200, {}, b"{}"))
            first = r.ask()
            assert (first["fault"], len(auth.seen), len(r.up.seen)) == ("ConfigFault", 1, 1)
            second = r.ask()

    assert second["fault"] is None
    assert len(auth.seen) == 2
    assert [s.header("Authorization") for s in r.up.seen] == [f"Bearer {a}" for a in issued]
