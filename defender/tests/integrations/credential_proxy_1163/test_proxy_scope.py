"""#1163 the proxy's own checks, at its request boundary: tenant, destination, route and token
bounds. A refused request is never sent and never reads the store."""
from __future__ import annotations

from datetime import timedelta

import pytest
from fastapi.testclient import TestClient

from defender.tests.integrations.credential_proxy_1163 import _harness as H
from defender.tests.integrations.credential_proxy_1163 import _tenant as T
from defender.tests.integrations.credential_proxy_1163._target import proxy
from defender.tests.tenancy.tenant_1108_p4._support import OTHER_TENANT_ID, published_tenant


def _client(deps) -> TestClient:
    return TestClient(proxy().create_app(deps))


def test_s1_another_tenants_system_is_refused_the_same_whether_or_not_it_exists(
        tmp_path, data_root):
    """A's token naming a system only B has is refused before any store read or send, with the
    same answer as before B had that system and its credential. O1."""
    with H.upstream() as up, \
            published_tenant(tmp_path / "a", root=data_root, repo_name="a") as a, \
            published_tenant(tmp_path / "b", root=data_root, tenant_id=OTHER_TENANT_ID,
                             repo_name="b") as b:
        store = H.FakeStore()
        client = _client(T.deps({a.tenant_id: T.exports_of(a), b.tenant_id: T.exports_of(b)},
                                store))
        tok = T.token(a.tenant_id, {("crm", "r")})
        without_b = T.ask(client, tok, "crm", "GET", f"{up.url}/accounts")

        b.merge(H.access_files("crm", H.declaration(up.url + "/")), "B adds crm")
        b.publish()
        store.sets[(b.tenant_id, "crm")] = T.static_set()
        with_b = T.ask(client, tok, "crm", "GET", f"{up.url}/accounts")

    assert with_b["fault"] == "ConfigFault"
    assert with_b == without_b
    assert store.reads == []
    assert up.seen == []


@pytest.mark.parametrize(("url_of", "fault"), [
    pytest.param(lambda up, other: f"{up}/api/users/x", None, id="under-base"),
    pytest.param(lambda up, other: f"{up}/api/../admin", "ConfinementFault", id="dotdot"),
    pytest.param(lambda up, other: f"{up}/api/%2e%2e/admin", "ConfinementFault",
                 id="encoded-dotdot"),
    pytest.param(lambda up, other: f"http://127.0.0.1:{other}/api/users/x", "ConfigFault",
                 id="other-port"),
    pytest.param(lambda up, other: up.replace("http://", "https://") + "/api/users/x",
                 "ConfigFault", id="other-scheme"),
    pytest.param(lambda up, other: up.replace("127.0.0.1", "localhost") + "/api/users/x",
                 "ConfigFault", id="other-host"),
])
def test_s2_a_url_outside_the_declared_bases_is_refused_unsent(
        tmp_path, data_root, url_of, fault):
    """Only URLs under a declared base are sent; `..` is a confinement refusal, another scheme,
    host or port a config refusal. O2, O7."""
    with H.upstream() as up, T.identity_via_proxy(
            tmp_path / "forge", data_root, H.declaration(up.url + "/api/")) as t:
        store = H.FakeStore({(t.tenant_id, "identity"): T.static_set()})
        answer = T.ask(_client(T.deps({t.tenant_id: T.exports_of(t)}, store)),
                       T.token(t.tenant_id, {("identity", "r")}), "identity", "GET",
                       url_of(up.url, H.free_port()))

    assert answer["fault"] == fault, answer
    if fault is None:
        assert (answer["status"], up.paths()) == (200, ["/api/users/x"])
    else:
        assert up.seen == []


READS = (("POST", "/search"),)
WRITES = (("POST", "/tickets/*/comments"),)


@pytest.mark.parametrize(("method", "path", "grant", "fault"), [
    pytest.param("GET", "/users/x", {("identity", "r")}, None, id="get-is-a-read"),
    pytest.param("POST", "/search", {("identity", "r")}, None, id="listed-post-read"),
    pytest.param("POST", "/admin", {("identity", "rw")}, "ConfinementFault", id="unlisted-post"),
    pytest.param("DELETE", "/users/x", {("identity", "rw")}, "ConfinementFault", id="delete"),
    pytest.param("POST", "/tickets/7/comments", {("identity", "r")}, "ConfinementFault",
                 id="write-with-read-grant"),
    pytest.param("POST", "/tickets/7/comments", {("identity", "r"), ("cmdb", "rw")},
                 "ConfinementFault", id="write-grant-on-another-system"),
    pytest.param("POST", "/tickets/7/comments", {("identity", "rw")}, None, id="write-granted"),
])
def test_s3_only_declared_reads_and_granted_writes_are_sent(
        tmp_path, data_root, method, path, grant, fault):
    """GET is a read; another method is a read only if listed; a declared write needs `rw` on
    that system. O3, O7."""
    with H.upstream() as up, T.identity_via_proxy(
            tmp_path / "forge", data_root,
            H.declaration(up.url + "/", reads=READS, writes=WRITES)) as t:
        store = H.FakeStore({(t.tenant_id, "identity"): T.static_set()})
        answer = T.ask(_client(T.deps({t.tenant_id: T.exports_of(t)}, store)),
                       T.token(t.tenant_id, grant), "identity", method, f"{up.url}{path}",
                       body={"q": 1} if method == "POST" else None)

    assert answer["fault"] == fault, answer
    assert [(s.method, s.path) for s in up.seen] == ([] if fault else [(method, path)])


@pytest.mark.parametrize(("verdict", "expires_in", "grant"), [
    pytest.param(True, timedelta(minutes=-1), {("identity", "r")}, id="expired"),
    pytest.param(False, timedelta(hours=1), {("identity", "r")}, id="bad-signature"),
    pytest.param(True, timedelta(hours=1), {("cmdb", "r")}, id="system-not-granted"),
])
def test_s4_a_token_out_of_its_bounds_is_refused_unsent(
        tmp_path, data_root, verdict, expires_in, grant):
    """Expired, unverified, or not granting the system: `ConfigFault`, no store read, nothing
    sent; the same token in bounds is sent. O8, O7."""
    with H.upstream() as up, T.identity_via_proxy(
            tmp_path / "forge", data_root, H.declaration(up.url + "/")) as t:
        store = H.FakeStore({(t.tenant_id, "identity"): T.static_set()})
        verifier = H.FakeVerifier(verdict)
        client = _client(T.deps({t.tenant_id: T.exports_of(t)}, store, verifier=verifier))
        answer = T.ask(client, T.token(t.tenant_id, grant, expires_in=expires_in),
                       "identity", "GET", f"{up.url}/users/x")
        assert (answer["fault"], store.reads, up.seen) == ("ConfigFault", [], [])
        assert len(verifier.calls) == 1

        verifier.verdict = True
        control = T.ask(client, T.token(t.tenant_id, {("identity", "r")}),
                        "identity", "GET", f"{up.url}/users/x")
    assert (control["fault"], control["status"], up.paths()) == (None, 200, ["/users/x"])


def test_s5_a_401_on_a_freshly_issued_oauth_token_is_a_breaker_not_retried(tmp_path, data_root):
    """Probe: the upstream refuses the access token just issued: `ConfigFault`, one exchange,
    one send, no retry. O7."""
    issued: list[str] = []
    with H.upstream() as up:
        up.replies["/oauth/token"] = H.token_endpoint(issued)
        up.replies["/api/x"] = (401, {}, b'{"detail":"token rejected"}')
        decl = H.declaration(up.url + "/api/",
                             scheme=H.oauth_scheme(up.url + "/oauth/token"))
        with T.identity_via_proxy(tmp_path / "forge", data_root, decl) as t:
            store = H.FakeStore({(t.tenant_id, "identity"): proxy().CredentialSet(
                kind="oauth-client-credentials",
                fields={"client_id": H.CLIENT_ID, "client_secret": H.CANARY_SECRET}, version=1)})
            answer = T.ask(_client(T.deps({t.tenant_id: T.exports_of(t)}, store)),
                           T.token(t.tenant_id, {("identity", "r")}), "identity", "GET",
                           f"{up.url}/api/x")

    assert answer["fault"] == "ConfigFault"
    assert up.paths() == ["/oauth/token", "/api/x"]
    assert up.seen[1].headers.get("Authorization") == f"Bearer {issued[0]}"
