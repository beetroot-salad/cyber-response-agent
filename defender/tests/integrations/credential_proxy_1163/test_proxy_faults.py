"""#1163 the proxy's fault table (O7, A9): every outcome is classified, a refused request is
never sent, and a breaker or transport outcome is told apart from a plain refusal."""
from __future__ import annotations

import gzip
import json
import ssl
import tracemalloc
import zlib

import pytest

from defender.tests.integrations.credential_proxy_1163 import _harness as H
from defender.tests.integrations.credential_proxy_1163 import _tenant as T
from defender.tests.integrations.credential_proxy_1163._target import ACCESS_FILE
from defender.tests.support.shared._tls_server import chain, issue, tls_server
from defender.tests.support.tenancy._host1214 import counting_calls

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


#: #1363 O4: the proxy's label in its final record. Wire name `origin` (left to the contract); values
#: `request`, `setup`, `access`, and none for a system's answer.
LABEL_FIELD = "origin"


def _label_of(response) -> object:
    from defender.kit.proxy_client import decode_reply

    return getattr(decode_reply(response.content).final, LABEL_FIELD, "<no such field>")


def test_1363_o4_the_proxy_labels_each_refusal_where_it_raises_it(tmp_path, data_root):
    """No credential set is `setup`, a token that does not grant the system is `request`, an expired
    token `access`; a system's own answer carries no label. #1363 O4."""
    from datetime import timedelta

    with T.rig(tmp_path / "forge", data_root, creds=None) as r:
        no_set = r.post()
        r.store.sets[(r.t.tenant_id, "identity")] = T.static_set()
        ungranted = r.post(grant={("cmdb", "r")})
        expired = r.post(tok=r.tok(expires_in=timedelta(minutes=-1)))
        r.up.replies[PATH] = (404, {}, b"{}")
        answered = r.post()

    assert [_label_of(x) for x in (no_set, ungranted, expired, answered)] == [
        "setup", "request", "access", None]


def _oauth_rig(tmp_path, data_root, token_url, **deps_kw):
    return T.rig(tmp_path / "forge", data_root, lambda u: H.declaration(
        u + BASE, scheme=H.oauth_scheme(token_url)), creds=T.oauth_set(), **deps_kw)


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


def test_f3_a_401_with_a_body_over_the_limit_still_evicts_the_access_token(tmp_path, data_root):
    """The upstream refusing the cached token with a body past the limit is still a `ConfigFault`
    after one send, and the next request exchanges afresh and succeeds. #1412 O8."""
    issued: list[str] = []
    with H.upstream() as auth:
        auth.replies["/token"] = H.token_endpoint(issued)
        with T.rig(tmp_path / "forge", data_root, lambda u: H.declaration(
                u + BASE, scheme=H.oauth_scheme(auth.url + "/token")),
                creds=T.oauth_set(), max_response_bytes=64) as r:
            r.up.replies[PATH] = lambda s: (
                (401, {}, b"x" * 200) if len(r.up.seen) == 1 else (200, {}, b"{}"))
            first = r.ask()
            second = r.ask()

    assert (first["status"], first["fault"], first["body_whole"]) == (401, "ConfigFault", False)
    assert second["fault"] is None
    assert len(auth.seen) == 2
    assert [s.header("Authorization") for s in r.up.seen] == [f"Bearer {a}" for a in issued]


# --- #1375 O2/O3: trust and the token reply's cap, unchanged by building contexts once ----------

@pytest.mark.parametrize("leg", ["upstream", "token exchange"])
def test_1375_o2_a_system_is_trusted_by_the_bundle_not_the_environment(
        tmp_path, data_root, monkeypatch, leg):
    """#1375 O2: the upstream call and the token exchange verify a system's certificate against
    the bundle they always used, never one the environment names: with `SSL_CERT_FILE` naming the
    very CA that signed the system's certificate, the connection is still refused and the server
    gets no request. Control: a client that does trust that CA reaches the server."""
    import ssl

    import httpx

    token_reply = json.dumps({"access_token": "AT", "expires_in": 3600}).encode()
    with tls_server(tmp_path, lambda *_: (200, token_reply)) as server:
        url = f"https://127.0.0.1:{server.port}"
        with httpx.Client(verify=ssl.create_default_context(cafile=str(server.ca)),
                          trust_env=False) as trusting:
            assert trusting.get(url + "/").status_code == 200, "control: the server answers"
        server.got.clear()
        monkeypatch.setenv("SSL_CERT_FILE", str(server.ca))
        monkeypatch.delenv("SSL_CERT_DIR", raising=False)
        if leg == "upstream":
            with T.rig(tmp_path / "forge", data_root, lambda _u: H.declaration(url + BASE)) as r:
                answer = r.ask(url=f"{url}{PATH}")
        else:
            with _oauth_rig(tmp_path, data_root, url + "/token") as r:
                answer = r.ask()
            assert r.up.seen == [], "the API request was sent without a token"

    assert answer["fault"] == "TransportFault", answer
    assert "(ConnectError)" in (answer["detail"] or ""), answer
    assert server.got == [], "the request reached a server the proxy should not trust"


@pytest.mark.parametrize(("size", "fault", "limit"), [
    pytest.param(65536, None, 8 << 20, id="at-the-cap"),
    pytest.param(65537, "ConfigFault", 8 << 20, id="over-the-cap"),
    pytest.param(65536, None, 1024, id="above-a-smaller-reply-limit"),
])
def test_1375_o3_a_token_reply_over_the_cap_is_a_config_fault_unsent(
        tmp_path, data_root, size, fault, limit):
    """#1375 O3: the token endpoint's reply is read up to `TOKEN_REPLY_CAP` (64 KiB): a reply of
    exactly the cap is used, one byte more is `ConfigFault` saying so, and the API request is never
    sent. The cap is its own, not `max_response_bytes` (#1412 O3)."""
    head = json.dumps({"access_token": "AT-cap", "expires_in": 3600, "pad": ""}).encode()
    body = head[:-2] + b"x" * (size - len(head)) + head[-2:]
    assert len(body) == size
    assert json.loads(body)["access_token"] == "AT-cap"
    with H.upstream() as auth:
        auth.replies["/token"] = (200, {"Content-Type": "application/json"}, body)
        with _oauth_rig(tmp_path, data_root, auth.url + "/token", max_response_bytes=limit) as r:
            answer = r.ask()

    assert answer["fault"] == fault, answer
    if fault is None:
        assert r.up.paths() == [PATH]
    else:
        assert "more than 65536 bytes" in answer["detail"], answer
        assert r.up.seen == []


def _accept_encoding(seen: H.Seen) -> str | None:
    return next((v for k, v in seen.headers.items() if k.lower() == "accept-encoding"), None)


_TOKEN = json.dumps({"access_token": "AT-1383", "expires_in": 3600}).encode()


@pytest.mark.parametrize(("encoding", "body", "fault"), [
    pytest.param("identity", b'{"ok": true}', None, id="identity-control"),
    pytest.param("Identity", b'{"ok": true}', None, id="identity-any-case"),
    pytest.param("identity, identity", b'{"ok": true}', None, id="identity-listed-twice"),
    pytest.param("gzip", gzip.compress(b'{"ok": true}'), "UpstreamFault", id="gzip"),
    pytest.param("deflate", zlib.compress(b'{"ok": true}'), "UpstreamFault", id="deflate"),
    pytest.param("identity, gzip", gzip.compress(b'{"ok": true}'), "UpstreamFault",
                 id="gzip-listed-after-identity"),
])
def test_1383_a_compressed_upstream_reply_is_an_upstream_fault(
        tmp_path, data_root, encoding, body, fault):
    """#1383: the proxy asks for an uncompressed reply even when the adapter asks otherwise, and
    a reply compressed anyway is an `UpstreamFault` saying so, however small it decodes to."""
    with T.rig(tmp_path / "forge", data_root) as r:
        r.up.replies[PATH] = (200, {"Content-Type": "application/json",
                                    "Content-Encoding": encoding}, body)
        answer = r.ask(headers={"Accept-Encoding": "gzip, br"})

    assert [_accept_encoding(s) for s in r.up.seen] == ["identity"]
    assert answer["fault"] == fault, answer
    if fault is None:
        assert json.loads(answer["body"]) == {"ok": True}
    else:
        assert "compressed" in answer["detail"], answer
        assert answer["body"] == ""


@pytest.mark.parametrize(("encoding", "body", "fault"), [
    pytest.param(None, _TOKEN, None, id="plain-control"),
    pytest.param("gzip", gzip.compress(_TOKEN), "ConfigFault", id="gzip"),
])
def test_1383_a_compressed_token_reply_is_a_config_fault_unsent(
        tmp_path, data_root, encoding, body, fault):
    """#1383: the token exchange asks for an uncompressed reply; one compressed anyway is
    `ConfigFault` saying so, and the API request is never sent."""
    headers = {"Content-Type": "application/json"} | (
        {} if encoding is None else {"Content-Encoding": encoding})
    with H.upstream() as auth:
        auth.replies["/token"] = (200, headers, body)
        with _oauth_rig(tmp_path, data_root, auth.url + "/token") as r:
            answer = r.ask()

    assert [_accept_encoding(s) for s in auth.seen] == ["identity"]
    assert answer["fault"] == fault, answer
    if fault is None:
        assert r.up.paths() == [PATH]
    else:
        assert "compressed" in answer["detail"], answer
        assert r.up.seen == []


@pytest.mark.parametrize(("status", "fault"), [
    pytest.param(503, "TransportFault", id="503"),
    pytest.param(401, "ConfigFault", id="401"),
    pytest.param(404, "UpstreamFault", id="404"),
])
def test_1383_a_compressed_error_reply_keeps_its_status_fault(tmp_path, data_root, status, fault):
    """#1383 review: a compressed non-2xx reply is classified by its status, as the same reply
    uncompressed is, and keeps its headers; only its body is withheld, and the detail says so."""
    with T.rig(tmp_path / "forge", data_root) as r:
        r.up.replies[PATH] = (status, {"Content-Encoding": "gzip", "Retry-After": "30"},
                              gzip.compress(b"down"))
        answer = r.ask()

    assert answer["fault"] == fault, answer
    assert answer["detail"] == (f"identity answered {status} with a compressed body (gzip), "
                                "withheld"), answer
    assert (answer["body"], answer["headers"].get("retry-after")) == ("", "30"), answer


@pytest.mark.parametrize("status", [204, 304])
def test_1383_a_bodyless_reply_marked_compressed_is_not_refused(tmp_path, data_root, status):
    """#1383 review: a reply with no body has nothing to inflate; its encoding is no fault."""
    with T.rig(tmp_path / "forge", data_root) as r:
        r.up.replies[PATH] = (status, {"Content-Encoding": "gzip", "X-Seen": "yes"}, b"")
        answer = r.ask()

    assert answer["detail"] == (None if status == 204 else f"identity answered {status}"), answer
    assert answer["headers"].get("x-seen") == "yes", answer


@pytest.mark.parametrize(("status", "fault", "said"), [
    pytest.param(503, "TransportFault", "answered 503", id="503"),
    pytest.param(400, "ConfigFault", "refused the exchange (400)", id="400"),
])
def test_1383_a_compressed_token_error_keeps_its_status_fault(
        tmp_path, data_root, status, fault, said):
    """#1383 review: a compressed token-endpoint error is classified by its status (a 5xx is
    still a transport fault), and the API request is never sent."""
    with H.upstream() as auth:
        auth.replies["/token"] = (status, {"Content-Encoding": "gzip"}, gzip.compress(b"{}"))
        with _oauth_rig(tmp_path, data_root, auth.url + "/token") as r:
            answer = r.ask()

    assert answer["fault"] == fault, answer
    assert said in answer["detail"], answer
    assert r.up.seen == []


def test_1383_a_compression_bomb_is_never_inflated(tmp_path, data_root):
    """#1383: the reply is read as raw network bytes, so 128 MiB of zeros sent as ~128 KiB of
    gzip never becomes 128 MiB in the proxy, not even one inflated chunk of it."""
    packer, block = zlib.compressobj(wbits=31), b"\0" * (1 << 20)
    bomb = b"".join(packer.compress(block) for _ in range(128)) + packer.flush()
    with T.rig(tmp_path / "forge", data_root, max_response_bytes=1024) as r:
        r.up.replies[PATH] = (200, {"Content-Encoding": "gzip"}, bomb)
        r.ask()
        tracemalloc.start()
        try:
            answer = r.ask()
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()

    assert answer["fault"] == "UpstreamFault", answer
    assert peak < 16 << 20, f"peak {peak >> 20} MiB while refusing the bomb"


@pytest.mark.parametrize(("status", "fault"), [
    pytest.param(200, "UpstreamFault", id="200"),
    pytest.param(503, "TransportFault", id="503"),
    pytest.param(401, "ConfigFault", id="401"),
])
def test_1383_an_oversized_reply_keeps_its_status_fault_and_headers(
        tmp_path, data_root, status, fault):
    """#1383 review: a body over the cap is withheld like a compressed one: the status still
    decides the fault (a 2xx is the upstream's), and the headers still arrive. Only a 2xx says
    to narrow the query (#1412 O3)."""
    with T.rig(tmp_path / "forge", data_root, max_response_bytes=1024) as r:
        r.up.replies[PATH] = (status, {"Retry-After": "30"}, b"a" * 1025)
        answer = r.ask()

    assert answer["fault"] == fault, answer
    if status == 200:
        assert "more than 1024 bytes" in answer["detail"], answer
        assert "narrow" in answer["detail"], answer
    else:
        assert answer["detail"] == (f"identity answered {status} with more than 1024 bytes, "
                                    "withheld"), answer
    assert (answer["status"], answer["body_whole"]) == (status, False)
    assert (answer["body"], answer["headers"].get("retry-after")) == ("", "30"), answer


def test_1383_an_oversized_token_error_is_a_transport_fault(tmp_path, data_root):
    """#1383 review: a token endpoint's 5xx is a transport fault however large its body."""
    with H.upstream() as auth:
        auth.replies["/token"] = (503, {}, b"x" * (65536 + 1))
        with _oauth_rig(tmp_path, data_root, auth.url + "/token") as r:
            answer = r.ask()

    assert answer["fault"] == "TransportFault", answer
    assert "answered 503" in answer["detail"], answer
    assert r.up.seen == []


# --- #1391 O4: a declaration's `ca` is the only trust for that system's legs ------------------

ACCESS = ACCESS_FILE.format(system="identity")


def _ok(*_: object) -> tuple[int, bytes]:
    return 200, b"{}"


def _ca_rig(tmp_path, data_root, base: str, ca: bytes, *, scheme=None, public_ca=None):
    """A rig whose identity declaration is `base` with `ca` (an OAuth set stored with `scheme`);
    `public_ca` is the proxy's public bundle (default: the shipped one)."""
    return T.rig(tmp_path / "forge", data_root,
                 lambda _u: H.declaration(base, ca=ca, scheme=scheme),
                 **({"creds": T.oauth_set()} if scheme is not None else {}),
                 **({"public_ca_file": public_ca} if public_ca is not None else {}))


def test_1391_o4_a_declared_ca_reaches_its_private_upstream_and_dropping_it_refuses_it(
        tmp_path, data_root):
    """A server under a private root is reached with that root as `ca`; the same declaration
    merged without `ca` is refused unsent (public bundle, no trust left behind). #1391 O4, P4."""
    pki = chain()
    with tls_server(tmp_path, _ok, served=pki.served()) as server:
        base = server.url + BASE
        with _ca_rig(tmp_path, data_root, base, pki.root.cert) as r:
            trusted = r.ask(url=server.url + PATH)
            reached = [p for _, p, _ in server.seen]
            r.t.merge({ACCESS: H.declaration(base)}, "drop the ca")
            r.t.publish()
            dropped = r.ask(url=server.url + PATH)

    assert (trusted["fault"], trusted["status"]) == (None, 200), trusted
    assert reached == [PATH]
    assert dropped["fault"] == "TransportFault", dropped
    assert [p for _, p, _ in server.seen] == [PATH], "the request reached an untrusted server"


def test_1391_o4_a_ca_naming_another_root_refuses_even_what_the_environment_trusts(
        tmp_path, data_root, monkeypatch):
    """`ca` is sole trust: with another root declared, the server is refused unsent although
    `SSL_CERT_FILE` names its signer; the detail names the system. Control: its own CA. #1391 O4, P4."""
    other = issue("another private root", ca=True)
    with tls_server(tmp_path, _ok) as server:
        monkeypatch.setenv("SSL_CERT_FILE", str(server.ca))
        monkeypatch.delenv("SSL_CERT_DIR", raising=False)
        base = server.url + BASE
        with _ca_rig(tmp_path, data_root, base, server.ca.read_bytes()) as r:
            control = r.ask(url=server.url + PATH)
            r.t.merge({ACCESS: H.declaration(base, ca=other.cert)}, "another root")
            r.t.publish()
            refused = r.ask(url=server.url + PATH)

    assert control["fault"] is None, control
    assert refused["fault"] == "TransportFault", refused
    assert (refused["detail"] or "").startswith("identity "), refused
    assert len(server.seen) == 1, "the refused request reached the server"


@pytest.mark.parametrize(("trusted", "fault"), [
    pytest.param("root", None, id="root-control"),
    pytest.param("intermediate", "TransportFault", id="intermediate-only"),
])
def test_1391_o4_the_chain_must_end_at_a_root_in_ca(tmp_path, data_root, trusted, fault):
    """A server presenting leaf+intermediate is reached when `ca` holds the root, refused unsent
    when it holds only the intermediate. The context handed to the leg carries no partial-chain
    flag, whatever Python's own defaults are (the context is not built from them). #1391 O4, F7."""
    import httpx

    pki = chain()
    ca = pki.root.cert if trusted == "root" else pki.intermediate.cert
    with (tls_server(tmp_path, _ok, served=pki.served()) as server,
          _ca_rig(tmp_path, data_root, server.url + BASE, ca) as r,
          counting_calls(client=httpx.AsyncClient.__init__,
                         transport=httpx.AsyncHTTPTransport.__init__) as calls):
        answer = r.ask(url=server.url + PATH)

    assert answer["fault"] == fault, answer
    assert len(server.seen) == (1 if fault is None else 0)
    # httpx takes the context as `verify=` on the client or on its transport: either route counts.
    handed = [c["verify"] for c in calls.locals["client"] + calls.locals["transport"]
              if isinstance(c.get("verify"), ssl.SSLContext)]
    assert handed, "no TLS context was handed to a client or transport: the verify flags cannot be judged"
    assert not [c for c in handed if c.verify_flags & ssl.VERIFY_X509_PARTIAL_CHAIN], (
        "a context handed to the ca leg accepts a partial chain: the verify flags are inherited, "
        "not an exact named set (F7)")


@pytest.mark.parametrize("with_ca", [pytest.param(True, id="ca"), pytest.param(False, id="public")])
def test_1391_o4_no_context_writes_session_keys_where_the_environment_says(
        tmp_path, data_root, monkeypatch, with_ca):
    """`SSLKEYLOGFILE` set when the proxy starts: no context handed to a leg, the `ca` one or the
    public one, writes the session keys there, so the injected credential cannot be read from a
    capture. Python's default context honours that variable; the proxy's are not built from it."""
    import httpx

    monkeypatch.setenv("SSLKEYLOGFILE", str(tmp_path / "keys.log"))
    with (tls_server(tmp_path, _ok) as server,
          _ca_rig(tmp_path, data_root, server.url + BASE,
                  server.ca.read_bytes() if with_ca else None,
                  public_ca=None if with_ca else server.ca) as r,
          counting_calls(client=httpx.AsyncClient.__init__,
                         transport=httpx.AsyncHTTPTransport.__init__) as calls):
        answer = r.ask(url=server.url + PATH)

    assert (answer["fault"], answer["status"]) == (None, 200), answer
    handed = [c["verify"] for c in calls.locals["client"] + calls.locals["transport"]
              if isinstance(c.get("verify"), ssl.SSLContext)]
    assert handed, "no TLS context was handed to a client or transport: the key log cannot be judged"
    assert [c.keylog_filename for c in handed] == [None] * len(handed), (
        "a context handed to a leg writes its session keys to the file the environment names")
    assert not (tmp_path / "keys.log").exists()


def test_1391_o4_ca_adds_nothing_from_the_public_bundle_and_a_system_without_one_keeps_it(
        tmp_path, data_root):
    """With the public bundle holding the server's CA: a `ca` naming another root refuses the
    server unsent, and the same system without `ca` reaches it. #1391 O4, P4, F8."""
    other = issue("another private root", ca=True)
    with tls_server(tmp_path, _ok) as server:
        base = server.url + BASE
        with _ca_rig(tmp_path, data_root, base, other.cert, public_ca=server.ca) as r:
            pinned = r.ask(url=server.url + PATH)
            reached_pinned = len(server.seen)
            r.t.merge({ACCESS: H.declaration(base)}, "drop the ca")
            r.t.publish()
            public = r.ask(url=server.url + PATH)

    assert pinned["fault"] == "TransportFault", pinned
    assert reached_pinned == 0, "the request reached a server only the public bundle trusts"
    assert (public["fault"], public["status"]) == (None, 200), public


def test_1391_o4_the_token_exchange_of_a_declaration_with_ca_trusts_that_ca(tmp_path, data_root):
    """An OAuth declaration with `ca`: the token endpoint and the API under that CA are both
    reached, the API call carrying the exchanged token. #1391 O4."""
    token_reply = json.dumps({"access_token": "AT-1391", "expires_in": 3600}).encode()
    pki = chain()

    def answer(_method: str, path: str, _body: bytes) -> tuple[int, bytes]:
        return (200, token_reply) if path == "/token" else (200, b"{}")

    with (tls_server(tmp_path, answer, served=pki.served()) as server,
          _ca_rig(tmp_path, data_root, server.url + BASE, pki.root.cert,
                  scheme=H.oauth_scheme(server.url + "/token")) as r):
        got = r.ask(url=server.url + PATH)

    assert got["fault"] is None, got
    assert [(m, p) for m, p, _ in server.seen] == [("POST", "/token"), ("GET", PATH)]
    assert server.seen[1][2].get("authorization") == "Bearer AT-1391"


def test_1391_o4_the_token_exchange_of_a_declaration_with_ca_does_not_trust_the_public_bundle(
        tmp_path, data_root):
    """OAuth with a `ca` naming another root: the token endpoint (signed by the public bundle here)
    is refused and the API is never called; the same declaration without `ca` reaches it. #1391 O4, D13."""
    other = issue("another private root", ca=True)
    token_reply = json.dumps({"access_token": "AT-1391", "expires_in": 3600}).encode()
    control_dir = tmp_path / "control"
    control_dir.mkdir()
    with (tls_server(control_dir, lambda *_: (200, token_reply)) as control,
          _ca_rig(control_dir, data_root, control.url + BASE, None,
                  scheme=H.oauth_scheme(control.url + "/token"), public_ca=control.ca) as r):
        reached = r.ask(url=control.url + PATH)
    assert reached["fault"] is None, f"control: without `ca` the bundle's server is refused: {reached}"
    assert [(m, p) for m, p, _ in control.seen] == [("POST", "/token"), ("GET", PATH)]

    with (tls_server(tmp_path, lambda *_: (200, token_reply)) as server,
          _ca_rig(tmp_path, data_root, server.url + BASE, other.cert,
                  scheme=H.oauth_scheme(server.url + "/token"), public_ca=server.ca) as r):
        got = r.ask(url=server.url + PATH)

    assert got["fault"] == "TransportFault", got
    assert server.seen == [], "the token endpoint or the API was reached"
