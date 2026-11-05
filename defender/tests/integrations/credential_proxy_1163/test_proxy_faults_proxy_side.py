"""#1163 repair (proxy side): the response cap holds for bodies with no honest Content-Length,
and a request the proxy cannot process is still classified and audited (O7, A9)."""
from __future__ import annotations

import contextlib
import gzip
import http.server
import json
import random
import socket
import threading
import time
import uuid
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient

from defender.tests.integrations.credential_proxy_1163 import _harness as H
from defender.tests.integrations.credential_proxy_1163 import _stream1412 as W
from defender.tests.integrations.credential_proxy_1163 import _tenant as T
from defender.kit.faults import ConfigFault
from defender.configuration.issuer import DEPLOYMENT_ISSUER
from defender.kit.faults import AdapterFault, TransportFault
from defender.tests.tenancy.tenant_1108_p4.test_r6_issuer import tls_issuer  # noqa: F401 — fixture
from defender.tests.integrations.credential_proxy_1163._target import (
    PROXY_PATH,
    REMOVED_CONFIG_KEYS,
    app_from_config,
    transit_verifier,
)

BASE = T.BASE_PATH
PATH = f"{BASE}/users/x"
CAP = 1024


@contextlib.contextmanager
def _chunked_upstream(chunks: list[bytes], pause: float = 0.0):
    """A loopback HTTP/1.1 server answering every GET with `chunks` as a chunked body and no
    Content-Length, `pause` seconds apart. Yields its base URL."""
    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self) -> None:  # noqa: N802 — http.server's dispatch name
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            for chunk in chunks:
                self.wfile.write(f"{len(chunk):x}\r\n".encode() + chunk + b"\r\n")
                self.wfile.flush()
                time.sleep(pause)
            self.wfile.write(b"0\r\n\r\n")

        def log_message(self, *_) -> None:
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()


def _pieces(sizes: list[int]) -> list[bytes]:
    """Chunks of the given sizes, each filled with its own letter so a prefix is recognisable."""
    return [bytes([97 + i % 26]) * size for i, size in enumerate(sizes)]


@pytest.mark.parametrize(("sizes", "over"), [
    pytest.param([CAP], False, id="one-chunk-at-the-limit"),
    pytest.param([512, 512], False, id="two-chunks-at-the-limit"),
    pytest.param([1, CAP - 1], False, id="small-then-large-at-the-limit"),
    pytest.param([CAP - 1, 1], False, id="large-then-one-at-the-limit"),
    pytest.param([400, 400, 224], False, id="three-chunks-at-the-limit"),
    pytest.param([CAP + 1], True, id="one-chunk-over"),
    pytest.param([CAP, 1], True, id="limit-then-one"),
    pytest.param([CAP - 1, 2], True, id="chunk-crossing-the-limit"),
    pytest.param([600, 600], True, id="two-chunks-crossing-the-limit"),
    pytest.param([400] * 20, True, id="many-small-over"),
])
def test_f1_a_chunked_reply_is_whole_at_the_limit_and_withheld_past_it(
        tmp_path, data_root, sizes, over):
    """At the limit a chunked reply (no Content-Length) is complete; one byte past, nothing past the
    limit is forwarded, a chunk crossing it not at all, the status stands, `UpstreamFault` says to
    narrow the query. #1412 O3."""
    chunks = _pieces(sizes)
    with _chunked_upstream(chunks, pause=0.02) as base, T.rig(
            tmp_path / "forge", data_root, lambda _u: H.declaration(base + BASE),
            max_response_bytes=CAP) as r:
        forwarded, final = W.decoded(r.post(url=f"{base}{PATH}").content)

    sent = b"".join(chunks)
    assert final["status"] == 200
    if over:
        assert (final["fault"], final["body_whole"]) == ("UpstreamFault", False)
        assert "narrow" in final["detail"]
        whole_chunks = {sum(sizes[:k]) for k in range(len(sizes) + 1) if sum(sizes[:k]) <= CAP}
        assert len(forwarded) in whole_chunks, f"{len(forwarded)} bytes is not a run of whole chunks"
        assert sent.startswith(forwarded)
    else:
        assert (final["fault"], final["body_whole"], forwarded) == (None, True, sent)


@pytest.mark.parametrize(("declared", "sends", "whole"), [
    pytest.param(CAP, CAP, True, id="declared-at-the-limit"),
    pytest.param(CAP + 1, 1, False, id="declared-one-over"),
    pytest.param(CAP * 2, 1, False, id="declared-double"),
])
def test_o3_a_declared_size_over_the_limit_forwards_nothing_and_stops_at_its_first_byte(
        tmp_path, data_root, declared, sends, whole):
    """A reply declaring more than the limit is hung up on at its first body byte (this upstream
    sends no other) and forwards nothing; one declaring exactly the limit is whole. #1412 O3."""
    def script(conn: socket.socket) -> None:
        conn.sendall(W.head(200, declared) + b"a" * sends)

    with W.scripted(script) as up, T.rig(
            tmp_path / "forge", data_root, lambda _u: H.declaration(up.url + BASE),
            max_response_bytes=CAP) as r:
        forwarded, final = W.decoded(r.post(url=f"{up.url}{PATH}", timeout_sec=5).content)
        hung_up = up.hung_up.wait(2)

    assert final["status"] == 200
    if whole:
        assert (final["fault"], final["body_whole"], forwarded) == (None, True, b"a" * CAP)
    else:
        assert (forwarded, final["fault"], final["body_whole"]) == (b"", "UpstreamFault", False)
        assert "narrow" in final["detail"]
        assert hung_up, "the proxy kept the upstream connection after the first body byte"


@pytest.mark.parametrize(("method", "status", "reason", "fault"), [
    pytest.param("HEAD", 200, "OK", None, id="head"),
    pytest.param("GET", 304, "Not Modified", "UpstreamFault", id="not-modified"),
])
def test_o3_a_reply_with_no_body_declaring_an_oversize_has_nothing_to_withhold(
        tmp_path, data_root, method, status, reason, fault):
    """HEAD and 304 declaring more than the limit: status and headers stand, an empty body counts
    as whole, and no over-limit fault. #1412 O3."""
    def script(conn: socket.socket) -> None:
        conn.sendall(W.head(status, CAP * 2, reason, b"X-Kept: yes\r\n"))

    with W.scripted(script) as up, T.rig(
            tmp_path / "forge", data_root, lambda _u: H.declaration(up.url + BASE),
            max_response_bytes=CAP) as r:
        answer = r.ask(method, url=f"{up.url}{PATH}", timeout_sec=5)

    assert (answer["status"], answer["fault"], answer["body"], answer["body_whole"]) == (
        status, fault, "", True)
    assert answer["headers"]["x-kept"] == "yes"
    assert "narrow" not in (answer["detail"] or "")


@pytest.mark.parametrize("size", [1, CAP, CAP + 1, 50_000])
def test_f1_a_compressed_response_is_refused_whatever_it_expands_to(tmp_path, data_root, size):
    """A gzip reply is an `UpstreamFault` saying so, whether it would expand within the cap or
    past it: the proxy asks for none and never inflates one (#1383). O7."""
    with T.rig(tmp_path / "forge", data_root, max_response_bytes=CAP) as r:
        r.up.replies[PATH] = (200, {"Content-Type": "text/plain", "Content-Encoding": "gzip"},
                              gzip.compress(b"a" * size))
        answer = r.ask()

    assert answer["fault"] == "UpstreamFault", answer
    assert "compressed body (gzip)" in answer["detail"], answer
    assert answer["body"] == ""
    assert "narrow" not in answer["detail"], "compressed is checked before the limit"


def test_f1_a_compressed_reply_over_the_limit_is_refused_as_compressed_not_as_too_large(
        tmp_path, data_root):
    """A gzip body that is itself over the limit, declared as such, is the compressed refusal:
    the compressed check comes first and does not say to narrow. #1412 O3, O8."""
    packed = gzip.compress(random.Random(1412).randbytes(3 * CAP))
    with T.rig(tmp_path / "forge", data_root, max_response_bytes=CAP) as r:
        r.up.replies[PATH] = (200, {"Content-Type": "text/plain", "Content-Encoding": "gzip"}, packed)
        answer = r.ask()

    assert len(packed) > CAP, "the fixture is over the limit as sent"
    assert (answer["status"], answer["fault"], answer["body_whole"]) == (200, "UpstreamFault", False)
    assert "compressed body (gzip)" in answer["detail"]
    assert "narrow" not in answer["detail"]


# --- A9 a request that cannot be processed is classified and audited --------------------------

def _raw(r, doc: dict, *, text: str | None = None):
    """POST `text` (default: `doc` as JSON with ASCII escapes, so a lone surrogate travels as
    `\\udXXX`) to the proxy as raw bytes, with a valid token."""
    content = (text if text is not None else json.dumps(doc)).encode("ascii")
    return r.client.post(PROXY_PATH, headers={"Authorization": f"Bearer {r.tok()}"},
                         content=content)


def _doc(r, **over):
    return {"system": "identity", "method": "GET", "url": f"{r.up.url}{PATH}",
            "headers": {}, "body": None} | over


@pytest.mark.parametrize("where", ["header", "url", "body", "system", "method"])
def test_f4_a_lone_surrogate_in_a_request_is_classified_and_audited(
        tmp_path, data_root, where):
    """A request holding a lone surrogate (in a header value, the URL, the body, the system or
    the method) gets a 200 answer with a fault class and one audit record; nothing is sent. O7, A9, A13."""
    lone = "\ud800"
    with T.rig(tmp_path / "forge", data_root, lambda u: H.declaration(
            u + BASE, writes=(("POST", "/tickets"),))) as r:
        doc = _doc(r)
        if where == "header":
            doc["headers"] = {"X-A": f"v{lone}"}
        elif where == "url":
            doc["url"] = f"{r.up.url}{BASE}/users/{lone}"
        elif where == "body":
            doc.update(method="POST", url=f"{r.up.url}{BASE}/tickets", body=f"{{\"x\": \"{lone}\"}}")
        elif where == "system":
            doc["system"] = lone
        else:
            doc["method"] = f"G{lone}T"
        grant = {("identity", "rw")}
        response = r.client.post(PROXY_PATH, headers={"Authorization": f"Bearer {r.tok(grant)}"},
                                 content=json.dumps(doc).encode("ascii"))
        control = r.ask()

    assert response.status_code == 200, response.text
    answer = T.answer_of(response.content)
    assert answer["fault"] in ("ConfigFault", "ConfinementFault"), answer
    assert r.up.paths() == [PATH], "only the control request was sent"
    assert control["fault"] is None
    refused = [rec for rec in r.audit.records if not rec["outcome"].startswith("sent ")]
    assert [rec["outcome"] for rec in refused] == [answer["fault"]], "the refusal was audited once"
    sent = [rec for rec in r.audit.records if rec["outcome"].startswith("sent ")]
    assert len(sent) == 1, "the control request was audited as sent"


@pytest.mark.parametrize("shape", ["whole-request", "in-headers"])
def test_f4_deeply_nested_json_is_classified_and_audited(tmp_path, data_root, shape):
    """A request body nested far beyond any parser's depth gets a 200 answer with a fault class
    and one audit record; the proxy still serves the next request. O7, A9, A13."""
    depth = 200_000
    nested = "[" * depth + "]" * depth
    with T.rig(tmp_path / "forge", data_root) as r:
        text = nested if shape == "whole-request" else (
            f'{{"system": "identity", "method": "GET", "url": "{r.up.url}{PATH}", '
            f'"headers": {{"X-A": {nested}}}}}')
        response = _raw(r, {}, text=text)
        control = r.ask()

    assert response.status_code == 200, response.status_code
    answer = T.answer_of(response.content)
    assert answer["fault"] in ("ConfigFault", "ConfinementFault"), answer
    assert (control["fault"], r.up.paths()) == (None, [PATH])
    records = r.audit.records
    assert len(records) == 2, records
    assert records[0]["outcome"] == answer["fault"], records
    assert records[1]["outcome"].startswith("sent "), records


class _BrokenStore(H.FakeStore):
    """A store port that fails in a way nobody foresaw."""

    def read(self, tenant_id: str, system: str):
        super().read(tenant_id, system)
        raise RuntimeError("unforeseen")


def test_f5_a_request_the_proxy_cannot_process_is_a_transport_fault_and_audited(
        tmp_path, data_root):
    """An unforeseen failure inside the proxy is `TransportFault` (r7 A18: a retry may
    succeed, the system is not marked down), audited, and sends nothing. A9, A13."""
    with T.rig(tmp_path / "forge", data_root, store=_BrokenStore()) as r:
        answer = r.ask()

    assert answer["fault"] == "TransportFault"
    assert r.up.seen == []
    assert [rec["outcome"] for rec in r.audit.records] == ["TransportFault"]


def _config(tmp_path, **over):
    """The operator config of A13/A26: a token, the KV mount, the data root, the audit file."""
    return {"openbao_token": "t", "kv_mount": "kv", "data_root": str(tmp_path),
            "audit_path": str(tmp_path / "audit.jsonl")} | over


def test_f6_the_remaining_config_builds_the_proxy(tmp_path):
    """Control for the config cases: exactly the keys A26 leaves build an app. A13, A26."""
    assert app_from_config(_config(tmp_path)) is not None


@pytest.mark.parametrize("bad", [{"upstream_timeout_sec": "30"}, {"audit_path": 5},
                                 {"audit_path": "audit\0.jsonl"}, {"max_response_bytes": None},
                                 {"data_root": 5}, {"data_root": "root\0dir"}],
                         ids=["quoted-number", "path-not-text", "nul-in-path", "null-cap",
                              "root-not-text", "nul-in-root"])
def test_f6_an_operator_config_value_of_the_wrong_type_is_a_config_fault(tmp_path, bad):
    """A configuration value of the wrong type or shape stops the proxy with `ConfigFault`
    naming the configuration, never a raw `TypeError` or `ValueError` (review of #1355)."""
    with pytest.raises(ConfigFault):
        app_from_config(_config(tmp_path, **bad))


@pytest.mark.parametrize("key", [*REMOVED_CONFIG_KEYS, "bogus_key"])
def test_a26_a_removed_or_unknown_config_key_is_a_config_fault(tmp_path, key):
    """`tenant_keys`, `tenant_exports`, `transit_mount` and `openbao_addr` are unknown keys: an
    old config refuses to start, as any unknown key does. A26, r8.2."""
    value = {} if key.startswith("tenant_") else "x"
    with pytest.raises(ConfigFault):
        app_from_config(_config(tmp_path, **{key: value}))


def test_a26_a_config_without_a_data_root_is_a_config_fault(tmp_path):
    """The one new key is required. A26."""
    config = _config(tmp_path)
    del config["data_root"]
    with pytest.raises(ConfigFault):
        app_from_config(config)


# --- A26 the proxy keeps no tenant list -------------------------------------------------------

DEPLOYMENT_OPENBAO = DEPLOYMENT_ISSUER.openbao_url


def test_a26_the_proxy_calls_the_deployments_openbao_over_https_on_the_fixed_transit_mount(
        tmp_path, data_root):
    """With no address in its config, verify goes to the deployment's https OpenBao at
    `/v1/transit/verify/request-token-<tenant>` carrying the configured token, then the credential
    read follows an accepted signature. A26, A25, A11."""
    tid, calls = str(uuid.uuid4()), []
    signer = H.FakeSigner()
    good = {}

    def openbao(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        if "/transit/verify/" in request.url.path:
            valid = json.loads(request.content)["signature"] in good
            return httpx.Response(200, json={"data": {"valid": valid}})
        return httpx.Response(404, json={"errors": []})

    with H.upstream() as up, T.identity_via_proxy(
            tmp_path / "forge", data_root, H.declaration(up.url + BASE), tenant_id=tid):
        client = TestClient(app_from_config(
            _config(tmp_path, data_root=str(data_root)), transport=httpx.MockTransport(openbao)))
        url, grant = f"{up.url}{BASE}/users/x", {("identity", "r")}
        refused = T.ask(client, T.token(tid, grant, signer=signer), "identity", "GET", url)
        verify = calls[0]
        tok = T.token(tid, grant, signer=signer)
        good[tok.rpartition(".")[2]] = True
        accepted = T.ask(client, tok, "identity", "GET", url)

    assert refused["fault"] == "ConfigFault"
    assert (verify.method, str(verify.url)) == (
        "POST", f"{DEPLOYMENT_OPENBAO}/v1/transit/verify/request-token-{tid}")
    assert DEPLOYMENT_OPENBAO.startswith("https://")
    assert {c.headers["X-Vault-Token"] for c in calls} == {"t"}
    assert any(c.url.path == f"/v1/kv/data/{tid}/identity" for c in calls), (
        "positive control: an accepted signature leads to the credential read")
    assert accepted["fault"] == "ConfigFault", "no credential stored: nothing is sent"
    assert up.seen == []


def test_a26_the_proxys_openbao_client_trusts_the_deployments_ca_and_no_web_proxy(tls_issuer, monkeypatch):  # noqa: F811
    """The proxy's OpenBao calls trust what the deployment's TLS client trusts by default (`SSL_CERT_FILE`/`SSL_CERT_DIR`,
    `DeploymentIssuer.ca_cert` None) and never go through a web proxy from the environment (A26, P-1)."""
    port, got, folder = tls_issuer
    monkeypatch.delenv("SSL_CERT_DIR", raising=False)
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:9")
    monkeypatch.setenv("ALL_PROXY", "http://127.0.0.1:9")
    monkeypatch.setenv("SSL_CERT_FILE", str(folder / "server.pem"))
    with contextlib.suppress(AdapterFault):  # the stand-in server answers no verdict; reaching it is the point
        transit_verifier(f"https://localhost:{port}", "t").verify(b"p", "s", tenant_id=str(uuid.uuid4()))
    assert got, "a server the trusted CA signed is reached, past the environment's web proxy"
    got.clear()
    monkeypatch.setenv("SSL_CERT_FILE", str(folder / "trusted.pem"))
    with pytest.raises(TransportFault):
        transit_verifier(f"https://localhost:{port}", "t").verify(b"p", "s", tenant_id=str(uuid.uuid4()))
    assert got == [], "control: a server another CA signed is refused before anything is sent"


class _AnyStore(H.FakeStore):
    """A store holding a static key for every tenant it is asked about."""

    def read(self, tenant_id: str, system: str):
        super().read(tenant_id, system)
        return T.static_set()


def test_a26_a_tenant_published_after_the_proxy_started_is_served_without_config(
        tmp_path, data_root):
    """A tenant the proxy was never told about, whose exports appear under the data root later, is
    served with its own declaration and key; the first tenant still is. A26."""
    other = str(uuid.uuid4())
    with T.rig(tmp_path / "forge", data_root, store=_AnyStore()) as r:
        first = r.ask()
        with T.identity_via_proxy(tmp_path / "other", data_root, H.declaration(
                r.up.url + "/other"), tenant_id=other, repo_name="other"):
            later = T.ask(r.client, T.token(other, T.GRANT_R, signer=r.signer), "identity",
                          "GET", f"{r.up.url}/other/users/x")

    assert (first["fault"], later["fault"]) == (None, None)
    assert r.up.paths() == [f"{BASE}/users/x", "/other/users/x"]


@pytest.mark.parametrize("bad", [
    pytest.param(lambda root, other: f"../{root.name}/{other}", id="traversal"),
    pytest.param(lambda root, other: str(root / other), id="absolute"),
    pytest.param(lambda root, other: f"{other}/.", id="dot-segment"),
    pytest.param(lambda root, other: f"{other}/../{other}", id="dotdot-segment"),
    pytest.param(lambda root, other: "", id="empty"),
])
def test_a26_a_token_naming_no_valid_tenant_id_is_refused_whatever_the_verifier_says(
        tmp_path, data_root, bad):
    """With a verifier that accepts every signature, a token whose tenant claim is not a tenant
    UUID but spells a path to another tenant's real exports is a ConfigFault, unsent and with no
    credential read; control: that tenant's own token is served. A26."""
    other = str(uuid.uuid4())
    with T.rig(tmp_path / "forge", data_root, store=_AnyStore()) as r:
        r.verifier = H.FakeVerifier()
        r.rebuild()
        with T.identity_via_proxy(tmp_path / "other", data_root, H.declaration(
                r.up.url + "/other"), tenant_id=other, repo_name="other"):
            url = f"{r.up.url}/other/users/x"
            control = T.ask(r.client, T.token(other, T.GRANT_R, signer=r.signer), "identity",
                            "GET", url)
            reads, seen = list(r.store.reads), r.up.paths()
            forged = T.forged_token(r.signer, r.tok(), bad(data_root, other))
            refused = T.ask(r.client, forged, "identity", "GET", url)

    assert (control["fault"], len(seen)) == (None, 1)
    assert refused["fault"] == "ConfigFault"
    assert (list(r.store.reads), r.up.paths()) == (reads, seen)


def test_a26_a_bad_tenant_id_is_refused_before_any_openbao_path_is_built(tmp_path, data_root):
    """With the real verifier over a recording transport, a token whose tenant claim is not a
    tenant UUID is a ConfigFault with zero OpenBao requests; control: a real tenant's token makes
    the verify call. A26, A11."""
    tid, calls = str(uuid.uuid4()), []

    def openbao(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(200, json={"data": {"valid": True}})

    signer = H.FakeSigner()
    with H.upstream() as up, T.identity_via_proxy(
            tmp_path / "forge", data_root, H.declaration(up.url + BASE), tenant_id=tid):
        client = TestClient(app_from_config(
            _config(tmp_path, data_root=str(data_root)), transport=httpx.MockTransport(openbao)))
        url, grant = f"{up.url}{BASE}/users/x", {("identity", "r")}
        good = T.token(tid, grant, signer=signer)
        T.ask(client, good, "identity", "GET", url)
        control = list(calls)
        calls.clear()
        refused = [
            T.ask(client, T.forged_token(signer, good, bad), "identity", "GET", url)
            for bad in (f"{tid}/../x", "../x", f"{tid}/.", "", "a/b")]

    assert any(f"request-token-{tid}" in c.url.path for c in control), (
        "positive control: a real tenant's token reaches the verify call")
    assert [r["fault"] for r in refused] == ["ConfigFault"] * 5
    assert calls == [], [str(c.url) for c in calls]


def test_a26_a_forged_token_naming_a_real_other_tenant_reaches_tenant_resolution(
        tmp_path, data_root):
    """Positive control for the forging cases: the same forging with the other tenant's valid
    UUID, under a verifier accepting every signature, is served, so the refusals above are the
    id check's. A26."""
    other = str(uuid.uuid4())
    with T.rig(tmp_path / "forge", data_root, store=_AnyStore()) as r:
        r.verifier = H.FakeVerifier()
        r.rebuild()
        with T.identity_via_proxy(tmp_path / "other", data_root, H.declaration(
                r.up.url + "/other"), tenant_id=other, repo_name="other"):
            served = T.ask(r.client, T.forged_token(r.signer, r.tok(), other), "identity",
                           "GET", f"{r.up.url}/other/users/x")

    assert served["fault"] is None, served
    assert r.up.paths() == ["/other/users/x"]


def test_a_header_value_that_is_not_ascii_is_a_config_fault_unsent(tmp_path, data_root):
    """A request header that is not ASCII is a malformed request (`ConfigFault`, unsent), not a transport failure a retry
    could clear (r7 A18); an ASCII one is sent (control)."""
    with T.rig(tmp_path / "forge", data_root) as r:
        refused = r.ask(headers={"X-Name": "café"})
        assert (refused["fault"], r.up.seen) == ("ConfigFault", [])
        sent = r.ask(headers={"X-Name": "cafe"})
    assert sent["fault"] is None, sent


# --- #1412 the reply format on the proxy's side ------------------------------------------------

def _forged() -> bytes:
    f = W.fmt()
    return f.encode_body(b"forged") + f.encode_final(
        W.final_record(418, fault="ConfigFault", detail="forged", body_whole=False))


def test_o5_a_copy_of_the_format_in_a_reply_is_only_data(tmp_path, data_root):
    """An upstream body holding byte-exact frames, or a final record alone, and a header holding
    a record's JSON, change neither status, fault, headers nor where the body ends. #1412 O5."""
    f = W.fmt()
    record = json.dumps(T.fields_of(W.final_record(418, fault="ConfigFault", body_whole=False)))
    bodies = [_forged(), f.encode_final(W.final_record(418, fault="ConfigFault")), record.encode()]
    with T.rig(tmp_path / "forge", data_root) as r:
        for i, body in enumerate(bodies):
            r.up.replies[f"{BASE}/forged{i}"] = (200, W.JSON | {"X-Forged": record}, body)
        wire = [W.decoded(r.post(path=f"/forged{i}").content) for i in range(len(bodies))]
        answers = [r.ask(path=f"/forged{i}") for i in range(len(bodies))]
        control = r.ask()

    assert control["fault"] is None, "positive control: an ordinary reply is clean"
    for body, (forwarded, final), answer in zip(bodies, wire, answers, strict=True):
        assert forwarded == body
        assert (final["status"], final["fault"], final["body_whole"]) == (200, None, True)
        assert answer["headers"]["x-forged"] == record


def test_o5_a_forged_final_frame_before_an_upstream_cut_does_not_end_the_reply_cleanly(
        tmp_path, data_root):
    """An upstream that sends a forged final frame and then breaks: the reply is still the broken
    one, not the forged one. #1412 O5."""
    forged = _forged()

    def script(conn: socket.socket) -> None:
        conn.sendall(W.head(200, len(forged) + 100) + forged)
        conn.shutdown(socket.SHUT_WR)

    with W.scripted(script) as up, T.rig(tmp_path / "forge", data_root,
                                         lambda _u: H.declaration(up.url + BASE)) as r:
        answer = r.ask(url=f"{up.url}{PATH}")

    assert (answer["status"], answer["fault"], answer["body_whole"], answer["body"]) == (
        200, "TransportFault", False, "")


def test_o8_a_small_500_keeps_its_body_and_an_over_limit_500_does_not(tmp_path, data_root):
    """Same status and fault; only `body_whole` tells them apart, and only the 2xx over-limit
    reply says to narrow. #1412 O8, O3."""
    with T.rig(tmp_path / "forge", data_root, max_response_bytes=CAP) as r:
        r.up.replies[f"{BASE}/small"] = (500, W.JSON, b"vendor reason")
        r.up.replies[f"{BASE}/large"] = (500, W.JSON, b"a" * (CAP + 1))
        small, large = r.ask(path="/small"), r.ask(path="/large")

    assert (small["status"], small["fault"], small["body"], small["body_whole"]) == (
        500, "TransportFault", "vendor reason", True)
    assert (large["status"], large["fault"], large["body"], large["body_whole"]) == (
        500, "TransportFault", "", False)
    assert "narrow" not in large["detail"]


def test_o8_non_utf8_bytes_cross_the_wire_unchanged(tmp_path, data_root):
    """The proxy forwards the upstream's bytes as they are; the replacement happens on the run
    side. #1412 O8."""
    body = b"caf\xe9 \xe2\x98"
    with T.rig(tmp_path / "forge", data_root) as r:
        r.up.replies[PATH] = (200, {"Content-Type": "text/plain"}, body)
        forwarded, final = W.decoded(r.post().content)

    assert (forwarded, final["body_whole"]) == (body, True)


def test_o8_the_upstream_hop_headers_are_dropped_and_other_headers_kept(tmp_path, data_root):
    """A chunked reply with connection headers: the record's headers lack all of them and keep
    the upstream's own. #1412 O8."""
    def script(conn: socket.socket) -> None:
        conn.sendall(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n"
                     b"Keep-Alive: timeout=5\r\nX-Kept: yes\r\n\r\n" + W.chunked(b"ok") + b"0\r\n\r\n")

    with W.scripted(script) as up, T.rig(tmp_path / "forge", data_root,
                                         lambda _u: H.declaration(up.url + BASE)) as r:
        answer = r.ask(url=f"{up.url}{PATH}")

    assert (answer["body"], answer["headers"].get("x-kept")) == ("ok", "yes")
    assert not {"transfer-encoding", "connection", "keep-alive", "content-length"} & set(answer["headers"])


def _media(response: Any) -> str:
    return response.headers["content-type"].split(";")[0].strip()


def test_o9_every_reply_carries_the_formats_content_type_and_is_no_old_json(tmp_path, data_root):
    """An answer, an over-limit reply, a refusal and the audit-withheld refusal all carry the
    proxy's content type, and none parses as the old JSON reply. #1412 O9."""
    kind = W.fmt().REPLY_CONTENT_TYPE.split(";")[0].strip()
    with T.rig(tmp_path / "forge", data_root, max_response_bytes=CAP) as r:
        r.up.replies[f"{BASE}/big"] = (200, W.JSON, b"a" * (CAP + 1))
        replies = [r.post(), r.post(path="/big"), r.post(grant=set())]
        r.audit = H.FailingAudit()
        r.rebuild()
        replies.append(r.post())

    for response in replies:
        assert _media(response) == kind
        with pytest.raises(ValueError):  # noqa: PT011 — json's decode error is a ValueError
            json.loads(response.content)
        assert W.fmt().decode_reply(response.content) is not None


def test_p3_the_pipeline_cannot_run_without_the_routes_send(tmp_path, data_root):
    """`handle` called with no send function raises `TypeError` before anything is sent or
    audited, while the route answers the same request. #1412 P3."""
    from defender.credential_proxy._app import _Proxy

    with T.rig(tmp_path / "forge", data_root) as r:
        proxy = _Proxy(T.deps(r.data_root, r.store, verifier=r.verifier, audit=r.audit))
        request = json.dumps({"system": "identity", "method": "GET", "url": f"{r.up.url}{PATH}",
                              "headers": {}, "body": None}).encode()
        assert r.ask()["fault"] is None, "positive control: the route answers it"
        before = (len(r.up.seen), len(r.audit.records))
        with pytest.raises(TypeError):
            proxy.handle(f"Bearer {r.tok()}", request)

    assert (len(r.up.seen), len(r.audit.records)) == before
