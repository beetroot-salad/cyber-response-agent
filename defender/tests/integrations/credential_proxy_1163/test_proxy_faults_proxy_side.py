"""#1163 repair (proxy side): the response cap holds for bodies with no honest Content-Length,
and a request the proxy cannot process is still classified and audited (O7, A9)."""
from __future__ import annotations

import contextlib
import gzip
import http.server
import json
import threading
import uuid

import httpx
import pytest
from fastapi.testclient import TestClient

from defender.tests.integrations.credential_proxy_1163 import _harness as H
from defender.tests.integrations.credential_proxy_1163 import _tenant as T
from defender.kit.faults import ConfigFault
from defender.configuration.issuer import DEPLOYMENT_ISSUER
from defender.tests.integrations.credential_proxy_1163._target import (
    PROXY_PATH,
    REMOVED_CONFIG_KEYS,
    app_from_config,
)

BASE = T.BASE_PATH
PATH = f"{BASE}/users/x"
CAP = 1024


@contextlib.contextmanager
def _chunked_upstream(chunks: list[bytes]):
    """A loopback HTTP/1.1 server answering every GET with `chunks` as a chunked body and no
    Content-Length. Yields its base URL."""
    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self) -> None:  # noqa: N802 — http.server's dispatch name
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            for chunk in chunks:
                self.wfile.write(f"{len(chunk):x}\r\n".encode() + chunk + b"\r\n")
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


@pytest.mark.parametrize(("chunks", "fault"), [
    pytest.param([b"a" * 512, b"a" * 512], None, id="chunked-at-the-cap"),
    pytest.param([b"a" * 512, b"a" * 512, b"a"], "UpstreamFault", id="chunked-over-the-cap"),
    pytest.param([b"a" * 400] * 20, "UpstreamFault", id="chunked-many-small-over-the-cap"),
])
def test_f1_a_chunked_response_is_capped_like_any_other(tmp_path, data_root, chunks, fault):
    """A chunked reply (no Content-Length) up to the cap passes; one byte over is an
    `UpstreamFault` with no body. O7."""
    with _chunked_upstream(chunks) as base, T.rig(
            tmp_path / "forge", data_root, lambda _u: H.declaration(base + BASE),
            max_response_bytes=CAP) as r:
        answer = r.ask(url=f"{base}{PATH}")

    assert answer["fault"] == fault, answer["fault"]
    if fault is None:
        assert len(answer["body"]) == CAP
    else:
        assert answer["body"] == ""


@pytest.mark.parametrize(("size", "fault"), [(CAP, None), (CAP + 1, "UpstreamFault"),
                                              (50_000, "UpstreamFault")])
def test_f1_a_compressed_response_is_capped_after_it_is_expanded(
        tmp_path, data_root, size, fault):
    """A gzip reply whose wire size is tiny is capped on its expanded size: 1024 bytes pass, more
    are an `UpstreamFault`. O7."""
    with T.rig(tmp_path / "forge", data_root, max_response_bytes=CAP) as r:
        r.up.replies[PATH] = (200, {"Content-Type": "text/plain", "Content-Encoding": "gzip"},
                              gzip.compress(b"a" * size))
        answer = r.ask()

    assert answer["fault"] == fault, answer["fault"]
    if fault is None:
        assert answer["body"] == "a" * CAP
    else:
        assert answer["body"] == ""


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
    answer = response.json()
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
    answer = response.json()
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
