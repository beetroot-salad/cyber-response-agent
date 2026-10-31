"""#1163 against a real OpenBao (decision T1): the write-only store, rotation without restart, and
transit-signed tokens. Policies are the product's own text, applied by the fixture."""
from __future__ import annotations

import asyncio
import base64
import json

import pytest
from fastapi.testclient import TestClient

from defender.kit.faults import ConfigFault
from defender.tests.integrations.credential_proxy_1163 import _harness as H
from defender.tests.integrations.credential_proxy_1163 import _tenant as T
from defender.tests.integrations.credential_proxy_1163._target import proxy, secrets_writer

pytestmark = pytest.mark.openbao

KEY = "request-tokens"
TENANT = "5c1b1163-7a2e-4d3f-9b8c-0e1f2a3b4c5d"


def _tokens(bao) -> dict[str, str]:
    """One token per role, each holding only the product's policy for that role."""
    policies = proxy().store_policies(kv_mount=bao.kv_mount, transit_mount=bao.transit_mount,
                                      key=KEY)
    return {role: bao.token_for(bao.apply_policy(role, hcl)) for role, hcl in policies.items()}


def _writer(bao, token):
    return secrets_writer().OpenBaoSecrets(addr=bao.addr, token=token, mount=bao.kv_mount)


def _store(bao, token):
    return proxy().OpenBaoStore(addr=bao.addr, token=token, mount=bao.kv_mount)


def test_b1_the_writer_sets_and_asks_but_only_the_proxy_reads(openbao):
    """The writer's token sets a whole set and learns it exists, and is refused a read; the
    proxy's token reads the value. O5."""
    tokens = _tokens(openbao)
    assert {"writer", "proxy", "launcher"} <= set(tokens)
    writer = _writer(openbao, tokens["writer"])
    asyncio.run(writer.put_credentials(TENANT, "identity", {"api_key": H.CANARY_KEY}))

    assert asyncio.run(writer.has_credentials(TENANT, "identity")) is True
    assert asyncio.run(writer.has_credentials(TENANT, "cmdb")) is False
    with pytest.raises(ConfigFault) as refused:
        _store(openbao, tokens["writer"]).read(TENANT, "identity")
    assert H.CANARY_KEY not in str(refused.value)
    got = _store(openbao, tokens["proxy"]).read(TENANT, "identity")
    assert (got.fields, got.version) == ({"api_key": H.CANARY_KEY}, 1)
    with pytest.raises(ConfigFault):  # the proxy may not write
        asyncio.run(_writer(openbao, tokens["proxy"]).put_credentials(
            TENANT, "identity", {"api_key": "x" * 32}))


def _secret_sent(seen: H.Seen) -> str:
    """Everything a token exchange carried that could hold the client secret."""
    scheme, _, value = (seen.headers.get("Authorization") or "").partition(" ")
    basic = base64.b64decode(value).decode() if scheme == "Basic" else ""
    return seen.body + basic


def test_b2_a_rotated_set_is_used_from_the_next_request(tmp_path, data_root, openbao):
    """A set rotated between two requests is used, with a fresh exchange, from the second; the
    secret goes only to the token URL, the access token only to the base. O6, O2, O9."""
    tokens = _tokens(openbao)
    writer = _writer(openbao, tokens["writer"])
    issued: list[str] = []
    with H.upstream() as up:
        up.replies["/oauth/token"] = H.token_endpoint(issued)
        decl = H.declaration(up.url + "/api/",
                             scheme=H.oauth_scheme(up.url + "/oauth/token"))
        with T.identity_via_proxy(tmp_path / "forge", data_root, decl) as t:
            asyncio.run(writer.put_credentials(t.tenant_id, "identity", {
                "client_id": H.CLIENT_ID, "client_secret": H.CANARY_SECRET + "-1"}))
            audit = H.AuditRecorder()
            client = TestClient(proxy().create_app(T.deps(
                {t.tenant_id: T.exports_of(t)}, _store(openbao, tokens["proxy"]), audit=audit)))
            tok = T.token(t.tenant_id, {("identity", "r")})
            first = T.ask(client, tok, "identity", "GET", f"{up.url}/api/users")
            asyncio.run(writer.put_credentials(t.tenant_id, "identity", {
                "client_id": H.CLIENT_ID, "client_secret": H.CANARY_SECRET + "-2"}))
            second = T.ask(client, tok, "identity", "GET", f"{up.url}/api/users")

    assert (first["fault"], second["fault"]) == (None, None)
    exchanges = [s for s in up.seen if s.path == "/oauth/token"]
    calls = [s for s in up.seen if s.path == "/api/users"]
    assert (len(exchanges), len(calls)) == (2, 2)
    assert H.CANARY_SECRET + "-1" in _secret_sent(exchanges[0])
    assert H.CANARY_SECRET + "-2" in _secret_sent(exchanges[1])
    assert [c.headers.get("Authorization") for c in calls] == [f"Bearer {a}" for a in issued]
    for call in calls:
        assert H.CANARY_SECRET not in json.dumps(call.headers) + call.body
    for exchange in exchanges:
        assert not any(a in json.dumps(exchange.headers) + exchange.body for a in issued)
    assert len(audit.records) == 2
    assert not any(s in repr(audit.records) for s in (H.CANARY_SECRET, *issued))


def test_b3_a_transit_signed_token_altered_after_signing_is_refused(tmp_path, data_root, openbao):
    """The launcher signs, the proxy verifies: the token as signed is sent, the same token with
    one claim changed is refused unsent. O8, H11."""
    tokens = _tokens(openbao)
    openbao.ok("POST", f"{openbao.transit_mount}/keys/{KEY}", json={"type": "ed25519"})
    signer = proxy().TransitSigner(addr=openbao.addr, token=tokens["launcher"],
                                   mount=openbao.transit_mount, key=KEY)
    verifier = proxy().TransitVerifier(addr=openbao.addr, token=tokens["proxy"],
                                       mount=openbao.transit_mount, key=KEY)
    with H.upstream() as up, T.identity_via_proxy(
            tmp_path / "forge", data_root, H.declaration(up.url + "/")) as t:
        store = H.FakeStore({(t.tenant_id, "identity"): T.static_set()})
        client = TestClient(proxy().create_app(T.deps(
            {t.tenant_id: T.exports_of(t)}, store, verifier=verifier)))
        tok = T.token(t.tenant_id, {("identity", "r")}, signer=signer)
        claims = H.claims_of(tok)
        claims["investigation"] = "another-run"
        payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
        altered = f"{payload}.{tok.rpartition('.')[2]}"

        refused = T.ask(client, altered, "identity", "GET", f"{up.url}/users/x")
        sent = T.ask(client, tok, "identity", "GET", f"{up.url}/users/x")

    assert refused["fault"] == "ConfigFault"
    assert (sent["fault"], up.paths()) == (None, ["/users/x"])
    assert store.reads == [(t.tenant_id, "identity")]
