"""#1163 against a real OpenBao (decision T1): the write-only store, rotation without restart, and
transit-signed tokens. Policies are the product's own text, applied by the fixture."""
from __future__ import annotations

import asyncio
import base64
import json
import uuid

import pytest

from defender.kit.faults import ConfigFault, TransportFault
from defender.tests.integrations.credential_proxy_1163 import _harness as H
from defender.tests.integrations.credential_proxy_1163 import _tenant as T
from defender.tests.integrations.credential_proxy_1163._target import proxy, secrets_writer

pytestmark = pytest.mark.openbao

TENANT = "5c1b1163-7a2e-4d3f-9b8c-0e1f2a3b4c5d"
OTHER = "9d4e1163-0f6a-4b7c-8e2d-1a3b5c7d9e0f"
STATIC = "static"


def _key(tenant: str = TENANT) -> str:
    """The tenant's transit key name, as the proxy package names it (not computed here)."""
    return proxy().transit_key_for(tenant)


OAUTH = "oauth-client-credentials"


def _tokens(bao, tenant_keys=None) -> dict[str, str]:
    """One token per role, each holding only the product's policy for that role. Each tenant has
    its own launcher role, `launcher-<tenant_id>`; `launcher` is `TENANT`'s."""
    keys = tenant_keys or {TENANT: _key(TENANT), OTHER: _key(OTHER)}
    policies = proxy().store_policies(kv_mount=bao.kv_mount, transit_mount=bao.transit_mount,
                                      tenant_keys=keys)
    tokens = {role: bao.token_for(bao.apply_policy(role, hcl)) for role, hcl in policies.items()}
    if f"launcher-{TENANT}" in tokens:
        tokens["launcher"] = tokens[f"launcher-{TENANT}"]
    return tokens


def _writer(bao, token):
    return secrets_writer().OpenBaoSecrets(addr=bao.addr, token=token, mount=bao.kv_mount)


def _store(bao, token):
    return proxy().OpenBaoStore(addr=bao.addr, token=token, mount=bao.kv_mount)


def _put(writer, tenant, system, kind, fields):
    asyncio.run(writer.put_credentials(tenant, system, kind, fields))


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def test_b1_the_writer_sets_and_asks_but_only_the_proxy_reads(openbao):
    """The writer sets a whole set and learns it exists, is refused a read with no value in the
    refusal, and the proxy reads it but cannot write. O5."""
    tokens = _tokens(openbao)
    assert {"writer", "proxy", "launcher"} <= set(tokens)
    writer = _writer(openbao, tokens["writer"])
    _put(writer, TENANT, "identity", STATIC, {"api_key": H.CANARY_KEY})

    assert asyncio.run(writer.has_credentials(TENANT, "identity")) is True
    assert asyncio.run(writer.has_credentials(TENANT, "cmdb")) is False
    with pytest.raises(ConfigFault) as refused:
        _store(openbao, tokens["writer"]).read(TENANT, "identity")
    assert H.CANARY_KEY not in str(refused.value)
    got = _store(openbao, tokens["proxy"]).read(TENANT, "identity")
    assert (got.fields, got.version) == ({"api_key": H.CANARY_KEY}, 1)
    with pytest.raises(ConfigFault):  # the proxy may not write
        _put(_writer(openbao, tokens["proxy"]), TENANT, "identity", STATIC, {"api_key": "x" * 32})
    assert _store(openbao, tokens["proxy"]).read(TENANT, "identity").fields == {
        "api_key": H.CANARY_KEY}


def test_b1_at_the_wire_the_writer_gets_metadata_and_never_the_value(openbao):
    """With the writer's token, reading data is a 403 and the existence (metadata) read answers
    without the value; the proxy's token reads data. O5."""
    tokens = _tokens(openbao)
    _put(_writer(openbao, tokens["writer"]), TENANT, "identity", STATIC,
         {"api_key": H.CANARY_KEY})
    kv, path = openbao.kv_mount, f"{TENANT}/identity"

    refused = openbao.call("GET", f"{kv}/data/{path}", token=tokens["writer"])
    asked = openbao.call("GET", f"{kv}/metadata/{path}", token=tokens["writer"])
    allowed = openbao.call("GET", f"{kv}/data/{path}", token=tokens["proxy"])

    assert refused.status_code == 403
    assert H.CANARY_KEY not in refused.text
    assert asked.status_code == 200
    assert H.CANARY_KEY not in asked.text
    assert allowed.status_code == 200
    assert H.CANARY_KEY in allowed.text
    for verb in ("LIST", "DELETE"):  # no other power on the set
        assert openbao.call(verb, f"{kv}/metadata/{TENANT}", token=tokens["writer"]
                            ).status_code == 403, verb
    assert openbao.call("DELETE", f"{kv}/metadata/{path}", token=tokens["writer"]
                        ).status_code == 403


def test_b6_the_kind_is_stored_with_the_set_and_a_write_replaces_the_whole_set(openbao):
    """The proxy's read returns the kind written with the fields; a later write replaces every
    field and moves the version on. A4, O5, O6."""
    tokens = _tokens(openbao)
    writer, store = _writer(openbao, tokens["writer"]), _store(openbao, tokens["proxy"])
    _put(writer, TENANT, "crm", OAUTH, {"client_id": H.CLIENT_ID, "client_secret": H.CANARY_SECRET})
    first = store.read(TENANT, "crm")
    assert (first.kind, first.fields, first.version) == (
        OAUTH, {"client_id": H.CLIENT_ID, "client_secret": H.CANARY_SECRET}, 1)

    _put(writer, TENANT, "crm", STATIC, {"api_key": H.CANARY_KEY})
    second = store.read(TENANT, "crm")
    assert (second.kind, second.fields, second.version) == (
        STATIC, {"api_key": H.CANARY_KEY}, 2)
    assert store.read(TENANT, "absent") is None


def _secret_sent(seen: H.Seen) -> str:
    """Everything a token exchange carried that could hold the client secret."""
    scheme, _, value = (seen.headers.get("Authorization") or "").partition(" ")
    basic = base64.b64decode(value).decode() if scheme == "Basic" else ""
    return seen.body + basic


def test_b2_a_rotated_oauth_set_is_used_with_a_fresh_exchange(tmp_path, data_root, openbao):
    """A set rotated between two requests is used, with a fresh exchange, from the second; the
    secret goes only to the token URL, the access token only to the base. O6, O2, O9."""
    tokens = _tokens(openbao)
    writer = _writer(openbao, tokens["writer"])
    issued: list[str] = []
    with H.upstream() as up:
        up.replies["/oauth/token"] = H.token_endpoint(issued)
        decl = H.declaration(up.url + T.BASE_PATH,
                             scheme=H.oauth_scheme(up.url + "/oauth/token"))
        with T.identity_via_proxy(tmp_path / "forge", data_root, decl) as t:
            _put(writer, t.tenant_id, "identity", OAUTH, {
                "client_id": H.CLIENT_ID, "client_secret": H.CANARY_SECRET + "-1"})
            audit = H.AuditRecorder()
            client = T.client_of(T.deps({t.tenant_id: T.exports_of(t)},
                                        _store(openbao, tokens["proxy"]), audit=audit))
            tok = T.token(t.tenant_id, {("identity", "r")})
            first = T.ask(client, tok, "identity", "GET", f"{up.url}{T.BASE_PATH}/users")
            _put(writer, t.tenant_id, "identity", OAUTH, {
                "client_id": H.CLIENT_ID, "client_secret": H.CANARY_SECRET + "-2"})
            second = T.ask(client, tok, "identity", "GET", f"{up.url}{T.BASE_PATH}/users")

    assert (first["fault"], second["fault"]) == (None, None)
    exchanges = [s for s in up.seen if s.path == "/oauth/token"]
    calls = [s for s in up.seen if s.path == f"{T.BASE_PATH}/users"]
    assert (len(exchanges), len(calls)) == (2, 2)
    assert H.CANARY_SECRET + "-1" in _secret_sent(exchanges[0])
    assert H.CANARY_SECRET + "-2" in _secret_sent(exchanges[1])
    assert [c.headers.get("Authorization") for c in calls] == [f"Bearer {a}" for a in issued]
    for call in calls:
        assert H.CANARY_SECRET not in call.blob()
    for exchange in exchanges:
        assert not any(a in exchange.blob() for a in issued)
    assert len(audit.records) == 2
    assert not any(s in repr(audit.records) for s in (H.CANARY_SECRET, *issued))


def test_b2_a_rotated_static_key_is_sent_from_the_next_request(tmp_path, data_root, openbao):
    """The upstream sees the old key on the first request and the new one on the second, with
    no restart. O6."""
    tokens = _tokens(openbao)
    writer = _writer(openbao, tokens["writer"])
    with H.upstream() as up, T.identity_via_proxy(
            tmp_path / "forge", data_root, H.declaration(up.url + T.BASE_PATH)) as t:
        client = T.client_of(T.deps({t.tenant_id: T.exports_of(t)},
                                    _store(openbao, tokens["proxy"])))
        tok = T.token(t.tenant_id, {("identity", "r")})
        url = f"{up.url}{T.BASE_PATH}/users/x"
        _put(writer, t.tenant_id, "identity", STATIC, {"api_key": "old-" + H.CANARY_KEY})
        first = T.ask(client, tok, "identity", "GET", url)
        _put(writer, t.tenant_id, "identity", STATIC, {"api_key": "new-" + H.CANARY_KEY})
        second = T.ask(client, tok, "identity", "GET", url)

    assert (first["fault"], second["fault"]) == (None, None)
    assert [s.header("Authorization") for s in up.seen] == [
        "Bearer old-" + H.CANARY_KEY, "Bearer new-" + H.CANARY_KEY]


def _tokens_for(bao, tenant_id: str) -> dict[str, str]:
    """Role tokens for exactly `tenant_id`: its transit key and its own launcher role."""
    return _tokens(bao, {tenant_id: _key(tenant_id)})


def _transit(bao, tokens, tenant_id: str = TENANT):
    """`tenant_id`'s transit key (`_key(tenant_id)`), a signer holding that tenant's launcher
    token for it, and a verifier holding the proxy's token that verifies that tenant with it."""
    bao.ok("POST", f"{bao.transit_mount}/keys/{_key(tenant_id)}", json={"type": "ed25519"})
    signer = proxy().TransitSigner(addr=bao.addr, token=tokens[f"launcher-{tenant_id}"],
                                   mount=bao.transit_mount, key=_key(tenant_id))
    return signer, _verifier(bao, tokens, tenant_id)


def _verifier(bao, tokens, tenant_id: str = TENANT):
    """The proxy's verifier for `tenant_id`, over `_key(tenant_id)`."""
    return proxy().TransitVerifier(addr=bao.addr, token=tokens["proxy"],
                                   mount=bao.transit_mount, keys={tenant_id: _key(tenant_id)})


def test_b3_a_launcher_signed_token_is_accepted_and_an_altered_one_refused(
        tmp_path, data_root, openbao):
    """The launcher signs, the proxy verifies: the token as signed is sent, the same token with
    one claim changed is refused unsent. O8, H11."""
    with H.upstream() as up, T.identity_via_proxy(
            tmp_path / "forge", data_root, H.declaration(up.url + T.BASE_PATH)) as t:
        tokens = _tokens_for(openbao, t.tenant_id)
        signer, verifier = _transit(openbao, tokens, t.tenant_id)
        store = H.FakeStore({(t.tenant_id, "identity"): T.static_set()})
        client = T.client_of(T.deps({t.tenant_id: T.exports_of(t)}, store, verifier=verifier))
        tok = T.token(t.tenant_id, {("identity", "r")}, signer=signer)
        claims = H.claims_of(tok)
        claims["investigation"] = "another-run"
        payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
        altered = f"{payload}.{tok.rpartition('.')[2]}"
        url = f"{up.url}{T.BASE_PATH}/users/x"

        refused = T.ask(client, altered, "identity", "GET", url)
        reads_after_refusal, seen_after_refusal = list(store.reads), up.paths()
        sent = T.ask(client, tok, "identity", "GET", url)

    assert (refused["fault"], reads_after_refusal, seen_after_refusal) == ("ConfigFault", [], [])
    assert (sent["fault"], up.paths()) == (None, [f"{T.BASE_PATH}/users/x"])
    assert store.reads == [(t.tenant_id, "identity")]


def test_b3_a_token_signed_by_a_different_transit_key_is_refused(tmp_path, data_root, openbao):
    """A token signed under another key of the same transit mount is refused unsent; control:
    the key the proxy verifies with is accepted. O8, H11."""
    openbao.ok("POST", f"{openbao.transit_mount}/keys/other-key", json={"type": "ed25519"})
    stranger = proxy().TransitSigner(addr=openbao.addr, token=openbao.root_token,
                                     mount=openbao.transit_mount, key="other-key")
    with H.upstream() as up, T.identity_via_proxy(
            tmp_path / "forge", data_root, H.declaration(up.url + T.BASE_PATH)) as t:
        tokens = _tokens_for(openbao, t.tenant_id)
        signer, verifier = _transit(openbao, tokens, t.tenant_id)
        store = H.FakeStore({(t.tenant_id, "identity"): T.static_set()})
        client = T.client_of(T.deps({t.tenant_id: T.exports_of(t)}, store, verifier=verifier))
        url = f"{up.url}{T.BASE_PATH}/users/x"
        grant = {("identity", "r")}
        foreign = T.ask(client, T.token(t.tenant_id, grant, signer=stranger),
                        "identity", "GET", url)
        reads_after_foreign, seen_after_foreign = list(store.reads), up.paths()
        own = T.ask(client, T.token(t.tenant_id, grant, signer=signer), "identity", "GET", url)

    assert (foreign["fault"], reads_after_foreign, seen_after_foreign) == ("ConfigFault", [], [])
    assert own["fault"] is None
    assert len(up.seen) == 1


def test_b4_transit_policies_let_the_launcher_sign_only_and_the_proxy_verify_only(openbao):
    """Launcher: sign yes, verify/read/export no. Proxy: verify yes (valid and altered), sign/
    read/export no. O8, H11, C35."""
    tokens = _tokens(openbao)
    _transit(openbao, tokens)
    m, payload = openbao.transit_mount, _b64(b"claims-1163")
    signed = openbao.call("POST", f"{m}/sign/{_key(TENANT)}", token=tokens["launcher"],
                          json={"input": payload})
    assert signed.status_code == 200
    signature = signed.json()["data"]["signature"]

    def verify(token, data=payload):
        return openbao.call("POST", f"{m}/verify/{_key(TENANT)}", token=token,
                            json={"input": data, "signature": signature})

    assert verify(tokens["launcher"]).status_code == 403
    valid, altered = verify(tokens["proxy"]), verify(tokens["proxy"], _b64(b"claims-1164"))
    assert (valid.status_code, valid.json()["data"]["valid"]) == (200, True)
    assert (altered.status_code, altered.json()["data"]["valid"]) == (200, False)
    assert openbao.call("POST", f"{m}/sign/{_key(TENANT)}", token=tokens["proxy"],
                        json={"input": payload}).status_code == 403
    for role in ("launcher", "proxy"):
        assert openbao.call("GET", f"{m}/keys/{_key(TENANT)}", token=tokens[role]).status_code == 403, role
        assert openbao.call("GET", f"{m}/export/signing-key/{_key(TENANT)}", token=tokens[role]
                            ).status_code == 403, role


def test_b4_the_signer_and_verifier_classes_fail_loud_without_their_own_power(openbao):
    """A signer holding the proxy's token and a verifier holding the launcher's raise
    ConfigFault, not a verdict. Control: each with its own token works. O8, H11."""
    tokens = _tokens(openbao)
    signer, verifier = _transit(openbao, tokens)
    signature = signer.sign(b"claims-1163")
    assert verifier.verify(b"claims-1163", signature, tenant_id=TENANT) is True
    assert verifier.verify(b"claims-1164", signature, tenant_id=TENANT) is False

    wrong_signer = proxy().TransitSigner(addr=openbao.addr, token=tokens["proxy"],
                                         mount=openbao.transit_mount, key=_key(TENANT))
    wrong_verifier = proxy().TransitVerifier(addr=openbao.addr, token=tokens["launcher"],
                                             mount=openbao.transit_mount, keys={TENANT: _key(TENANT)})
    with pytest.raises(ConfigFault):
        wrong_signer.sign(b"claims-1163")
    with pytest.raises(ConfigFault):
        wrong_verifier.verify(b"claims-1163", signature, tenant_id=TENANT)


def test_b7_a_credential_write_is_in_openbaos_audit_and_its_value_is_not(
        openbao, openbao_audit):
    """The audit device records the write by path and operation and holds the value only as its
    HMAC, never the canary. O9, A4."""
    canary = "canary-audit-1163-" + uuid.uuid4().hex
    tokens = _tokens(openbao)
    _put(_writer(openbao, tokens["writer"]), TENANT, "identity", STATIC, {"api_key": canary})

    text = openbao_audit.text()
    entries = [json.loads(line) for line in text.splitlines() if line.strip()]
    writes = [e for e in entries if e.get("type") == "request"
              and e["request"].get("operation") in ("create", "update")
              and openbao.kv_mount in e["request"].get("path", "")
              and TENANT in e["request"]["path"] and "identity" in e["request"]["path"]]
    assert writes, "no audit entry for the credential write"
    # The HMAC is asked for after `text` was read, so only the write itself can hold it.
    assert openbao_audit.hash_of(canary) in json.dumps(writes), (
        "the value did not reach the audit as its HMAC")
    assert canary not in text


def test_b8_an_unreachable_store_or_verifier_answers_transport_fault_and_sends_nothing(
        tmp_path, data_root, openbao):
    """With the store unreachable, or the verifier, the proxy answers TransportFault (a retry
    may succeed; the system is not marked down) and sends nothing; control: the reachable store
    sends. H11, O7, r7 A18."""
    dead = f"http://127.0.0.1:{H.free_port()}"
    with H.upstream() as up, T.identity_via_proxy(
            tmp_path / "forge", data_root, H.declaration(up.url + T.BASE_PATH)) as t:
        tokens = _tokens_for(openbao, t.tenant_id)
        signer, verifier = _transit(openbao, tokens, t.tenant_id)
        dead_store = proxy().OpenBaoStore(addr=dead, token=tokens["proxy"],
                                          mount=openbao.kv_mount)
        dead_verifier = proxy().TransitVerifier(addr=dead, token=tokens["proxy"],
                                                mount=openbao.transit_mount,
                                                keys={t.tenant_id: _key(t.tenant_id)})
        _put(_writer(openbao, tokens["writer"]), t.tenant_id, "identity", STATIC,
             {"api_key": H.CANARY_KEY})
        tok = T.token(t.tenant_id, {("identity", "r")}, signer=signer)
        url = f"{up.url}{T.BASE_PATH}/users/x"
        exports = {t.tenant_id: T.exports_of(t)}

        def answer(store, verifier_):
            return T.ask(T.client_of(T.deps(exports, store, verifier=verifier_)),
                         tok, "identity", "GET", url)

        no_store = answer(dead_store, verifier)
        no_verifier = answer(_store(openbao, tokens["proxy"]), dead_verifier)
        assert up.seen == []
        control = answer(_store(openbao, tokens["proxy"]), verifier)

    assert (no_store["fault"], no_verifier["fault"]) == ("TransportFault", "TransportFault")
    assert control["fault"] is None
    assert len(up.seen) == 1


def test_b8_a_signer_or_verifier_that_cannot_reach_openbao_raises_transport_fault(openbao):
    """The real signer and verifier against a dead address raise TransportFault, not a raw
    transport error; control: against the live server they work. O8, H11, O7, r7 A18."""
    tokens = _tokens(openbao)
    signer, verifier = _transit(openbao, tokens)
    dead = f"http://127.0.0.1:{H.free_port()}"
    dead_signer = proxy().TransitSigner(addr=dead, token=tokens["launcher"],
                                        mount=openbao.transit_mount, key=_key(TENANT))
    dead_verifier = proxy().TransitVerifier(addr=dead, token=tokens["proxy"],
                                            mount=openbao.transit_mount, keys={TENANT: _key(TENANT)})
    signature = signer.sign(b"claims-1163")
    assert verifier.verify(b"claims-1163", signature, tenant_id=TENANT) is True

    with pytest.raises(TransportFault):
        dead_signer.sign(b"claims-1163")
    with pytest.raises(TransportFault):
        dead_verifier.verify(b"claims-1163", signature, tenant_id=TENANT)


class _Always(dict):
    """A fake OpenBao's replies: the same answer to every path."""

    def __init__(self, reply: H.Reply) -> None:
        super().__init__()
        self.reply = reply

    def get(self, _path, _default=None):
        return self.reply


@pytest.mark.parametrize(("status", "fault"), [
    (503, TransportFault), (500, TransportFault), (403, ConfigFault), (400, ConfigFault)])
def test_b9_openbao_5xx_is_retryable_and_4xx_is_the_operators_to_fix(status, fault):
    """An OpenBao that answers 5xx (sealed, standby, failing) is `TransportFault` for the store,
    the verifier and the signer alike; a 4xx (policy refusal, bad request) is `ConfigFault`.
    r7 A18."""
    with H.upstream() as bao:
        bao.replies = _Always((status, {"Content-Type": "application/json"},
                               json.dumps({"errors": ["no"]}).encode()))
        store = proxy().OpenBaoStore(addr=bao.url, token="t", mount="kv")
        verifier = proxy().TransitVerifier(addr=bao.url, token="t", mount="transit",
                                           keys={TENANT: _key(TENANT)})
        signer = proxy().TransitSigner(addr=bao.url, token="t", mount="transit", key=_key(TENANT))
        with pytest.raises(fault):
            store.read(TENANT, "identity")
        with pytest.raises(fault):
            verifier.verify(b"claims-1163", "vault:v1:x", tenant_id=TENANT)
        with pytest.raises(fault):
            signer.sign(b"claims-1163")


def test_b10_each_tenants_launcher_signs_only_with_its_own_key(openbao):
    """A launcher policy per tenant: A's login signs with A's key and is refused B's, and B's
    with A's, at the wire and through the signer class. O8, A11."""
    tokens = _tokens(openbao)
    for key in (_key(TENANT), _key(OTHER)):
        openbao.ok("POST", f"{openbao.transit_mount}/keys/{key}", json={"type": "ed25519"})
    a, b = tokens[f"launcher-{TENANT}"], tokens[f"launcher-{OTHER}"]
    m, payload = openbao.transit_mount, _b64(b"claims-1163")

    def sign(token, key):
        return openbao.call("POST", f"{m}/sign/{key}", token=token, json={"input": payload})

    assert (sign(a, _key(TENANT)).status_code, sign(b, _key(OTHER)).status_code) == (200, 200)
    assert (sign(a, _key(OTHER)).status_code, sign(b, _key(TENANT)).status_code) == (403, 403)
    for tenant_token, foreign in ((a, _key(OTHER)), (b, _key(TENANT))):
        crossed = proxy().TransitSigner(addr=openbao.addr, token=tenant_token,
                                        mount=openbao.transit_mount, key=foreign)
        with pytest.raises(ConfigFault):
            crossed.sign(b"claims-1163")


def test_b10_the_proxy_verifies_with_the_key_of_the_tenant_the_token_names(
        tmp_path, data_root, openbao):
    """A token naming A signed with B's key is ConfigFault, unsent, no store read; control: A's
    key is accepted. O8, O1, A11."""
    with H.upstream() as up, T.identity_via_proxy(
            tmp_path / "forge", data_root, H.declaration(up.url + T.BASE_PATH)) as t:
        tokens = _tokens(openbao, {t.tenant_id: _key(t.tenant_id), OTHER: _key(OTHER)})
        for key in (_key(t.tenant_id), _key(OTHER)):
            openbao.ok("POST", f"{openbao.transit_mount}/keys/{key}", json={"type": "ed25519"})
        signer = {tenant: proxy().TransitSigner(
            addr=openbao.addr, token=tokens[f"launcher-{tenant}"], mount=openbao.transit_mount,
            key=key) for tenant, key in ((t.tenant_id, _key(t.tenant_id)), (OTHER, _key(OTHER)))}
        verifier = proxy().TransitVerifier(
            addr=openbao.addr, token=tokens["proxy"], mount=openbao.transit_mount,
            keys={t.tenant_id: _key(t.tenant_id), OTHER: _key(OTHER)})
        store = H.FakeStore({(t.tenant_id, "identity"): T.static_set()})
        client = T.client_of(T.deps({t.tenant_id: T.exports_of(t)}, store, verifier=verifier))
        url, grant = f"{up.url}{T.BASE_PATH}/users/x", {("identity", "r")}

        crossed = T.ask(client, T.token(t.tenant_id, grant, signer=signer[OTHER]),
                        "identity", "GET", url)
        assert (crossed["fault"], store.reads, up.seen) == ("ConfigFault", [], [])
        own = T.ask(client, T.token(t.tenant_id, grant, signer=signer[t.tenant_id]),
                    "identity", "GET", url)

    assert own["fault"] is None
    assert up.paths() == [f"{T.BASE_PATH}/users/x"]


def test_b9_no_openbao_token_is_in_any_repr_of_the_store_signer_or_verifier(openbao):
    """No role's token, nor the root token, appears in the repr or str of the writer, store,
    signer or verifier; each still works. O10."""
    tokens = _tokens(openbao)
    signer, verifier = _transit(openbao, tokens)
    writer, store = _writer(openbao, tokens["writer"]), _store(openbao, tokens["proxy"])
    _put(writer, TENANT, "identity", STATIC, {"api_key": H.CANARY_KEY})
    assert store.read(TENANT, "identity").fields == {"api_key": H.CANARY_KEY}
    assert verifier.verify(b"c", signer.sign(b"c"), tenant_id=TENANT) is True

    for obj in (writer, store, signer, verifier):
        shown = repr(obj) + str(obj)
        for secret in (*tokens.values(), openbao.root_token):
            assert secret not in shown, type(obj).__name__
        assert type(obj).__name__ in shown
    assert H.CANARY_KEY not in repr(store.read(TENANT, "identity"))
