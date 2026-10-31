"""#1163 against a real OpenBao (decision T1): the write-only store, rotation without restart, and
transit-signed tokens. Policies are the product's own text, applied by the fixture."""
from __future__ import annotations

import asyncio
import base64
import json
import uuid

import pytest

from defender.kit.faults import ConfigFault
from defender.tests.integrations.credential_proxy_1163 import _harness as H
from defender.tests.integrations.credential_proxy_1163 import _tenant as T
from defender.tests.integrations.credential_proxy_1163._target import proxy, secrets_writer

pytestmark = pytest.mark.openbao

KEY = "request-tokens"
TENANT = "5c1b1163-7a2e-4d3f-9b8c-0e1f2a3b4c5d"
OTHER = "9d4e1163-0f6a-4b7c-8e2d-1a3b5c7d9e0f"
STATIC = "static"
OAUTH = "oauth-client-credentials"


def _tokens(bao, **policy_kw) -> dict[str, str]:
    """One token per role, each holding only the product's policy for that role."""
    policies = proxy().store_policies(kv_mount=bao.kv_mount, transit_mount=bao.transit_mount,
                                      key=KEY, **policy_kw)
    return {role: bao.token_for(bao.apply_policy(role, hcl)) for role, hcl in policies.items()}


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


def test_b5_a_writer_scoped_to_one_tenant_is_refused_on_anothers_path(openbao):
    """A writer policy made for tenant A sets and asks on A's path and is refused on B's, for the
    write and the existence check alike. O5, O1."""
    tokens = _tokens(openbao, tenant=TENANT)
    writer = _writer(openbao, tokens["writer"])
    _put(writer, TENANT, "identity", STATIC, {"api_key": H.CANARY_KEY})
    assert asyncio.run(writer.has_credentials(TENANT, "identity")) is True

    with pytest.raises(ConfigFault):
        _put(writer, OTHER, "identity", STATIC, {"api_key": H.CANARY_KEY})
    with pytest.raises(ConfigFault):  # refused, not "absent"
        asyncio.run(writer.has_credentials(OTHER, "identity"))
    assert openbao.call("GET", f"{openbao.kv_mount}/metadata/{OTHER}/identity").status_code == 404


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


def _transit(bao, tokens, key=KEY):
    bao.ok("POST", f"{bao.transit_mount}/keys/{key}", json={"type": "ed25519"})
    signer = proxy().TransitSigner(addr=bao.addr, token=tokens["launcher"],
                                   mount=bao.transit_mount, key=key)
    verifier = proxy().TransitVerifier(addr=bao.addr, token=tokens["proxy"],
                                       mount=bao.transit_mount, key=key)
    return signer, verifier


def test_b3_a_launcher_signed_token_is_accepted_and_an_altered_one_refused(
        tmp_path, data_root, openbao):
    """The launcher signs, the proxy verifies: the token as signed is sent, the same token with
    one claim changed is refused unsent. O8, H11."""
    tokens = _tokens(openbao)
    signer, verifier = _transit(openbao, tokens)
    with H.upstream() as up, T.identity_via_proxy(
            tmp_path / "forge", data_root, H.declaration(up.url + T.BASE_PATH)) as t:
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
    tokens = _tokens(openbao)
    signer, verifier = _transit(openbao, tokens)
    openbao.ok("POST", f"{openbao.transit_mount}/keys/other-key", json={"type": "ed25519"})
    stranger = proxy().TransitSigner(addr=openbao.addr, token=openbao.root_token,
                                     mount=openbao.transit_mount, key="other-key")
    with H.upstream() as up, T.identity_via_proxy(
            tmp_path / "forge", data_root, H.declaration(up.url + T.BASE_PATH)) as t:
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
    signed = openbao.call("POST", f"{m}/sign/{KEY}", token=tokens["launcher"],
                          json={"input": payload})
    assert signed.status_code == 200
    signature = signed.json()["data"]["signature"]

    def verify(token, data=payload):
        return openbao.call("POST", f"{m}/verify/{KEY}", token=token,
                            json={"input": data, "signature": signature})

    assert verify(tokens["launcher"]).status_code == 403
    valid, altered = verify(tokens["proxy"]), verify(tokens["proxy"], _b64(b"claims-1164"))
    assert (valid.status_code, valid.json()["data"]["valid"]) == (200, True)
    assert (altered.status_code, altered.json()["data"]["valid"]) == (200, False)
    assert openbao.call("POST", f"{m}/sign/{KEY}", token=tokens["proxy"],
                        json={"input": payload}).status_code == 403
    for role in ("launcher", "proxy"):
        assert openbao.call("GET", f"{m}/keys/{KEY}", token=tokens[role]).status_code == 403, role
        assert openbao.call("GET", f"{m}/export/signing-key/{KEY}", token=tokens[role]
                            ).status_code == 403, role


def test_b4_the_signer_and_verifier_classes_fail_loud_without_their_own_power(openbao):
    """A signer holding the proxy's token and a verifier holding the launcher's raise
    ConfigFault, not a verdict. Control: each with its own token works. O8, H11."""
    tokens = _tokens(openbao)
    signer, verifier = _transit(openbao, tokens)
    signature = signer.sign(b"claims-1163")
    assert verifier.verify(b"claims-1163", signature) is True
    assert verifier.verify(b"claims-1164", signature) is False

    wrong_signer = proxy().TransitSigner(addr=openbao.addr, token=tokens["proxy"],
                                         mount=openbao.transit_mount, key=KEY)
    wrong_verifier = proxy().TransitVerifier(addr=openbao.addr, token=tokens["launcher"],
                                             mount=openbao.transit_mount, key=KEY)
    with pytest.raises(ConfigFault):
        wrong_signer.sign(b"claims-1163")
    with pytest.raises(ConfigFault):
        wrong_verifier.verify(b"claims-1163", signature)


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


def test_b8_an_unreachable_store_or_verifier_answers_config_fault_and_sends_nothing(
        tmp_path, data_root, openbao):
    """With the store unreachable, or the verifier, the proxy answers ConfigFault and sends
    nothing; control: the reachable store sends. H11, O7."""
    tokens = _tokens(openbao)
    signer, verifier = _transit(openbao, tokens)
    dead = f"http://127.0.0.1:{H.free_port()}"
    dead_store = proxy().OpenBaoStore(addr=dead, token=tokens["proxy"], mount=openbao.kv_mount)
    dead_verifier = proxy().TransitVerifier(addr=dead, token=tokens["proxy"],
                                            mount=openbao.transit_mount, key=KEY)
    with H.upstream() as up, T.identity_via_proxy(
            tmp_path / "forge", data_root, H.declaration(up.url + T.BASE_PATH)) as t:
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

    assert (no_store["fault"], no_verifier["fault"]) == ("ConfigFault", "ConfigFault")
    assert control["fault"] is None
    assert len(up.seen) == 1


def test_b9_no_openbao_token_is_in_any_repr_of_the_store_signer_or_verifier(openbao):
    """No role's token, nor the root token, appears in the repr or str of the writer, store,
    signer or verifier; each still works. O10."""
    tokens = _tokens(openbao)
    signer, verifier = _transit(openbao, tokens)
    writer, store = _writer(openbao, tokens["writer"]), _store(openbao, tokens["proxy"])
    _put(writer, TENANT, "identity", STATIC, {"api_key": H.CANARY_KEY})
    assert store.read(TENANT, "identity").fields == {"api_key": H.CANARY_KEY}
    assert verifier.verify(b"c", signer.sign(b"c")) is True

    for obj in (writer, store, signer, verifier):
        shown = repr(obj) + str(obj)
        for secret in (*tokens.values(), openbao.root_token):
            assert secret not in shown, type(obj).__name__
        assert type(obj).__name__ in shown
    assert H.CANARY_KEY not in repr(store.read(TENANT, "identity"))
