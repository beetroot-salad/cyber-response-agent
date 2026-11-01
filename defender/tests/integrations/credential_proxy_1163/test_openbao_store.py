"""#1163 against a real OpenBao (decision T1): the write-only store, rotation without restart, and
transit-signed tokens on the fixed `transit/` mount. Policies are the product's own text, applied
by the fixture; tests isolate by fresh tenant uuid (a fresh key), not by mount (r8.2 A25, A26)."""
from __future__ import annotations

import asyncio
import base64
import json
import uuid

import pytest

from defender.kit.faults import ConfigFault, TransportFault
from defender.tests.integrations.credential_proxy_1163 import _harness as H
from defender.tests.integrations.credential_proxy_1163 import _tenant as T
from defender.tests.integrations.credential_proxy_1163._target import (
    proxy,
    secrets_writer,
    transit_verifier,
)

pytestmark = pytest.mark.openbao

STATIC = "static"
OAUTH = "oauth-client-credentials"
#: The operator-provisioned templated sign policy of A24'/A25, as the design spells its rule: a
#: fixture for OpenBao's own templating (the product ships no policy file for it).
SIGN_HCL = ('path "transit/sign/request-token-{{identity.entity.metadata.tenant_id}}" {\n'
            '  capabilities = ["update"]\n}\n')


def _key(tenant: str) -> str:
    """The tenant's transit key name, as the proxy package names it (not computed here)."""
    return proxy().transit_key_for(tenant)


def _tokens(bao) -> dict[str, str]:
    """One token per role, each holding only the product's policy for that role."""
    policies = proxy().store_policies(kv_mount=bao.kv_mount)
    return {role: bao.token_for(bao.apply_policy(role, hcl)) for role, hcl in policies.items()}


def _writer(bao, token):
    return secrets_writer().OpenBaoSecrets(addr=bao.addr, token=token, mount=bao.kv_mount)


def _store(bao, token):
    return proxy().OpenBaoStore(addr=bao.addr, token=token, mount=bao.kv_mount)


def _verifier(bao, tokens):
    return transit_verifier(bao.addr, tokens["proxy"])


def _put(writer, tenant, system, kind, fields):
    asyncio.run(writer.put_credentials(tenant, system, kind, fields))


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def test_a25_the_product_names_a_writer_policy_and_a_proxy_policy_and_no_tenant_policy(openbao):
    """`store_policies` yields the writer's and the proxy's policy only (no `launcher-<id>`), and
    the key naming rule is A11's `request-token-<id>`. A25, A11."""
    tenant = openbao.tenant(key=False)

    assert set(proxy().store_policies(kv_mount=openbao.kv_mount)) == {"writer", "proxy"}
    assert _key(tenant) == openbao.key_name(tenant) == f"request-token-{tenant}"


def test_b1_the_writer_sets_and_asks_but_only_the_proxy_reads(openbao):
    """The writer sets a whole set and learns it exists, is refused a read with no value in the
    refusal, and the proxy reads it but cannot write. O5."""
    tenant = openbao.tenant(key=False)
    tokens = _tokens(openbao)
    writer = _writer(openbao, tokens["writer"])
    _put(writer, tenant, "identity", STATIC, {"api_key": H.CANARY_KEY})

    assert asyncio.run(writer.has_credentials(tenant, "identity")) is True
    assert asyncio.run(writer.has_credentials(tenant, "cmdb")) is False
    with pytest.raises(ConfigFault) as refused:
        _store(openbao, tokens["writer"]).read(tenant, "identity")
    assert H.CANARY_KEY not in str(refused.value)
    got = _store(openbao, tokens["proxy"]).read(tenant, "identity")
    assert (got.fields, got.version) == ({"api_key": H.CANARY_KEY}, 1)
    with pytest.raises(ConfigFault):  # the proxy may not write
        _put(_writer(openbao, tokens["proxy"]), tenant, "identity", STATIC, {"api_key": "x" * 32})
    assert _store(openbao, tokens["proxy"]).read(tenant, "identity").fields == {
        "api_key": H.CANARY_KEY}


def test_b1_at_the_wire_the_writer_gets_metadata_and_never_the_value(openbao):
    """With the writer's token, reading data is a 403 and the existence (metadata) read answers
    without the value; the proxy's token reads data. O5."""
    tenant = openbao.tenant(key=False)
    tokens = _tokens(openbao)
    _put(_writer(openbao, tokens["writer"]), tenant, "identity", STATIC,
         {"api_key": H.CANARY_KEY})
    kv, path = openbao.kv_mount, f"{tenant}/identity"

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
        assert openbao.call(verb, f"{kv}/metadata/{tenant}", token=tokens["writer"]
                            ).status_code == 403, verb
    assert openbao.call("DELETE", f"{kv}/metadata/{path}", token=tokens["writer"]
                        ).status_code == 403


def test_b6_the_kind_is_stored_with_the_set_and_a_write_replaces_the_whole_set(openbao):
    """The proxy's read returns the kind written with the fields; a later write replaces every
    field and moves the version on. A4, O5, O6."""
    tenant = openbao.tenant(key=False)
    tokens = _tokens(openbao)
    writer, store = _writer(openbao, tokens["writer"]), _store(openbao, tokens["proxy"])
    _put(writer, tenant, "crm", OAUTH, {"client_id": H.CLIENT_ID, "client_secret": H.CANARY_SECRET})
    first = store.read(tenant, "crm")
    assert (first.kind, first.fields, first.version) == (
        OAUTH, {"client_id": H.CLIENT_ID, "client_secret": H.CANARY_SECRET}, 1)

    _put(writer, tenant, "crm", STATIC, {"api_key": H.CANARY_KEY})
    second = store.read(tenant, "crm")
    assert (second.kind, second.fields, second.version) == (
        STATIC, {"api_key": H.CANARY_KEY}, 2)
    assert store.read(tenant, "absent") is None


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
            client = T.client_of(T.deps(data_root,
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
        client = T.client_of(T.deps(data_root,
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


def _published(scratch, data_root, up, tenant_id, repo_name="fixture"):
    return T.identity_via_proxy(scratch / "forge", data_root, H.declaration(up.url + T.BASE_PATH),
                                tenant_id=tenant_id, repo_name=repo_name)


def test_b3_a_signed_token_is_accepted_and_an_altered_one_refused(tmp_path, data_root, openbao):
    """The signer signs, the proxy verifies with the real key: the token as signed is sent, the
    same token with one claim changed is refused unsent. O8, H11."""
    tid = openbao.tenant()
    with H.upstream() as up, _published(tmp_path, data_root, up, tid) as t:
        verifier = _verifier(openbao, _tokens(openbao))
        store = H.FakeStore({(tid, "identity"): T.static_set()})
        client = T.client_of(T.deps(data_root, store, verifier=verifier))
        tok = T.token(tid, {("identity", "r")}, signer=openbao.signer(tid))
        claims = H.claims_of(tok)
        claims["investigation"] = "another-run"
        payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
        altered = f"{payload}.{tok.rpartition('.')[2]}"
        url = f"{up.url}{T.BASE_PATH}/users/x"

        refused = T.ask(client, altered, "identity", "GET", url)
        reads_after_refusal, seen_after_refusal = list(store.reads), up.paths()
        sent = T.ask(client, tok, "identity", "GET", url)

    assert t.tenant_id == tid
    assert (refused["fault"], reads_after_refusal, seen_after_refusal) == ("ConfigFault", [], [])
    assert (sent["fault"], up.paths()) == (None, [f"{T.BASE_PATH}/users/x"])
    assert store.reads == [(tid, "identity")]


def test_b3_a_token_naming_one_tenant_signed_with_another_tenants_key_is_refused(
        tmp_path, data_root, openbao):
    """A token naming A signed with B's key is ConfigFault, unsent, no store read; control: A's
    key is accepted. O8, O1, A11."""
    tid, other = openbao.tenant(), openbao.tenant()
    with H.upstream() as up, _published(tmp_path, data_root, up, tid):
        store = H.FakeStore({(tid, "identity"): T.static_set()})
        client = T.client_of(T.deps(data_root, store, verifier=_verifier(openbao, _tokens(openbao))))
        url, grant = f"{up.url}{T.BASE_PATH}/users/x", {("identity", "r")}

        crossed = T.ask(client, T.token(tid, grant, signer=openbao.signer(other)),
                        "identity", "GET", url)
        assert (crossed["fault"], store.reads, up.seen) == ("ConfigFault", [], [])
        own = T.ask(client, T.token(tid, grant, signer=openbao.signer(tid)), "identity", "GET", url)

    assert own["fault"] is None
    assert up.paths() == [f"{T.BASE_PATH}/users/x"]


def test_b4_the_proxy_verifies_any_tenants_key_and_does_nothing_else_with_transit(openbao):
    """One policy covers a tenant whose key was made after it was applied: verify (valid and
    altered) yes; sign, key read, export no; a key outside `request-token-*` no. The writer has no
    transit power. O8, H11, C35, A25."""
    tokens = _tokens(openbao)
    tenant = openbao.tenant()
    openbao.ok("POST", f"transit/keys/outside-{openbao.tag}", json={"type": "ed25519"})
    m, key, payload = openbao.transit_mount, _key(tenant), _b64(b"claims-1163")
    signature = openbao.signer(tenant).sign(b"claims-1163")

    def verify(token, data=payload, name=key):
        return openbao.call("POST", f"{m}/verify/{name}", token=token,
                            json={"input": data, "signature": signature})

    try:
        valid, altered = verify(tokens["proxy"]), verify(tokens["proxy"], _b64(b"claims-1164"))
        assert (valid.status_code, valid.json()["data"]["valid"]) == (200, True)
        assert (altered.status_code, altered.json()["data"]["valid"]) == (200, False)
        assert verify(tokens["proxy"], name=f"outside-{openbao.tag}").status_code == 403
        assert openbao.call("POST", f"{m}/sign/{key}", token=tokens["proxy"],
                            json={"input": payload}).status_code == 403
        assert openbao.call("GET", f"{m}/keys/{key}", token=tokens["proxy"]).status_code == 403
        assert openbao.call("GET", f"{m}/export/signing-key/{key}", token=tokens["proxy"]
                            ).status_code == 403
        assert verify(tokens["writer"]).status_code == 403
        assert openbao.call("POST", f"{m}/sign/{key}", token=tokens["writer"],
                            json={"input": payload}).status_code == 403
    finally:
        outside = f"{m}/keys/outside-{openbao.tag}"
        openbao.call("POST", f"{outside}/config", json={"deletion_allowed": True})
        openbao.call("DELETE", outside)


def test_a25_a_sign_login_signs_with_its_own_tenants_key_only(openbao):
    """Under the templated sign policy, a login whose entity carries tenant A signs with A's key,
    is refused B's, and cannot verify or read the key; the proxy verifies A's signature. A25, A24'."""
    a, b = openbao.tenant(), openbao.tenant()
    policy = openbao.apply_policy("defender-tenant-sign", SIGN_HCL)
    login = openbao.sign_login(policy, a)
    proxy_token = _tokens(openbao)["proxy"]
    m, payload = openbao.transit_mount, _b64(b"claims-1163")

    def sign(tenant):
        return openbao.call("POST", f"{m}/sign/{_key(tenant)}", token=login, json={"input": payload})

    own = sign(a)
    assert own.status_code == 200, "control: the login signs with its own tenant's key"
    assert sign(b).status_code == 403
    signature = own.json()["data"]["signature"]
    assert openbao.call("POST", f"{m}/verify/{_key(a)}", token=login,
                        json={"input": payload, "signature": signature}).status_code == 403
    assert openbao.call("GET", f"{m}/keys/{_key(a)}", token=login).status_code == 403
    verdict = openbao.call("POST", f"{m}/verify/{_key(a)}", token=proxy_token,
                           json={"input": payload, "signature": signature})
    assert verdict.json()["data"]["valid"] is True


def test_b4_the_verifier_class_fails_loud_without_its_own_power(openbao):
    """A verifier holding the writer's token raises ConfigFault, not a verdict. Control: the
    proxy's token gives True for the signed payload and False for another. O8, H11."""
    tokens = _tokens(openbao)
    tenant = openbao.tenant()
    signature = openbao.signer(tenant).sign(b"claims-1163")
    verifier = _verifier(openbao, tokens)
    assert verifier.verify(b"claims-1163", signature, tenant_id=tenant) is True
    assert verifier.verify(b"claims-1164", signature, tenant_id=tenant) is False

    with pytest.raises(ConfigFault):
        transit_verifier(openbao.addr, tokens["writer"]).verify(
            b"claims-1163", signature, tenant_id=tenant)


def test_b7_a_credential_write_is_in_openbaos_audit_and_its_value_is_not(
        openbao, openbao_audit):
    """The audit device records the write by path and operation and holds the value only as its
    HMAC, never the canary. O9, A4."""
    canary = "canary-audit-1163-" + uuid.uuid4().hex
    tenant = openbao.tenant(key=False)
    tokens = _tokens(openbao)
    _put(_writer(openbao, tokens["writer"]), tenant, "identity", STATIC, {"api_key": canary})

    text = openbao_audit.text()
    entries = [json.loads(line) for line in text.splitlines() if line.strip()]
    writes = [e for e in entries if e.get("type") == "request"
              and e["request"].get("operation") in ("create", "update")
              and openbao.kv_mount in e["request"].get("path", "")
              and tenant in e["request"]["path"] and "identity" in e["request"]["path"]]
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
    tid = openbao.tenant()
    with H.upstream() as up, _published(tmp_path, data_root, up, tid):
        tokens = _tokens(openbao)
        verifier = _verifier(openbao, tokens)
        dead_store = proxy().OpenBaoStore(addr=dead, token=tokens["proxy"],
                                          mount=openbao.kv_mount)
        dead_verifier = transit_verifier(dead, tokens["proxy"])
        _put(_writer(openbao, tokens["writer"]), tid, "identity", STATIC,
             {"api_key": H.CANARY_KEY})
        tok = T.token(tid, {("identity", "r")}, signer=openbao.signer(tid))
        url = f"{up.url}{T.BASE_PATH}/users/x"

        def answer(store, verifier_):
            return T.ask(T.client_of(T.deps(data_root, store, verifier=verifier_)),
                         tok, "identity", "GET", url)

        no_store = answer(dead_store, verifier)
        no_verifier = answer(_store(openbao, tokens["proxy"]), dead_verifier)
        assert up.seen == []
        control = answer(_store(openbao, tokens["proxy"]), verifier)

    assert (no_store["fault"], no_verifier["fault"]) == ("TransportFault", "TransportFault")
    assert control["fault"] is None
    assert len(up.seen) == 1


def test_b8_a_verifier_that_cannot_reach_openbao_raises_transport_fault(openbao):
    """The real verifier against a dead address raises TransportFault, not a raw transport
    error; control: against the live server it works. O8, H11, O7, r7 A18."""
    tokens = _tokens(openbao)
    tenant = openbao.tenant()
    signature = openbao.signer(tenant).sign(b"claims-1163")
    assert _verifier(openbao, tokens).verify(b"claims-1163", signature, tenant_id=tenant) is True

    dead = transit_verifier(f"http://127.0.0.1:{H.free_port()}", tokens["proxy"])
    with pytest.raises(TransportFault):
        dead.verify(b"claims-1163", signature, tenant_id=tenant)


class _Always(dict):
    """A fake OpenBao's replies: the same answer to every path."""

    def __init__(self, reply: H.Reply) -> None:
        super().__init__()
        self.reply = reply

    def get(self, _path, _default=None):
        return self.reply


TENANT_FOR_STATUS = "5c1b1163-7a2e-4d3f-9b8c-0e1f2a3b4c5d"


def _always(status):
    return _Always((status, {"Content-Type": "application/json"},
                    json.dumps({"errors": ["no"]}).encode()))


@pytest.mark.parametrize(("status", "fault"), [
    (503, TransportFault), (500, TransportFault), (403, ConfigFault), (400, ConfigFault)])
def test_b9_openbao_5xx_is_retryable_and_4xx_is_the_operators_to_fix(status, fault):
    """An OpenBao that answers 5xx (sealed, standby, failing) is `TransportFault` for the store
    and the verifier; a 4xx (policy refusal, bad request) is `ConfigFault`. r7 A18, A26."""
    with H.upstream() as bao:
        bao.replies = _always(status)
        store = proxy().OpenBaoStore(addr=bao.url, token="t", mount="kv")
        verifier = transit_verifier(bao.url, "t")
        with pytest.raises(fault):
            store.read(TENANT_FOR_STATUS, "identity")
        with pytest.raises(fault):
            verifier.verify(b"claims-1163", "vault:v1:x", tenant_id=TENANT_FOR_STATUS)


def test_b9_a_404_is_no_credential_for_the_store_and_a_destroyed_key_for_the_verifier():
    """A 404 on a credential read is "no credential set" (None, not a refusal); the verifier's
    404 (a destroyed key) is a ConfigFault. r7 A18, A26."""
    with H.upstream() as bao:
        bao.replies = _always(404)
        store = proxy().OpenBaoStore(addr=bao.url, token="t", mount="kv")
        verifier = transit_verifier(bao.url, "t")
        assert store.read(TENANT_FOR_STATUS, "identity") is None
        with pytest.raises(ConfigFault):
            verifier.verify(b"claims-1163", "vault:v1:x", tenant_id=TENANT_FOR_STATUS)


def test_a26_an_offboarded_tenants_token_is_refused_once_its_key_is_destroyed(
        tmp_path, data_root, openbao):
    """The same token is served while the tenant's key exists and is a ConfigFault, unsent and
    with no credential read, after the key is destroyed as offboarding does. A26, A25."""
    tid = openbao.tenant()
    with H.upstream() as up, _published(tmp_path, data_root, up, tid):
        store = H.FakeStore({(tid, "identity"): T.static_set()})
        client = T.client_of(T.deps(data_root, store, verifier=_verifier(openbao, _tokens(openbao))))
        tok = T.token(tid, {("identity", "r")}, signer=openbao.signer(tid))
        url = f"{up.url}{T.BASE_PATH}/users/x"
        before = T.ask(client, tok, "identity", "GET", url)
        reads, seen = list(store.reads), up.paths()

        openbao.destroy_key(tid)
        after = T.ask(client, tok, "identity", "GET", url)

    assert (before["fault"], len(reads), len(seen)) == (None, 1, 1)
    assert after["fault"] == "ConfigFault"
    assert (store.reads, up.paths()) == (reads, seen)


def test_a26_a_missing_key_and_a_missing_exports_folder_are_distinct_config_faults(
        tmp_path, data_root, openbao):
    """A tenant with exports and no key, and one with a key and no exports folder, are both
    ConfigFault, unsent, and their details differ; a tenant with both is served. A26 detail."""
    keyless, folderless, whole = openbao.tenant(key=False), openbao.tenant(), openbao.tenant()
    with H.upstream() as up, _published(tmp_path / "a", data_root, up, keyless, "a"), \
            _published(tmp_path / "b", data_root, up, whole, "b"):
        store = H.FakeStore({(t, "identity"): T.static_set() for t in (keyless, folderless, whole)})
        client = T.client_of(T.deps(data_root, store, verifier=_verifier(openbao, _tokens(openbao))))
        url, grant = f"{up.url}{T.BASE_PATH}/users/x", {("identity", "r")}
        # the keyless tenant has no key to sign with, so its token is signed under another key
        no_key = T.ask(client, T.token(keyless, grant, signer=openbao.signer(whole)),
                       "identity", "GET", url)
        no_folder = T.ask(client, T.token(folderless, grant, signer=openbao.signer(folderless)),
                          "identity", "GET", url)
        assert up.seen == []
        control = T.ask(client, T.token(whole, grant, signer=openbao.signer(whole)),
                        "identity", "GET", url)

    assert (no_key["fault"], no_folder["fault"], control["fault"]) == ("ConfigFault", "ConfigFault", None)
    assert (bool(no_key["detail"]), bool(no_folder["detail"])) == (True, True)
    assert no_key["detail"] != no_folder["detail"], "the two refusals read alike"


def test_b9_no_openbao_token_is_in_any_repr_of_the_store_or_verifier(openbao):
    """No role's token, nor the root token, appears in the repr or str of the writer, store or
    verifier; each still works. O10."""
    tokens = _tokens(openbao)
    tenant = openbao.tenant()
    verifier = _verifier(openbao, tokens)
    writer, store = _writer(openbao, tokens["writer"]), _store(openbao, tokens["proxy"])
    _put(writer, tenant, "identity", STATIC, {"api_key": H.CANARY_KEY})
    assert store.read(tenant, "identity").fields == {"api_key": H.CANARY_KEY}
    assert verifier.verify(b"c", openbao.signer(tenant).sign(b"c"), tenant_id=tenant) is True

    for obj in (writer, store, verifier):
        shown = repr(obj) + str(obj)
        for secret in (*tokens.values(), openbao.root_token):
            assert secret not in shown, type(obj).__name__
        assert type(obj).__name__ in shown
    assert H.CANARY_KEY not in repr(store.read(tenant, "identity"))
