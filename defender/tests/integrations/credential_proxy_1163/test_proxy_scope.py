"""#1163 the proxy's own checks, at its request boundary: tenant, destination, route and token
bounds. A refused request is never sent and never reads the store."""
from __future__ import annotations

import base64
from datetime import timedelta

import pytest

from defender.tests.integrations.credential_proxy_1163 import _adapter1163 as A
from defender.tests.integrations.credential_proxy_1163 import _harness as H
from defender.tests.integrations.credential_proxy_1163 import _tenant as T
from defender.tests.tenancy.tenant_1108_p4._support import OTHER_TENANT_ID

KEY_A = "canary-tenant-a-key-1163-aaaa11"
KEY_B = "canary-tenant-b-key-1163-bbbb22"


# --- O1 tenant scope (r5 A10) ----------------------------------------------------------------

def test_s1_a_token_delivers_only_its_own_tenants_credential(tmp_path, data_root):
    """Both tenants declare `crm`; A's token sends only A's canary, reads only A's path and is
    audited as A. Control: B's token sends B's. O1, A10."""
    with H.upstream() as up, T.crm_pair(tmp_path, data_root, up.url + "/crm", up.url + "/crm") as (a, b):
        store = H.FakeStore({(a.tenant_id, "crm"): T.static_set(KEY_A),
                             (b.tenant_id, "crm"): T.static_set(KEY_B)})
        audit = H.AuditRecorder()
        client = T.client_of(T.deps({a.tenant_id: T.exports_of(a), b.tenant_id: T.exports_of(b)},
                                    store, audit=audit))
        from_a = T.ask(client, T.token(a.tenant_id, {("crm", "r")}), "crm", "GET",
                       f"{up.url}/crm/accounts")
        seen_after_a = list(up.seen)
        reads_after_a = list(store.reads)
        audit_after_a = list(audit.records)
        from_b = T.ask(client, T.token(b.tenant_id, {("crm", "r")}), "crm", "GET",
                       f"{up.url}/crm/accounts")

    assert from_a["fault"] is None
    assert [s.header("Authorization") for s in seen_after_a] == [f"Bearer {KEY_A}"]
    assert not any(KEY_B in s.blob() for s in seen_after_a)
    assert reads_after_a == [(a.tenant_id, "crm")]
    assert [r["tenant"] for r in audit_after_a] == [a.tenant_id]
    assert from_b["fault"] is None
    assert up.seen[1].header("Authorization") == f"Bearer {KEY_B}"  # control
    assert store.reads[1] == (b.tenant_id, "crm")


def test_s1_a_tenants_token_cannot_reach_the_other_tenants_base(tmp_path, data_root):
    """A's token to a URL under B's base is refused unsent and unread; A's own base works.
    O1, O2."""
    with H.upstream() as up, T.crm_pair(tmp_path, data_root, up.url + "/a", up.url + "/b") as (a, b):
        store = H.FakeStore({(a.tenant_id, "crm"): T.static_set(KEY_A),
                             (b.tenant_id, "crm"): T.static_set(KEY_B)})
        client = T.client_of(T.deps({a.tenant_id: T.exports_of(a), b.tenant_id: T.exports_of(b)},
                                    store))
        tok = T.token(a.tenant_id, {("crm", "r")})
        refused = T.ask(client, tok, "crm", "GET", f"{up.url}/b/accounts")
        assert (refused["fault"], up.seen, store.reads) == ("ConfigFault", [], [])
        control = T.ask(client, tok, "crm", "GET", f"{up.url}/a/accounts")

    assert (control["fault"], up.paths()) == (None, ["/a/accounts"])


def test_s1_a_system_a_lacks_is_refused_the_same_whether_or_not_b_declares_it(
        tmp_path, data_root):
    """A's token granting `billing`, which A does not declare, is refused identically before and
    after B declares it, unsent and unread; B's own token then works. O1, A10."""
    with H.upstream() as up, T.crm_pair(tmp_path, data_root, up.url + "/crm", up.url + "/crm") as (a, b):
        store = H.FakeStore()
        client = T.client_of(T.deps({a.tenant_id: T.exports_of(a), b.tenant_id: T.exports_of(b)},
                                    store))
        grant = {("billing", "r")}
        tok = T.token(a.tenant_id, grant)
        without_b = T.ask(client, tok, "billing", "GET", f"{up.url}/billing/invoices")

        b.merge(H.access_files("billing", H.declaration(up.url + "/billing"),
                               env=H.http_proxy_env("billing")), "B adds billing")
        b.publish()
        store.sets[(b.tenant_id, "billing")] = T.static_set(KEY_B)
        with_b = T.ask(client, tok, "billing", "GET", f"{up.url}/billing/invoices")
        assert (with_b, store.reads, up.seen) == (without_b, [], [])
        control = T.ask(client, T.token(b.tenant_id, grant), "billing", "GET",
                        f"{up.url}/billing/invoices")

    assert with_b["fault"] == "ConfigFault"
    assert control["fault"] is None
    assert up.seen[0].header("Authorization") == f"Bearer {KEY_B}"


@pytest.mark.parametrize("kind", ["unmapped-tenant", "exports-without-current"])
def test_s1_a_token_whose_tenant_has_no_exports_is_refused(tmp_path, data_root, kind):
    """A valid token for a tenant with no exports is refused, unsent and unread; the published
    tenant's token works beside it. O1, O7."""
    ghosts = {}
    if kind == "exports-without-current":
        (tmp_path / "ghost" / "exports").mkdir(parents=True)
        ghosts = {OTHER_TENANT_ID: tmp_path / "ghost" / "exports"}
    with T.rig(tmp_path / "forge", data_root, ghosts=ghosts) as r:
        refused = r.ask(tok=T.token(OTHER_TENANT_ID, T.GRANT_R, signer=r.signer))
        assert (refused["fault"], r.up.seen, r.store.reads) == ("ConfigFault", [], [])
        control = r.ask()

    assert (control["fault"], r.up.paths()) == (None, ["/api/v2/users/x"])


# --- O2 destination scope: one base, non-root (A2, A9) ---------------------------------------

@pytest.mark.parametrize(("url_of", "fault"), [
    pytest.param(lambda up, other: f"{up}/api/v2/users/x", None, id="under-base"),
    pytest.param(lambda up, other: f"{up}/api/v2/users?limit=5", None, id="under-base-query"),
    pytest.param(lambda up, other: f"{up}/api/v2x/users", "ConfigFault", id="sibling-prefix"),
    pytest.param(lambda up, other: f"{up}/admin", "ConfigFault", id="same-origin-outside"),
    pytest.param(lambda up, other: f"{up}/", "ConfigFault", id="origin-root"),
    pytest.param(lambda up, other: f"{up}/api/v2/../admin", "ConfinementFault", id="dotdot"),
    pytest.param(lambda up, other: f"{up}/api/v2/users/../../admin", "ConfinementFault",
                 id="dotdot-twice"),
    pytest.param(lambda up, other: f"{up}/api/v2/%2e%2e/admin", "ConfinementFault",
                 id="encoded-dotdot"),
    pytest.param(lambda up, other: f"{up}/api/v2/%2E%2e/admin", "ConfinementFault",
                 id="encoded-dotdot-mixed-case"),
    pytest.param(lambda up, other: f"{up}/api/v2/..;/admin", "ConfinementFault",
                 id="dotdot-path-parameter"),
    pytest.param(lambda up, other: f"{up}/api/v2/%2e%2e%3b/admin", "ConfinementFault",
                 id="encoded-dotdot-path-parameter"),
    pytest.param(lambda up, other: f"http://127.0.0.1:{other}/api/v2/users/x", "ConfigFault",
                 id="other-port"),
    pytest.param(lambda up, other: up.replace("http://", "https://") + "/api/v2/users/x",
                 "ConfigFault", id="other-scheme"),
    pytest.param(lambda up, other: up.replace("127.0.0.1", "localhost") + "/api/v2/users/x",
                 "ConfigFault", id="other-host"),
    pytest.param(lambda up, other: f"{up}@localhost/api/v2/users/x", "ConfigFault",
                 id="userinfo-disguise"),
])
def test_s2_a_url_outside_the_declared_base_is_refused_unsent(
        tmp_path, data_root, url_of, fault):
    """Only URLs under the one non-root base are sent; `..` is a confinement refusal, another
    scheme, host, port or path a config refusal. O2, O7, A2, A9."""
    with T.rig(tmp_path / "forge", data_root) as r:
        answer = r.ask(url=url_of(r.up.url, H.free_port()))

    assert answer["fault"] == fault, answer
    if fault is None:
        assert (answer["status"], len(r.up.seen)) == (200, 1)
        assert r.up.seen[0].path.startswith("/api/v2/users")
        assert r.store.reads == [(r.t.tenant_id, "identity")]
    else:
        assert (r.up.seen, r.store.reads) == ([], [])


def test_s2_the_query_string_reaches_the_upstream_with_the_path(tmp_path, data_root):
    """A query under the base is forwarded intact next to the injected key. O2."""
    with T.rig(tmp_path / "forge", data_root) as r:
        answer = r.ask(path="/users?limit=5&name=dana")

    assert answer["fault"] is None
    assert [s.path for s in r.up.seen] == ["/api/v2/users?limit=5&name=dana"]


# --- O3 route scope (routes are relative to the base, A2) ------------------------------------

READS = (("POST", "/search"),)
WRITES = (("POST", "/tickets/*/comments"), ("PUT", "/tickets/*"), ("DELETE", "/tickets/*"))
RW = {("identity", "rw")}
RD = {("identity", "r")}


@pytest.mark.parametrize(("method", "path", "grant", "fault"), [
    pytest.param("GET", "/users/x", RD, None, id="get-is-a-read"),
    pytest.param("HEAD", "/users/x", RD, None, id="head-is-a-read"),
    pytest.param("GET", "/tickets/7/comments", RD, None, id="get-on-a-write-route-is-a-read"),
    pytest.param("POST", "/search", RD, None, id="listed-post-read"),
    pytest.param("PUT", "/search", RW, "ConfinementFault", id="listed-read-other-method"),
    pytest.param("POST", "/admin", RW, "ConfinementFault", id="unlisted-post"),
    pytest.param("DELETE", "/users/x", RW, "ConfinementFault", id="undeclared-delete"),
    pytest.param("DELETE", "/tickets/7", RD, "ConfinementFault", id="declared-delete-read-grant"),
    pytest.param("DELETE", "/tickets/7", RW, None, id="declared-delete-granted"),
    pytest.param("POST", "/tickets/7/comments", RD, "ConfinementFault", id="write-with-read-grant"),
    pytest.param("PUT", "/tickets/7", RD, "ConfinementFault", id="put-write-with-read-grant"),
    pytest.param("POST", "/tickets/7/comments", {("identity", "r"), ("cmdb", "rw")},
                 "ConfinementFault", id="write-grant-on-another-system"),
    pytest.param("POST", "/tickets/7/comments", RW, None, id="write-granted"),
    pytest.param("PUT", "/tickets/7", RW, None, id="put-write-granted"),
    pytest.param("POST", "/tickets/7/delete", RW, "ConfinementFault", id="undeclared-under-rw"),
    pytest.param("POST", "/tickets/..;/comments", RW, "ConfinementFault", id="write-wildcard-path-parameter"),
])
def test_s3_only_declared_reads_and_granted_writes_are_sent(
        tmp_path, data_root, method, path, grant, fault):
    """GET and HEAD are reads; another method is a read only if listed; a declared write needs
    `rw` on that system. Routes are relative to the base. O3, O7, A2."""
    body = '{"q": 1}' if method in ("POST", "PUT") else None
    with T.rig(tmp_path / "forge", data_root, lambda u: H.declaration(
            u + T.BASE_PATH, reads=READS, writes=WRITES)) as r:
        answer = r.ask(method, path, grant=grant, body=body)

    assert answer["fault"] == fault, answer
    assert [(s.method, s.path, s.body) for s in r.up.seen] == (
        [] if fault else [(method, f"/api/v2{path}", body or "")])


def test_s3_a_listed_route_is_relative_to_the_base_not_the_origin(tmp_path, data_root):
    """A listed `/search` read is `<base>/search`: the origin's `/search` is outside the base,
    and `<base>/api/v2/search` matches no route. O3, A2."""
    with T.rig(tmp_path / "forge", data_root, lambda u: H.declaration(
            u + T.BASE_PATH, reads=READS)) as r:
        origin_level = r.ask("POST", "", url=f"{r.up.url}/search", grant=RD, body="{}")
        doubled = r.ask("POST", "/api/v2/search", grant=RD, body="{}")
        assert (origin_level["fault"], doubled["fault"]) == ("ConfigFault", "ConfinementFault")
        assert (r.up.seen, r.store.reads) == ([], [])
        control = r.ask("POST", "/search", grant=RD, body="{}")

    assert (control["fault"], r.up.paths()) == (None, ["/api/v2/search"])


# --- O8 token bounds -------------------------------------------------------------------------

def test_s4_a_token_out_of_its_bounds_is_refused_before_any_store_read(tmp_path, data_root):
    """Unverified, expired, ungranted and garbage tokens are refused unsent and unread, the
    unverified one by a verify call; the token in bounds is sent. O8, O7."""
    with T.rig(tmp_path / "forge", data_root) as r:
        r.verifier = H.FakeVerifier(False)
        r.rebuild()
        bad_sig = r.ask(tok=T.token(r.t.tenant_id, RD, signer=r.signer))
        assert len(r.verifier.calls) >= 1
        r.verifier.verdict = True
        expired = r.ask(tok=r.tok(expires_in=timedelta(minutes=-1)))
        ungranted = r.ask(grant={("cmdb", "r")})
        garbage = r.ask(tok="not-a-token")
        assert [a["fault"] for a in (bad_sig, expired, ungranted, garbage)] == ["ConfigFault"] * 4
        assert (r.store.reads, r.up.seen) == ([], [])
        control = r.ask()

    assert (control["fault"], control["status"], r.up.paths()) == (None, 200, ["/api/v2/users/x"])


def _edited(tok: str, edit) -> str:
    payload, _, signature = tok.rpartition(".")
    raw = base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)).decode()
    changed = edit(raw)
    assert changed != raw, "the edit changed nothing"
    new = base64.urlsafe_b64encode(changed.encode()).decode().rstrip("=")
    return f"{new}.{signature}"


def test_s4_a_token_edited_under_its_signature_is_refused(tmp_path, data_root):
    """Claims edited after signing (a write grant added, another tenant named) are refused
    unsent; the unedited token is sent. O8, O1."""
    with H.upstream() as up, T.crm_pair(tmp_path, data_root, up.url + "/crm", up.url + "/crm") as (a, b):
        store = H.FakeStore({(a.tenant_id, "crm"): T.static_set(KEY_A),
                             (b.tenant_id, "crm"): T.static_set(KEY_B)})
        signer = H.FakeSigner()
        client = T.client_of(T.deps(
            {a.tenant_id: T.exports_of(a), b.tenant_id: T.exports_of(b)}, store,
            verifier=H.PairedVerifier(signer)))
        tok = T.token(a.tenant_id, {("crm", "r")}, signer=signer)
        as_b = T.ask(client, _edited(tok, lambda s: s.replace(a.tenant_id, b.tenant_id)),
                     "crm", "GET", f"{up.url}/crm/accounts")
        escalated = T.ask(client, _edited(tok, lambda s: s.replace('"r"', '"rw"')),
                          "crm", "GET", f"{up.url}/crm/accounts")
        assert (as_b["fault"], escalated["fault"]) == ("ConfigFault", "ConfigFault")
        assert (up.seen, store.reads) == ([], [])
        control = T.ask(client, tok, "crm", "GET", f"{up.url}/crm/accounts")

    assert control["fault"] is None
    assert up.seen[0].header("Authorization") == f"Bearer {KEY_A}"


def test_s4_a_token_naming_one_tenant_signed_with_the_others_key_is_refused(
        tmp_path, data_root):
    """A token naming A but signed with B's key is `ConfigFault`, unsent, no store read;
    control: signed with A's key it is sent. O8, O1, A11."""
    with H.upstream() as up, T.crm_pair(tmp_path, data_root, up.url + "/crm", up.url + "/crm") as (a, b):
        store = H.FakeStore({(a.tenant_id, "crm"): T.static_set(KEY_A),
                             (b.tenant_id, "crm"): T.static_set(KEY_B)})
        signer_a, signer_b = H.FakeSigner("tenant-a"), H.FakeSigner("tenant-b")
        verifier = H.KeyedVerifier({a.tenant_id: signer_a, b.tenant_id: signer_b})
        client = T.client_of(T.deps(
            {a.tenant_id: T.exports_of(a), b.tenant_id: T.exports_of(b)}, store,
            verifier=verifier))
        url = f"{up.url}/crm/accounts"
        crossed = T.ask(client, T.token(a.tenant_id, {("crm", "r")}, signer=signer_b),
                        "crm", "GET", url)
        assert crossed["fault"] == "ConfigFault"
        assert (up.seen, store.reads) == ([], [])
        assert {tenant for *_, tenant in verifier.calls} == {a.tenant_id}
        control = T.ask(client, T.token(a.tenant_id, {("crm", "r")}, signer=signer_a),
                        "crm", "GET", url)

    assert control["fault"] is None
    assert [s.header("Authorization") for s in up.seen] == [f"Bearer {KEY_A}"]


def test_s4_the_proxy_verifies_the_payload_and_signature_the_signer_produced(
        tmp_path, data_root):
    """The verifier is asked about exactly the (payload, signature) the launcher's signer
    produced for the token. O8."""
    with T.rig(tmp_path / "forge", data_root) as r:
        tok = r.tok()
        assert r.ask(tok=tok)["fault"] is None

    assert r.verifier.calls == [(r.signer.payloads[0], "vault:v1:fake-signature-1")]
    claims = A.claims_of_payload(r.signer.payloads[0])  # the signed payload is the claims
    assert claims["investigation"] == T.RUN_ID
