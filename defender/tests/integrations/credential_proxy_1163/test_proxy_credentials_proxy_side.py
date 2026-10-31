"""#1163 repair (proxy side): the OAuth access-token cache keyed per tenant and system and
expiring, the adapter's headers refused or stripped, the Basic echo scrub."""
from __future__ import annotations

import base64
import json
import time

import pytest

from defender.tests.integrations.credential_proxy_1163 import _adapter1163 as A
from defender.tests.integrations.credential_proxy_1163 import _harness as H
from defender.tests.integrations.credential_proxy_1163 import _tenant as T
from defender.tests.tenancy.tenant_1108_p4._support import OTHER_TENANT_ID, published_tenant

BASE = T.BASE_PATH
SECRET_A = "canary-client-secret-1163-tenant-a"
SECRET_B = "canary-client-secret-1163-tenant-b"


def _oauth_files(system: str, base: str, token_url: str) -> dict[str, str]:
    return H.access_files(system, H.declaration(base, scheme=H.oauth_scheme(token_url)),
                          env=H.http_proxy_env(system))


# --- A8 the access-token cache is per tenant and per system ---------------------------------

def test_c3_two_tenants_with_one_token_url_and_set_version_never_share_an_access_token(
        tmp_path, data_root):
    """Tenant B, same token URL and set version as A, exchanges with B's own secret and sends
    B's own access token; A's repeat reuses A's. A8, O1."""
    issued: list[str] = []
    with H.upstream() as auth, H.upstream() as up:
        auth.replies["/token"] = H.token_endpoint(issued)
        files = _oauth_files("crm", up.url + "/crm", auth.url + "/token")
        with published_tenant(tmp_path / "a", root=data_root, repo_name="a", files=files) as a, \
                published_tenant(tmp_path / "b", root=data_root, tenant_id=OTHER_TENANT_ID,
                                 repo_name="b", files=files) as b:
            store = H.FakeStore({(a.tenant_id, "crm"): T.oauth_set(SECRET_A),
                                 (b.tenant_id, "crm"): T.oauth_set(SECRET_B)})
            client = T.client_of(T.deps(
                {a.tenant_id: T.exports_of(a), b.tenant_id: T.exports_of(b)}, store))
            url, grant = f"{up.url}/crm/accounts", {("crm", "r")}
            tok_a, tok_b = T.token(a.tenant_id, grant), T.token(b.tenant_id, grant)
            for tok in (tok_a, tok_b, tok_a):
                assert T.ask(client, tok, "crm", "GET", url)["fault"] is None

    assert issued == ["AT-1-canary-1163", "AT-2-canary-1163"], "one exchange per tenant"
    assert H.carries(auth.seen[0], SECRET_A, client_id=H.CLIENT_ID)
    assert H.carries(auth.seen[1], SECRET_B, client_id=H.CLIENT_ID)
    assert [s.header("Authorization") for s in up.seen] == [
        f"Bearer {issued[0]}", f"Bearer {issued[1]}", f"Bearer {issued[0]}"]


def test_c3_two_systems_of_one_tenant_with_one_token_url_never_share_an_access_token(
        tmp_path, data_root):
    """Systems `crm` and `billing` of one tenant, same token URL, secret and set version, each
    exchange for their own access token, then reuse it. A8."""
    issued: list[str] = []
    with H.upstream() as auth, H.upstream() as up:
        auth.replies["/token"] = H.token_endpoint(issued)
        decls = {s: H.declaration(f"{up.url}/{s}", scheme=H.oauth_scheme(auth.url + "/token"))
                 for s in ("crm", "billing")}
        with A.published(tmp_path / "forge", data_root, decls) as t:
            store = H.FakeStore({(t.tenant_id, s): T.oauth_set() for s in decls})
            client = T.client_of(T.deps({t.tenant_id: T.exports_of(t)}, store))
            tok = T.token(t.tenant_id, {("crm", "r"), ("billing", "r")})
            for system in ("crm", "billing", "crm", "billing"):
                assert T.ask(client, tok, system, "GET",
                             f"{up.url}/{system}/items")["fault"] is None

    assert len(issued) == 2, "one exchange per system"
    assert [(s.path, s.header("Authorization")) for s in up.seen] == [
        ("/crm/items", f"Bearer {issued[0]}"), ("/billing/items", f"Bearer {issued[1]}"),
        ("/crm/items", f"Bearer {issued[0]}"), ("/billing/items", f"Bearer {issued[1]}")]


def test_c3_an_access_token_is_exchanged_again_once_its_stated_life_less_the_margin_is_over(
        tmp_path, data_root):
    """With `expires_in` 32 s (2 s past the 30 s margin) the token is reused while fresh and
    exchanged again after that. A8, O7."""
    issued: list[str] = []

    def short(seen):
        status, headers, body = H.token_endpoint(issued)(seen)
        return status, headers, json.dumps({**json.loads(body), "expires_in": 32}).encode()

    with H.upstream() as auth:
        auth.replies["/token"] = short
        with T.rig(tmp_path / "forge", data_root, lambda u: H.declaration(
                u + BASE, scheme=H.oauth_scheme(auth.url + "/token")), creds=T.oauth_set()) as r:
            tok = r.tok()
            r.ask(tok=tok)
            r.ask(tok=tok)
            fresh_issued = list(issued)
            time.sleep(2.3)
            r.ask(tok=tok)

    assert fresh_issued == ["AT-1-canary-1163"], "control: reused while within its life"
    assert issued == ["AT-1-canary-1163", "AT-2-canary-1163"]
    assert [s.header("Authorization") for s in r.up.seen] == [
        f"Bearer {issued[0]}", f"Bearer {issued[0]}", f"Bearer {issued[1]}"]


# --- O2, O4 the adapter's own headers -------------------------------------------------------

ADAPTER_VALUE = "adapter-supplied-canary-1163"


@pytest.mark.parametrize(("scheme", "name"), [
    pytest.param(H.header_scheme("X-Api-Key"), "x-api-key", id="own-header-lower-case"),
    pytest.param(H.header_scheme("X-Api-Key"), "X-API-KEY", id="own-header-upper-case"),
    pytest.param({"scheme": "bearer", "field": "api_key"}, "authorization",
                 id="authorization-lower-case"),
    pytest.param({"scheme": "bearer", "field": "api_key"}, "AUTHORIZATION",
                 id="authorization-upper-case"),
    pytest.param({"scheme": "bearer", "field": "api_key"}, "Cookie", id="cookie"),
    pytest.param({"scheme": "bearer", "field": "api_key"}, "cookie", id="cookie-lower-case"),
    pytest.param({"scheme": "bearer", "field": "api_key"}, "Proxy-Authorization",
                 id="proxy-authorization"),
    pytest.param({"scheme": "bearer", "field": "api_key"}, "proxy-authorization",
                 id="proxy-authorization-lower-case"),
])
def test_c1_an_adapters_own_credential_header_is_never_forwarded_in_any_case(
        tmp_path, data_root, scheme, name):
    """An adapter's credential-bearing header, however cased, is refused or stripped and the
    declared credential is the only one sent; a plain header passes. O2, O4."""
    with T.rig(tmp_path / "forge", data_root, _decl(scheme)) as r:
        answer = r.ask(headers={name: ADAPTER_VALUE, "Accept": "application/json"})
        assert answer["fault"] in (None, "ConfigFault", "ConfinementFault"), answer
        sent_with = len(r.up.seen)
        control = r.ask(headers={"Accept": "application/json"})

    assert control["fault"] is None
    assert len(r.up.seen) == sent_with + 1, "control: the request without the header is sent"
    for seen in r.up.seen:
        assert ADAPTER_VALUE not in seen.blob()
    credential = [v for k, v in r.up.seen[-1].headers.items()
                  if k.lower() in ("x-api-key", "authorization")]
    assert credential == [H.CANARY_KEY if scheme["scheme"] == "header" else f"Bearer {H.CANARY_KEY}"]


def test_c1_an_adapter_cannot_steer_the_upstream_with_a_host_header(tmp_path, data_root):
    """A `Host` header naming another host is refused or dropped: the upstream sees the declared
    base's own authority. O2."""
    with T.rig(tmp_path / "forge", data_root) as r:
        answer = r.ask(headers={"Host": "attacker.invalid", "host": "attacker.invalid"})
        control = r.ask()

    assert answer["fault"] in (None, "ConfigFault", "ConfinementFault"), answer
    assert control["fault"] is None
    authority = r.up.url.removeprefix("http://")
    assert r.up.seen, "control: something was sent"
    for seen in r.up.seen:
        assert "attacker.invalid" not in seen.blob()
        assert seen.header("Host") == authority


def _decl(scheme):
    return lambda u: H.declaration(u + BASE, scheme=scheme)


# --- O4 the whole injected Authorization header -------------------------------------------

def test_c2_an_upstream_echoing_the_whole_basic_authorization_header_returns_no_encoded_password(
        tmp_path, data_root):
    """An upstream that echoes the received `Authorization` header (`Basic <base64>`) in body
    and header returns neither the base64 of `user:password` nor the password. O4, N6."""
    packed = base64.b64encode(f"svc-reader:{H.CANARY_KEY}".encode()).decode()
    with T.rig(tmp_path / "forge", data_root, _decl(H.basic_scheme()),
               creds=T.basic_set("svc-reader", H.CANARY_KEY)) as r:
        r.up.replies[f"{BASE}/users/x"] = H.echo_secret(lambda s: s.header("Authorization"))
        answer = r.ask()

    assert answer["fault"] is None
    assert r.up.seen[0].header("Authorization") == f"Basic {packed}", "control: Basic was sent"
    shown = json.dumps(answer)
    assert packed not in shown
    assert H.CANARY_KEY not in shown
    assert answer["body"].startswith("before-")
    assert answer["body"].endswith("-after")
