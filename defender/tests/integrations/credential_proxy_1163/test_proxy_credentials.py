"""#1163 how the proxy applies a credential: the declared scheme, the echo scrub, OAuth exchange
and cache, rotation. Fakes inject and record; the proxy judges."""
from __future__ import annotations

import base64
import json

import pytest

from defender.tests.integrations.credential_proxy_1163 import _harness as H
from defender.tests.integrations.credential_proxy_1163 import _tenant as T

BASE = T.BASE_PATH


def _decl(scheme):
    return lambda u: H.declaration(u + BASE, scheme=scheme)


# --- scheme application ----------------------------------------------------------------------

@pytest.mark.parametrize(("scheme", "creds", "header", "expected"), [
    pytest.param(H.basic_scheme(), lambda: T.basic_set("svc-reader", H.CANARY_KEY), "Authorization",
                 "Basic " + base64.b64encode(f"svc-reader:{H.CANARY_KEY}".encode()).decode(),
                 id="basic"),
    pytest.param(H.header_scheme("X-Api-Key"), T.static_set, "X-Api-Key", H.CANARY_KEY,
                 id="header"),
    pytest.param({"scheme": "bearer", "field": "api_key"}, T.static_set, "Authorization",
                 f"Bearer {H.CANARY_KEY}", id="bearer"),
])
def test_c1_each_static_scheme_injects_the_declared_form(
        tmp_path, data_root, scheme, creds, header, expected):
    """Bearer, basic and header schemes send the key in their declared form. A4, O2."""
    with T.rig(tmp_path / "forge", data_root, _decl(scheme), creds=creds()) as r:
        answer = r.ask()

    assert answer["fault"] is None
    assert r.up.seen[0].header(header) == expected


def test_c1_an_adapter_supplied_credential_never_reaches_the_upstream(tmp_path, data_root):
    """A mis-written adapter's own Authorization or key header is not forwarded; a plain Accept
    header is. O2, O4."""
    adapter_value = "adapter-supplied-canary-1163"
    with T.rig(tmp_path / "forge", data_root, _decl(H.header_scheme("X-Api-Key"))) as r:
        answer = r.ask(headers={"Authorization": f"Bearer {adapter_value}",
                                "X-Api-Key": adapter_value, "Accept": "application/json"})

    # Strip-or-refuse is undecided (design gap): either is fine, forwarding is not.
    assert answer["fault"] in (None, "ConfigFault", "ConfinementFault"), answer
    if answer["fault"] is None:
        assert len(r.up.seen) == 1
    for seen in r.up.seen:
        assert adapter_value not in seen.blob()
        assert seen.header("Accept") == "application/json"  # control
        assert seen.header("X-Api-Key") == H.CANARY_KEY


@pytest.mark.parametrize(("oauth_declared", "creds"), [
    pytest.param(True, T.static_set, id="static-set-under-oauth"),
    pytest.param(False, T.oauth_set, id="oauth-set-under-bearer"),
])
def test_c1_a_kind_that_does_not_fit_the_declared_scheme_is_refused_unsent(
        tmp_path, data_root, oauth_declared, creds):
    """A set whose kind does not fit the declared scheme is `ConfigFault` with nothing sent,
    not even an exchange. A4, O7."""
    issued: list[str] = []
    with H.upstream() as auth:
        auth.replies["/token"] = H.token_endpoint(issued)
        scheme = (H.oauth_scheme(auth.url + "/token") if oauth_declared
                  else {"scheme": "bearer", "field": "api_key"})
        with T.rig(tmp_path / "forge", data_root, _decl(scheme), creds=creds()) as r:
            answer = r.ask()

    assert answer["fault"] == "ConfigFault"
    assert (r.up.seen, auth.seen, issued) == ([], [], [])


@pytest.mark.parametrize(("scheme", "fields"), [
    pytest.param({"scheme": "bearer", "field": "api_key"}, {"other": "x" * 20}, id="bearer"),
    pytest.param(H.basic_scheme(), {"username": "u"}, id="basic-no-password"),
    pytest.param(H.header_scheme(), {}, id="header"),
])
def test_c1_a_field_the_scheme_needs_being_missing_is_a_config_fault(
        tmp_path, data_root, scheme, fields):
    """A set lacking a field the declared scheme names is refused unsent. O7, A9."""
    with T.rig(tmp_path / "forge", data_root, _decl(scheme),
               creds=T.custom_set(fields)) as r:
        answer = r.ask()

    assert answer["fault"] == "ConfigFault"
    assert r.up.seen == []


# --- O4 echo scrub ---------------------------------------------------------------------------

def _assert_scrubbed(answer, secret, *, body=("before-", "-after"), header=("hdr-", "-end")):
    assert secret not in json.dumps(answer), "a secret value came back"
    assert answer["body"].startswith(body[0]), answer["body"]
    assert answer["body"].endswith(body[1]), answer["body"]
    assert len(answer["body"]) > len(body[0]) + len(body[1]), "nothing marks the removed value"
    echoes = [v for v in answer["headers"].values() if v.startswith(header[0])]
    assert echoes, answer["headers"]
    assert echoes[0].endswith(header[1]), echoes
    assert len(echoes[0]) > len(header[0]) + len(header[1]), "nothing marks the removed value"


@pytest.mark.parametrize(("scheme", "creds", "secret_of", "secret"), [
    pytest.param({"scheme": "bearer", "field": "api_key"}, T.static_set,
                 lambda s: s.header("Authorization").removeprefix("Bearer "), H.CANARY_KEY,
                 id="static-key"),
    pytest.param(H.basic_scheme(), lambda: T.basic_set("svc-reader", H.CANARY_KEY),
                 lambda s: H.basic_parts(s)[1], H.CANARY_KEY, id="basic-password"),
    pytest.param(H.header_scheme("X-Api-Key"), T.static_set,
                 lambda s: s.header("X-Api-Key"), H.CANARY_KEY, id="custom-header-value"),
])
def test_c2_an_echoed_static_credential_comes_back_as_a_marker(
        tmp_path, data_root, scheme, creds, secret_of, secret):
    """An upstream that echoes the credential in its body and a header returns a marker in
    both, with the surrounding text intact. O4, N6."""
    with T.rig(tmp_path / "forge", data_root, _decl(scheme), creds=creds()) as r:
        r.up.replies[f"{BASE}/users/x"] = H.echo_secret(secret_of)
        answer = r.ask()

    assert answer["fault"] is None
    _assert_scrubbed(answer, secret)


def test_c2_the_basic_username_is_not_a_secret_and_survives_the_scrub(tmp_path, data_root):
    """Echoing username and password returns the username and a marker for the password.
    O4, A4."""
    with T.rig(tmp_path / "forge", data_root, _decl(H.basic_scheme()),
               creds=T.basic_set("svc-reader", H.CANARY_KEY)) as r:
        r.up.replies[f"{BASE}/users/x"] = H.echo_secret(
            lambda s: "{}-and-{}".format(*H.basic_parts(s)))
        answer = r.ask()

    assert "svc-reader-and-" in answer["body"]
    assert H.CANARY_KEY not in json.dumps(answer)


def test_c2_a_static_sets_username_is_public_under_every_scheme(tmp_path, data_root):
    """The scrub and the write API share one rule of what is secret (r7 A19): a static set's
    `username` is not, whatever the declared scheme; its other fields are."""
    with T.rig(tmp_path / "forge", data_root, _decl({"scheme": "bearer", "field": "api_key"}),
               creds=T.custom_set({"api_key": H.CANARY_KEY, "username": "svc-reader"})) as r:
        r.up.replies[f"{BASE}/users/x"] = H.echo_secret(
            lambda s: "svc-reader-and-" + s.header("Authorization").removeprefix("Bearer "))
        answer = r.ask()

    assert answer["fault"] is None
    assert "svc-reader-and-" in answer["body"]
    assert H.CANARY_KEY not in json.dumps(answer)


def test_c2_an_error_reply_does_not_carry_the_credential_either(tmp_path, data_root):
    """A 403 whose body and header echo the key yields a fault answer without it anywhere.
    O4, O7."""
    with T.rig(tmp_path / "forge", data_root) as r:
        r.up.replies[f"{BASE}/users/x"] = (
            403, {"X-Why": f"key {H.CANARY_KEY} refused"}, f"bad {H.CANARY_KEY}".encode())
        answer = r.ask()

    assert answer["fault"] == "UpstreamFault"
    assert H.CANARY_KEY not in json.dumps(answer)


# --- OAuth client credentials ----------------------------------------------------------------

def test_c3_the_client_secret_goes_only_to_the_token_url_and_the_access_token_only_to_the_base(
        tmp_path, data_root):
    """The exchange carries the secret and no token; API calls carry the token and no secret
    or request token; a repeat reuses the token. O2, O4, A8."""
    issued: list[str] = []
    with H.upstream() as auth:
        auth.replies["/token"] = H.token_endpoint(issued)
        with T.rig(tmp_path / "forge", data_root, lambda u: H.declaration(
                u + BASE, scheme=H.oauth_scheme(auth.url + "/token")), creds=T.oauth_set()) as r:
            tok = r.tok()
            first = r.ask(tok=tok)
            second = r.ask(tok=tok)

    assert (first["fault"], second["fault"]) == (None, None)
    assert issued == ["AT-1-canary-1163"]
    assert len(auth.seen) == 1
    assert H.carries(auth.seen[0], H.CANARY_SECRET, client_id=H.CLIENT_ID)  # control
    assert not any(issued[0] in s.blob() or tok in s.blob() for s in auth.seen)
    assert len(r.up.seen) == 2
    for seen in r.up.seen:
        assert seen.header("Authorization") == f"Bearer {issued[0]}"
        assert not H.carries(seen, H.CANARY_SECRET, client_id=H.CLIENT_ID)
        assert tok not in seen.blob()


def test_c3_an_echoed_client_secret_and_access_token_come_back_as_markers(tmp_path, data_root):
    """An upstream naming both in its reply gets markers for both and the client id intact.
    O4."""
    issued: list[str] = []
    with H.upstream() as auth:
        auth.replies["/token"] = H.token_endpoint(issued)
        with T.rig(tmp_path / "forge", data_root, lambda u: H.declaration(
                u + BASE, scheme=H.oauth_scheme(auth.url + "/token")), creds=T.oauth_set()) as r:
            r.up.replies[f"{BASE}/users/x"] = lambda s: (
                200, {"X-Echo": f"hdr-{H.CANARY_SECRET}-{issued[-1]}-end"},
                f"id-{H.CLIENT_ID}-cs-{H.CANARY_SECRET}-at-{issued[-1]}-end".encode())
            answer = r.ask()

    assert answer["fault"] is None
    assert H.CANARY_SECRET not in json.dumps(answer)
    assert issued[0] not in json.dumps(answer)
    assert f"id-{H.CLIENT_ID}-cs-" in answer["body"]
    assert any(v.startswith("hdr-") and v.endswith("-end") for v in answer["headers"].values())


def test_c3_the_request_token_is_never_sent_upstream(tmp_path, data_root):
    """Neither the token nor its signature appears in anything any upstream saw. O4, O8."""
    with T.rig(tmp_path / "forge", data_root) as r:
        tok = r.tok()
        r.ask(tok=tok, headers={"X-Trace": "t1"})

    signature = tok.rpartition(".")[2]
    assert r.up.seen
    assert not any(tok in s.blob() or signature in s.blob() for s in r.up.seen)
    assert r.up.seen[0].header("X-Trace") == "t1"  # control: non-auth headers pass


def test_c3_an_access_token_already_expired_at_issue_is_exchanged_again(tmp_path, data_root):
    """A token endpoint answering `expires_in: 0` gets a fresh exchange on each request, never
    a reuse. O7, A8."""
    issued: list[str] = []

    def short(seen):
        status, headers, body = H.token_endpoint(issued)(seen)
        doc = json.loads(body)
        doc["expires_in"] = 0
        return status, headers, json.dumps(doc).encode()

    with H.upstream() as auth:
        auth.replies["/token"] = short
        with T.rig(tmp_path / "forge", data_root, lambda u: H.declaration(
                u + BASE, scheme=H.oauth_scheme(auth.url + "/token")), creds=T.oauth_set()) as r:
            r.ask()
            r.ask()

    assert len(issued) == 2
    assert [s.header("Authorization") for s in r.up.seen] == [f"Bearer {a}" for a in issued]


@pytest.mark.parametrize(("stated", "exchanges"), [("3600", 1), ("soon", 2), (-5, 2)],
                         ids=["decimal text", "not a number", "negative"])
def test_c3b_a_lifetime_stated_as_text_is_used_and_an_unusable_one_is_no_lifetime(tmp_path, data_root, stated, exchanges):
    """`expires_in: "3600"` is a lifetime (the token is reused); one that is not a non-negative number is no stated
    lifetime: the token is used, not reused, and the request is not refused. O7, A8."""
    issued: list[str] = []

    def answer(seen):
        status, headers, body = H.token_endpoint(issued)(seen)
        return status, headers, json.dumps({**json.loads(body), "expires_in": stated}).encode()

    with H.upstream() as auth:
        auth.replies["/token"] = answer
        with T.rig(tmp_path / "forge", data_root, lambda u: H.declaration(
                u + BASE, scheme=H.oauth_scheme(auth.url + "/token")), creds=T.oauth_set()) as r:
            r.ask()
            r.ask()

    assert len(issued) == exchanges
    assert [s.header("Authorization") for s in r.up.seen] == [f"Bearer {issued[0]}", f"Bearer {issued[-1]}"]


# --- O6 rotation, A8 cache key ---------------------------------------------------------------

def test_c4_a_rotated_static_key_is_used_from_the_next_request(tmp_path, data_root):
    """Replacing the stored set between two requests changes the key the upstream sees. O6."""
    new_key = "canary-rotated-key-1163-c4d5e6"
    with T.rig(tmp_path / "forge", data_root) as r:
        r.ask()
        r.store.sets[(r.t.tenant_id, "identity")] = T.static_set(new_key, version=2)
        r.ask()

    assert [s.header("Authorization") for s in r.up.seen] == [
        f"Bearer {H.CANARY_KEY}", f"Bearer {new_key}"]


def test_c4_a_rotated_oauth_set_drops_the_cached_access_token(tmp_path, data_root):
    """A new credential-set version causes a new exchange carrying the new secret, and the
    next call uses the new token. O6, A8."""
    new_secret = "canary-rotated-secret-1163-f7a8b9"
    issued: list[str] = []
    with H.upstream() as auth:
        auth.replies["/token"] = H.token_endpoint(issued)
        with T.rig(tmp_path / "forge", data_root, lambda u: H.declaration(
                u + BASE, scheme=H.oauth_scheme(auth.url + "/token")), creds=T.oauth_set()) as r:
            r.ask()
            r.store.sets[(r.t.tenant_id, "identity")] = T.oauth_set(new_secret, version=2)
            r.ask()

    assert len(auth.seen) == 2
    assert H.carries(auth.seen[1], new_secret, client_id=H.CLIENT_ID)
    assert [s.header("Authorization") for s in r.up.seen] == [f"Bearer {a}" for a in issued]


@pytest.mark.parametrize("change", ["scopes", "token-url"])
def test_c4_a_merged_change_to_the_auth_block_means_a_fresh_exchange(
        tmp_path, data_root, change):
    """After a merged, published change of scopes or token URL, the next request exchanges
    afresh (at the new URL) rather than reuse the cached token. A8."""
    issued: list[str] = []
    with H.upstream() as auth:
        auth.replies["/token"] = H.token_endpoint(issued)
        auth.replies["/token2"] = H.token_endpoint(issued)
        with T.rig(tmp_path / "forge", data_root, lambda u: H.declaration(
                u + BASE, scheme=H.oauth_scheme(auth.url + "/token")), creds=T.oauth_set()) as r:
            r.ask()
            scheme = (H.oauth_scheme(auth.url + "/token", ("read", "write")) if change == "scopes"
                      else H.oauth_scheme(auth.url + "/token2"))
            r.t.merge({"settings/systems/identity/access.yaml": H.declaration(
                r.up.url + BASE, scheme=scheme)}, "change auth block")
            r.t.publish()
            r.ask()

    assert len(issued) == 2
    assert [s.path for s in auth.seen] == ["/token", "/token" if change == "scopes" else "/token2"]
    assert r.up.seen[1].header("Authorization") == f"Bearer {issued[1]}"
