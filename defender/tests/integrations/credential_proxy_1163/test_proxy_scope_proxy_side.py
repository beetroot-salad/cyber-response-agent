"""#1163 repair (proxy side): the proxy's own checks held to their edges: the tenant a token
names, the write route's method, OPTIONS, and the token's claim bounds."""
from __future__ import annotations

import base64
import json
from datetime import timedelta

import pytest

from defender.tests.integrations.credential_proxy_1163 import _harness as H
from defender.tests.integrations.credential_proxy_1163 import _tenant as T

KEY_A = "canary-tenant-a-key-1163-aaaa11"
KEY_B = "canary-tenant-b-key-1163-bbbb22"
RD = {("identity", "r")}
RW = {("identity", "rw")}


def _forged(r, *, investigation: str | None = None, grant=None) -> str:
    """A token whose claims are the minter's own except `investigation` and `grant`, signed by
    the rig's signer: the mint's own shape checks are bypassed."""
    claims = H.claims_of(r.tok())
    if investigation is not None:
        claims["investigation"] = investigation
    if grant is not None:
        claims["grant"] = [list(entry) for entry in grant]
    payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
    return f"{payload}.{r.signer.sign(payload.encode())}"


# --- O1, O8 the tenant a token names selects the key it is verified with ---------------------

def test_s4_each_of_two_tenants_tokens_is_verified_with_its_own_key(tmp_path, data_root):
    """Each tenant's token signed with its own key is sent as that tenant, and a token naming
    either tenant signed with the other's key is refused, whichever tenant comes first. O8, O1, A11."""
    with H.upstream() as up, T.crm_pair(tmp_path, data_root, up.url + "/crm", up.url + "/crm") as (a, b):
        store = H.FakeStore({(a.tenant_id, "crm"): T.static_set(KEY_A),
                             (b.tenant_id, "crm"): T.static_set(KEY_B)})
        signer_a, signer_b = H.FakeSigner("tenant-a"), H.FakeSigner("tenant-b")
        verifier = H.KeyedVerifier({a.tenant_id: signer_a, b.tenant_id: signer_b})
        client = T.client_of(T.deps(
            {a.tenant_id: T.exports_of(a), b.tenant_id: T.exports_of(b)}, store,
            verifier=verifier))
        url, grant = f"{up.url}/crm/accounts", {("crm", "r")}

        a_as_b = T.ask(client, T.token(a.tenant_id, grant, signer=signer_b), "crm", "GET", url)
        b_as_a = T.ask(client, T.token(b.tenant_id, grant, signer=signer_a), "crm", "GET", url)
        assert (a_as_b["fault"], b_as_a["fault"]) == ("ConfigFault", "ConfigFault")
        assert (up.seen, store.reads) == ([], [])
        own_b = T.ask(client, T.token(b.tenant_id, grant, signer=signer_b), "crm", "GET", url)
        own_a = T.ask(client, T.token(a.tenant_id, grant, signer=signer_a), "crm", "GET", url)

    assert (own_a["fault"], own_b["fault"]) == (None, None)
    assert [s.header("Authorization") for s in up.seen] == [f"Bearer {KEY_B}", f"Bearer {KEY_A}"]
    assert {tenant for *_, tenant in verifier.calls} == {a.tenant_id, b.tenant_id}


# --- O3 write routes are matched on the method too -------------------------------------------

WRITE_ROUTES = (("PUT", "/tickets/*"), ("DELETE", "/tickets/*"))


@pytest.mark.parametrize(("method", "fault"), [
    pytest.param("POST", "ConfinementFault", id="post-on-a-put-delete-route"),
    pytest.param("PATCH", "ConfinementFault", id="patch-on-a-put-delete-route"),
    pytest.param("PUT", None, id="put-is-declared"),
    pytest.param("DELETE", None, id="delete-is-declared"),
])
def test_s3_a_write_route_matches_only_the_methods_it_lists(tmp_path, data_root, method, fault):
    """A path declared as a write only for PUT and DELETE is not writable by another method
    even under `rw`; the declared methods are sent. O3, O7."""
    body = '{"q": 1}' if method != "DELETE" else None
    with T.rig(tmp_path / "forge", data_root, lambda u: H.declaration(
            u + T.BASE_PATH, writes=WRITE_ROUTES)) as r:
        answer = r.ask(method, "/tickets/7", grant=RW, body=body)

    assert answer["fault"] == fault, answer
    assert [(s.method, s.path) for s in r.up.seen] == (
        [] if fault else [(method, f"{T.BASE_PATH}/tickets/7")])


@pytest.mark.parametrize("grant", [RD, RW], ids=["read-grant", "write-grant"])
def test_s3_options_is_not_a_read(tmp_path, data_root, grant):
    """OPTIONS on a path no route lists is refused as undeclared, under a read or a write
    grant; GET on the same path is sent. O3, O7."""
    with T.rig(tmp_path / "forge", data_root, lambda u: H.declaration(
            u + T.BASE_PATH, writes=WRITE_ROUTES)) as r:
        refused = r.ask("OPTIONS", "/users/x", grant=grant)
        assert (refused["fault"], r.up.seen, r.store.reads) == ("ConfinementFault", [], [])
        control = r.ask("GET", "/users/x", grant=grant)

    assert (control["fault"], r.up.paths()) == (None, [f"{T.BASE_PATH}/users/x"])


# --- O8 token claim bounds --------------------------------------------------------------------

def test_s4_a_token_expired_twenty_seconds_ago_is_refused(tmp_path, data_root):
    """A token whose expiry passed 20 s ago is refused unsent and unread (no clock leeway);
    a token with an hour left is sent. O8, O7."""
    with T.rig(tmp_path / "forge", data_root) as r:
        expired = r.ask(tok=r.tok(expires_in=timedelta(seconds=-20)))
        assert (expired["fault"], r.up.seen, r.store.reads) == ("ConfigFault", [], [])
        control = r.ask()

    assert (control["fault"], r.up.paths()) == (None, [f"{T.BASE_PATH}/users/x"])


def test_s4_a_token_naming_no_investigation_is_refused(tmp_path, data_root):
    """A validly signed token whose investigation is empty is refused unsent and unread; the
    same token naming a run is sent. O8, O7."""
    with T.rig(tmp_path / "forge", data_root) as r:
        refused = r.ask(tok=_forged(r, investigation=""))
        assert (refused["fault"], r.up.seen, r.store.reads) == ("ConfigFault", [], [])
        control = r.ask(tok=_forged(r, investigation=T.RUN_ID))

    assert (control["fault"], r.up.paths()) == (None, [f"{T.BASE_PATH}/users/x"])
    assert r.audit.records[-1]["investigation"] == T.RUN_ID


@pytest.mark.parametrize("grant", [
    pytest.param([("identity", "r"), ("identity", "rw")], id="read-then-write"),
    pytest.param([("identity", "rw"), ("identity", "r")], id="write-then-read"),
    pytest.param([("identity", "r"), ("identity", "r")], id="same-mode-twice"),
])
def test_s4_a_token_granting_one_system_twice_is_refused(tmp_path, data_root, grant):
    """A validly signed token listing a system twice, whatever the modes, is refused unsent
    and unread, so no entry can pick the stronger mode; one entry is honoured. O8, O3."""
    with T.rig(tmp_path / "forge", data_root, lambda u: H.declaration(
            u + T.BASE_PATH, writes=WRITE_ROUTES)) as r:
        refused = r.ask("PUT", "/tickets/7", tok=_forged(r, grant=grant), body="{}")
        assert (refused["fault"], r.up.seen, r.store.reads) == ("ConfigFault", [], [])
        control = r.ask("PUT", "/tickets/7", tok=_forged(r, grant=[("identity", "rw")]), body="{}")

    assert (control["fault"], [s.method for s in r.up.seen]) == (None, ["PUT"])
