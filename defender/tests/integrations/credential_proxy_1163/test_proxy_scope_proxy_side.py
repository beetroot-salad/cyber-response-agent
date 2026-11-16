"""#1163 repair (proxy side): the proxy's own checks held to their edges: the tenant a token
names, the write route's method, OPTIONS, and the token's claim bounds."""
from __future__ import annotations

import base64
import json
import random
from datetime import timedelta
from urllib.parse import quote, unquote

import pytest

from defender.kit.faults import ConfigFault
from defender.records._alert_input import case_key_of

from defender.tests.integrations.credential_proxy_1163 import _harness as H
from defender.tests.integrations.credential_proxy_1163 import _tenant as T

KEY_A = "canary-tenant-a-key-1163-aaaa11"
KEY_B = "canary-tenant-b-key-1163-bbbb22"
RD = {("identity", "r")}
#: X1: a write pass is `rw` naming its ticket (the third string of the entry).
TK = "T-1"
RW = {("identity", "rw", TK)}
#: The one write route X2 allows: the case system's comment route, one wildcard at the key.
CASE_ROUTE = ("POST", "/tickets/*/comments")
COMMENT = f"/tickets/{TK}/comments"


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

WRITE_ROUTES = (CASE_ROUTE,)


@pytest.mark.parametrize(("method", "fault"), [
    pytest.param("PUT", "ConfinementFault", id="put-on-a-post-route"),
    pytest.param("PATCH", "ConfinementFault", id="patch-on-a-post-route"),
    pytest.param("DELETE", "ConfinementFault", id="delete-on-a-post-route"),
    pytest.param("POST", None, id="post-is-declared"),
])
def test_s3_a_write_route_matches_only_the_method_it_lists(tmp_path, data_root, method, fault):
    """A path declared as a write only for POST is not writable by another method even under a pass on that ticket;
    the declared method is sent. O3, O7, X1."""
    body = '{"q": 1}' if method != "DELETE" else None
    with T.rig(tmp_path / "forge", data_root, lambda u: H.declaration(
            u + T.BASE_PATH, writes=WRITE_ROUTES)) as r:
        answer = r.ask(method, COMMENT, grant=RW, body=body)

    assert answer["fault"] == fault, answer
    assert [(s.method, s.path) for s in r.up.seen] == (
        [] if fault else [(method, f"{T.BASE_PATH}{COMMENT}")])


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
    pytest.param([("identity", "r"), ("identity", "rw", TK)], id="read-then-write"),
    pytest.param([("identity", "rw", TK), ("identity", "r")], id="write-then-read"),
    pytest.param([("identity", "rw", TK), ("identity", "rw", "T-2")], id="two-passes"),
    pytest.param([("identity", "r"), ("identity", "r")], id="same-mode-twice"),
])
def test_s4_a_token_granting_one_system_twice_is_refused(tmp_path, data_root, grant):
    """A validly signed token listing a system twice, whatever the modes, is refused unsent
    and unread, so no entry can pick the stronger mode; one entry is honoured. O8, O3."""
    with T.rig(tmp_path / "forge", data_root, lambda u: H.declaration(
            u + T.BASE_PATH, writes=WRITE_ROUTES)) as r:
        refused = r.ask("POST", COMMENT, tok=_forged(r, grant=grant), body="{}")
        assert (refused["fault"], r.up.seen, r.store.reads) == ("ConfigFault", [], [])
        control = r.ask("POST", COMMENT, tok=_forged(r, grant=[("identity", "rw", TK)]), body="{}")

    assert (control["fault"], [s.method for s in r.up.seen]) == (None, ["POST"])


# --- X1 a write pass names its ticket ----------------------------------------------------------

REFUSED = ("ConfigFault", "ConfinementFault")


def _declaring(**kw):
    return lambda u: H.declaration(u + T.BASE_PATH, **{"writes": (CASE_ROUTE,), **kw})


def _case_keys() -> list[str]:
    """Keys of `case_key_of`'s grammar as a class: every one-character key the grammar admits, edges that stress the
    transport's quoting (`%`, an encoded separator spelled out, `*`, query and fragment characters, dots inside), the
    longest key, and seeded random keys of every length class. The grammar's own predicate filters the candidates."""
    alphabet = [chr(c) for c in range(0x21, 0x7F)]
    rng = random.Random(1471)
    drawn = ["".join(rng.choice(alphabet) for _ in range(rng.choice((2, 3, 8, 40, 127, 128)))) for _ in range(40)]
    edges = ["%41", "%2F", "%252F", "a%", "%", "*", "a*b", "?q=1#f", "..a", "a..", ".a", "a.", "~", "T-1", "x" * 128]
    keys = [k for k in [*alphabet, *edges, *drawn] if case_key_of(k) == k]
    assert len(keys) > 120, "premise: the class is generated, not a hand list"
    assert {"%", "*"} <= set(keys), "premise: the class reaches the quoted characters"
    assert (case_key_of("/"), case_key_of("..")) == (None, None), "premise: the grammar refuses what the class omits"
    return keys


def test_x1_a_pass_comments_on_its_ticket_whatever_the_key_and_on_no_other(tmp_path, data_root):
    """For every key of the case-key grammar, the pass naming it sends a comment on that key (the transport's
    `quote(key, safe="")` form) and refuses one on a longer key, and on a key the segment decodes to only by a second
    decoding; so the proxy compares the decoded segment. X1."""
    keys = _case_keys()
    with T.rig(tmp_path / "forge", data_root, _declaring()) as r:
        for key in keys:
            grant = {("identity", "rw", key)}
            path = f"/tickets/{quote(key, safe='')}/comments"
            r.up.seen.clear()
            sent = r.ask("POST", path, grant=grant, body="{}")
            assert (sent["fault"], [(s.method, s.path) for s in r.up.seen]) == (
                None, [("POST", f"{T.BASE_PATH}{path}")]), key
            r.up.seen.clear()
            other = r.ask("POST", f"/tickets/{quote(key + 'x', safe='')}/comments", grant=grant, body="{}")
            assert (other["fault"] in REFUSED, r.up.seen) == (True, []), key
            if unquote(key) != key:  # the key spelled raw decodes to another key: not the pass's
                raw = r.ask("POST", f"/tickets/{key}/comments", grant=grant, body="{}")
                assert (raw["fault"] in REFUSED, r.up.seen) == (True, []), key


@pytest.mark.parametrize(("method", "path", "sent"), [
    pytest.param("POST", COMMENT, True, id="the-ticket"),
    pytest.param("POST", "/tickets/T-2/comments", False, id="another-ticket"),
    pytest.param("POST", "/tickets/T-10/comments", False, id="a-longer-key"),
    pytest.param("POST", "/tickets/T-/comments", False, id="a-prefix-of-the-key"),
    pytest.param("POST", "/tickets//comments", False, id="an-empty-segment"),
    pytest.param("POST", "/tickets/T-1/comments/x", False, id="one-segment-too-many"),
    pytest.param("POST", "/tickets/T-1", False, id="one-segment-too-few"),
    pytest.param("PUT", COMMENT, False, id="another-method"),
    pytest.param("POST", "/tickets/T-1/transitions", False, id="another-route"),
    pytest.param("POST", "/admin", False, id="an-unlisted-post"),
    pytest.param("DELETE", "/users/x", False, id="an-undeclared-delete"),
    pytest.param("DELETE", "/tickets/T-1", False, id="a-delete-of-the-ticket"),
    pytest.param("PUT", "/search", False, id="a-put-on-a-read-path"),
    pytest.param("POST", "/tickets/..;/comments", False, id="a-path-parameter-in-the-ticket-segment"),
    pytest.param("POST", "/tickets/T-1/..;/comments", False, id="a-path-parameter-after-the-ticket"),
    pytest.param("GET", COMMENT, True, id="a-read-of-the-ticket"),
    pytest.param("GET", "/tickets/T-2/comments", True, id="a-read-of-another-ticket"),
    pytest.param("GET", "/users/x", True, id="a-read-elsewhere"),
    pytest.param("HEAD", "/users/x", True, id="a-head-elsewhere"),
])
def test_x1_under_a_pass_only_the_comment_route_on_its_ticket_writes_and_reads_are_unaffected(
        tmp_path, data_root, method, path, sent):
    """Under the pass naming T-1: a comment on T-1 passes; another ticket, another route, shape or method is refused
    unsent and unread; reads pass as under a read grant. X1."""
    with T.rig(tmp_path / "forge", data_root, _declaring()) as r:
        answer = r.ask(method, path, grant=RW, body='{"q": 1}' if method == "POST" else None)

    if sent:
        assert answer["fault"] is None, answer
        assert [(s.method, s.path) for s in r.up.seen] == [(method, f"{T.BASE_PATH}{path}")]
    else:
        assert (answer["fault"] in REFUSED, r.up.seen, r.store.reads) == (True, [], []), answer


@pytest.mark.parametrize(("declared", "path"), [
    pytest.param({"writes": (CASE_ROUTE, ("PUT", "/tickets/*"))}, COMMENT, id="a-second-write-route"),
    pytest.param({"writes": (CASE_ROUTE, ("POST", "/tickets/*/transitions"))}, COMMENT, id="a-second-route-same-method"),
    pytest.param({"writes": (("POST", "/tickets/*/comments/*"),)}, f"{COMMENT}/x", id="two-wildcards"),
    pytest.param({"writes": (("POST", "/*/*/comments"),)}, COMMENT, id="a-widened-route"),
    pytest.param({"writes": (("POST", f"/tickets/{TK}/comments"),)}, COMMENT, id="no-wildcard"),
    pytest.param({"reads": (("POST", "/search"),)}, COMMENT, id="a-non-get-read"),
    pytest.param({"reads": (("PATCH", "/tickets/*"),)}, COMMENT, id="a-mutating-read"),
])
def test_x1_a_declaration_that_breaks_the_cover_rule_refuses_every_write_under_a_pass(
        tmp_path, data_root, declared, path):
    """A system declaring other than exactly one write route with one wildcard and only GET reads is written on no
    route even on the pass's own ticket: the proxy enforces X2 itself. Control: the compliant declaration sends the
    same request. X1, X2."""
    with T.rig(tmp_path / "forge", data_root, _declaring(**declared)) as r:
        refused = r.ask("POST", path, grant=RW, body="{}")
        assert (refused["fault"] in REFUSED, r.up.seen, r.store.reads) == (True, [], []), refused
    with T.rig(tmp_path / "control", data_root, _declaring(reads=(("GET", "/search"),))) as r:
        control = r.ask("POST", COMMENT, grant=RW, body="{}")

    assert (control["fault"], [s.method for s in r.up.seen]) == (None, ["POST"])


@pytest.mark.parametrize("grant", [
    pytest.param([("identity", "rw")], id="rw-without-a-ticket"),
    pytest.param([("identity", "r", TK)], id="a-ticket-on-a-read-entry"),
    pytest.param([("identity", "rw", TK, "x")], id="four-strings"),
    pytest.param([("identity", "rw", "")], id="an-empty-ticket"),
    pytest.param([("identity", "rw", 7)], id="a-ticket-that-is-not-a-string"),
    pytest.param([("identity", "rw", None)], id="a-null-ticket"),
])
def test_x1_a_token_whose_entry_breaks_the_ticket_binding_is_refused_unsent_and_unread(tmp_path, data_root, grant):
    """A validly signed token with an `rw` entry and no ticket, a ticket on an `r` entry, or any other entry shape is
    refused by the proxy, whatever the request; the pass naming the ticket is sent. X1, C-2."""
    with T.rig(tmp_path / "forge", data_root, _declaring()) as r:
        for method, path in (("POST", COMMENT), ("GET", "/users/x")):
            refused = r.ask(method, path, tok=_forged(r, grant=grant), body="{}")
            assert (refused["fault"] in REFUSED, r.up.seen, r.store.reads) == (True, [], []), (method, refused)
        control = r.ask("POST", COMMENT, tok=_forged(r, grant=[("identity", "rw", TK)]), body="{}")

    assert (control["fault"], [s.method for s in r.up.seen]) == (None, ["POST"])


def _not_case_keys() -> list[str]:
    """Third strings outside `case_key_of`'s grammar, by membership: one-character strings of every code the key refuses
    (separators, control and non-ASCII, space), an over-long key, a key made only of dots, and keys holding a refused
    character."""
    refused = [chr(c) for c in (*range(0x00, 0x21), 0x7F, 0xE9, 0x2603)] + ["/", "\\", ";"]
    candidates = [*refused, "x" * 129, ".", "..", "...", "a/b", "a;b", "a\\b", "a b", "a\n", "é", "T-1/..", "../x"]
    keys = [k for k in candidates if k and case_key_of(k) is None]
    assert len(keys) > 30
    assert {"/", ".."} <= set(keys)
    return keys


def test_x1_a_third_string_that_is_not_a_case_key_is_refused_at_the_mint_and_at_the_proxy(tmp_path, data_root):
    """Every string outside the case-key grammar is refused as a ticket, minted (`ConfigFault`, nothing signed) or
    forged (refused by the proxy, unsent); a key of the grammar mints and is sent. X1, C-2."""
    with T.rig(tmp_path / "forge", data_root, _declaring()) as r:
        for key in _not_case_keys():
            with pytest.raises(ConfigFault):
                r.tok({("identity", "rw", key)})
            forged = r.ask("POST", COMMENT, tok=_forged(r, grant=[("identity", "rw", key)]), body="{}")
            assert (forged["fault"] in REFUSED, r.up.seen) == (True, []), repr(key)
        minted = r.tok(RW)

    assert H.claims_of(minted)["grant"] == [["identity", "rw", TK]], "the entry is [system, rw, ticket] on the wire"


@pytest.mark.parametrize("grant", [
    pytest.param({("identity", "rw")}, id="rw-without-a-ticket"),
    pytest.param({("identity", "r", TK)}, id="a-ticket-on-a-read-entry"),
])
def test_x1_the_mint_refuses_an_entry_that_breaks_the_ticket_binding(tmp_path, data_root, grant):
    """The minter refuses an `rw` entry with no ticket and a ticket on an `r` entry (`ConfigFault`); the two entry
    forms it accepts mint. X1, C-2."""
    with T.rig(tmp_path / "forge", data_root, _declaring()) as r:
        with pytest.raises(ConfigFault):
            r.tok(grant)
        both = r.tok({("identity", "r"), ("cmdb", "rw", TK)})

    assert sorted(H.claims_of(both)["grant"]) == [["cmdb", "rw", TK], ["identity", "r"]]
