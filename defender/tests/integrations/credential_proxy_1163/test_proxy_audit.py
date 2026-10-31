"""#1163 O9 at the proxy: one audit record per proxied request, refusals included, and never
a secret value."""
from __future__ import annotations

import json

from defender.tests.integrations.credential_proxy_1163 import _harness as H
from defender.tests.integrations.credential_proxy_1163 import _tenant as T
from defender.tests.integrations.credential_proxy_1163._target import AUDIT_KEYS

BASE = T.BASE_PATH


def test_a1_every_request_is_one_record_naming_who_what_and_how_it_ended(tmp_path, data_root):
    """Sent, upstream-refused and policy-refused requests each leave one record with tenant,
    system, investigation, commit, method, relative path and outcome. O9, A4."""
    with T.rig(tmp_path / "forge", data_root, lambda u: H.declaration(
            u + BASE, writes=(("POST", "/tickets"),))) as r:
        r.up.replies[f"{BASE}/missing"] = (404, {}, b"{}")
        r.ask(path="/users/dana")
        r.ask(path="/missing")
        r.ask("POST", "/tickets", grant={("identity", "r")}, body="{}")
        r.ask("DELETE", "/users/dana")
        r.ask(url=f"{r.up.url}/outside")

    assert len(r.audit.records) == 5
    for record in r.audit.records:
        assert set(AUDIT_KEYS) <= set(record), record
        assert (record["tenant"], record["system"], record["investigation"]) == (
            r.t.tenant_id, "identity", T.RUN_ID)
        assert record["commit"] == r.t.commit
    assert [(x["method"], x["outcome"]) for x in r.audit.records] == [
        ("GET", "sent 200"), ("GET", "sent 404"), ("POST", "ConfinementFault"),
        ("DELETE", "ConfinementFault"), ("GET", "ConfigFault")]
    assert [x["path"] for x in r.audit.records[:4]] == [
        "/users/dana", "/missing", "/tickets", "/users/dana"]


def test_a1_a_request_refused_on_its_token_is_still_one_record(tmp_path, data_root):
    """An unverifiable and a garbage token are each audited with their fault class,
    not in the fields asserted. O9, O8."""
    with T.rig(tmp_path / "forge", data_root) as r:
        r.verifier = H.FakeVerifier(False)
        r.rebuild()
        r.ask(tok=r.tok())
        r.ask(tok="not-a-token")

    assert [x["outcome"] for x in r.audit.records] == ["ConfigFault", "ConfigFault"]


def test_a1_no_secret_value_is_in_the_audit(tmp_path, data_root):
    """Across static and OAuth requests, the key, client secret, access token, request token
    and its signature are absent from every record. O9, O4."""
    issued: list[str] = []
    with H.upstream() as auth:
        auth.replies["/token"] = H.token_endpoint(issued)
        with T.rig(tmp_path / "forge", data_root, lambda u: H.declaration(
                u + BASE, scheme=H.oauth_scheme(auth.url + "/token")),
                creds=T.oauth_set()) as r:
            tok = r.tok()
            r.ask(tok=tok)
            r.store.sets[(r.t.tenant_id, "identity")] = T.static_set()
            r.ask(tok=tok)  # kind mismatch: refused
            r.ask(tok=tok, url=f"{r.up.url}/outside")

    text = json.dumps(r.audit.records)
    assert len(r.audit.records) == 3
    for secret in (H.CANARY_KEY, H.CANARY_SECRET, issued[0], tok, tok.rpartition(".")[2]):
        assert secret not in text
