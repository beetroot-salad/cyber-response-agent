"""#1163 query flow: the real identity adapter, the http-proxy transport, the proxy served on
loopback and a recording upstream."""
from __future__ import annotations

import json
import logging
from pathlib import Path

import pytest

from defender.integrations import identity_adapter
from defender.integrations.confinement import ConfinementFault
from defender.kit.faults import ConfigFault, TransportFault, UpstreamFault
from defender.systems.verbs import VerbContext
from defender.tests.integrations.credential_proxy_1163 import _harness as H
from defender.tests.integrations.credential_proxy_1163 import _tenant as T
from defender.tests.integrations.credential_proxy_1163._target import PROXY_URL_ENV, proxy
from defender.tests.tenancy.tenant_1108_p4._support import DEFENDER

GRANT = {("identity", "r")}


def _ctx(tmp_path: Path, record, proxy_url: str, tok: str) -> VerbContext:
    return VerbContext(defender_dir=DEFENDER, run_dir=tmp_path / "run",
                       env={PROXY_URL_ENV: proxy_url}, tenant=record, request_token=tok)


def test_q1_a_query_reaches_the_upstream_with_the_key_and_returns_it_scrubbed(
        tmp_path, data_root, caplog):
    """Adapter -> transport -> proxy -> upstream: the key is injected, echoed back as a marker,
    and audited without its value. O2, O4, O9, Q1."""
    caplog.set_level(logging.DEBUG)
    with H.upstream() as up, T.identity_via_proxy(
            tmp_path / "forge", data_root, H.declaration(up.url + "/")) as t:
        store = H.FakeStore({(t.tenant_id, "identity"): T.static_set()})
        audit = H.AuditRecorder()
        tok = T.token(t.tenant_id, GRANT)
        app = proxy().create_app(T.deps({t.tenant_id: T.exports_of(t)}, store, audit=audit))
        with H.serve_asgi(app) as proxy_url:
            ctx = _ctx(tmp_path, T.run_record(t), proxy_url, tok)
            result = identity_adapter.get_user(ctx, user="dev.dana")

    assert [(s.method, s.path) for s in up.seen] == [("GET", "/users/dev.dana")]
    sent = up.seen[0].headers
    assert sent.get("Authorization") == f"Bearer {H.CANARY_KEY}"  # positive control
    assert not any(tok in value for value in sent.values()), "the request token went upstream"

    assert result["path"] == "/users/dev.dana"
    assert result["authorization"].startswith("Bearer ")
    assert H.CANARY_KEY not in json.dumps(result), "the echoed key reached the adapter"
    assert H.CANARY_KEY not in caplog.text
    assert tok not in caplog.text
    assert tok not in repr(ctx), "the request token shows in the context's repr (O10)"
    assert store.reads == [(t.tenant_id, "identity")]

    assert len(audit.records) == 1
    entry = audit.records[0]
    assert {k: entry.get(k) for k in ("tenant", "system", "investigation", "commit", "route")} == {
        "tenant": t.tenant_id, "system": "identity", "investigation": T.RUN_ID,
        "commit": t.commit, "route": "GET /users/dev.dana"}
    assert "outcome" in entry
    assert H.CANARY_KEY not in repr(audit.records)
    assert tok not in repr(audit.records)


def _redirect(seen):
    return 302, {"Location": "/users/elsewhere"}, b""


@pytest.mark.parametrize(("reply", "store_has_set", "fault", "exit_code"), [
    pytest.param((401, {}, b'{"detail":"bad key"}'), True, ConfigFault, 2, id="401-breaker"),
    pytest.param((403, {}, b'{"detail":"out of scope"}'), True, UpstreamFault, 1, id="403"),
    pytest.param((404, {}, b'{"detail":"no user"}'), True, UpstreamFault, 1, id="404"),
    pytest.param(_redirect, True, UpstreamFault, 1, id="3xx-not-followed"),
    pytest.param(None, False, ConfigFault, 2, id="no-credential-set"),
])
def test_q2_the_proxys_fault_class_comes_back_as_the_adapters_fault(
        tmp_path, data_root, reply, store_has_set, fault, exit_code):
    """Each O7 row the upstream or the store decides surfaces from the verb as its own fault
    class and exit; a redirect is not followed. O7, O2."""
    with H.upstream() as up, T.identity_via_proxy(
            tmp_path / "forge", data_root, H.declaration(up.url + "/")) as t:
        if reply is not None:
            up.replies["/users/dev.dana"] = reply
        store = H.FakeStore({(t.tenant_id, "identity"): T.static_set()} if store_has_set else {})
        app = proxy().create_app(T.deps({t.tenant_id: T.exports_of(t)}, store))
        with H.serve_asgi(app) as proxy_url:
            ctx = _ctx(tmp_path, T.run_record(t), proxy_url, T.token(t.tenant_id, GRANT))
            with pytest.raises((ConfigFault, TransportFault, UpstreamFault,
                                ConfinementFault)) as raised:
                identity_adapter.get_user(ctx, user="dev.dana")

    assert type(raised.value) is fault, raised.value
    assert raised.value.exit_code == exit_code
    assert up.paths() == (["/users/dev.dana"] if store_has_set else [])
    assert H.CANARY_KEY not in str(raised.value)


def test_q3_an_unreachable_proxy_is_a_transport_fault(tmp_path, data_root):
    """Nothing listens at the proxy's address: `TransportFault`, exit 2, nothing sent. O7."""
    with H.upstream() as up, T.identity_via_proxy(
            tmp_path / "forge", data_root, H.declaration(up.url + "/")) as t:
        ctx = _ctx(tmp_path, T.run_record(t), f"http://127.0.0.1:{H.free_port()}",
                   T.token(t.tenant_id, GRANT))
        with pytest.raises(TransportFault) as raised:
            identity_adapter.get_user(ctx, user="dev.dana")
    assert raised.value.exit_code == 2
    assert up.seen == []
