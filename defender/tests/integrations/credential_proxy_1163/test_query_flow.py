"""#1163 query flow: the real identity adapter, the http-proxy transport, the real proxy served on
loopback and a recording upstream, over a non-root base (r5 A2)."""
from __future__ import annotations

import inspect
import json
import logging

import pytest

from defender.integrations import _stub_transport as transport
from defender.integrations import identity_adapter
from defender.integrations.confinement import ConfinementFault
from defender.kit.faults import AdapterFault, ConfigFault, TransportFault, UpstreamFault
from defender.tests.integrations.credential_proxy_1163 import _adapter1163 as A
from defender.tests.integrations.credential_proxy_1163 import _harness as H
from defender.tests.integrations.credential_proxy_1163 import _tenant as T

GRANT = {("identity", "r")}
API = "/api/v2"


def _published(tmp_path, data_root, up, **decl):
    return A.published(tmp_path / "forge", data_root,
                       {"identity": H.declaration(up.url + API, **decl)})


def _store(t, **kw):
    return H.FakeStore({} if kw.get("empty") else {(t.tenant_id, "identity"): T.static_set()})


def test_q1_a_query_reaches_the_upstream_with_the_key_and_returns_it_scrubbed(
        tmp_path, data_root, caplog):
    """Adapter -> transport -> proxy -> upstream under a non-root base: the key is injected,
    the echo comes back without it, and the run sees none. O2, O4, A2."""
    caplog.set_level(logging.DEBUG)
    with H.upstream() as up, _published(tmp_path, data_root, up) as t:
        tok = T.token(t.tenant_id, GRANT)
        audit = H.AuditRecorder()
        with A.proxy_for(t, _store(t), audit=audit) as (url, tap):
            ctx = A.ctx_for(tmp_path, T.run_record(t), url, tok)
            result = identity_adapter.get_user(ctx, user="dev.dana")

    assert [(s.method, s.path) for s in up.seen] == [("GET", f"{API}/users/dev.dana")]
    sent = up.seen[0].headers
    assert sent.get("Authorization") == f"Bearer {H.CANARY_KEY}"  # positive control
    assert not any(tok in v for v in sent.values()), "the request token went upstream"
    assert tap.tokens == [tok], "positive control: the proxy was sent the token"
    assert result["path"] == f"{API}/users/dev.dana"
    assert result["authorization"].startswith("Bearer ")
    assert H.CANARY_KEY not in json.dumps(result)
    assert H.CANARY_KEY not in caplog.text
    assert tok not in caplog.text
    (entry,) = audit.records  # the path is relative to the base (A2, A4), never the base's own
    assert {k: entry.get(k) for k in ("tenant", "system", "investigation", "commit", "method",
                                      "path")} == {
        "tenant": t.tenant_id, "system": "identity", "investigation": T.RUN_ID,
        "commit": t.commit, "method": "GET", "path": "/users/dev.dana"}
    assert H.CANARY_KEY not in repr(audit.records)
    assert tok not in repr(audit.records)
    assert tok not in repr(ctx), "the request token shows in the context's repr (O10)"


def test_q1b_the_transport_functions_are_called_as_today_and_routes_are_relative_to_the_base(
        tmp_path, data_root):
    """`http_get`/`http_post` keep their signatures; a declared POST read succeeds relative to
    the base, an undeclared POST is refused unsent. A5, O3, A2."""
    with H.upstream() as up, _published(
            tmp_path, data_root, up, reads=(("POST", "/search"),)) as t:
        tok = T.token(t.tenant_id, GRANT)
        with A.proxy_for(t, _store(t)) as (url, _tap):
            ctx = A.ctx_for(tmp_path, T.run_record(t), url, tok)
            config = transport.load_config(ctx, "identity", "IDENTITY")
            got = transport.http_get(ctx, config, "/users/dev.dana", system="identity")
            posted = transport.http_post(ctx, config, "/search", {"q": 1}, system="identity")
            with pytest.raises(ConfinementFault) as refused:
                transport.http_post(ctx, config, "/users/dev.dana", {}, system="identity")

    assert got["path"] == f"{API}/users/dev.dana"
    assert "path" in posted
    assert refused.value.exit_code == 1
    assert [(s.method, s.path) for s in up.seen] == [
        ("GET", f"{API}/users/dev.dana"), ("POST", f"{API}/search")]
    assert H.CANARY_KEY not in json.dumps(config), "the config handed to adapters holds a key"


def test_q1c_the_adapter_api_gains_no_credential_parameter():
    """The shared transport's signatures are unchanged. A5, H6."""
    names = {fn.__name__: list(inspect.signature(fn).parameters) for fn in (
        transport.http_get, transport.http_post, transport._request)}
    assert names == {
        "http_get": ["ctx", "config", "path", "system", "params"],
        "http_post": ["ctx", "config", "path", "body", "system"],
        "_request": ["ctx", "config", "url", "system", "method", "body"]}


def _redirect(_seen):
    return 302, {"Location": f"{API}/users/elsewhere"}, b""


@pytest.mark.parametrize(("reply", "has_set", "fault", "exit_code", "sent"), [
    pytest.param((401, {}, b'{"detail":"bad key"}'), True, ConfigFault, 2, 1, id="401"),
    pytest.param((403, {}, b'{"detail":"out of scope"}'), True, UpstreamFault, 1, 1, id="403"),
    pytest.param((404, {}, b'{"detail":"no user"}'), True, UpstreamFault, 1, 1, id="404"),
    pytest.param(_redirect, True, UpstreamFault, 1, 1, id="3xx-not-followed"),
    pytest.param((503, {}, b'{"detail":"down"}'), True, TransportFault, 2, 1, id="5xx"),
    pytest.param(None, False, ConfigFault, 2, 0, id="no-credential-set"),
])
def test_q2_the_proxys_fault_class_comes_back_as_the_adapters_fault(
        tmp_path, data_root, reply, has_set, fault, exit_code, sent):
    """Each O7 row the upstream or the store decides is raised by the verb as that class and
    exit; a redirect is not followed. O7, A9."""
    with H.upstream() as up, _published(tmp_path, data_root, up) as t:
        if reply is not None:
            up.replies[f"{API}/users/dev.dana"] = reply
        with A.proxy_for(t, _store(t, empty=not has_set)) as (url, _tap):
            ctx = A.ctx_for(tmp_path, T.run_record(t), url, T.token(t.tenant_id, GRANT))
            with pytest.raises(AdapterFault) as raised:
                identity_adapter.get_user(ctx, user="dev.dana")
    assert type(raised.value) is fault, raised.value
    assert raised.value.exit_code == exit_code
    assert len(up.seen) == sent
    assert H.CANARY_KEY not in str(raised.value)


@pytest.mark.parametrize(("reply", "fault"), [
    pytest.param((400, {}, b'{"detail":"field user.name unknown"}'), UpstreamFault, id="4xx"),
    pytest.param((503, {}, b'{"detail":"field user.name unknown"}'), TransportFault, id="5xx"),
])
def test_q2c_a_systems_error_reaches_the_model_with_the_systems_own_reason(tmp_path, data_root, reply, fault):
    """An upstream error raised through the proxy carries the vendor's own `detail`, as on the docker path: it is what
    the model and pitfalls curation learn from. O7, A9."""
    with H.upstream() as up, _published(tmp_path, data_root, up) as t:
        up.replies[f"{API}/users/dev.dana"] = reply
        with A.proxy_for(t, _store(t)) as (url, _tap):
            ctx = A.ctx_for(tmp_path, T.run_record(t), url, T.token(t.tenant_id, GRANT))
            with pytest.raises(AdapterFault) as raised:
                identity_adapter.get_user(ctx, user="dev.dana")
    assert type(raised.value) is fault, raised.value
    assert "field user.name unknown" in str(raised.value)


def test_q2b_requests_the_declaration_does_not_allow_are_refused_unsent(tmp_path, data_root):
    """`..` leaving the base is a ConfinementFault; another host and the same origin outside
    the base are ConfigFaults; none is sent. The control is the in-base call. O2, O7, A9, A6."""
    with (H.upstream() as up, _published(tmp_path, data_root, up) as t,
          A.proxy_for(t, _store(t)) as (url, _tap)):
        ctx = A.ctx_for(tmp_path, T.run_record(t), url, T.token(t.tenant_id, GRANT))
        config = transport.load_config(ctx, "identity", "IDENTITY")
        with pytest.raises(ConfinementFault) as escaped:
            identity_adapter.get_user(ctx, user="../../secret")
        refused = []
        for foreign in ("http://elsewhere.invalid/x", f"{up.url}/other/x",
                        up.url.replace("http://", "https://") + f"{API}/x"):
            with pytest.raises(ConfigFault) as raised:
                transport._request(ctx, config, foreign, system="identity", method="GET")
            refused.append(raised.value.exit_code)
        assert up.seen == []
        identity_adapter.get_user(ctx, user="dev.dana")
    assert escaped.value.exit_code == 1
    assert refused == [2, 2, 2]
    assert up.paths() == [f"{API}/users/dev.dana"]


def test_q3_an_unreachable_proxy_is_a_transport_fault_and_nothing_is_sent(tmp_path, data_root):
    """Nothing listens at the proxy's address: `TransportFault`, exit 2. O7, A9."""
    with H.upstream() as up, _published(tmp_path, data_root, up) as t:
        ctx = A.ctx_for(tmp_path, T.run_record(t), f"http://127.0.0.1:{H.free_port()}",
                        T.token(t.tenant_id, GRANT))
        with pytest.raises(TransportFault) as raised:
            identity_adapter.get_user(ctx, user="dev.dana")
    assert raised.value.exit_code == 2
    assert up.seen == []


def test_q4_the_proxy_address_comes_from_the_run_not_from_the_models_environment(
        tmp_path, data_root):
    """An address placed in `ctx.env` is not used; the one the run handed in is. A9."""
    decoy = {A.DECOY_PROXY_ENV: f"http://127.0.0.1:{H.free_port()}"}
    with H.upstream() as up, _published(tmp_path, data_root, up) as t:
        tok = T.token(t.tenant_id, GRANT)
        with A.proxy_for(t, _store(t)) as (url, tap):
            record = T.run_record(t)
            via_run = A.ctx_for(tmp_path, record, url, tok, env=decoy)
            assert identity_adapter.get_user(via_run, user="dev.dana")["path"]
            tokens_before = list(tap.tokens)
            env_only = A.ctx_for(tmp_path, record, None, tok, env={A.DECOY_PROXY_ENV: url})
            with pytest.raises(AdapterFault):
                identity_adapter.get_user(env_only, user="dev.dana")
    assert tap.tokens == tokens_before, "the proxy was reached through the environment's address"
    assert len(up.seen) == 1


def test_q5_a_record_is_read_once_and_the_declaration_file_is_not_read_again(
        tmp_path, data_root):
    """Adapters read the record's parsed declaration: editing the file after the record was
    resolved changes the target of no call on it; a fresh record sees the edit. A5."""
    from defender.integrations.confinement import TransportCapture
    from defender.tests.integrations.credential_proxy_1163._target import ACCESS_FILE
    from defender.tests.tenancy.tenant_1108_p4._support import export_dir

    with H.upstream() as old, H.upstream() as new, _published(tmp_path, data_root, old) as t:
        record = T.run_record(t)
        (export_dir(t.tenant, t.commit) / ACCESS_FILE.format(system="identity")).write_text(
            H.declaration(new.url + API), encoding="utf-8")
        targets = []
        for rec in (record, T.run_record(t)):
            capture = TransportCapture()
            ctx = A.ctx_for(tmp_path, rec, f"http://127.0.0.1:{H.free_port()}", "unused",
                            capture=capture)
            with pytest.raises(TransportFault):
                identity_adapter.get_user(ctx, user="dev.dana")
            targets.append(capture.requests[-1].url)
    assert targets == [f"{old.url}{API}/users/dev.dana", f"{new.url}{API}/users/dev.dana"]
