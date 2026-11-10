"""#1163 query flow: the real identity adapter, the http-proxy transport, the real proxy served on
loopback and a recording upstream, over a non-root base (r5 A2)."""
from __future__ import annotations

import base64
import contextlib
import inspect
import json
import logging
from urllib.parse import urlsplit

import pytest

from defender.kit import transport
from defender.integrations import elastic_adapter, identity_adapter
from defender.kit.faults import ConfinementFault
from defender.integrations.confinement import (
    TransportCapture,
    confine_read_endpoint,
)
from defender.kit.faults import AdapterFault, ConfigFault, TransportFault, UpstreamFault
from defender.tests.integrations.credential_proxy_1163 import _adapter1163 as A
from defender.tests.integrations.credential_proxy_1163 import _harness as H
from defender.tests.integrations.credential_proxy_1163 import _tenant as T
from defender.tests.support.shared._tls_server import chain, tls_server
from defender.tests.tenancy.tenant_1108_p4._support import export_dir, published_tenant

GRANT = {("identity", "r")}
API = "/api/v2"


def _published(tmp_path, data_root, up, **decl):
    return A.published(tmp_path / "forge", data_root,
                       {"identity": H.declaration(up.url + API, **decl)})


def _store(t, **kw):
    return H.FakeStore({} if kw.get("empty") else {(t.tenant_id, "identity"): T.static_set()})


def test_q1_a_query_reaches_the_upstream_with_the_key_and_returns_the_echo_unaltered(
        tmp_path, data_root, caplog):
    """Adapter -> transport -> proxy -> upstream under a non-root base: the key is injected and
    the upstream's echo of it comes back as sent. O2, A2, #1412 O7."""
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
    assert result["authorization"] == f"Bearer {H.CANARY_KEY}"
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
    """`transport.request` sends a GET and a declared POST read relative to the base; an
    undeclared POST is refused unsent. A5, O3, A2; #1391 r5 T1."""
    with H.upstream() as up, _published(
            tmp_path, data_root, up, reads=(("POST", "/search"),)) as t:
        tok = T.token(t.tenant_id, GRANT)
        with A.proxy_for(t, _store(t)) as (url, _tap):
            ctx = A.ctx_for(tmp_path, T.run_record(t), url, tok)
            config = transport.load_config(ctx, "identity", "IDENTITY")
            got = transport.request(ctx, "identity", "GET", "/users/{user}", {"user": "dev.dana"},
                                    timeout_sec=10)
            posted = transport.request(ctx, "identity", "POST", "/search", body={"q": 1},
                                       timeout_sec=10)
            with pytest.raises(ConfinementFault) as refused:
                transport.request(ctx, "identity", "POST", "/users/dev.dana", body={},
                                  timeout_sec=10)

    assert got["path"] == f"{API}/users/dev.dana"
    assert "path" in posted
    assert refused.value.exit_code == 1
    assert [(s.method, s.path) for s in up.seen] == [
        ("GET", f"{API}/users/dev.dana"), ("POST", f"{API}/search")]
    assert H.CANARY_KEY not in json.dumps(config), "the config handed to adapters holds a key"


def test_q1c_the_adapter_api_gains_no_credential_parameter():
    """The shared transport takes no credential: the proxy holds it. A5, H6; #1391 r5 T1."""
    names = {fn.__name__: list(inspect.signature(fn).parameters) for fn in (
        transport.request, transport.host_write)}
    assert names == {
        "request": ["ctx", "system", "method", "template", "values", "query", "body",
                    "timeout_sec", "answer", "error_detail"],
        "host_write": ["ctx", "system", "method", "template", "values", "body", "timeout_sec"]}


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


def test_q2d_a_large_reply_arrives_whole_and_one_over_the_limit_tells_the_model_to_narrow(
        tmp_path, data_root):
    """A 3 MiB reply comes back through adapter, transport and proxy as today's parsed answer; a
    200 over the limit raises the agent-fixable `UpstreamFault` saying to narrow the query.
    #1412 O2, O3."""
    document = {"user": "dev.dana", "pad": "x" * (3 << 20)}
    with H.upstream() as up, _published(tmp_path, data_root, up) as t:
        up.replies[f"{API}/users/dev.dana"] = (200, {"Content-Type": "application/json"},
                                               json.dumps(document).encode())
        tok = T.token(t.tenant_id, GRANT)
        with A.proxy_for(t, _store(t)) as (url, _tap):
            whole = identity_adapter.get_user(A.ctx_for(tmp_path, T.run_record(t), url, tok), user="dev.dana")
        with A.proxy_for(t, _store(t), max_response_bytes=1 << 20) as (url, _tap), \
                pytest.raises(AdapterFault) as raised:
            identity_adapter.get_user(A.ctx_for(tmp_path, T.run_record(t), url, tok), user="dev.dana")

    assert whole == document
    assert type(raised.value) is UpstreamFault
    assert (raised.value.exit_code, raised.value.proxy_own) == (1, False)
    assert "narrow" in str(raised.value)


def test_q2b_requests_the_declaration_does_not_allow_are_refused_unsent(tmp_path, data_root):
    """`..` is a ConfinementFault before the proxy is asked (#1391 r5 T2); a URL to another host,
    or to the same origin outside the base, handed to the proxy is a ConfigFault; none is sent.
    The control is the in-base call. O2, O7, A9, A6."""
    with (H.upstream() as up, _published(tmp_path, data_root, up) as t,
          A.proxy_for(t, _store(t)) as (url, _tap)):
        ctx = A.ctx_for(tmp_path, T.run_record(t), url, T.token(t.tenant_id, GRANT))
        with pytest.raises(ConfinementFault) as escaped:
            identity_adapter.get_user(ctx, user="../../secret")
        refused = []
        for foreign in ("http://elsewhere.invalid/x", f"{up.url}/other/x",
                        up.url.replace("http://", "https://") + f"{API}/x"):
            with pytest.raises(ConfigFault) as raised:
                transport._proxy_request(ctx, foreign, system="identity", method="GET",
                                         body=None, timeout_sec=10)
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


# --- #1391 O3: Elastic through the proxy --------------------------------------------------------

ES_BASIC = "Basic " + base64.b64encode(f"svc-reader:{H.CANARY_KEY}".encode()).decode()
HIT = {"@timestamp": "2026-11-03T10:00:00Z", "user": {"name": "root"}}


_elastic = A.elastic_proxied


def test_1391_o3_query_is_a_search_of_the_events_index_with_basic_auth_added_by_the_proxy(
        tmp_path, data_root):
    """`query` sends one POST <base>/<events index>/_search, Basic auth added by the proxy,
    and returns the hits in the verb's envelope. #1391 O3."""
    with H.upstream() as up, _elastic(tmp_path, data_root, up.url) as (ctx, tap):
        up.replies[f"/{A.ELASTIC_EVENTS}/_search"] = (200, {"Content-Type": "application/json"},
            json.dumps({"hits": {"total": {"value": 1}, "hits": [{"_source": HIT}]}}).encode())
        result = elastic_adapter.VERBS["query"](ctx, native_query="user.name:root")

    assert [(s.method, s.path) for s in up.seen] == [
        ("POST", f"/{A.ELASTIC_EVENTS}/_search?ignore_unavailable=true")]
    assert up.seen[0].header("Authorization") == ES_BASIC
    assert json.loads(up.seen[0].body)["query"]["bool"]["must"] == [
        {"query_string": {"query": "user.name:root"}}]
    assert len(tap.tokens) == 1
    assert result == {"index": A.ELASTIC_EVENTS, "total": 1, "returned": 1, "sort": "desc",
                      "truncated": False, "hits": [HIT]}


def test_1391_o3_health_check_reads_elasticsearch_under_its_private_ca_and_reports_no_kibana(
        tmp_path, data_root):
    """Over https with the declaration's `ca`, settings with no URL/Kibana/container key pass
    and `health-check` is one GET /_cluster/health reported without Kibana. #1391 O3, O4, D2, P5."""
    pki = chain("lab")
    health = json.dumps({"status": "green", "number_of_nodes": 3}).encode()
    with (tls_server(tmp_path, lambda *_: (200, health), served=pki.served()) as server,
          _elastic(tmp_path, data_root, server.url, ca=pki.root.cert) as (ctx, _tap)):
        assert elastic_adapter.check_settings(ctx.tenant) is None
        result = elastic_adapter.VERBS["health-check"](ctx)

    assert [(m, p) for m, p, _ in server.seen] == [("GET", "/_cluster/health")]
    assert server.seen[0][2].get("authorization") == ES_BASIC
    assert result == {"system": "elastic", "connected": True, "elasticsearch": "green",
                      "nodes": 3}


def test_1391_o3_under_a_base_with_a_path_esql_and_health_reach_it_relative_to_the_base(
        tmp_path, data_root):
    """Base `<host>/es`: the adapter's allowlist admits `/_query` and `/_cluster/health` relative
    to the base; both reach `/es/...` and esql returns its rows. #1391 O3."""
    rows = {"columns": [{"name": "user.name", "type": "keyword"}], "values": [["root"]]}
    q = f"FROM {A.ELASTIC_EVENTS} | KEEP user.name | LIMIT 1"
    with H.upstream() as up, _elastic(tmp_path, data_root, up.url + "/es") as (ctx, _tap):
        up.replies["/es/_query"] = (200, {}, json.dumps(rows).encode())
        up.replies["/es/_cluster/health"] = (200, {}, b'{"status": "yellow", "number_of_nodes": 1}')
        got = elastic_adapter.VERBS["esql"](ctx, query=q)
        health = elastic_adapter.VERBS["health-check"](ctx)

    assert [(s.method, s.path) for s in up.seen] == [
        ("POST", "/es/_query?format=json"), ("GET", "/es/_cluster/health")]
    assert json.loads(up.seen[0].body) == {"query": q}
    assert got == {"query": q, "columns": rows["columns"], "row_count": 1, "values": [["root"]]}
    assert health["elasticsearch"] == "yellow"


@pytest.mark.parametrize("index", [".security-7", "*", "logs-*,alerts-*,.security-7", "-logs-*"])
def test_1391_o3_an_index_outside_the_configured_patterns_never_reaches_the_proxy(
        tmp_path, data_root, index):
    """`query` on an index whose reach widens is a ConfinementFault before the proxy is asked;
    control: an index under the events pattern is sent. #1391 O3, P3."""
    with H.upstream() as up, _elastic(tmp_path, data_root, up.url) as (ctx, tap):
        with pytest.raises(ConfinementFault):
            elastic_adapter.VERBS["query"](ctx, native_query="*", index=index)
        assert (tap.tokens, up.seen) == ([], [])
        elastic_adapter.VERBS["query"](ctx, native_query="*", index="logs-2026.11.03")

    assert [s.path.split("?")[0] for s in up.seen] == ["/logs-2026.11.03/_search"]


@pytest.mark.parametrize("base_path", ["", "/es"], ids=["root-base", "path-base"])
@pytest.mark.parametrize("index", ["logs-/..", "logs-/../.."])
def test_1391_o3_an_index_that_resolves_to_an_unlisted_endpoint_is_refused_before_the_proxy(
        tmp_path, data_root, base_path, index):
    """An index inside the events pattern whose path resolves to `/_search` is a ConfinementFault
    with nothing sent, at the root and at a base with a path; the listed read passes on the same
    channel. #1391 O3, P3, F5."""
    with H.upstream() as up, _elastic(tmp_path, data_root, up.url + base_path) as (ctx, tap):
        with pytest.raises(ConfinementFault):
            elastic_adapter.VERBS["query"](ctx, native_query="*", index=index)
        refused = (list(tap.tokens), list(up.seen))  # a snapshot: the control call below appends
        elastic_adapter.VERBS["query"](ctx, native_query="*", index="logs-2026.11.03")

    assert refused == ([], [])
    assert [s.path.split("?")[0] for s in up.seen] == [f"{base_path}/logs-2026.11.03/_search"]


def _answered(status: int) -> tuple[int, dict, bytes]:
    return status, {"Content-Type": "application/json"}, b'{"error": {"reason": "no privilege"}}'


@pytest.mark.parametrize(("verb", "kw", "path", "status", "fault"), [
    pytest.param("esql", {"query": "FROM .security-7 | LIMIT 1"}, "/_query", 401, ConfigFault,
                 id="esql-401"),
    pytest.param("esql", {"query": "FROM .security-7 | LIMIT 1"}, "/_query", 403, UpstreamFault,
                 id="esql-403-role-lacks-the-index"),
    pytest.param("esql", {"query": "FROM .security-7 | LIMIT 1"}, "/_query", 503, TransportFault,
                 id="esql-503"),
    pytest.param("query", {"native_query": "*"}, f"/{A.ELASTIC_EVENTS}/_search", 403,
                 ConfigFault, id="query-403"),
    pytest.param("alerts", {"native_query": "*"}, f"/{A.ELASTIC_ALERTS}/_search", 403,
                 ConfigFault, id="alerts-403"),
    pytest.param("esql", {"query": "FROM .security-7 | LIMIT 1"}, "/_query", 403,
                 UpstreamFault, id="esql-403"),
])
def test_1391_o3_elastic_faults_follow_the_proxys_classification(
        tmp_path, data_root, verb, kw, path, status, fault):
    """ES|QL `FROM .security-7` passes the adapter and is sent; 401 and 5xx come back as
    ConfigFault and TransportFault. A 403 on `query`/`alerts` (whose index is confined to the
    configured ones) is a setup fault (ConfigFault); on `esql`, which names its own indexes, it
    is the agent's (UpstreamFault). #1391 O3, D8, D11; PR #1409 review (human decision)."""
    with H.upstream() as up, _elastic(tmp_path, data_root, up.url) as (ctx, _tap):
        up.replies[path] = _answered(status)
        with pytest.raises(AdapterFault) as raised:
            elastic_adapter.VERBS[verb](ctx, **kw)

    assert type(raised.value) is fault, raised.value
    if status == 403 and fault is ConfigFault:
        assert "`read`" in str(raised.value), "the setup fault does not name the missing privilege"
    assert [s.path.split("?")[0] for s in up.seen] == [path]


@pytest.mark.parametrize(("verb", "kw", "path"), [
    pytest.param("query", {"native_query": "*"}, f"/{A.ELASTIC_EVENTS}/_search", id="query"),
    pytest.param("esql", {"query": f"FROM {A.ELASTIC_EVENTS} | LIMIT 1"}, "/_query", id="esql"),
])
def test_1391_elastic_query_errors_reach_the_agent_as_their_root_cause(
        tmp_path, data_root, verb, kw, path):
    """A 400 in Elasticsearch's error shape reaches the agent as its root cause's type and reason,
    not the whole nested error document (shard lists, stack of causes). PR #1409 review."""
    filler = [{"shard": n, "index": "logs", "reason": {"type": "x", "reason": "y" * 200}}
              for n in range(50)]
    body = json.dumps({"error": {
        "root_cause": [{"type": "query_shard_exception", "reason": "Failed to parse query [a:(]"}],
        "type": "search_phase_execution_exception", "reason": "all shards failed",
        "failed_shards": filler}, "status": 400}).encode()
    with H.upstream() as up, _elastic(tmp_path, data_root, up.url) as (ctx, _tap):
        up.replies[path] = (400, {"Content-Type": "application/json"}, body)
        with pytest.raises(UpstreamFault) as raised:
            elastic_adapter.VERBS[verb](ctx, **kw)

    text = str(raised.value)
    assert "query_shard_exception: Failed to parse query [a:(]" in text, text
    assert "failed_shards" not in text, text
    assert len(text) < 500, text


def test_1391_an_elastic_error_given_as_text_reaches_the_agent_as_that_text(tmp_path, data_root):
    """Elasticsearch's plain error form (`{"error": "<text>", "status": 400}`) reaches the agent
    as the text itself. PR #1409 review."""
    body = json.dumps({"error": "no handler found for uri [/x] and method [POST]",
                       "status": 400}).encode()
    with H.upstream() as up, _elastic(tmp_path, data_root, up.url) as (ctx, _tap):
        up.replies["/_query"] = (400, {"Content-Type": "application/json"}, body)
        with pytest.raises(UpstreamFault) as raised:
            elastic_adapter.VERBS["esql"](ctx, query=f"FROM {A.ELASTIC_EVENTS} | LIMIT 1")

    assert str(raised.value).endswith(": no handler found for uri [/x] and method [POST]"), (
        raised.value)


@pytest.mark.parametrize(("status", "fault", "names"), [
    pytest.param(401, ConfigFault, None, id="401"),
    pytest.param(403, ConfigFault, "monitor", id="403-names-the-monitor-privilege"),
    pytest.param(503, TransportFault, None, id="503"),
])
def test_1391_o3_health_check_faults_by_the_reply_and_a_403_names_the_monitor_privilege(
        tmp_path, data_root, status, fault, names):
    """`health-check` maps 401 to ConfigFault, 5xx to TransportFault, and 403 to a ConfigFault
    naming the cluster `monitor` privilege (a setup mistake). #1391 O3, D11."""
    with H.upstream() as up, _elastic(tmp_path, data_root, up.url) as (ctx, _tap):
        up.replies["/_cluster/health"] = _answered(status)
        with pytest.raises(AdapterFault) as raised:
            elastic_adapter.VERBS["health-check"](ctx)

    assert type(raised.value) is fault, raised.value
    if names:
        assert names in str(raised.value), raised.value
    assert [s.path for s in up.seen] == ["/_cluster/health"], "the request was never sent"


# Retired by #1391 O1/O2, as its docstring said: `test_1391_o3_elastic_without_the_http_proxy_method_
# is_a_settings_fault_naming_the_key` (D12's interim `ELASTIC_TRANSPORT` refusal). There is no
# access-method key now; a leftover `ELASTIC_TRANSPORT` is refused as a key Elastic does not read
# (`test_1391_o2_a_key_the_adapter_does_not_read_is_refused_by_name[elastic-transport]`).


def test_1391_o3_elastic_on_the_http_proxy_method_with_no_access_yaml_is_a_settings_fault(
        tmp_path, data_root):
    """Elastic's settings with no access declaration beside them are a ConfigFault naming it at the
    settings check and at a verb, nothing sent. #1391 O3, P1."""
    with H.upstream() as up, _elastic(tmp_path, data_root, up.url,
                                      declared=False) as (ctx, tap):
        with pytest.raises(ConfigFault, match="system elastic access"):  # #1366 DC6
            elastic_adapter.check_settings(ctx.tenant)
        with pytest.raises(ConfigFault, match="system elastic access"):
            elastic_adapter.VERBS["query"](ctx, native_query="*")

    assert (tap.tokens, up.seen) == ([], [])


@pytest.mark.parametrize("leftover", ["ELASTICSEARCH_URL", "KIBANA_URL"])
def test_1391_o3_a_leftover_base_key_beside_the_declaration_is_refused_by_name(
        tmp_path, data_root, leftover):
    """`ELASTICSEARCH_URL`/`KIBANA_URL` in config.env beside a declaration is a ConfigFault naming
    it at the settings check and at a verb, nothing sent. #1391 O3, F4."""
    with H.upstream() as up, _elastic(tmp_path, data_root, up.url,
                                      env_extra=f'{leftover}="https://old.example:9200"\n') as (ctx, tap):
        with pytest.raises(ConfigFault, match=leftover):
            elastic_adapter.check_settings(ctx.tenant)
        with pytest.raises(ConfigFault, match=leftover):
            elastic_adapter.VERBS["query"](ctx, native_query="*")

    assert (tap.tokens, up.seen) == ([], [])


def test_1391_o3_each_elastic_request_is_captured_once_and_reaches_the_proxy_once(
        tmp_path, data_root):
    """Every Elastic verb records exactly one capture and makes one proxy call (one upstream
    request); each capture passes the endpoint allowlist at the root base. #1391 O3, F8, P3."""
    capture = TransportCapture()
    hits = json.dumps({"hits": {"total": {"value": 0}, "hits": []}}).encode()
    verbs = (("query", {"native_query": "*"}, "POST"), ("alerts", {"native_query": "*"}, "POST"),
             ("esql", {"query": f"FROM {A.ELASTIC_EVENTS} | LIMIT 1"}, "POST"),
             ("health-check", {}, "GET"))
    with H.upstream() as up, _elastic(tmp_path, data_root, up.url,
                                      ctx_kw={"capture": capture}) as (ctx, tap):
        up.replies[f"/{A.ELASTIC_EVENTS}/_search"] = (200, {}, hits)
        up.replies[f"/{A.ELASTIC_ALERTS}/_search"] = (200, {}, hits)
        up.replies["/_query"] = (200, {}, b'{"columns": [], "values": []}')
        up.replies["/_cluster/health"] = (200, {}, b'{"status": "green", "number_of_nodes": 1}')
        for verb, kw, _method in verbs:
            before = (len(capture.requests), len(tap.tokens), len(up.seen))
            elastic_adapter.VERBS[verb](ctx, **kw)
            after = (len(capture.requests), len(tap.tokens), len(up.seen))
            assert tuple(a - b for a, b in zip(after, before, strict=True)) == (1, 1, 1), verb

    assert [(r.system, r.method) for r in capture.requests] == [
        ("elastic", method) for _verb, _kw, method in verbs]
    sent = [urlsplit(r.url)[:3] for r in capture.requests]
    assert sent == [urlsplit(up.url)._replace(path=s.path.split("?")[0])[:3] for s in up.seen], (
        "a capture names a URL other than the one sent")
    for request in capture.requests:
        confine_read_endpoint(request.system, request.url, method=request.method)


@pytest.mark.parametrize(("verb", "kw", "timeout"), [
    pytest.param("query", {"native_query": "*"}, 30, id="query"),
    pytest.param("alerts", {"native_query": "*"}, 30, id="alerts"),
    pytest.param("esql", {"query": f"FROM {A.ELASTIC_EVENTS} | LIMIT 1"}, 30, id="esql"),
    pytest.param("health-check", {}, 10, id="health-check"),
])
def test_1391_o3_each_verb_asks_the_proxy_for_its_constant_timeout(
        tmp_path, data_root, verb, kw, timeout):
    """The adapter's constants ride the proxy call as `timeout_sec`: 30 s for query, alerts and
    esql, 10 s for health-check (no timeout key). #1391 O3, F8."""
    with H.upstream() as up, _elastic(tmp_path, data_root, up.url) as (ctx, tap):
        for path in (f"/{A.ELASTIC_EVENTS}/_search", f"/{A.ELASTIC_ALERTS}/_search"):
            up.replies[path] = (200, {}, b'{"hits": {"hits": []}}')
        up.replies["/_query"] = (200, {}, b'{"columns": [], "values": []}')
        up.replies["/_cluster/health"] = (200, {}, b'{"status": "green", "number_of_nodes": 1}')
        elastic_adapter.VERBS[verb](ctx, **kw)

    assert [json.loads(b)["timeout_sec"] for b in tap.bodies] == [timeout]


def test_1391_o3_an_index_edit_after_resolve_does_not_reach_the_wire(tmp_path, data_root):
    """The run's record is parsed once: an events-index edit made to the settings after resolve
    changes nothing a verb sends, while a record resolved after it sends the edit. #1391 O3
    (restores the elastic half of `test_o2_adapter_config_snapshot`)."""
    with H.upstream() as up, published_tenant(
            tmp_path / "forge", root=data_root, files=A.elastic_files(up.url)) as t:
        store = H.FakeStore({(t.tenant_id, "elastic"): T.basic_set()})
        record = T.run_record(t)
        config = export_dir(t.tenant, t.commit) / "settings/systems/elastic/config.env"
        config.write_text(config.read_text(encoding="utf-8").replace(
            f'"{A.ELASTIC_EVENTS}"', '"edited-*"'), encoding="utf-8")
        with A.proxy_for(t, store) as (url, _tap):
            token = T.token(t.tenant_id, {("elastic", "r")})
            elastic_adapter.query(A.ctx_for(tmp_path, record, url, token), native_query="*")
            elastic_adapter.query(A.ctx_for(tmp_path / "later", T.run_record(t), url, token),
                                  native_query="*")

    assert [s.path.split("?")[0] for s in up.seen] == [
        f"/{A.ELASTIC_EVENTS}/_search", "/edited-*/_search"]


def test_1391_o3_alerts_keeps_its_output_shape_through_the_proxy(tmp_path, data_root):
    """`alerts` returns the search envelope over the alerts index, as before. #1391 O3, P5."""
    alert = {"@timestamp": "2026-11-03T10:00:00Z", "rule": {"name": "ssh brute force"}}
    with H.upstream() as up, _elastic(tmp_path, data_root, up.url) as (ctx, _tap):
        up.replies[f"/{A.ELASTIC_ALERTS}/_search"] = (200, {}, json.dumps(
            {"hits": {"total": {"value": 1}, "hits": [{"_source": alert}]}}).encode())
        result = elastic_adapter.VERBS["alerts"](ctx, native_query="rule.name:ssh*")

    assert result == {"index": A.ELASTIC_ALERTS, "total": 1, "returned": 1, "sort": "desc",
                      "truncated": False, "hits": [alert]}


def test_1391_o3_the_bodies_the_proxy_is_sent_are_the_queries_as_asked(tmp_path, data_root):
    """The search body carries no cut and the ES|QL body no added bound: the cut at a branch
    point is the oracle's (#1385 O1), and esql echoes the query it sent. #1391 O3, D1 (replaces
    the `_http_json` source pin)."""
    q = f"FROM {A.ELASTIC_EVENTS} | KEEP user.name"
    with H.upstream() as up, _elastic(tmp_path, data_root, up.url) as (ctx, _tap):
        up.replies[f"/{A.ELASTIC_EVENTS}/_search"] = (200, {}, b'{"hits": {"hits": []}}')
        up.replies["/_query"] = (200, {}, b'{"columns": [], "values": []}')
        elastic_adapter.VERBS["query"](ctx, native_query="*")
        echoed = elastic_adapter.VERBS["esql"](ctx, query=q)

    search, esql = (json.loads(s.body) for s in up.seen)
    assert "post_filter" not in search, search
    assert search["query"]["bool"]["filter"] == [], search
    assert esql == {"query": q}, esql
    assert echoed["query"] == q


# --- #1391 O1/O2, O5, Q4: one access method, host-state over an endpoint-query API -------------

#: Every lab adapter with network access (O1), and the config.env each one reads in full: the
#: keys it declares (Q4), no access method, no base, no Docker key.
_NETWORK_ENVS = {
    "cmdb": 'CMDB_TIMEOUT_SEC="5"\n',
    "identity": 'IDENTITY_TIMEOUT_SEC="5"\n',
    "change-mgmt": 'CHANGE_MGMT_TIMEOUT_SEC="5"\n',
    "threat-intel": 'THREAT_INTEL_TIMEOUT_SEC="5"\n',
    "ticket": 'TICKET_TIMEOUT_SEC="5"\nTICKET_KEY_PATTERN="[A-Z]+-[0-9]+"\n',
    "elastic": f'ELASTIC_EVENTS_INDEX="{A.ELASTIC_EVENTS}"\nELASTIC_ALERTS_INDEX="{A.ELASTIC_ALERTS}"\n',
    "host-state": "",
}

_VERB_PARAMS = {
    "host": "web-1", "at": "2026-05-25T15:00:00Z", "path": "/etc/passwd", "user": "root",
    "key": "T-1391", "cr_id": "CR-1391", "value": "203.0.113.7", "native_query": "*",
    "query": f"FROM {A.ELASTIC_EVENTS} | LIMIT 1", "container_id": "c0ffee1391",
    "actor": "svc-1391", "pattern": "nightly-backup",
}


def _adapter_of(system):
    import importlib
    return importlib.import_module(f"defender.integrations.{system.replace('-', '_')}_adapter")


def _decl_for(system, base):
    if system == "elastic":
        return H.declaration(base, scheme=H.basic_scheme(), reads=A.ELASTIC_READS)
    if system == "threat-intel":  # its lookup carries the value in a POST body (#1391 r5 T3)
        return H.declaration(base, reads=(("POST", "/lookup"),))
    return H.declaration(base)


def _set_for(system):
    return T.basic_set() if system == "elastic" else T.static_set()


@contextlib.contextmanager
def _proxied(tmp_path, data_root, up, system, *, env=None, declared=True):
    """`system` declared at the upstream's base behind the real proxy, its config.env `env`
    (default: its complete one); yields the verb context and the proxy's `Tap`."""
    files = H.access_files(system, _decl_for(system, up.url),
                           env=_NETWORK_ENVS[system] if env is None else env)
    if not declared:
        del files[f"settings/systems/{system}/access.yaml"]  # #1366 O9: nothing to delete from; none planted = empty access
    with published_tenant(tmp_path / "forge", root=data_root, files=files) as t:
        store = H.FakeStore({(t.tenant_id, system): _set_for(system)})
        with A.proxy_for(t, store) as (url, tap):
            yield A.ctx_for(tmp_path, T.run_record(t), url,
                            T.token(t.tenant_id, {(system, "r")})), tap


def _params(fn):
    return {p.name: _VERB_PARAMS.get(p.name, "x")
            for p in inspect.signature(fn).parameters.values()
            if p.kind is inspect.Parameter.KEYWORD_ONLY and p.default is inspect.Parameter.empty}


#: Audit events of a process being started, by any route (`subprocess`, `os.system`, spawn, exec).
_PROCESS_EVENTS = ("subprocess.Popen", "os.system", "os.posix_spawn", "os.exec", "os.spawn",
                   "os.fork", "os.forkpty")
#: What the audit hook records while `_watching` is non-empty. The hook cannot be removed once
#: added, so it is added once per process and records only inside `_processes_started`.
_started: list[tuple[str, object]] = []
_watching: list[bool] = []
_hooked: list[bool] = []


def _audit(event, args):
    if _watching and event.startswith(_PROCESS_EVENTS):
        _started.append((event, args[:2] if isinstance(args, tuple) else args))


@contextlib.contextmanager
def _processes_started():
    """Every process start inside the block, from Python's audit events."""
    import sys

    if not _hooked:
        sys.addaudithook(_audit)
        _hooked.append(True)
    _started.clear()
    _watching.append(True)
    try:
        yield _started
    finally:
        _watching.clear()


@pytest.mark.parametrize("system", sorted(_NETWORK_ENVS))
def test_1391_o1_a_declaration_alone_puts_a_system_on_the_proxy_and_no_verb_forks_a_process(
        tmp_path, data_root, system):
    """A system folder holding an access declaration and only its own keys passes the settings
    check, and every verb reaches the system through the proxy without starting a process (no
    `docker`). #1391 O1, O2, P1."""
    with H.upstream() as up, _proxied(tmp_path, data_root, up, system) as (ctx, tap):
        assert _adapter_of(system).check_settings(ctx.tenant) is None
        outcomes = {}
        with _processes_started() as started:
            for name, fn in _adapter_of(system).VERBS.items():
                try:
                    fn(ctx, **_params(fn))
                except Exception as exc:  # noqa: BLE001 — the test reads whatever the verb raised
                    outcomes[name] = exc
                else:
                    outcomes[name] = None
            forked = list(started)

    assert forked == [], f"{system}'s verbs started processes: {forked}"
    config_faults = {v: str(e) for v, e in outcomes.items() if isinstance(e, ConfigFault)}
    assert config_faults == {}, f"{system} refused complete settings: {config_faults}"
    assert up.seen, f"positive control: {system}'s verbs reached the upstream: {outcomes}"
    assert len(tap.tokens) == len(up.seen), "every upstream request went through the proxy"


def test_1391_o1_the_process_watch_sees_a_process_start():
    """Positive control for the watch the no-process test relies on."""
    import subprocess
    import sys

    with _processes_started() as started:
        subprocess.run([sys.executable, "-c", "pass"], check=True)
    assert any(event == "subprocess.Popen" for event, _ in started), started


@pytest.mark.parametrize("system", sorted(_NETWORK_ENVS))
def test_1391_o1_a_network_system_with_no_declaration_is_a_settings_fault_naming_it(
        tmp_path, data_root, system):
    """No `access.yaml` is a settings fault, never a fallback to another access method. P1."""
    with (H.upstream() as up,
          _proxied(tmp_path, data_root, up, system, declared=False) as (ctx, tap),
          pytest.raises(ConfigFault, match=rf"system {system} access")):  # #1366 DC6
        _adapter_of(system).check_settings(ctx.tenant)
    assert (tap.tokens, up.seen) == ([], [])


@pytest.mark.parametrize(("system", "key"), [
    pytest.param("cmdb", "CMDB_TRANSPORT", id="transport-http-proxy"),
    pytest.param("cmdb", "CMDB_DOCKER_CONTEXT", id="docker-context"),
    pytest.param("cmdb", "CMDB_BASTION_HOST", id="bastion"),
    pytest.param("ticket", "TICKET_TIMEOUT", id="typo"),
    pytest.param("identity", "IDENTITY_DOCKER_CONTEXT", id="identity-docker-context"),
    pytest.param("elastic", "ELASTIC_TRANSPORT", id="elastic-transport"),
    pytest.param("elastic", "ELASTIC_ES_CONTAINER", id="es-container"),
    pytest.param("elastic", "ELASTIC_KIBANA_CONTAINER", id="kibana-container"),
    pytest.param("elastic", "ELASTIC_SSL_VERIFY", id="ssl-verify"),
    pytest.param("elastic", "ELASTIC_DOCKER_CONTEXT", id="elastic-docker-context"),
    pytest.param("host-state", "HOST_STATE_TRANSPORT", id="host-state-transport-docker-exec"),
    pytest.param("host-state", "HOST_STATE_DOCKER_CONTEXT", id="host-state-docker-context"),
    pytest.param("host-state", "UNPREFIXED", id="unprefixed"),
])
def test_1391_o2_a_key_the_adapter_does_not_read_is_refused_by_name(
        tmp_path, data_root, system, key):
    """Any config.env key the system's adapter does not declare (a retired Docker key, the old
    access method, a typo) is a settings fault naming it, at the check and at a verb, nothing
    sent. #1391 O2, Q4/D10."""
    # The old access method a leftover names: what each lab system's file held before.
    value = ("http-proxy" if key in ("CMDB_TRANSPORT", "ELASTIC_TRANSPORT")
             else "docker-exec" if key.endswith("_TRANSPORT") else "soc-playground")
    env = _NETWORK_ENVS[system] + f'{key}="{value}"\n'
    with H.upstream() as up, _proxied(tmp_path, data_root, up, system, env=env) as (ctx, tap):
        with pytest.raises(ConfigFault, match=key):
            _adapter_of(system).check_settings(ctx.tenant)
        verb = _adapter_of(system).VERBS["health-check"]
        with pytest.raises(ConfigFault, match=key):
            verb(ctx)
    assert (tap.tokens, up.seen) == ([], [])


def _json(payload):
    return (200, {"Content-Type": "application/json"}, json.dumps(payload).encode())


@pytest.mark.parametrize(("verb", "params", "route", "answer", "result"), [
    pytest.param("health-check", {}, "/hosts",
                 {"hosts": [{"name": "web-1", "running": True},
                            {"name": "db-1", "running": False}]},
                 {"system": "host-state", "connected": True, "hosts_present": ["web-1"],
                  "hosts_missing": ["db-1"]}, id="health-check"),
    pytest.param("proc-tree", {"host": "config-mgmt-1"}, "/hosts/config-mgmt-1/processes",
                 {"ps_output": "PID PPID\n1 0 init\n"},
                 {"host": "config-mgmt-1", "ps_output": "PID PPID\n1 0 init\n"}, id="proc-tree"),
    pytest.param("passwd", {"host": "web-1"}, "/hosts/web-1/accounts",
                 {"entries": ["root:x:0:0:root:/root:/bin/bash"]},
                 {"host": "web-1", "entries": ["root:x:0:0:root:/root:/bin/bash"]}, id="passwd"),
    pytest.param("authorized-keys", {"host": "db-1", "user": "deploy"},
                 "/hosts/db-1/accounts/deploy/authorized-keys",
                 {"path": "/home/deploy/.ssh/authorized_keys", "keys": ["ssh-ed25519 AAAA k"]},
                 {"host": "db-1", "user": "deploy", "path": "/home/deploy/.ssh/authorized_keys",
                  "keys": ["ssh-ed25519 AAAA k"]}, id="authorized-keys"),
    pytest.param("fim-checksum", {"host": "web-1", "path": "/etc/passwd"},
                 "/hosts/web-1/files/sha256", {"sha256": "ab" * 32},
                 {"host": "web-1", "path": "/etc/passwd", "sha256": "ab" * 32}, id="fim-checksum"),
    pytest.param("package-list", {"host": "web-1"}, "/hosts/web-1/packages",
                 {"packages": ["openssh-server 1:9.6"]},
                 {"host": "web-1", "packages": ["openssh-server 1:9.6"]}, id="package-list"),
    pytest.param("container-inspect", {"container_id": "c0ffee"}, "/containers/c0ffee",
                 {"name": "web-1", "image": "lab/web:1"},
                 {"container_id": "c0ffee", "name": "web-1", "image": "lab/web:1"},
                 id="container-inspect"),
])
def test_1391_o5_host_state_verbs_are_gets_on_the_endpoint_query_api_with_unchanged_outputs(
        tmp_path, data_root, verb, params, route, answer, result):
    """Each host-state verb is one bearer-authenticated GET on its route under the declared base,
    and returns today's output shape (P5); health-check carries no docker context. #1391 O5."""
    from defender.integrations import host_state_adapter

    with H.upstream() as up, _proxied(tmp_path, data_root, up, "host-state") as (ctx, _tap):
        up.replies[route] = _json(answer)
        got = host_state_adapter.VERBS[verb](ctx, **params)

    (seen,) = up.seen
    assert (seen.method, seen.path.split("?", 1)[0]) == ("GET", route)
    assert seen.header("Authorization") == f"Bearer {H.CANARY_KEY}"
    if verb == "fim-checksum":
        assert urlsplit(seen.path).query == "path=%2Fetc%2Fpasswd"
    assert got == result


@pytest.mark.parametrize(("status", "fault"), [
    pytest.param(404, UpstreamFault, id="not-enrolled-or-no-user-404"),
    pytest.param(400, UpstreamFault, id="bad-user-or-path-400"),
    pytest.param(503, TransportFault, id="host-stopped-503"),
])
def test_1391_o5_host_state_faults_follow_the_pinned_status_table(
        tmp_path, data_root, status, fault):
    """The endpoint-query service's status decides the fault (design r4's table): 404 and 400
    are the agent's to fix, 503 is the host down. #1391 O5."""
    from defender.integrations import host_state_adapter

    route = "/hosts/elasticsearch/processes"
    with H.upstream() as up, _proxied(tmp_path, data_root, up, "host-state") as (ctx, _tap):
        up.replies[route] = (status, {"Content-Type": "application/json"},
                             b'{"detail": "service says no"}')
        with pytest.raises(AdapterFault) as raised:
            host_state_adapter.VERBS["proc-tree"](ctx, host="elasticsearch")
    assert type(raised.value) is fault, raised.value
    assert "service says no" in str(raised.value)


@pytest.mark.parametrize("host", ["web-1/accounts/root", "web-1%2Faccounts%2Froot"])
def test_1391_o5_host_state_refuses_a_host_that_is_not_one_path_segment(tmp_path, data_root, host):
    """A host carrying `/`, spelled out or encoded, is refused before anything is sent: the agent
    cannot steer the request to another route of the service. #1391 O5, r5 T2."""
    from defender.integrations import host_state_adapter

    with (H.upstream() as up, _proxied(tmp_path, data_root, up, "host-state") as (ctx, _tap),
          pytest.raises(ConfinementFault, match="`host`")):
        host_state_adapter.VERBS["authorized-keys"](ctx, host=host, user="x")
    assert up.seen == []
