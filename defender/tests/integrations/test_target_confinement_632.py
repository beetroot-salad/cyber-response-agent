"""#632 target fidelity: a verb cannot be aimed outside the system it is declared under. Host-state refuses hosts outside its inventory; elastic refuses indices outside the configured patterns; every outbound request is confined to a declared (path, method) read endpoint, observed through the transport capture seam. Not covered: `elastic.esql` selects its target inside the FROM clause, which the verb-level check does not reach."""
from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("pydantic_ai")

from defender.systems.verbs import VerbContext  # noqa: E402
from defender.tests.tenancy.tenant_1107_settings import _spec1107 as S  # noqa: E402
from defender.integrations import elastic_adapter, host_state_adapter  # noqa: E402
from defender.integrations import identity_adapter  # noqa: E402
from defender.integrations.confinement import (  # noqa: E402
    READ_ENDPOINT_ALLOWLIST,
    AllowlistError,
    ConfinementFault,
    ReadEndpointAllowlist,
    TransportCapture,
    confine_index,
    confine_read_endpoint,
    normalize_endpoint,
)
from defender.kit.faults import TransportFault  # noqa: E402
from defender.integrations.host_state_adapter import (  # noqa: E402
    HOST_STATE_PROGRAMS,
    confine_host,
    confine_host_state_call,
)

pytestmark = pytest.mark.e2e

CONFIGURED_PATTERNS = ("logs-*", "security-audit-*")
#: Writes an agent-facing (read-class) request must never reach. #1359: the playground's one
#: comment write is the host's, through the write-endpoint table (D-6, tests below); under the
#: read class it is still refused, as are the ticket's other writes.
WRITE_ENDPOINTS = (
    ("ticket", "/tickets", "POST"),
    ("ticket", "/tickets/SOC-1/transitions", "POST"),
    ("ticket", "/tickets/SOC-1/comments", "POST"),
    ("elastic", "/logs-2026.01.01/_update/1", "POST"),
)
TICKET_READ_PATH = "/tickets"
REAL_STUB_ENDPOINTS = tuple(
    (system, path, "GET") for system, path in (
        ("change-mgmt", "/health"), ("change-mgmt", "/changes"),
        ("change-mgmt", "/changes/active"), ("change-mgmt", "/changes/CR-1042"),
        ("cmdb", "/health"), ("cmdb", "/hosts"), ("cmdb", "/hosts/web-1"), ("cmdb", "/roles"),
        ("identity", "/health"), ("identity", "/users"), ("identity", "/roles"),
        ("identity", "/users/dev.dana"), ("identity", "/users/dev.dana/can_access"),
        ("identity", "/users/dev.dana/authorized_hosts"),
        ("threat-intel", "/health"), ("threat-intel", "/indicators"),
        ("threat-intel", "/lookup/1.2.3.4"),
        ("ticket", "/health"), ("ticket", TICKET_READ_PATH), ("ticket", "/tickets/SOC-777"),
    )
)


def _tree(root: Path, *, url: str = "http://127.0.0.1:1") -> Any:
    """The run's tenant record, resolved from a real tenant folder under `root` carrying only the
    elastic and host-state config. The transport is unreachable on purpose: a `ConfinementFault`
    (not a `TransportFault`) shows confinement refused before any transport was attempted."""
    S.plant(root, configs={"elastic": (
        f"ELASTICSEARCH_URL={url}\n"
        f"KIBANA_URL={url}\n"
        "ELASTIC_EVENTS_INDEX=logs-*\n"
        "ELASTIC_ALERTS_INDEX=security-audit-*\n"
        "ELASTIC_SSL_VERIFY=true\n"
        "ELASTIC_TRANSPORT=docker-exec\n"
        "ELASTIC_DOCKER_CONTEXT=no-such-context-632-test\n"
        "ELASTIC_ES_CONTAINER=es-632\n"
        "ELASTIC_KIBANA_CONTAINER=kibana-632\n"),
        "host-state": ("HOST_STATE_TRANSPORT=docker-exec\n"
                       "HOST_STATE_DOCKER_CONTEXT=no-such-context-632-test\n")})
    return S.resolve(root)


def _ctx(tmp_path: Path) -> VerbContext:
    return VerbContext(defender_dir=tmp_path / "tree", tenant=_tree(tmp_path / "tree"),
                       run_dir=tmp_path / "run", env={})


def test_host_state_refuses_a_host_outside_its_inventory(tmp_path: Path):
    assert "elasticsearch" not in host_state_adapter.KNOWN_HOSTS

    with pytest.raises(ConfinementFault) as caught:
        confine_host("elasticsearch")
    assert "elasticsearch" in str(caught.value)

    ctx = _ctx(tmp_path)
    for verb in ("proc-tree", "passwd"):
        with pytest.raises(ConfinementFault):
            host_state_adapter.VERBS[verb](ctx, host="elasticsearch")


@pytest.mark.parametrize("near_miss", [
    "ELASTICSEARCH", "Web-1", " web-1", "web-1 ", "web", "web-1-shadow",
])
def test_a_case_variant_of_an_inventory_host_is_refused_not_normalized(near_miss: str):
    with pytest.raises(ConfinementFault):
        confine_host(near_miss)
    assert near_miss not in host_state_adapter.KNOWN_HOSTS


def test_a_host_state_verb_confines_the_program_and_the_container_target_together():
    """The rule checks the pair: the program against a per-system allowlist and the container
    target against the declared inventory."""
    assert set(HOST_STATE_PROGRAMS) >= {"ps", "cat", "getent", "sha256sum", "dpkg-query"}

    confine_host_state_call("cat", "web-1")

    with pytest.raises(ConfinementFault):
        confine_host_state_call("cat", "defender")        # the agent's own container
    with pytest.raises(ConfinementFault):
        confine_host_state_call("cat", "ticket-store")    # another granted system's store
    with pytest.raises(ConfinementFault):
        confine_host_state_call("curl", "web-1")          # in-inventory target, ungated program


@pytest.mark.parametrize("widening", [
    ".security-7",  # an index outside the configured patterns altogether
    "logs-*,security-audit-*,.security-7", "*", "-logs-*",
])
def test_an_index_expression_whose_reach_widens_refuses_the_whole_call(
    tmp_path: Path, widening: str,
):
    with pytest.raises(ConfinementFault):
        confine_index(widening, CONFIGURED_PATTERNS)

    ctx = _ctx(tmp_path)
    with pytest.raises(ConfinementFault):
        elastic_adapter.VERBS["query"](ctx, native_query="FROM x", index=widening)


@pytest.mark.parametrize("inside", [
    "logs-*",                 # a configured pattern, fed back verbatim
    "logs-2026.01.01",        # a CONCRETE index under it — the daily index every real read hits
    "logs-2026.01.*",         # a strictly NARROWER wildcard
    "security-audit-2026.01", # the same, on the second configured pattern
])
def test_an_inventory_host_and_a_configured_index_still_run(tmp_path: Path, inside: str):
    confine_host("web-1")
    assert confine_index(inside, CONFIGURED_PATTERNS) == inside, \
        "an index whose reach is inside the configured patterns was rewritten or refused"

    ctx = _ctx(tmp_path)
    with pytest.raises(TransportFault):
        elastic_adapter.VERBS["query"](ctx, native_query="FROM x", index=inside)
    with pytest.raises(TransportFault):
        host_state_adapter.VERBS["proc-tree"](ctx, host="web-1")


def test_the_transport_capture_seam_records_every_resolved_request(tmp_path: Path):
    capture = TransportCapture()
    ctx = VerbContext(defender_dir=tmp_path / "tree", tenant=_tree(tmp_path / "tree"),
                      run_dir=tmp_path / "run", env={}, capture=capture)

    with pytest.raises(TransportFault):
        elastic_adapter.VERBS["query"](ctx, native_query="FROM x", index="logs-*")

    assert capture.requests, "the seam recorded nothing — the transport bypasses it"
    request = capture.requests[-1]
    assert request.system == "elastic"
    assert normalize_endpoint(request.url) == "/logs-*/_search", \
        "the seam records something other than the resolved request target"
    assert request.method == "POST", (
        "the seam records no HTTP method — the read allowlist keys on (path, method) pairs, "
        "so a capture without the method leaves the rule's second half unobservable"
    )

    unobserved = VerbContext(defender_dir=tmp_path / "bare", tenant=_tree(tmp_path / "bare"),
                             run_dir=tmp_path / "run2", env={})
    with pytest.raises(TransportFault):
        elastic_adapter.VERBS["query"](unobserved, native_query="FROM x", index="logs-*")


def test_an_r_classed_verb_may_only_reach_a_declared_read_endpoint(tmp_path: Path):
    required = {"elastic", *(system for system, _, _ in REAL_STUB_ENDPOINTS)}
    assert required <= set(READ_ENDPOINT_ALLOWLIST), (
        f"the read allowlist declares no endpoints for "
        f"{sorted(required - set(READ_ENDPOINT_ALLOWLIST))} — this test drives a real read on "
        f"all {len(required)} of {sorted(required)}, so every one of them needs entries"
    )
    for system, entries in READ_ENDPOINT_ALLOWLIST.items():
        assert entries, f"{system} declares an empty read-endpoint allowlist — an open gate"
        for entry in entries:
            assert len(entry) == 2, (
                f"{system} declares a read-endpoint entry that is not an "
                f"(endpoint, method) pair ({entry!r})"
            )
            assert entry[1], (
                f"{system} declares a read-endpoint entry with no method ({entry!r}) — an "
                f"endpoint-only key cannot separate the ticket read from the ticket write"
            )

    capture = TransportCapture()
    ctx = VerbContext(defender_dir=tmp_path / "tree", tenant=_tree(tmp_path / "tree"),
                      run_dir=tmp_path / "run", env={}, capture=capture)
    for verb, kwargs in (("query", {"native_query": "FROM x", "index": "logs-*"}),
                         ("alerts", {"native_query": "*", "index": "security-audit-*"}),
                         ("esql", {"query": "FROM logs-* | LIMIT 1"}),
                         ("health-check", {})):
        with pytest.raises(TransportFault):
            elastic_adapter.VERBS[verb](ctx, **kwargs)

    assert len(capture.requests) >= 4, "some real elastic verb reached no captured endpoint"
    for request in capture.requests:
        assert request.method, "the capture seam records no method — the rule has no key"
        confine_read_endpoint(request.system, request.url, method=request.method,
                              verb_class="r")

    for system, endpoint, method in REAL_STUB_ENDPOINTS:
        confine_read_endpoint(system, f"http://host{endpoint}", method=method, verb_class="r")

    assert all(method == "GET" for _, method in READ_ENDPOINT_ALLOWLIST["ticket"]), (
        "the ticket read allowlist holds a non-GET entry, so the write refusals below pass or "
        "fail for another reason"
    )

    for system, endpoint, method in WRITE_ENDPOINTS:
        with pytest.raises(ConfinementFault):
            confine_read_endpoint(system, f"http://host{endpoint}", method=method,
                                  verb_class="r")

    confine_read_endpoint("ticket", f"http://host{TICKET_READ_PATH}", method="GET",
                          verb_class="r")
    with pytest.raises(ConfinementFault):
        confine_read_endpoint("ticket", f"http://host{TICKET_READ_PATH}", method="POST",
                              verb_class="r")


def _stub_tree(root: Path, system: str, prefix: str, *, bastion: str) -> Any:
    """The run's tenant record from a real tenant folder under `root` carrying one stub system's
    config.env (no monkeypatch). `bastion` names a docker context this host does not know."""
    S.plant(root, configs={system: (
        f"{prefix}_URL_BASE=http://stub-{system}\n"
        f"{prefix}_BASTION_HOST=stub-bastion\n"
        f"{prefix}_TIMEOUT_SEC=2\n"
        f"{prefix}_TRANSPORT=docker-exec\n"
        f"{prefix}_DOCKER_CONTEXT={bastion}\n")})
    return S.resolve(root)


def test_a_non_elastic_stub_adapter_is_confined_through_the_real_shared_transport(
    tmp_path: Path,
):
    ctx = VerbContext(
        defender_dir=tmp_path / "tree",
        tenant=_stub_tree(tmp_path / "tree", "identity", "IDENTITY",
                                bastion="no-such-context-632-test"),
        run_dir=tmp_path / "run", env={}, capture=TransportCapture(),
    )

    with pytest.raises(ConfinementFault):
        identity_adapter.get_user(ctx, user="../../secret")
    assert not ctx.capture.requests, (
        "the out-of-bounds request was captured before being refused — confinement must "
        "run before the capture, and BEFORE any transport is attempted"
    )

    with pytest.raises(TransportFault):
        identity_adapter.get_user(ctx, user="dev.dana")
    assert ctx.capture.requests, (
        "the in-bounds call recorded nothing — the real adapter never reached the shared "
        "transport's capture seam"
    )
    request = ctx.capture.requests[-1]
    assert request.system == "identity"
    assert normalize_endpoint(request.url) == "/users/dev.dana"
    assert request.method == "GET"


def _crm_tree(root: Path, *, via: str) -> Any:
    """The run's record for a TENANT-ONLY system `crm` (in no product allowlist) reached `via`
    `docker-exec` or `http-proxy` (#1163)."""
    from defender.tests.integrations.credential_proxy_1163 import _adapter1163 as A
    from defender.tests.integrations.credential_proxy_1163 import _harness as H

    if via == "docker-exec":
        folder = S.plant(root, configs={"crm": (
            'CRM_URL_BASE=http://crm.invalid\nCRM_BASTION_HOST=b\nCRM_TIMEOUT_SEC=2\n'
            'CRM_TRANSPORT=docker-exec\nCRM_DOCKER_CONTEXT=no-such-context-1163\n')})
    else:
        folder = S.plant(root, configs={"crm": A.env_text("crm")})
        for rel, text in H.access_files("crm", H.declaration("http://crm.invalid/api")).items():
            (folder / rel).parent.mkdir(parents=True, exist_ok=True)
            (folder / rel).write_text(text, encoding="utf-8")
    return S.resolve(root)


def test_a_tenant_only_system_is_confined_by_the_allowlist_on_docker_exec_only(tmp_path: Path):
    """#1163 A6: `crm` on docker-exec is refused by the product allowlist before capture (regression
    guard); on http-proxy the adapter guard records the capture and does not confine."""
    from defender.integrations import _stub_transport as transport

    docker = VerbContext(defender_dir=tmp_path / "tree", tenant=_crm_tree(tmp_path / "d", via="docker-exec"),
                         run_dir=tmp_path / "run", env={}, capture=TransportCapture())
    config = transport.load_config(docker, "crm", "CRM")
    with pytest.raises(ConfinementFault):
        transport.http_get(docker, config, "/accounts/1", system="crm")
    assert not docker.capture.requests

    from defender.tests.integrations.credential_proxy_1163 import _adapter1163 as A
    from defender.tests.integrations.credential_proxy_1163 import _harness as H

    proxied = A.ctx_for(tmp_path, _crm_tree(tmp_path / "p", via="http-proxy"),
                        f"http://127.0.0.1:{H.free_port()}", "unused", capture=TransportCapture())
    config = transport.load_config(proxied, "crm", "CRM")
    with pytest.raises(TransportFault):
        transport.http_get(proxied, config, "/accounts/1", system="crm")
    (request,) = proxied.capture.requests
    assert (request.system, request.method) == ("crm", "GET")
    assert normalize_endpoint(request.url) == "/api/accounts/1"


def test_the_read_endpoint_allowlist_cannot_be_built_with_a_methodless_entry():
    assert isinstance(READ_ENDPOINT_ALLOWLIST, ReadEndpointAllowlist), (
        "the shipped read-endpoint allowlist is not a constructed allowlist, so nothing in "
        "production refuses a method-less entry"
    )
    assert isinstance(READ_ENDPOINT_ALLOWLIST, Mapping), (
        "the allowlist type is not a Mapping — the endpoint rule's own test reads this table "
        "by key set, by system and by subscript"
    )

    for methodless in (
        ("/tickets",),         # a one-element entry: no method at all
        ("/tickets", ""),      # a present-but-empty method token
        ("/tickets", None),    # the shape a half-migrated entry takes
        "/tickets",            # a bare path string
    ):
        with pytest.raises(AllowlistError):
            ReadEndpointAllowlist({"ticket": (methodless,)})

    ok = ReadEndpointAllowlist({"ticket": ((TICKET_READ_PATH, "GET"),)})
    assert tuple(ok["ticket"]) == ((TICKET_READ_PATH, "GET"),), \
        "a well-authored (endpoint, method) pair did not survive construction"
    confine_read_endpoint("elastic", "http://es:9200/_cluster/health", method="GET",
                          verb_class="r")


def test_the_two_post_with_body_reads_still_pass_the_endpoint_check():
    confine_read_endpoint("elastic", "http://es:9200/logs-*/_search", method="POST",
                          verb_class="r")
    confine_read_endpoint("elastic", "http://es:9200/_query?format=json", method="POST",
                          verb_class="r")
    confine_read_endpoint("elastic", "http://es:9200/_cluster/health", method="GET",
                          verb_class="r")

    with pytest.raises(ConfinementFault):
        confine_read_endpoint("elastic", "http://es:9200/logs-*/_update/1", method="POST",
                              verb_class="r")
    with pytest.raises(ConfinementFault):
        confine_read_endpoint("elastic", "http://es:9200/logs-*/_search", method="DELETE",
                              verb_class="r")


def test_the_endpoint_check_binds_on_the_resolved_normalized_path_without_the_query_string():
    assert normalize_endpoint("http://es:9200/logs-*/_search?pretty=true&x=1") == "/logs-*/_search"
    assert normalize_endpoint("http://es:9200//logs-*//_search/") == "/logs-*/_search"

    confine_read_endpoint("elastic", "http://es:9200/logs-*/_search?pretty=true", method="POST",
                          verb_class="r")

    with pytest.raises(ConfinementFault):
        confine_read_endpoint("elastic", "http://es:9200/logs-*/_search/../../_update/1",
                              method="POST", verb_class="r")
    with pytest.raises(ConfinementFault):
        confine_read_endpoint("elastic", "http://es:9200/%5Flogs/../_update/1", method="POST",
                              verb_class="r")


# ---- the host write entry and the write-endpoint table (#1359 D-6) ---------------------------------

COMMENT_PATH = "/tickets/SOC-1/comments"


#: The one place the host write entry's call shape is spelled (D-6/D-15: name and four arguments;
#: house style adds the config and `system=`). `_host_write` and the planted adapter source below
#: both use this text, with `ctx`, `cfg`, `method`, `path`, `payload` in scope; the code stage
#: changes the shape here only.
HTTP_WRITE_CALL = 'transport.http_write(ctx, cfg, method, path, payload, system="ticket")'


def _host_write(ctx: VerbContext, cfg: dict[str, str], method: str, path: str,
                body: dict | None = None) -> Any:
    """The shared transport's host write entry, called as `HTTP_WRITE_CALL` spells it."""
    from defender.integrations import _stub_transport as transport

    return eval(HTTP_WRITE_CALL, {"transport": transport},  # noqa: S307 - a constant of this file
                {"ctx": ctx, "cfg": cfg, "method": method, "path": path, "payload": body or {}})


def _docker_ticket_ctx(tmp_path: Path, monkeypatch: Any) -> tuple[VerbContext, Any]:
    """A run context over the playground tenant's `ticket` system on the docker route, its store
    a fake `docker` that records every call."""
    from defender.tests.support.runtime.engine import _spec767 as M

    M.use_case_record(monkeypatch, tmp_path / "dfn")
    store = M.FakeStore(tmp_path / "store")
    return S.verb_context(M.current_record(), tmp_path / "run", store.env({})), store


def _ticket_cfg(ctx: VerbContext) -> dict[str, str]:
    from defender.integrations import _stub_transport as transport

    return transport.load_config(ctx, "ticket", "TICKET", ("URL_BASE", "BASTION_HOST", "TIMEOUT_SEC"))


def test_the_guard_admits_the_ticket_comment_as_a_write_and_the_retired_system_nowhere():
    """What the guard admits, not how the table is stored (D-15): `ticket` may POST its comment
    path at class `rw`; the retired `case-history` system is refused at every class, comment path
    included; no create or transition path is admitted for `ticket`. O3, O2."""
    confine_read_endpoint("ticket", f"http://host{COMMENT_PATH}", method="POST", verb_class="rw")
    for verb_class in ("r", "rw"):
        for method, path in (("POST", COMMENT_PATH), ("POST", "/tickets"), ("GET", "/tickets")):
            with pytest.raises(ConfinementFault):
                confine_read_endpoint("case-history", f"http://host{path}", method=method,
                                      verb_class=verb_class)
    for path in ("/tickets", "/tickets/SOC-1/transitions"):
        with pytest.raises(ConfinementFault):
            confine_read_endpoint("ticket", f"http://host{path}", method="POST", verb_class="rw")


def test_the_write_class_admits_the_ticket_comment_and_refuses_every_other_write():
    """The same guard, at class `rw`: `ticket` POST /tickets/*/comments passes; another method, a
    create, a transition and another system's write are `ConfinementFault`s. Control: the same
    comment path under the read class is refused. D-6."""
    confine_read_endpoint("ticket", f"http://host{COMMENT_PATH}", method="POST", verb_class="rw")
    for system, path, method in (
        ("ticket", COMMENT_PATH, "PATCH"), ("ticket", COMMENT_PATH, "DELETE"),
        ("ticket", "/tickets", "POST"), ("ticket", "/tickets/SOC-1/transitions", "POST"),
        ("ticket", "/tickets/SOC-1", "PATCH"), ("cmdb", "/hosts", "POST"),
        ("elastic", "/logs-2026.01.01/_update/1", "POST"),
    ):
        with pytest.raises(ConfinementFault):
            confine_read_endpoint(system, f"http://host{path}", method=method, verb_class="rw")
    with pytest.raises(ConfinementFault):
        confine_read_endpoint("ticket", f"http://host{COMMENT_PATH}", method="POST",
                              verb_class="r")


def test_the_host_write_entry_reaches_the_allowed_comment_and_the_agent_entry_does_not(
        tmp_path: Path, monkeypatch: Any):
    """On the docker route `http_write` POSTs the one allowed path; the agent-facing `http_post`
    on that same path stays refused before any docker child is forked. D-6, P2."""
    from defender.integrations import _stub_transport as transport

    ctx, store = _docker_ticket_ctx(tmp_path, monkeypatch)
    cfg = _ticket_cfg(ctx)
    with pytest.raises(ConfinementFault):
        transport.http_post(ctx, cfg, COMMENT_PATH, {"body": "x"}, system="ticket")
    assert store.calls == [], "the agent-facing POST reached the store"

    _host_write(ctx, cfg, "POST", COMMENT_PATH, {"author": "a", "body": "x"})
    assert [(c.method, c.path) for c in store.calls] == [("POST", COMMENT_PATH)]


@pytest.mark.parametrize(("method", "path"), [
    ("PATCH", COMMENT_PATH), ("POST", "/tickets"), ("POST", "/tickets/SOC-1/transitions"),
    ("PATCH", "/tickets/SOC-1"), ("DELETE", "/tickets/SOC-1")])
def test_a_host_write_the_table_does_not_allow_is_a_confinement_fault_before_any_request(
        tmp_path: Path, monkeypatch: Any, method: str, path: str):
    """The host write entry is confined too: a write outside the table raises `ConfinementFault`
    and no docker child is forked (the request never reaches the store). D-6."""
    ctx, store = _docker_ticket_ctx(tmp_path, monkeypatch)
    cfg = _ticket_cfg(ctx)
    with pytest.raises(ConfinementFault):
        _host_write(ctx, cfg, method, path, {"body": "x"})
    assert store.calls == [], f"{method} {path} reached the store"


#: A planted `ticket_adapter.py`: the host's comment action exactly as the tenant's case-record
#: file reaches it, but it writes where the call below says (the write-table-bypass shape).
PLANTED_TICKET_ADAPTER = '''\
from defender.integrations import _stub_transport as transport


def check_settings(tenant):
    return None


def health_check(ctx):
    return {{}}


def add_case_comment(ctx, *, key, body):
    cfg = transport.load_config(ctx, "ticket", "TICKET", ("URL_BASE", "BASTION_HOST", "TIMEOUT_SEC"))
    method, path, payload = {method!r}, f"/tickets/{{key}}{suffix}", {{"body": body}}
    {write_call}
    return None


VERBS = {verbs}
'''

#: The planted adapter's `VERBS` as a harmless adapter spells it, and the three ways a cold read
#: refuses one that holds the comment action (r4 "Host-only, first layer").
HARMLESS_VERBS = '{"health-check": health_check}'
VERBS_HOLDING_THE_ACTION = {
    "dash-spelled key": '{"health-check": health_check, "add-case-comment": health_check}',
    "underscore-spelled key": '{"health-check": health_check, "add_case_comment": health_check}',
    "bare-name value": '{"health-check": health_check, "note": add_case_comment}',
}


def _leg_over_planted_adapter(tmp_path: Path, monkeypatch: Any, *, method: str, suffix: str,
                              verbs: str = HARMLESS_VERBS):
    """The record leg with a planted case adapter, the store a fake `docker`: (store, receipt)."""
    from defender import box as box_mod
    from defender.investigation import ticket_writer
    from defender.tests.support.runtime.engine import _spec767 as M
    from defender.tests.support.shared.contracts._spec1077 import fixture_run

    M.use_case_record(monkeypatch, tmp_path / "dfn")
    tree = tmp_path / "tree"
    (tree / "integrations").mkdir(parents=True)
    (tree / "integrations" / "ticket_adapter.py").write_text(
        PLANTED_TICKET_ADAPTER.format(method=method, suffix=suffix, verbs=verbs,
                                      write_call=HTTP_WRITE_CALL),
        encoding="utf-8")
    store = M.FakeStore(tmp_path / "store")
    run_dir = M.make_run(tmp_path / "runs")
    ticket_writer.record_case_ticket(
        fixture_run(run_dir), tenant=M.current_record(), defender_dir=tree,
        env=store.env(box_mod.run_env(S.DEFENDER, run_dir)))
    return store, M.receipt(run_dir)


def test_a_case_adapter_writing_outside_the_table_leaves_an_error_receipt_naming_the_write(
        tmp_path: Path, monkeypatch: Any):
    """Through the record leg, a case adapter whose write is not in the table yields an `error`
    receipt naming the refused method and path, with `url` null, and no request reaches the
    store. Control: the same planted adapter writing the allowed comment path is a `commented`
    receipt. D-6, D-10, r4 receipt reasons."""
    from defender.tests.support.runtime.engine import _spec767 as M

    control_store, control = _leg_over_planted_adapter(
        tmp_path / "control", monkeypatch, method="POST", suffix="/comments")
    assert control["status"] == "commented", control
    assert [(c.method, c.path) for c in control_store.calls] == [
        ("POST", f"/tickets/{M.CASE_KEY}/comments")]

    store, got = _leg_over_planted_adapter(tmp_path / "bad", monkeypatch, method="PATCH", suffix="")
    assert store.calls == [], "a write outside the table reached the store"
    assert got["status"] == "error", got
    assert got["ok"] is False, got
    assert got["url"] is None, got
    assert "PATCH" in got["reason"], got
    assert f"/tickets/{M.CASE_KEY}" in got["reason"], got


@pytest.mark.parametrize("spelling", list(VERBS_HOLDING_THE_ACTION))
def test_a_case_adapter_the_cold_read_refused_serves_no_comment(
        tmp_path: Path, monkeypatch: Any, spelling: str):
    """Through the record leg, a case adapter whose `VERBS` holds the comment action is refused by
    the cold read and does not serve the host's comment either: no request reaches the store, an
    `error` receipt (`url` null) names `settings/case-record.yaml` and says the adapter was
    refused. Control: the same adapter without that `VERBS` entry comments. O4, D-7 amended."""
    control_store, control = _leg_over_planted_adapter(
        tmp_path / "control", monkeypatch, method="POST", suffix="/comments")
    assert control["status"] == "commented", control
    assert len(control_store.calls) == 1, "positive control: the harmless adapter commented once"

    store, got = _leg_over_planted_adapter(
        tmp_path / "bad", monkeypatch, method="POST", suffix="/comments",
        verbs=VERBS_HOLDING_THE_ACTION[spelling])
    assert store.calls == [], f"{spelling}: a refused adapter still served the comment"
    assert (got["status"], got["ok"], got["url"]) == ("error", False, None), got
    reason = got["reason"].lower()
    assert "case-record.yaml" in reason, got
    assert str(tmp_path).lower() not in reason, f"the reason carries a host path: {got}"
    assert "adapter" in reason, got
    assert "refused" in reason, got
