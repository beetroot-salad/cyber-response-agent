"""#632 target fidelity: a verb cannot be aimed outside the system it is declared under. Host-state refuses hosts outside its inventory; elastic refuses indices outside the configured patterns; every outbound request is confined to a declared (path, method) read endpoint, observed through the transport capture seam. `elastic.esql` selects its targets inside the query text, so a parser confines every source it reads (FROM lists, LOOKUP JOIN, TS, subqueries, ENRICH) to the same patterns and refuses what it cannot classify (#1347 O2a). Not covered: the transport, which is unreachable on purpose here."""
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
TICKET_WRITER_SYSTEM = "case-history"
WRITE_ENDPOINTS = (
    (TICKET_WRITER_SYSTEM, "/tickets", "POST"),
    (TICKET_WRITER_SYSTEM, "/tickets/SOC-1/transitions", "POST"),
    (TICKET_WRITER_SYSTEM, "/tickets/SOC-1/comments", "POST"),
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


def _tree(root: Path, *, url: str = "http://127.0.0.1:1",
          alerts: str = "security-audit-*") -> Any:
    """The run's tenant record, resolved from a real tenant folder under `root` carrying only the
    elastic and host-state config. The transport is unreachable on purpose: a `ConfinementFault`
    (not a `TransportFault`) shows confinement refused before any transport was attempted."""
    S.plant(root, configs={"elastic": (
        f"ELASTICSEARCH_URL={url}\n"
        f"KIBANA_URL={url}\n"
        "ELASTIC_EVENTS_INDEX=logs-*\n"
        f"ELASTIC_ALERTS_INDEX={alerts}\n"
        "ELASTIC_SSL_VERIFY=true\n"
        "ELASTIC_TRANSPORT=docker-exec\n"
        "ELASTIC_DOCKER_CONTEXT=no-such-context-632-test\n"
        "ELASTIC_ES_CONTAINER=es-632\n"
        "ELASTIC_KIBANA_CONTAINER=kibana-632\n"),
        "host-state": ("HOST_STATE_TRANSPORT=docker-exec\n"
                       "HOST_STATE_DOCKER_CONTEXT=no-such-context-632-test\n")})
    return S.resolve(root)


def _ctx(tmp_path: Path, **tree: Any) -> VerbContext:
    return VerbContext(defender_dir=tmp_path / "tree", tenant=_tree(tmp_path / "tree", **tree),
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

    assert TICKET_WRITER_SYSTEM not in READ_ENDPOINT_ALLOWLIST, (
        f"the read allowlist declares read endpoints for {TICKET_WRITER_SYSTEM}, the ticket "
        f"writer's system, so the write refusals below pass for another reason"
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


ESQL_OUTSIDE = [
    pytest.param("FROM .security-7 | LIMIT 1", id="from-outside"),
    pytest.param("from .security-7", id="lowercase-from"),
    pytest.param('FROM ".security-7"', id="quoted-source"),
    pytest.param("FROM logs-*, .security-7", id="list-tail-outside"),
    pytest.param("FROM .security-7, logs-*", id="list-head-outside"),
    pytest.param("FROM logs-*,security-audit-*,.security-7 | LIMIT 1", id="list-no-spaces"),
    pytest.param('FROM "logs-*", ".security-7"', id="quoted-list"),
    pytest.param("FROM *", id="whole-cluster"),
    pytest.param("FROM logs-*,*", id="wildcard-in-list"),
    pytest.param("FROM remote:logs-*", id="cross-cluster-prefix"),
    pytest.param("FROM logs-* | LOOKUP JOIN .security-7 ON host.name", id="lookup-join"),
    pytest.param("FROM logs-* METADATA _index\n| LOOKUP JOIN .security-7 ON host.name",
                 id="lookup-join-after-metadata"),
    pytest.param("TS .security-7", id="ts-source"),
    pytest.param("TS .security-7 | LIMIT 1", id="ts-source-piped"),
    pytest.param("// c\nFROM .security-7", id="line-comment-before-source"),
    pytest.param("/* x */ FROM .security-7", id="block-comment-before-source"),
    pytest.param("FROM logs-*, // note\n .security-7", id="comment-inside-list"),
    pytest.param("FROM logs-*, (FROM .security-7)", id="subquery-source"),
    pytest.param("FROM (FROM .security-7)", id="only-a-subquery"),
    pytest.param("FROM logs-*, (FROM security-audit-*, (FROM .security-7))", id="nested-subquery"),
    pytest.param("FROM logs-* | ENRICH some-policy ON host.name", id="enrich"),
    pytest.param("FROM logs-* | WHERE x == 1 // c\n| LOOKUP JOIN .security-7 ON y",
                 id="lookup-after-trailing-comment"),
]

ESQL_UNCLASSIFIABLE = [
    pytest.param("", id="empty"),
    pytest.param("lorem ipsum", id="not-a-query"),
    pytest.param("FROM", id="from-without-target"),
    pytest.param("METRICS .security-7", id="unknown-source-command"),
    pytest.param("EXPLAIN (FROM .security-7)", id="unknown-wrapper"),
]

ESQL_INSIDE = [
    pytest.param("FROM logs-system.auth-* | LIMIT 1", id="from-inside"),
    pytest.param("FROM logs-*, security-audit-* | LIMIT 1", id="both-patterns"),
    pytest.param("FROM logs-system.auth-*,logs-system.syslog-* METADATA _index, _version",
                 id="list-with-metadata"),
    pytest.param("// c\nFROM logs-*", id="leading-line-comment"),
    pytest.param("/* x */ FROM logs-*", id="leading-block-comment"),
    pytest.param("FROM logs-* // FROM .security-7\n| LIMIT 1", id="comment-names-outside"),
    pytest.param("FROM logs-* /* , .security-7 */ | LIMIT 1", id="block-comment-in-list"),
    pytest.param('FROM logs-* | WHERE message == "x | FROM .security-7"', id="string-is-data"),
    pytest.param('FROM logs-* | WHERE message LIKE "FROM .security-7*"', id="like-string-is-data"),
    pytest.param("FROM logs-* | LOOKUP JOIN logs-lookup ON host.name", id="lookup-join-inside"),
    pytest.param("TS logs-metrics-* | LIMIT 1", id="ts-inside"),
    pytest.param("FROM logs-*, (FROM security-audit-* | LIMIT 1)", id="subquery-inside"),
    pytest.param("ROW a = 1", id="row-reads-no-index"),
    pytest.param("SHOW INFO", id="show-reads-no-index"),
]


@pytest.mark.parametrize("query", [*ESQL_OUTSIDE, *ESQL_UNCLASSIFIABLE])
def test_an_esql_with_a_source_outside_the_patterns_or_unclassifiable_is_refused(
    tmp_path: Path, query: str,
):
    """#1347 O2a: every source an ES|QL reads is confined; what cannot be classified is refused
    before any transport is attempted."""
    with pytest.raises(ConfinementFault):
        elastic_adapter.VERBS["esql"](_ctx(tmp_path), query=query)


@pytest.mark.parametrize("query", ESQL_INSIDE)
def test_an_esql_whose_every_source_is_inside_the_patterns_still_runs(tmp_path: Path, query: str):
    """#1347 O2a control: reaching the (unreachable) transport shows confinement admitted it."""
    with pytest.raises(TransportFault):
        elastic_adapter.VERBS["esql"](_ctx(tmp_path), query=query)


@pytest.mark.parametrize("query", [
    "FROM logs-falco.alerts-*\n| WHERE @timestamp >= \"2026-05-25T13:45:00Z\" | LIMIT 1",
    "FROM logs-system.auth-* | WHERE host.name == \"office-ws-1\" | LIMIT 1",
    "FROM logs-* | LIMIT 20",
    "FROM logs-system.syslog-* | LIMIT 1",
    "FROM .internal.alerts-security.alerts-default-*\n| STATS alerts = COUNT(*)",
    # A configured stream's own backing indexes hold the same, fingerprinted documents.
    "FROM logs-falco.alerts-*, .ds-logs-falco.alerts-* | LIMIT 5",
])
def test_the_recorded_real_esql_targets_are_not_refused(tmp_path: Path, query: str):
    """#1347 O2a/C21: targets seen in recorded runs, under the fixture tenant's real patterns."""
    ctx = _ctx(tmp_path, alerts=".internal.alerts-security.alerts-default-*")

    with pytest.raises(TransportFault):
        elastic_adapter.VERBS["esql"](ctx, query=query)


@pytest.mark.parametrize("query", ["FROM .security-7 | LIMIT 1", "// c\nFROM .security-7"])
def test_a_cut_run_confines_esql_exactly_as_an_ordinary_run_does(tmp_path: Path, query: str):
    """#1347 O2a: confinement is every run, with or without the cuts."""
    import datetime as dt

    cut = dt.datetime(2026, 10, 20, 9, 0, 0, tzinfo=dt.UTC)
    ctx = _ctx(tmp_path)
    ctx = VerbContext(defender_dir=ctx.defender_dir, tenant=ctx.tenant, run_dir=ctx.run_dir,
                      env={}, as_of=cut, arrived_by=cut)

    with pytest.raises(ConfinementFault):
        elastic_adapter.VERBS["esql"](ctx, query=query)
    with pytest.raises(TransportFault):
        elastic_adapter.VERBS["esql"](ctx, query="FROM logs-system.auth-* | LIMIT 1")
