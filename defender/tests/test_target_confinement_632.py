"""#632 part 4 — target fidelity: a verb cannot be aimed outside the system it is declared under.

One test per demand of `spec_graph_632-verb-authorization.yaml`, named by its
`discharged_by`. RED against `d01001e6` by construction.

Why this half exists at all: a `(role, system, verb)` grant does not bound what a role
REACHES. Today `_check_host` warns to stderr and proceeds, so a role granted only
host-state reads files inside the Elasticsearch, Kibana and ticket-store containers (c13);
and `resolved = index or config[index_key]`, quoted with `safe='-*,.'` and authenticated as
the cluster superuser, so a role granted only elastic reads any index in the cluster (c14).
Both refutations still stand at HEAD, unmodified (g13). Without this, the grant's universal
is false with the authorization layer working perfectly.

Both refusals are placed in the VERB, not in role policy: the verb is the unit that knows
its own boundary, so it is the unit that must not lie about it — which is also what keeps
target-selecting params out of role policy.

The endpoint half is observed through a TRANSPORT CAPTURE SEAM this spec mints (phase F,
finding 6): the adapters record each resolved request into a sink carried on the
`VerbContext` they already receive. Without it the allowlist could only be checked against
its own declared entries — an assertion no shipped allowlist can fail — and the outbound
request itself would stay unobserved, since the project's lint forbids the
`monkeypatch.setattr` that is the only other way to see it.

Recorded and NOT built (RS9): `elastic.esql` selects its target inside the ES|QL FROM
clause rather than through a param, so the verb-level target check does not reach it at
all, and O2 stays undischarged for the capability carrying 610 of ~1000 recorded calls.
Nothing here may read as though target confinement holds surface-general.
"""
from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")

from defender.runtime.circuit_breaker import error_class_for_exit  # noqa: E402
from defender.runtime.verbs import VerbContext  # noqa: E402
from defender.scripts.adapters import elastic_adapter, host_state_adapter  # noqa: E402
from defender.scripts.adapters.confinement import (  # noqa: E402
    HOST_STATE_PROGRAMS,
    READ_ENDPOINT_ALLOWLIST,
    ConfinementFault,
    TransportCapture,
    confine_host,
    confine_host_state_call,
    confine_index,
    confine_read_endpoint,
    normalize_endpoint,
)
from defender.scripts.adapters.faults import TransportFault  # noqa: E402

pytestmark = pytest.mark.e2e

CONFIGURED_PATTERNS = ("logs-*", "security-audit-*")
# The four estate-write endpoints that exist at HEAD, two of them ungated (g14). Every one
# lives outside the adapter set, and every one must fail the read-endpoint rule.
WRITE_ENDPOINTS = (
    "/tickets",
    "/tickets/SOC-1/transitions",
    "/tickets/SOC-1/comments",
    "/logs-2026.01.01/_update/1",
)
# The paths the five stub adapters really request, read off their own `http_get`/`http_get_obj`
# call sites and written HERE rather than taken from the allowlist — the whole point is that
# the two lists are independent, so a divergence is a failure rather than a tautology.
# Placeholders are bound because the check runs on resolved targets. Elastic's four are not
# here: they arrive through the capture seam on a real drive.
REAL_STUB_ENDPOINTS = (
    ("change-mgmt", "/health"), ("change-mgmt", "/changes"),
    ("change-mgmt", "/changes/active"), ("change-mgmt", "/changes/CR-1042"),
    ("cmdb", "/health"), ("cmdb", "/hosts"), ("cmdb", "/hosts/web-1"), ("cmdb", "/roles"),
    ("identity", "/health"), ("identity", "/users"), ("identity", "/roles"),
    ("identity", "/users/dev.dana"), ("identity", "/users/dev.dana/can_access"),
    ("identity", "/users/dev.dana/authorized_hosts"),
    ("threat-intel", "/health"), ("threat-intel", "/indicators"),
    ("threat-intel", "/lookup/1.2.3.4"),
    ("ticket", "/health"), ("ticket", "/tickets"), ("ticket", "/tickets/SOC-777"),
)


def _tree(root: Path, *, url: str = "http://127.0.0.1:1") -> Path:
    """A real defender tree carrying only the elastic system's config — enough for the real
    adapter to resolve its index and its transport, and unreachable on purpose so an
    ordering test can tell a confinement refusal from a transport failure."""
    d = root / "knowledge" / "environment" / "systems" / "elastic"
    d.mkdir(parents=True)
    (d / "config.env").write_text(
        f"ELASTICSEARCH_URL={url}\n"
        f"KIBANA_URL={url}\n"
        "ELASTIC_EVENTS_INDEX=logs-*\n"
        "ELASTIC_ALERTS_INDEX=security-audit-*\n",
        encoding="utf-8",
    )
    return root


def _ctx(tmp_path: Path) -> VerbContext:
    return VerbContext(defender_dir=_tree(tmp_path / "tree"), run_dir=tmp_path / "run", env={})




def test_host_state_refuses_a_host_outside_its_inventory(tmp_path: Path):
    """A host-state verb aimed at a container outside the declared inventory REFUSES before
    the docker exec, instead of warning on stderr and proceeding. The host_state_target the
    model supplies becomes the docker exec target verbatim today, so `passwd` and
    `proc-tree` run inside another granted system's store — the live refutation this demand
    is the correction to."""
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
    """A case, whitespace, substring or prefix variant of a declared inventory host is
    REFUSED, not warned-and-proceeded, and no normalization equates it to the real host —
    the confinement compares against the inventory as declared, so a near-miss buys nothing.

    Whether a near-miss earns its own distinct message is open and cosmetic; that it never
    resolves is not."""
    with pytest.raises(ConfinementFault):
        confine_host(near_miss)
    assert near_miss not in host_state_adapter.KNOWN_HOSTS


def test_a_host_state_verb_confines_the_program_and_the_container_target_together():
    """A host-state verb's confinement rule checks the PAIR: the program against a
    per-system allowlist, AND the container target against the declared inventory (§7 R4).
    Both halves, never either alone — the program alone does not bound reach (`cat` inside
    the ticket store is the disclosure), and the target alone does not bound effect.

    This is a second rule form, not a row in the endpoint table: host-state's six verbs
    reach the estate as a literal argv list through docker exec, with no URL anywhere for a
    row-shaped rule to apply to (g11, refuted).

    The two sharp cases are ORDINARY REFUSALS with no special-casing: the agent's own
    execution container, and the container holding another granted system's data store."""
    assert set(HOST_STATE_PROGRAMS) >= {"ps", "cat", "getent", "sha256sum", "dpkg-query"}

    confine_host_state_call("cat", "web-1")

    with pytest.raises(ConfinementFault):
        confine_host_state_call("cat", "defender")        # the agent's own container
    with pytest.raises(ConfinementFault):
        confine_host_state_call("cat", "ticket-store")    # another granted system's store
    with pytest.raises(ConfinementFault):
        confine_host_state_call("curl", "web-1")          # in-inventory target, ungated program




def test_an_elastic_read_refuses_an_index_outside_the_configured_patterns(tmp_path: Path):
    """An elastic read whose `elastic_index` param falls outside the system's configured
    patterns REFUSES, instead of overriding the configured index and reading it as the
    cluster superuser."""
    with pytest.raises(ConfinementFault):
        confine_index(".security-7", CONFIGURED_PATTERNS)

    ctx = _ctx(tmp_path)
    with pytest.raises(ConfinementFault):
        elastic_adapter.VERBS["query"](ctx, native_query="FROM x", index=".security-7")


@pytest.mark.parametrize("widening", ["logs-*,security-audit-*,.security-7", "*", "-logs-*"])
def test_an_index_expression_whose_reach_widens_refuses_the_whole_call(
    tmp_path: Path, widening: str,
):
    """Confinement evaluates REACH, not the literal, and refuses the WHOLE call (§7 R5). A
    comma is a multi-index list, `*` is a wildcard, and a leading `-` is an exclusion; all
    three are Elasticsearch's own grammar and all three pass today's URL quoting unescaped,
    against a superuser credential. A confinement that compares strings is not a
    confinement.

    Never silently narrow to the in-bounds members: silent narrowing satisfies the letter of
    the obligation while hiding an attempted cross-tenant read from the audit trail that
    exists to record it."""
    with pytest.raises(ConfinementFault):
        confine_index(widening, CONFIGURED_PATTERNS)

    ctx = _ctx(tmp_path)
    with pytest.raises(ConfinementFault):
        elastic_adapter.VERBS["query"](ctx, native_query="FROM x", index=widening)


def test_an_inventory_host_and_a_configured_index_still_run(tmp_path: Path):
    """An inventory host and a configured index still reach their stores unchanged — the
    confinement refuses the OUTSIDE, not the inside. The positive control both refusals
    need: without it, a rule that refused everything would pass every negative above.

    The observable difference is which fault arrives: an in-bounds target gets past the gate
    and fails on the (deliberately unreachable) transport, while an out-of-bounds one never
    reaches it."""
    confine_host("web-1")
    assert confine_index("logs-*", CONFIGURED_PATTERNS) == "logs-*"

    ctx = _ctx(tmp_path)
    with pytest.raises(TransportFault):
        elastic_adapter.VERBS["query"](ctx, native_query="FROM x", index="logs-*")
    with pytest.raises(TransportFault):
        host_state_adapter.VERBS["proc-tree"](ctx, host="web-1")


def test_target_confinement_refuses_before_any_transport_is_attempted(tmp_path: Path):
    """Target confinement refuses BEFORE any transport is attempted, so a live backend
    outage cannot arrive first and obscure the refusal. Ordering, not outcome — distinct
    from the refusals above, which pin the refusal itself.

    The tree here points every transport at an unreachable endpoint, so a rule that ran
    after the call would surface a transport fault and the confinement would be invisible in
    exactly the situation an attacker can arrange."""
    ctx = _ctx(tmp_path)

    with pytest.raises(ConfinementFault):
        elastic_adapter.VERBS["query"](ctx, native_query="FROM x", index="*")
    with pytest.raises(ConfinementFault):
        host_state_adapter.VERBS["passwd"](ctx, host="elasticsearch")


def test_an_in_bounds_calls_backend_outage_is_recorded_exactly_as_today(tmp_path: Path):
    """An in-bounds call's backend outage is recorded exactly as today: confinement changes
    NOTHING after the gate. The conservation half — without it the suite tests only the new
    restriction and silently regresses what the old surface quietly served.

    The fault, its exit code and its error class are the transport's own, unchanged: an
    infra failure that still advances the breaker, never reclassified into a policy
    refusal."""
    ctx = _ctx(tmp_path)
    with pytest.raises(TransportFault) as caught:
        elastic_adapter.VERBS["query"](ctx, native_query="FROM x", index="logs-*")

    assert error_class_for_exit(caught.value.exit_code) == "infra"
    assert error_class_for_exit(ConfinementFault("x").exit_code) != "infra", \
        "a target refusal is filed as an infra fault and would move the breaker"




def test_the_transport_capture_seam_records_every_resolved_request(tmp_path: Path):
    """The adapters expose a TRANSPORT CAPTURE SEAM: a sink threaded in through the same
    `VerbContext` every verb already receives, into which each outbound request records its
    RESOLVED target before the transport is attempted.

    Minted as a demand rather than waived. Without it the endpoint allowlist can only be
    checked against its own declared entries, which is an assertion the allowlist wins by
    definition; with it the rule meets the URLs the adapters really build. It is also the
    only observation channel for the payload obligation on this edge that does not require
    monkeypatching a transport symbol, which this project's lint ratchets against.

    The capture happens BEFORE the send, which is why it survives a transport that cannot
    connect — and that ordering is what lets the confinement rule bind on the resolved
    target rather than on a request that already left."""
    capture = TransportCapture()
    ctx = VerbContext(defender_dir=_tree(tmp_path / "tree"), run_dir=tmp_path / "run", env={},
                      capture=capture)

    with pytest.raises(TransportFault):
        elastic_adapter.VERBS["query"](ctx, native_query="FROM x", index="logs-*")

    assert capture.requests, "the seam recorded nothing — the transport bypasses it"
    request = capture.requests[-1]
    assert request.system == "elastic"
    assert normalize_endpoint(request.url) == "/logs-*/_search", \
        "the seam records something other than the resolved request target"

    unobserved = VerbContext(defender_dir=_tree(tmp_path / "bare"), run_dir=tmp_path / "run2",
                             env={})
    with pytest.raises(TransportFault):
        elastic_adapter.VERBS["query"](unobserved, native_query="FROM x", index="logs-*")


def test_an_r_classed_verb_may_only_reach_a_declared_read_endpoint(tmp_path: Path):
    """A verb classed `r` may only reach a declared read endpoint for its system, including
    a future verb wrapping the write client that already exists. The rule keys on the
    ENDPOINT because a method-based one does not work — Elasticsearch's search and ES|QL are
    both POST-with-body READS (c17, refuted), so "an `r` verb may not POST or send a body"
    would reject two working verbs.

    Checked against REAL endpoints, never against the allowlist's own entries. Feeding each
    declared pattern back to the checker is a tautology: it holds for whatever set ships, so
    an allowlist that quietly loses a system's real endpoint passes it. Both halves below
    come from outside the allowlist — elastic's through the transport capture seam on a real
    drive, the stub systems' as literals read off the adapters (the 17-pattern set g12
    censused). If the allowlist and the adapters diverge, this fails.

    The closed set is what makes it checkable in the other direction: every estate-write
    endpoint falls outside it, so an `r` verb that grew one fails."""
    assert set(READ_ENDPOINT_ALLOWLIST) >= {"elastic", "cmdb", "identity", "ticket"}
    for system, patterns in READ_ENDPOINT_ALLOWLIST.items():
        assert patterns, f"{system} declares an empty read-endpoint allowlist — an open gate"

    capture = TransportCapture()
    ctx = VerbContext(defender_dir=_tree(tmp_path / "tree"), run_dir=tmp_path / "run", env={},
                      capture=capture)
    for verb, kwargs in (("query", {"native_query": "FROM x", "index": "logs-*"}),
                         ("alerts", {"native_query": "*", "index": "security-audit-*"}),
                         ("esql", {"query": "FROM logs-* | LIMIT 1"}),
                         ("health-check", {})):
        with pytest.raises(TransportFault):
            elastic_adapter.VERBS[verb](ctx, **kwargs)

    assert len(capture.requests) >= 4, "some real elastic verb reached no captured endpoint"
    for request in capture.requests:
        confine_read_endpoint(request.system, request.url, verb_class="r")

    for system, endpoint in REAL_STUB_ENDPOINTS:
        confine_read_endpoint(system, f"http://host{endpoint}", verb_class="r")

    for endpoint in WRITE_ENDPOINTS:
        with pytest.raises(ConfinementFault):
            confine_read_endpoint("ticket", f"http://host{endpoint}", verb_class="r")


def test_the_two_post_with_body_reads_still_pass_the_endpoint_check():
    """Elastic's `_search` and `_query` — both POST-with-body reads — still pass the endpoint
    check, so the rule keys on the endpoint and not the method. The standing guard for the
    refutation that killed the method-based rule."""
    confine_read_endpoint("elastic", "http://es:9200/logs-*/_search", verb_class="r")
    confine_read_endpoint("elastic", "http://es:9200/_query?format=json", verb_class="r")
    confine_read_endpoint("elastic", "http://es:9200/_cluster/health", verb_class="r")

    with pytest.raises(ConfinementFault):
        confine_read_endpoint("elastic", "http://es:9200/logs-*/_update/1", verb_class="r")


def test_the_endpoint_check_binds_on_the_resolved_normalized_path_without_the_query_string():
    """The endpoint check binds on the RESOLVED request target, compared on a NORMALIZED
    path with the query string EXCLUDED (§7 R6).

    Post-interpolation is the only side where a path-altering parameter meets the check at
    all — against the verb's declared, uninterpolated pattern it would escape entirely.
    Dropping the query string keeps incidental adapter formatting out of the security
    boundary without weakening the path constraint the rule rests on."""
    assert normalize_endpoint("http://es:9200/logs-*/_search?pretty=true&x=1") == "/logs-*/_search"
    assert normalize_endpoint("http://es:9200//logs-*//_search/") == "/logs-*/_search"

    confine_read_endpoint("elastic", "http://es:9200/logs-*/_search?pretty=true", verb_class="r")

    with pytest.raises(ConfinementFault):
        confine_read_endpoint("elastic", "http://es:9200/logs-*/_search/../../_update/1",
                              verb_class="r")
    with pytest.raises(ConfinementFault):
        confine_read_endpoint("elastic", "http://es:9200/%5Flogs/../_update/1", verb_class="r")
