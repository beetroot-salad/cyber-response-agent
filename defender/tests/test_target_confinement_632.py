"""#632 part 4, target fidelity: a verb cannot be aimed outside the system it is declared under. Host-state refuses hosts outside its inventory; elastic refuses indices outside the configured patterns; every outbound request is confined to a declared (path, method) read endpoint, observed through the transport capture seam. NOT covered: `elastic.esql` selects its target inside the FROM clause, which the verb-level check does not reach."""
from __future__ import annotations

import inspect
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("pydantic_ai")

from defender.runtime.verbs import VerbContext  # noqa: E402
from defender.tests.tenant_1107_settings import _spec1107 as S  # noqa: E402
from defender.scripts.adapters import elastic_adapter, host_state_adapter  # noqa: E402
from defender.scripts.adapters import identity_adapter  # noqa: E402
from defender.scripts.adapters.confinement import (  # noqa: E402
    READ_ENDPOINT_ALLOWLIST,
    AllowlistError,
    ConfinementFault,
    ReadEndpointAllowlist,
    TransportCapture,
    confine_index,
    confine_read_endpoint,
    normalize_endpoint,
)
from defender.scripts.adapters.faults import TransportFault  # noqa: E402
from defender.scripts.adapters.host_state_adapter import (  # noqa: E402
    HOST_STATE_PROGRAMS,
    confine_host,
    confine_host_state_call,
)

pytestmark = pytest.mark.e2e

CONFIGURED_PATTERNS = ("logs-*", "security-audit-*")
# The four estate-write endpoints that exist at HEAD, as (system, path, METHOD) triples — the
# shape the rule now keys on. #767 D2 moves the host's ticket write from a transition to a
# comment; the transition route STAYS in this census because the stub still serves it and a
# person's close is now the release act — the triple is a property of the store, not of who
# currently calls it (`d_checked_in_censuses_move_together`).
#
# THE SYSTEM LITERAL IS THE ONE THE WRITER REALLY CARRIES, and correcting it is half of why
# the method axis had to exist. The ticket-store mutations are reached by a post-run script
# whose system identity is `case-history`, not `ticket`, and both configs resolve to the SAME
# host — so neither the system label nor the host separates a read from a write, and the
# previous literal `"ticket"` papered that over. What separates them is the method.
TICKET_WRITER_SYSTEM = "case-history"
WRITE_ENDPOINTS = (
    (TICKET_WRITER_SYSTEM, "/tickets", "POST"),
    (TICKET_WRITER_SYSTEM, "/tickets/SOC-1/transitions", "POST"),
    (TICKET_WRITER_SYSTEM, "/tickets/SOC-1/comments", "POST"),
    ("elastic", "/logs-2026.01.01/_update/1", "POST"),
)
# The collision the endpoint-only rule could not survive, kept as its own case because it is
# the test's whole stated purpose: a FUTURE read-classed verb wrapping the write client would
# carry the `ticket` system name and request the same `/tickets` path the real `list-tickets`
# read requests. Path alone admits and refuses one call; path+method does not.
TICKET_READ_PATH = "/tickets"
# The paths the five stub adapters really request, read off their own `http_get`/`http_get_obj`
# call sites and written HERE rather than taken from the allowlist — the whole point is that
# the two lists are independent, so a divergence is a failure rather than a tautology.
# Placeholders are bound because the check runs on resolved targets. Every one is a GET: the
# measurement over all 27 real (system, path, method) triples found no stub read on any other
# method. Elastic's are not here: they arrive through the capture seam on a real drive.
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
    """The run's tenant record (#1107), resolved from a real tenant folder under `root` that
    carries only the elastic system's config — enough for the real adapter to resolve its index
    and its transport, and unreachable on purpose so an ordering test can tell a confinement
    refusal from a transport failure. Returns the record the ctx is handed as `tenant`."""
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


def _kibana_status_path() -> str:
    """The second endpoint `elastic.health-check` reaches, recovered from the ADAPTER's own
    source rather than restated here."""
    src = inspect.getsource(elastic_adapter.health_check)
    found = re.findall(r'KIBANA_URL"\]\.rstrip\("/"\)\s*\+\s*"([^"]+)"', src)
    assert len(found) == 1, (
        f"the elastic health-check verb no longer builds exactly one Kibana-host URL "
        f"({found}) — the read allowlist's fourth entry is derived from that call site"
    )
    return found[0]




def test_host_state_refuses_a_host_outside_its_inventory(tmp_path: Path):
    """A host-state verb aimed at a container outside the declared inventory REFUSES before
    the docker exec, instead of warning on stderr and proceeding. The host_state_target the
    model supplies becomes the docker exec target verbatim today, so `passwd` and"""
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
    the confinement compares against the inventory as declared, so a near-miss buys nothing."""
    with pytest.raises(ConfinementFault):
        confine_host(near_miss)
    assert near_miss not in host_state_adapter.KNOWN_HOSTS


def test_a_host_state_verb_confines_the_program_and_the_container_target_together():
    """A host-state verb's confinement rule checks the PAIR: the program against a
    per-system allowlist, AND the container target against the declared inventory (§7 R4)."""
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
    three are Elasticsearch's own grammar and all three pass today's URL quoting unescaped,"""
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
    """An inventory host and an index whose REACH falls inside the configured patterns still
    reach their stores unchanged — the confinement refuses the OUTSIDE, not the inside. The
    positive control both refusals need: without it, a rule that refused everything would"""
    confine_host("web-1")
    assert confine_index(inside, CONFIGURED_PATTERNS) == inside, \
        "an index whose reach is inside the configured patterns was rewritten or refused"

    ctx = _ctx(tmp_path)
    with pytest.raises(TransportFault):
        elastic_adapter.VERBS["query"](ctx, native_query="FROM x", index=inside)
    with pytest.raises(TransportFault):
        host_state_adapter.VERBS["proc-tree"](ctx, host="web-1")


def test_target_confinement_refuses_before_any_transport_is_attempted(tmp_path: Path):
    """Target confinement refuses BEFORE any transport is attempted, so a live backend
    outage cannot arrive first and obscure the refusal. Ordering, not outcome — distinct
    from the refusals above, which pin the refusal itself."""
    ctx = _ctx(tmp_path)

    with pytest.raises(ConfinementFault):
        elastic_adapter.VERBS["query"](ctx, native_query="FROM x", index="*")
    with pytest.raises(ConfinementFault):
        host_state_adapter.VERBS["passwd"](ctx, host="elasticsearch")


def test_the_transport_capture_seam_records_every_resolved_request(tmp_path: Path):
    """The adapters expose a TRANSPORT CAPTURE SEAM: a sink threaded in through the same
    `VerbContext` every verb already receives, into which each outbound request records its
    RESOLVED target before the transport is attempted."""
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
    """A verb classed `r` may only reach a declared read endpoint for its system, including
    a future verb wrapping the write client that already exists. The allowlist's entries are
    `(URL pattern, HTTP METHOD)` PAIRS, and the capture seam records the method beside the"""
    # THE REQUIREMENT IS EVERY SYSTEM THIS TEST DRIVES A READ ON, computed from the two
    # sources the drive below uses rather than hand-listed. Stated as four names while six
    # systems get driven, an implementer who builds to the assertion fails the loop on a
    # message about a URL instead of about a missing system — and the list drifts again the
    # next time a stub read is added.
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

    # THE THREE TICKET-STORE WRITE REFUSALS BELOW REST ON THIS, and until now nothing said so.
    # `case-history` is the ticket WRITER's own system identity and a really configured system
    # in this tree — it has a config of its own — so an implementer who declares read endpoints
    # under it in good faith turns three of the four negatives green without touching a line of
    # this test. It reaches the estate as a writer only: no adapter declares a verb for it, so
    # a correct read allowlist has nothing to list.
    assert TICKET_WRITER_SYSTEM not in READ_ENDPOINT_ALLOWLIST, (
        f"the read allowlist declares read endpoints for {TICKET_WRITER_SYSTEM}, the ticket "
        f"WRITER's system identity — three of the four write refusals below then pass for a "
        f"reason this test no longer controls"
    )

    for system, endpoint, method in WRITE_ENDPOINTS:
        with pytest.raises(ConfinementFault):
            confine_read_endpoint(system, f"http://host{endpoint}", method=method,
                                  verb_class="r")

    # The collision itself, both ways round, under the ONE system name a read-classed verb
    # wrapping the write client would carry. This pair is the reason the axis exists: drop
    # either assertion and the rule is either unsatisfiable or blind to the case it was
    # written for.
    confine_read_endpoint("ticket", f"http://host{TICKET_READ_PATH}", method="GET",
                          verb_class="r")
    with pytest.raises(ConfinementFault):
        confine_read_endpoint("ticket", f"http://host{TICKET_READ_PATH}", method="POST",
                              verb_class="r")


def _stub_tree(root: Path, system: str, prefix: str, *, bastion: str) -> Any:
    """The run's tenant record (#1107), resolved from a real tenant folder under `root`
    carrying one stub system's config.env — the shape the record's `systems` entry is read
    from, not a monkeypatch of it. `bastion` names a docker context this host has never heard"""
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
    """The read-endpoint rule is enforced for a STUB system (identity, not elastic) by
    driving its REAL adapter through the REAL, unmocked `_stub_transport.py` — the shared
    function all five stub systems route through — rather than by calling"""
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
    """The read-endpoint allowlist CANNOT BE BUILT with an entry that names no HTTP method: it
    is assembled through a validating constructor that refuses one, and the shipped table is
    what that constructor returned."""
    assert isinstance(READ_ENDPOINT_ALLOWLIST, ReadEndpointAllowlist), (
        "the shipped read-endpoint allowlist is not a constructed allowlist, so nothing in "
        "production refuses a method-less entry — the constructor is not on the path the "
        "shipped table takes, which is the only path an author's mistake travels"
    )
    assert isinstance(READ_ENDPOINT_ALLOWLIST, Mapping), (
        "the allowlist type is not a Mapping — the endpoint rule's own test reads this table "
        "by key set, by system and by subscript"
    )

    for methodless in (
        ("/tickets",),         # a one-element entry: no method at all
        ("/tickets", ""),      # a present-but-empty method token
        ("/tickets", None),    # the shape a half-migrated entry takes
        "/tickets",            # a bare path string, the pre-F1 entry shape
    ):
        with pytest.raises(AllowlistError):
            ReadEndpointAllowlist({"ticket": (methodless,)})

    ok = ReadEndpointAllowlist({"ticket": ((TICKET_READ_PATH, "GET"),)})
    assert tuple(ok["ticket"]) == ((TICKET_READ_PATH, "GET"),), \
        "a well-authored (endpoint, method) pair did not survive construction"
    confine_read_endpoint("elastic", "http://es:9200/_cluster/health", method="GET",
                          verb_class="r")


def test_the_two_post_with_body_reads_still_pass_the_endpoint_check():
    """Elastic's `_search` and `_query` — both POST-with-body reads — still pass the endpoint
    check as LISTED PAIRS, so what the rule rejects is an unlisted (path, method) and never
    "POST" as such. The standing guard for the refutation that killed the blanket rule."""
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
    """The endpoint check binds on the RESOLVED request target, compared on a NORMALIZED
    path with the query string EXCLUDED (§7 R6)."""
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
