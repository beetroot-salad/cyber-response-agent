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

The allowlist's own AUTHORING integrity is a third demand here, not part of either rule: the
table stops being a bare module constant and is assembled through a constructor that refuses a
method-less entry, because F1 made the method the axis that separates the ticket read from the
ticket write and nothing in production noticed an entry authored without one.

Recorded and NOT built (RS9): `elastic.esql` selects its target inside the ES|QL FROM
clause rather than through a param, so the verb-level target check does not reach it at
all, and O2 stays undischarged for the capability carrying 610 of ~1000 recorded calls.
Nothing here may read as though target confinement holds surface-general.
"""
from __future__ import annotations

import inspect
import re
from collections.abc import Mapping
from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")

from defender.runtime.circuit_breaker import error_class_for_exit  # noqa: E402
from defender.runtime.verbs import VerbContext  # noqa: E402
from defender.scripts.adapters import elastic_adapter, host_state_adapter  # noqa: E402
from defender.scripts.adapters import identity_adapter  # noqa: E402
from defender.scripts.adapters.confinement import (  # noqa: E402
    HOST_STATE_PROGRAMS,
    READ_ENDPOINT_ALLOWLIST,
    AllowlistError,
    ConfinementFault,
    ReadEndpointAllowlist,
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
# The four estate-write endpoints that exist at HEAD, two of them ungated (g14), as
# (system, path, METHOD) triples — the shape the rule now keys on.
#
# THE SYSTEM LITERAL IS THE ONE THE WRITER REALLY CARRIES, and correcting it is half of why
# the method axis had to exist. The three ticket-store mutations are reached by a post-run
# script whose system identity is `case-history`, not `ticket`, and both configs resolve to
# the SAME host — so neither the system label nor the host separates a read from a write, and
# the previous literal `"ticket"` papered that over. What separates them is the method.
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


def _kibana_status_path() -> str:
    """The second endpoint `elastic.health-check` reaches, recovered from the ADAPTER's own
    source rather than restated here.

    The verb builds it as `KIBANA_URL + <path>`, on a different host from every other elastic
    read, and the first request failing is the only reason a drive against an unreachable tree
    never gets there. Reading it off the source keeps the allowlist obligation attached to the
    code that creates it: retarget the verb and this fixture follows, so the allowlist entry
    is required to follow too."""
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


@pytest.mark.parametrize("inside", [
    "logs-*",                 # a configured pattern, fed back verbatim
    "logs-2026.01.01",        # a CONCRETE index under it — the daily index every real read hits
    "logs-2026.01.*",         # a strictly NARROWER wildcard
    "security-audit-2026.01", # the same, on the second configured pattern
])
def test_an_inventory_host_and_a_configured_index_still_run(tmp_path: Path, inside: str):
    """An inventory host and an index whose REACH falls inside the configured patterns still
    reach their stores unchanged — the confinement refuses the OUTSIDE, not the inside. The
    positive control both refusals need: without it, a rule that refused everything would
    pass every negative above.

    THE CONTROL IS NOT THE CONFIGURED PATTERN FED BACK VERBATIM, and that is the whole of
    what this parametrization adds. Re-feeding `logs-*` is satisfied by bare string equality
    against the configured set — which computes no reach relation at all and rejects every
    concrete index the system really reads, so a confinement that had replaced reach with
    equality would ship green and break every elastic read on the first daily index. The
    subsuming cases below are what make the positive control an independent observation: each
    is a distinct string whose REACH is contained by a configured pattern, and none of them
    is in the configured set.

    The observable difference is which fault arrives: an in-bounds target gets past the gate
    and fails on the (deliberately unreachable) transport, while an out-of-bounds one never
    reaches it."""
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
    assert request.method == "POST", (
        "the seam records no HTTP method — the read allowlist keys on (path, method) pairs, "
        "so a capture without the method leaves the rule's second half unobservable"
    )

    unobserved = VerbContext(defender_dir=_tree(tmp_path / "bare"), run_dir=tmp_path / "run2",
                             env={})
    with pytest.raises(TransportFault):
        elastic_adapter.VERBS["query"](unobserved, native_query="FROM x", index="logs-*")


def test_an_r_classed_verb_may_only_reach_a_declared_read_endpoint(tmp_path: Path):
    """A verb classed `r` may only reach a declared read endpoint for its system, including
    a future verb wrapping the write client that already exists. The allowlist's entries are
    `(URL pattern, HTTP METHOD)` PAIRS, and the capture seam records the method beside the
    path.

    THE METHOD IS IN THE KEY BECAUSE WITHOUT IT THE RULE IS UNSATISFIABLE, not merely weak.
    The ticket store's "list the tickets" read and the writer's "create a ticket" mutation
    resolve to the same path under configs pointing at the same host, so a rule seeing only
    `(system, path)` is asked to admit and refuse one identical call. Over the 27 distinct
    (system, path, method) triples the real adapters and the real writer produce, path alone
    collides exactly once — here — and path+method collides nowhere.

    c17 is not overturned. It refuted a GLOBAL "an `r` verb may not POST", and elastic's two
    POST-with-body reads are listed pairs that still pass; what it never refuted is an
    allowlist whose entries each name a method.

    Checked against REAL endpoints, never against the allowlist's own entries. Feeding each
    declared pattern back to the checker is a tautology: it holds for whatever set ships, so
    an allowlist that quietly loses a system's real endpoint passes it. Both halves below
    come from outside the allowlist — elastic's through the transport capture seam on a real
    drive, the stub systems' as literals read off the adapters (the 17-pattern set g12
    censused). If the allowlist and the adapters diverge, this fails.

    The closed set is what makes it checkable in the other direction: every estate-write
    endpoint falls outside it under its own system and its own method, so an `r` verb that
    grew one fails."""
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


def _stub_tree(root: Path, system: str, prefix: str, *, bastion: str) -> Path:
    """A real defender tree carrying one stub system's config.env — the shape
    `_stub_transport.load_config` reads, not a monkeypatch of it. `bastion` names a
    docker context this host has never heard of, so a call that gets PAST confinement
    still never reaches a real container: it fails on the docker exec, the same
    ordering the elastic fixture above pins."""
    d = root / "knowledge" / "environment" / "systems" / system
    d.mkdir(parents=True)
    (d / "config.env").write_text(
        f"{prefix}_URL_BASE=http://stub-{system}\n"
        f"{prefix}_BASTION_HOST={bastion}\n"
        f"{prefix}_TIMEOUT_SEC=2\n",
        encoding="utf-8",
    )
    return root


def test_a_non_elastic_stub_adapter_is_confined_through_the_real_shared_transport(
    tmp_path: Path,
):
    """The read-endpoint rule is enforced for a STUB system (identity, not elastic) by
    driving its REAL adapter through the REAL, unmocked `_stub_transport.py` — the shared
    function all five stub systems route through — rather than by calling
    `confine_read_endpoint` as a standalone function on a literal string.

    `test_an_r_classed_verb_may_only_reach_a_declared_read_endpoint` above checks the stub
    systems' entries against paths read off the adapters as LITERALS (g12's census); it
    never drives a stub adapter's own call site, so it would still pass if the wiring lived
    only in `elastic_adapter.py`'s private `_http_json` and every stub adapter's shared
    transport skipped the check entirely — which is exactly what shipped until this test
    was added (#632 adversary finding: the shared transport carries five systems' worth of
    calls and none of them were confined).

    The adversarial half drives `identity_adapter.get_user` with a `user` value of
    `"../../secret"`: the verb builds `/users/../../secret`, no different from any other
    path segment as far as the adapter's own code is concerned, and `normalize_endpoint`
    resolves it to `/secret` — outside identity's declared allowlist. If `_request` no
    longer called `confine_read_endpoint` (this fix reverted), this call would sail past
    the check and reach `docker_exec_curl` instead of stopping at a `ConfinementFault`."""
    ctx = VerbContext(
        defender_dir=_stub_tree(tmp_path / "tree", "identity", "IDENTITY",
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
    what that constructor returned.

    Symmetric with the grant's authoring integrity, and minted for the same reason. Three
    hand-authored tables now carry the model's permissions. The per-role grant refuses a bad
    class token and a conflicting duplicate at construction; the generated roster must
    regenerate to its committed bytes, so a hand-edit is a load failure. The allowlist — the
    newest of the three — had nothing of the kind: a method-less entry was caught by one
    assertion over one committed literal, and by nothing in production.

    It is load-bearing rather than tidy because F1 resolved the ticket read/write collision by
    making THE METHOD the discriminating axis. An entry authored without one silently reopens
    exactly the collision the fork was resolved to close, and the read and the write are one
    resolved path on one host, so nothing else separates them.

    A SHAPE CHECK OVER THE COMMITTED CONSTANT IS NOT THIS DEMAND, which is why the endpoint
    rule's own test keeping one changes nothing here: that assertion certifies the literal
    that ships today and says nothing about an allowlist assembled or extended by any other
    route — the shape a future adapter registering its own read endpoints would take. So the
    refusal is observed by DRIVING construction, and the shipped table is required to be an
    instance of the constructed type: without that, a validating constructor nothing calls
    satisfies every raise below.

    THE TYPE MUST STAY A MAPPING OF SYSTEM TO ENTRIES. That is a joint constraint with the
    endpoint rule's own test rather than a convenience — that test takes the table's key set,
    iterates it by system and subscripts it, so a validating type that is not a Mapping makes
    the two demands unsatisfiable together.

    The positive control is the same entry WITH its method: it constructs, it keeps the pair it
    was authored with, and the shipped table — which went through the same constructor — still
    admits a real read. Without it, an implementation whose constructor refuses everything
    passes all four refusals here and breaks every elastic read in the tree."""
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
    "POST" as such. The standing guard for the refutation that killed the blanket rule.

    The negative half is per-pair too: the same host and the same listed path under a
    mutating method is refused, which is the property a method-blind allowlist cannot state
    at all."""
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


def test_the_elastic_read_allowlist_carries_the_kibana_host_endpoint():
    """The elastic read allowlist carries the endpoint on the KIBANA host that
    `elastic.health-check` reaches, alongside the three on the Elasticsearch host.

    This is a demand no correct implementation could satisfy without it, not a coverage gap.
    `health-check` is granted to gather on every system its grant reaches and it issues TWO
    requests, not one: the cluster-health GET against `ELASTICSEARCH_URL`, then a status GET
    against `KIBANA_URL` — a different base URL, and the only elastic read that leaves the
    Elasticsearch host. Every captured request is confined, so an allowlist enumerating three
    endpoints refuses the second the moment the first succeeds. No fixture in this suite named
    it before, and the standing guard beside this one listed three.

    It is not reachable through the capture seam on a hermetic drive: the first request fails
    on the deliberately unreachable transport and the verb never issues the second. So the
    target is recovered from the ADAPTER's own source rather than restated as a literal — the
    obligation stays attached to the call site that creates it, and retargeting the verb moves
    both together. Recorded rather than papered over: this half is pinned against the source
    and the rule, not against a driven request.

    The method half applies here too — the same path under a mutating method is refused, so
    listing the endpoint does not open it."""
    path = _kibana_status_path()
    assert path == "/api/status", \
        "the Kibana-host endpoint moved; the elastic read allowlist must move with it"

    confine_read_endpoint("elastic", f"http://kibana:5601{path}", method="GET", verb_class="r")

    with pytest.raises(ConfinementFault):
        confine_read_endpoint("elastic", f"http://kibana:5601{path}", method="POST",
                              verb_class="r")

    assert any(pattern.endswith(path) for pattern, _ in READ_ENDPOINT_ALLOWLIST["elastic"]), (
        f"elastic's read allowlist declares no entry for {path}, the second endpoint its "
        f"health-check verb reaches — a correct implementation fails the confinement drive"
    )


def test_the_endpoint_check_binds_on_the_resolved_normalized_path_without_the_query_string():
    """The endpoint check binds on the RESOLVED request target, compared on a NORMALIZED
    path with the query string EXCLUDED (§7 R6).

    Post-interpolation is the only side where a path-altering parameter meets the check at
    all — against the verb's declared, uninterpolated pattern it would escape entirely.
    Dropping the query string keeps incidental adapter formatting out of the security
    boundary without weakening the path constraint the rule rests on."""
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
