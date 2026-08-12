"""#808 item 3 — the harness-dispatched correlation lead.

Every test here is one demand of `spec-flow/specs/spec_graph_808.yaml`, named after its
`discharged_by` pointer and carrying that demand's observable-outcome prose in its docstring.
THE CODE DOES NOT EXIST YET: this suite is RED by construction.

THE TWO THINGS §7 REVERSED, AND WHY NEITHER CAN BE ASSUMED HERE
----------------------------------------------------------------
  * DELIVERY (K10, the run's biggest catch). The design's placement rests on "`ProcessHistory`
    runs before every main request and returns the message list". Brief R2 refutes BOTH
    halves: the processor returns `selection.render(...)` = `hydrate(store, session_id,
    role="send")`, a list rebuilt FROM THE STORE, so a plain append to `messages` is
    DISCARDED; and `_main_extra_capabilities` is entered only `if store is not None`. The
    seam exists (c8); the mechanism every answer reasoned from does not. §7 resolved: build a
    real injection mechanism that writes the summary INTO the store so the hydrated list
    carries it.
  * ACCOUNTING (K23, resolved in round 1 and WITHDRAWN in round 2). Round 1 discharged it as
    a side effect of K7's routing. P7 (both legs, executed) proves the routing buys nothing:
    a harness-driven `QueryCapture.wrap_tool_execute` call ran a real query and wrote a real
    `executed_queries.jsonl` row while `budget.json` stayed `{}`, and a positive control
    chaining the budget `Hooks` capability OUTSIDE `QueryCapture` moved it to `{tool_calls: 1}`
    on the identical call. Accounting is a `tool_execute`-hook composition side effect that
    pydantic-ai builds only when the MODEL dispatches the tool — nothing in a harness-driven
    invocation goes through it. Round 2 resolved: CHAIN the budget hooks around lead-0's
    calls, composing the capability order `build_agent_core` expresses. `subagent_spawns` is
    gated on the literal tool name "gather", so item 3's dispatch needs its own path beyond
    the chain (P5a/P7b, executed).
"""
from __future__ import annotations

import pytest

pytest.importorskip("pydantic_ai")

from defender.hooks.budget_enforcer import DEFAULT_LIMITS  # noqa: E402
from defender.runtime import session_store  # noqa: E402
from defender.runtime.driver import GATHER_REQUEST_LIMIT  # noqa: E402
from defender.tests._session_store_705 import sql, store_factory  # noqa: E402
from defender.tests.e2e._lead_zero_808 import (  # noqa: E402
    CORRELATION_REQUEST_LIMIT,
    CORRELATION_SUMMARY,
    L0,
    L3,
    UNAVAILABLE,
    alert_doc,
    ancestor,
    answer_hits,
    hit,
    run,
)
from defender.tests.e2e._replay_harness import Turn  # noqa: E402

pytestmark = pytest.mark.e2e

TWO_ACTORS = [
    hit(ts="2026-05-25T15:26:10.000Z", user="dev.dana", ip="172.18.0.15", host="office-ws-1"),
    hit(ts="2026-05-25T15:26:50.000Z", user="svc.config-mgmt", ip="172.18.0.4", host="db-1"),
]
# The same two actors over FOUR documents — `dev.dana` three times — so "the bind is a SET"
# is an assertion about what item 3's contract carries rather than a word in a docstring.
REPEATED_ACTORS = [
    TWO_ACTORS[0],
    hit(ts="2026-05-25T15:26:20.000Z", user="dev.dana", ip="172.18.0.15", host="office-ws-1"),
    hit(ts="2026-05-25T15:26:30.000Z", user="dev.dana", ip="172.18.0.4", host="db-1"),
    TWO_ACTORS[1],
]

RULE_ID = "v2-sshd-success-after-failures"
ALERT_TS = "2026-05-25T15:27:22.928Z"


def _loop(n: int) -> list[Turn]:
    """`n` DISTINCT query turns — distinct because three identical requests trip the repeat
    guard's dead end, which would end the lead on a count no ceiling test is about."""
    return [Turn(tool_calls=[("query", {
        "system": "elastic", "verb": "alerts",
        "params": {"native_query": f'user.name:"dev.dana" AND seq:{i}'}})]) for i in range(n)]


def test_correlation_lead_goal_and_dimensions_are_fixed_by_the_harness(tmp_path):
    """d16 — item 3's `goal` and `what_to_summarize` are authored by the HARNESS, not by the
    model, and they are recorded in the leads table where the suite can read them. The
    dimensions name an explicit ON-HOST count and an explicit FLEET-WIDE count as output
    fields, so the lead cannot drift into a general investigation.

    K18's cost, paid at the seam: the intent obligation names "the same-signature alert count
    on-host and fleet-wide" and the revision discharges it with an LLM prose summary whose
    fidelity demand (`d25`) is already a clause, because the hermetic suite scripts model
    turns and any test of the summary's CONTENT pins the script's own text. Requiring the two
    counts as NAMED dimensions moves the obligation from unassertable to
    assertable-at-the-seam — the sidecar's payload is what the suite can read.

    THE SIGNATURE HALF OF THAT QUOTE NO LONGER HOLDS, and deliberately (#859). "Same-signature"
    contradicted `d20` in the same contract — the goal says do NOT narrow to this alert's own
    rule — and, read literally, a per-rule breakdown is 8-16 `alerts` calls against `d21`'s
    request limit of 8, on a grant that withholds the one verb (`esql`) that could group by rule
    in a single call. The dimensions now say "across any rule". What this test asserts is
    unchanged and is what K18 actually moved to the seam: two NAMED count dimensions, one
    on-host and one fleet-wide."""
    res = run(tmp_path, run_id="lz808-contract", answer=answer_hits(TWO_ACTORS))

    sidecar = res.sidecar(L3)
    goal = sidecar["goal"]
    assert isinstance(goal, str), f"item 3's goal is not a string: {goal!r}"
    assert goal.strip(), "item 3's goal is falsy — claim_lead's swallow arm writes nothing"
    dims = " ".join(sidecar["what_to_summarize"]).lower()
    assert "on-host" in dims or "on host" in dims, \
        f"no on-host count is named as an output field: {sidecar['what_to_summarize']}"
    assert "fleet" in dims, \
        f"no fleet-wide count is named as an output field: {sidecar['what_to_summarize']}"
    assert "count" in dims, \
        "the obligation's COUNT survives only as prose the hermetic suite cannot assert"


def test_correlation_contract_binds_the_entity_sets_resolved_by_item_one(tmp_path):
    """d17/K9 — item 3's contract binds the entity SETS item 1 resolved off the ancestor
    documents: every distinct host, user and source IP, not a single chosen value.

    §7 resolved SETS over singletons because the singular reading drops half the discriminator
    on #808's own worked example — a two-leg sequence naming two users (`dev.dana`,
    `svc.config-mgmt`) from two sources (`172.18.0.15`, `172.18.0.4`) — and selects nothing at
    all on the 2-of-5 checked-in fixtures whose top-level `host.name` is null. The values are
    read off the RESOLVED DOCUMENTS, never off the alert's own top-level fields, which is the
    situation item 3 exists to work under (g16: the design's own cited template documents that
    `host.name` is normally null on a correlation alert).

    SETS, so DEDUPLICATED — driven, not described. The four documents name `dev.dana` three
    times and `svc.config-mgmt` once; a per-document bind carries the first three times over
    and hands the subagent a contract that reads as though one actor mattered three times as
    much. Asserted as a RATIO rather than a literal count so it survives any rendering the
    implementation picks: a value resolved three times must appear in the dimensions exactly as
    often as one resolved once, whether that is once each or once per named dimension."""
    res = run(tmp_path, run_id="lz808-entities",
              alert=alert_doc(**{"host": {"name": None}, "user": {"name": None}}),
              answer=answer_hits(REPEATED_ACTORS))

    sidecar = res.sidecar(L3)
    contract = str(sidecar)
    for value in ("dev.dana", "svc.config-mgmt", "172.18.0.15", "172.18.0.4",
                  "office-ws-1", "db-1"):
        assert value in contract, (
            f"{value!r} was resolved by item 1 and is missing from item 3's contract — a "
            "singular bind drops half the discriminator the change exists to surface"
        )

    # Ratio checked over `contract` (the WHOLE sidecar), not `sidecar["what_to_summarize"]`
    # alone: d16 only requires "on-host"/"fleet"/"count" WORDING there, never the raw entity
    # values, so an implementation that (correctly, per d17's own binds) interpolates the
    # resolved values into `goal` instead would leave `what_to_summarize`'s own count at 0 for
    # both actors — `0 == 0` passes regardless of deduplication, which is the vacuous-ratio
    # shape phase F checks for. `contract` already has a non-zero-count guarantee for both
    # actors from the presence loop just above, so the ratio below cannot pass by emptiness.
    assert contract.count("dev.dana") == contract.count("svc.config-mgmt"), (
        f"`dev.dana` (resolved by three documents) appears {contract.count('dev.dana')} times "
        f"in item 3's contract against {contract.count('svc.config-mgmt')} for "
        "`svc.config-mgmt` (resolved by one) — the bind is per-document, not a set"
    )


def test_correlation_contract_bounds_a_window_around_alert_timestamp(tmp_path):
    """d18 — item 3's contract bounds a time window around the alert's own
    `alert_timestamp`, so the correlation is scoped rather than open-ended.

    The precondition is part of the contract and not an accident: K9's promoted premise
    settled a missing or unparseable timestamp as "item 3 does not dispatch", while conceding
    that no sentence states it as a precondition on `d22`'s gate — which is worded in terms of
    ENTITIES resolving, not the timestamp. Both arms are asserted here."""
    res = run(tmp_path, run_id="lz808-window", answer=answer_hits(TWO_ACTORS))
    contract = str(res.sidecar(L3))
    assert "2026-05-25" in contract, \
        "item 3's contract names no window anchored on the alert's own timestamp"

    for label, bad in (("unparseable", "not-a-timestamp"), ("empty", "")):
        res_bad = run(tmp_path / f"bad-{label}", run_id=f"lz808-badts-{label}",
                      alert=alert_doc(timestamp=bad), answer=answer_hits(TWO_ACTORS))
        assert not res_bad.has_sidecar(L3), (
            f"[{label}] item 3 dispatched with a window it could not bound — the contract's "
            "own scope is then whatever the subagent decides"
        )


def test_correlation_lead_is_bound_to_the_alerts_index_only(tmp_path):
    """d19/F3 — "bound to the alerts index only" is ENFORCED, not prose: item 3 is dispatched
    with a narrowed verb grant that EXCLUDES `esql`, so an ES|QL call from the correlation
    subagent is denied and recorded as a policy denial, while `elastic.alerts` — which
    defaults to `ELASTIC_ALERTS_INDEX` and IS `confine_index`'d — still runs.

    Prose cannot carry it and the ledger says why: the correlation lead is a real gather
    subagent writing its OWN queries; the design's own named template for it
    (`skills/gather/queries/elastic/detection-alerts.md`) is an ESQL template; `confine_index`
    has exactly one production call site, inside `_search_verb`, serving only `query` and
    `alerts` (g6/r19); and `esql` POSTs its body straight to `/_query`, its FROM target never
    confined. P2 executed the consequence: a DENIED esql verb ran to completion.

    The paired positive control is in this same scenario, on the same address under the
    complementary condition: the `alerts` call the same grant admits reaches the backend and
    is recorded. The `rejected:` clauses — not the ticket store, not raw telemetry — are what
    become unassertable if this degrades to a clause."""
    res = run(tmp_path, run_id="lz808-grant", answer=answer_hits(TWO_ACTORS),
              gather_turns=[
                  Turn(tool_calls=[("query", {"system": "elastic", "verb": "esql",
                                              "params": {"query": "FROM logs-* | LIMIT 5"}})]),
                  Turn(tool_calls=[("query", {"system": "elastic", "verb": "alerts",
                                              "params": {"native_query": 'user.name:"dev.dana"'}})]),
                  Turn(text=CORRELATION_SUMMARY),
              ])

    verbs = [c.verb for c in res.rec.calls]
    assert "esql" not in verbs, \
        "the correlation subagent reached the one verb with no index confinement at all"
    assert "alerts" in verbs, \
        "the narrowed grant took the confined verb with it — item 3 can reach nothing"
    denied = [d for d in res.denials if d.get("verb") == "esql"]
    assert denied, "the esql call was refused with no policy denial recorded"


def test_correlation_lead_is_not_narrowed_to_the_alerts_own_rule_id(tmp_path):
    """d20 — item 3's contract is ANY signature, not just this alert's: neither the goal nor
    the dimensions narrow the correlation to the alert's own `rule.id`. An alert of a
    DIFFERENT rule on the same host or user is exactly the related behaviour already on the
    radar, which is the whole detection value the breadth exists for.

    Bound at `rule_id.domain.distinguished[any]` and asserted on the harness-authored contract
    rather than on the subagent's composed query, because that contract is the only part of
    item 3 the hermetic suite can read. The residue's Red flag 1 is why this is not credited
    as already-answered: no claim establishes that the lead's own query construction does not
    reinstate the narrowing, and the adversarial angle
    (`test_correlation_lead_any_signature_scope_widened_by_injection`) was never framed."""
    res = run(tmp_path, run_id="lz808-anysig", alert=alert_doc(rule_id=RULE_ID),
              answer=answer_hits(TWO_ACTORS))

    contract = str(res.sidecar(L3))
    assert RULE_ID not in contract, (
        "item 3's contract names this alert's own rule id — the correlation is narrowed to "
        "the signature that already fired, which is the opposite of what it is for"
    )


def test_correlation_lead_runs_under_a_request_limit_of_eight(tmp_path):
    """d21/F6 — item 3's dispatch runs under a per-call request limit of EIGHT, so a
    correlation lead that keeps asking is stopped at the eighth request.

    The number is the demand. "Reduced relative to GATHER_REQUEST_LIMIT = 40" names none, and
    `d21`'s "strictly below 40" is VACUOUS AT 39 — an unnumbered "reduced" is a knob nothing
    constrains. `request_limit` is already a per-CALL parameter of the dispatch (r8/c9), so
    the reduced budget costs a value, not a new knob."""
    res = run(tmp_path, run_id="lz808-budget8", answer=answer_hits(TWO_ACTORS),
              gather_turns=_loop(20))

    assert res.gather is not None
    assert res.gather.calls == CORRELATION_REQUEST_LIMIT, (
        f"the correlation lead made {res.gather.calls} requests, not "
        f"{CORRELATION_REQUEST_LIMIT} — its ceiling is not the reduced one"
    )


def test_mains_own_leads_still_run_under_the_full_forty(tmp_path):
    """R4 `GATHER_REQUEST_LIMIT.domain.distinguished[40]` + R7
    `interacts(run_investigation->GATHER_REQUEST_LIMIT)` — item 3's reduced ceiling is
    PER-DISPATCH: `run_investigation` still reads the module constant for its own dispatches,
    so a lead MAIN dispatches still runs under the full 40.

    R7's dual, at this reader's own edge: the value moved at one reader (lead-0's dispatch)
    and must be unchanged at the other. A demand bound at the knob itself reads green when
    "two of the three moved", which is precisely the escape — a per-investigation ceiling
    lowered to pay for a new gate's forced turns while another reader kept its own copy is
    the canonical shape of this bug.

    Driven with an alert that resolves NO entities, so item 3 does not dispatch and the one
    lead in the run is MAIN's own."""
    res = run(tmp_path, run_id="lz808-budget40", alert=alert_doc(ancestors=[]),
              answer=answer_hits([]),
              main_turns=[
                  Turn(tool_calls=[("gather", {
                      "lead_id": "l-001", "system": "elastic", "goal": "measure this lead",
                      "what_to_summarize": ["auth events"]})]),
                  Turn(text="Investigation complete."),
              ],
              gather_turns=_loop(GATHER_REQUEST_LIMIT + 5))

    assert not res.has_sidecar(L3), "item 3 dispatched off an empty resolution"
    assert res.gather is not None
    assert res.gather.calls == GATHER_REQUEST_LIMIT, (
        f"MAIN's own lead was stopped at {res.gather.calls} — item 3's reduced ceiling "
        "became the run's, and every ordinary lead silently lost its budget"
    )


def test_correlation_lead_is_dispatched_only_after_ancestors_resolve(tmp_path):
    """d22 — item 3 dispatches only when item 1 resolved at least one non-empty entity set:
    a FAILED resolution and a SUCCEEDED-EMPTY one both leave the correlation lead
    undispatched, and a SUCCEEDED-TRUNCATED one — nonempty but short — still dispatches.

    The gate is written against the resolution STATUS, not against an absence of entities:
    three states hide under the word "resolved" and `d0`'s old two-component return could not
    tell "resolution failed" from "resolution found nothing". K13 makes the distinction
    load-bearing, and P1b makes it unreadable from the wire (an unparseable body reaches the
    caller byte-identical to a genuine empty match)."""
    from defender.scripts.adapters.faults import TransportFault
    from defender.tests.e2e._lead_zero_808 import answer_raising

    failed = run(tmp_path / "failed", run_id="lz808-gate-failed",
                 answer=answer_raising(TransportFault("transport down")))
    assert not failed.has_sidecar(L3), "item 3 dispatched off a FAILED resolution"

    empty = run(tmp_path / "empty", run_id="lz808-gate-empty", answer=answer_hits([]))
    assert not empty.has_sidecar(L3), "item 3 dispatched off a SUCCEEDED-EMPTY resolution"

    truncated = run(tmp_path / "trunc", run_id="lz808-gate-trunc",
                    alert=alert_doc(ancestors=[ancestor(f"a{i}") for i in range(4)]),
                    answer=answer_hits(TWO_ACTORS, total=25, truncated=True))
    assert truncated.has_sidecar(L3), \
        "a truncated but NONEMPTY resolution blocked the dispatch — the entities it did " \
        "resolve are exactly what item 3 exists to correlate"


def test_correlation_summary_reaches_main_before_its_second_request(tmp_path):
    """d23/K10 — item 3's summary is in the message list MAIN is handed for its SECOND
    request. It gets there through a purpose-built injection mechanism that writes it INTO
    the session store, so the store-hydrated list carries it.

    Not by appending to `messages`: `ProcessHistory` returns `selection.render(...)` =
    `hydrate(store, session_id, role="send")`, a list rebuilt FROM the store, so a plain
    append is discarded (brief R2, refuting the design's own gloss). Pinned at the REQUEST
    boundary and not "before PLAN", because r17 (executed) establishes ORIENT and PLAN are
    headings in MAIN's prompted procedure with no runtime referent — a test pinned to PLAN
    pins a proxy."""
    marker = "11 fleet-wide"
    # The marker is a FRAGMENT of the scripted summary, chosen to be distinctive enough that
    # finding it in a request proves the summary reached it. Pinned to its source: the summary
    # is edited whenever item 3's dimensions change (#859 rewrote both), and a marker that
    # silently stopped being a substring would make both assertions below pass vacuously — the
    # negative because nothing carries it, the positive because it would red for the wrong
    # reason and invite raising the wrong half.
    assert marker in CORRELATION_SUMMARY, (
        f"the delivery marker {marker!r} is no longer a fragment of the scripted gather "
        f"summary {CORRELATION_SUMMARY!r} — re-derive it from the summary's current text"
    )
    res = run(tmp_path, run_id="lz808-delivery", answer=answer_hits(TWO_ACTORS),
              gather_turns=[Turn(text=CORRELATION_SUMMARY)])

    assert marker not in res.message_zero, \
        "the summary was in message 0 — item 3 blocked MAIN's first prompt rather than " \
        "being dispatched non-blockingly after it"
    assert marker in res.second_request, (
        "item 3's summary never reached MAIN: the dispatch happened, the lead ran, and the "
        "result went nowhere the model can read"
    )


def test_correlation_lead_is_the_second_session_in_a_store_whose_first_is_empty(tmp_path):
    """R2 `session_store.identity` — MAIN's session and item 3's land on distinct keys and
    each carries its own `agent_id` label, so a reader joining `session` rows can attribute
    them. An ORIENT-time dispatch makes lead-0's the SECOND session in a store whose first —
    MAIN's, created at driver.py:806, before `_user_prompt` at :838 — has ingested nothing,
    so every reader that walks sessions in creation order (`hydrate`, `selection.render`,
    `observe.write_trace`, `visualize_run`) sees the correlation lead's content first unless
    the label makes it attributable.

    The store allocates the `session_id`; the caller supplies the `agent_id`, and that label
    is the only thing that makes a harness lead's session attributable at all."""
    stores: list = []
    res = run(tmp_path / "run", run_id="lz808-sessions", answer=answer_hits(TWO_ACTORS),
              store_factory=store_factory(tmp_path, sink=stores), stores=stores)

    rows = sql(stores[-1], "SELECT session_id, agent_id FROM session ORDER BY rowid")
    labels = [agent_id for _, agent_id in rows]
    ids = [session_id for session_id, _ in rows]
    assert len(set(ids)) == len(ids), "two sessions share a key"
    assert labels[0] == "main", f"MAIN's session is not the first created: {labels}"
    assert f"gather:{L3}" in labels, (
        f"the correlation lead's session carries no attributable agent_id: {labels} — a "
        "reader walking creation order cannot tell whose content it is reading"
    )
    assert res.has_sidecar(L3)


def test_the_correlation_lead_ends_with_the_same_bookkeeping_every_lead_gets(tmp_path):
    """K15 — item 3 is a REAL gather subagent: its session ends with the same terminator
    bookkeeping every other lead's does, so a lead that was cut off is distinguishable in the
    store from one that finished.

    `_build_gather` and `_stamp_gather_terminator` are closures PRIVATE to `build_agent`,
    passed only to `register_gather_tool` (g19), so a harness caller cannot reach them without
    a refactor — which makes this a seam decision with a bound address, not a detail. A
    dispatch that skips them is a second, thinner path whose sessions end differently from
    every other lead's, and the reader joining `session` rows cannot tell the difference
    between "this lead finished" and "nobody stamped it".

    THE SEAM ACCEPTS A PRE-CLAIMED LEAD ID AND DOES NOT RE-CLAIM (§7 round 3, F3). F5 claims
    both reserved ids at run start, before MAIN's first turn, and `_run_gather` claims the lead
    ITSELF at tools_gather.py:277-285, raising `ModelRetry` on reuse — so a seam that re-used
    that path unchanged would raise on EVERY run, with no model in the loop to retry, on the
    frame `d41`'s handler must catch. Claim `a3` (executed) records exactly that sequence.
    Round 1's rationale — "the pathological collision cannot arise because the harness claims
    first" — is inverted: claiming first is what guarantees the collision, and the sentence is
    retracted.

    Both arms: the cut-off dispatch is stamped `request-limit`, the clean one is not stamped
    at all — `truncated_by` unset must keep meaning "this finished"."""
    cut_stores: list = []
    run(tmp_path / "cut", run_id="lz808-term-cut", answer=answer_hits(TWO_ACTORS),
        gather_turns=_loop(20), store_factory=store_factory(tmp_path / "cutdb", sink=cut_stores),
        stores=cut_stores)
    cut = dict(sql(cut_stores[-1], "SELECT agent_id, truncated_by FROM session"))
    assert cut.get(f"gather:{L3}") == session_store.TRUNCATED_BY_REQUEST_LIMIT, (
        f"item 3's cut-off session reads as one that finished ({cut!r}) — the harness "
        "dispatch skipped the terminator wiring the tool path supplies"
    )

    clean_stores: list = []
    run(tmp_path / "clean", run_id="lz808-term-clean", answer=answer_hits(TWO_ACTORS),
        store_factory=store_factory(tmp_path / "cleandb", sink=clean_stores),
        stores=clean_stores)
    clean = dict(sql(clean_stores[-1], "SELECT agent_id, truncated_by FROM session"))
    assert clean.get(f"gather:{L3}") is None, \
        "a correlation lead that finished was stamped as truncated"
    assert f"gather:{L3}" in clean, (
        "item 3 opened no session at all — the seam re-claimed the id F5 already claimed at "
        "run start and raised ModelRetry before it ever built the subagent (a3)"
    )


def test_lead_zeros_calls_and_item_threes_dispatch_move_the_runs_own_counters(tmp_path):
    """K23 — harness pre-turn work is CHARGED and VISIBLE: the budget hooks are chained around
    lead-0's calls, so item 1's backend calls move `budget.json`'s `tool_calls`, and item 3's
    dispatch moves `subagent_spawns` through an accounting path of its own.

    The mechanism has to be built, and P7 (both legs, executed) is why routing alone does not
    supply it. Leg 1: a harness-driven `QueryCapture.wrap_tool_execute` call ran a real query
    and wrote a real `executed_queries.jsonl` row while `budget.json` stayed `{}`; the
    positive control, chaining the budget `Hooks` capability OUTSIDE `QueryCapture` — the
    order `build_agent_core`'s `capabilities=[_make_hooks(...), …, QueryCapture(...)]`
    expresses, which `Agent.run()` composes only when the MODEL dispatches the tool — moved it
    to `{tool_calls: 1}` on the identical call. Leg 2: a direct `_run_gather()` call left
    `subagent_spawns` unmoved, because the increment is gated on the literal tool name
    "gather" and a harness dispatch emits no tool-use block.

    AND THE RUN'S CLOCK IS THE SAME QUESTION (§7 round 3, F2). The premise K23 came from names
    both halves — `test_pre_turn_work_spends_the_run_s_own_clock_and_call_pool` — and both
    prior rounds resolved only the counters, while the `run_accounting` boundary's own prose
    said lead-0 spends "real wall clock before MAIN's first prompt". It is not bookkeeping:
    `driver.py:795` starts `budget_started_monotonic` BEFORE `_user_prompt` at :838, the
    enforcer's `wall_clock_timeout`/`grace_seconds` are measured from it, and evaluation
    happens inside the very `tool_execute` hook P7a proved a harness-driven call never enters
    — so today the clock is spent and unenforced at the same time. K23's own resolved
    principle applies verbatim to seconds: a gate reporting a number while part of the spend
    is invisible reports a wrong number.

    Three runs, so every assertion is a difference rather than a level. `charged` does lead-0's
    work under the ordinary cap table; `idle` injects no registry, so lead-0 reaches nothing
    and dispatches nothing; `clocked` is `charged` under a cap table whose wall-clock budget is
    already spent, where the enforcer must stop lead-0's own call for the same reason it would
    stop MAIN's."""
    main_turns = [Turn(text="Investigation complete.")]
    charged = run(tmp_path / "charged", run_id="lz808-budget-on",
                  answer=answer_hits(TWO_ACTORS), main_turns=main_turns)
    idle = run(tmp_path / "idle", run_id="lz808-budget-off", verbs=None,
               main_turns=main_turns)

    spawns = charged.budget.get("subagent_spawns", 0)
    assert spawns == 1, (
        f"budget.json records {spawns} subagent spawns for a run whose only dispatch was "
        "item 3's — the harness dispatch escapes the spawn cap entirely (P7b)"
    )
    assert idle.budget.get("subagent_spawns", 0) == 0, \
        "the control run counted a spawn it never made"
    assert charged.rows_for(L0), \
        "the charged run made no item-1 call, so there is nothing for tool_calls to record"
    assert charged.has_sidecar(L3), \
        "the charged run dispatched no item 3, so there is nothing for spawns to record"

    delta = charged.budget.get("tool_calls", 0) - idle.budget.get("tool_calls", 0)
    expected = len(charged.rows_for(L0)) + 1      # item 1's calls, plus item 3's dispatch
    assert delta == expected, (
        f"lead-0's work moved tool_calls by {delta}, not {expected} — item 1's "
        f"{len(charged.rows_for(L0))} backend call(s) and item 3's dispatch spend real wall "
        "clock before MAIN's first prompt and are invisible to the run's own accounting"
    )

    # The clock, at the same seam as the counters. With the run's wall-clock budget already
    # spent, the enforcer must refuse lead-0's own call — which it can only do if lead-0's
    # calls pass through it and are measured against `budget_started_monotonic`, the origin
    # the driver starts BEFORE `_user_prompt`.
    clocked = run(tmp_path / "clocked", run_id="lz808-budget-clock",
                  answer=answer_hits(TWO_ACTORS), main_turns=main_turns,
                  limits={**DEFAULT_LIMITS, "wall_clock_timeout": 0, "grace_seconds": 0})
    assert clocked.rows_for(L0) == [], (
        "the run's wall-clock budget was already exhausted and lead-0's backend call ran "
        "anyway — its elapsed time is invisible to the enforcer that owns the run's clock, "
        "so 'no turn cost' stays true by definition while real seconds are spent"
    )
    assert not clocked.has_sidecar(L3), \
        "item 3 dispatched against an exhausted wall-clock budget"
    assert UNAVAILABLE in clocked.section(), \
        "the clock stopped lead-0 and the block does not say the slot is unavailable"
    assert clocked.main.calls >= 1, \
        "an exhausted clock ended the run before MAIN rather than degrading the slot"
