"""#672 — the executable spec for the benign judge's closed-ticket read as two typed tools.

Every ``test_*`` here is one demand of ``spec-flow/specs/spec_graph_672-closed-ticket-tool.yaml``
(or one classified premise of the phase-C dispositions), named after it and carrying its id in
the docstring. THE CODE DOES NOT EXIST YET: this suite is RED by construction against today's
tree — the drives below name the surface the implementation must build (the ``verbs=`` injection
seam on ``_run_judge_pydantic``, the ``closed_tickets`` ToolSet bit, the two registered tools) —
and that is the point: the tests are the spec the code is written against.

The resolved contract this suite pins (70-resolutions.md — the human's 13 decisions, which
REVERSED two of the classifier's recommendations; the fork letters below name them):

  Fork A  — ``key`` meets a defined schema at the tool boundary: anything outside it draws a
            retry-class response with ZERO store attempts; length is an explicit non-clause and
            flows to the store opaquely. (#684 replaced the metacharacter blacklist this
            originally shipped as with a grammar, moved that grammar into the ticket system's
            REQUIRED config, and made an absent one fail closed — see ROUND 4 below.)
  Fork B  — the tools mirror the query tool FULLY: every call writes a capture row into the
            judge run dir's queries table, and an oversized view is bounded with a truncation
            note + the persisted-payload pointer. NOT record-free (d0's provisional flip).
            The bound is the query tool's OWN passthrough ceiling, exactly (V-B).
  Fork C  — the case-under-judgment's OWN key is excluded at the tool boundary, state-
            independent (the leg's deps already identify its case); extended at the F round
            (V-A) to the LIST path — the self-case's record is filtered by IDENTITY,
            per-item, before the envelope.
  Fork D  — only the live closed-only read satisfies "the store confirmed it"; cached
            gather_raw payloads are context, never confirmation (wired into the rewritten
            teaching section; reachability probe: 65-forkd-probe.md).
  Fork E  — FULL circuit-breaker participation: an open breaker yields an immediate failed
            result with no transport attempt; judge-side infra faults trip it; business
            refusals (404 / non-closed, the exit-1 class) never do.
  Fork F  — run cutoff cuts the in-flight call loose: CancelledError re-raises immediately,
            and the unfinished attempt still counts as the one attempt.
  Fork G  — the list path re-checks each returned item's status client-side and drops or
            faults non-closed items before the envelope.
  Fork H  — Fork C's exclusion extends to a CLOSED ticket whose payload names the case's own
            key; any other quoted non-closed ticket rides the salted envelope unredacted
            (O2 scoped record-wise; the residual is the graph's N-note). #683's merge gate
            bound that extension to BOTH surfaces — it had been get-only, which left the
            precedent search serving what the confirm withholds; list drops the naming item
            per-item and serves its siblings (d31).
  f2      — names are frozen: bit ``closed_tickets``; tools ``list_closed_tickets`` /
            ``get_closed_ticket``.

F-ROUND RE-AUTHORING (75-verify-resolutions.md — phase F's 22 findings dispositioned; this
revision applies every auto-repair and V-A..V-G exactly):
  V-A the self-key screen extends to the list path (identity filter — d23 binds both tool
  paths, d24's re-check adds per-item self-key exclusion); V-B the truncation bound is the
  query tool's EXACT passthrough ceiling plus the note (d0); V-C the two stale teaching docs
  (docs/runtime-gates.md:42, docs/state-surface-adapters.md) join the M6 census with the
  d26 currency test; V-D the capture-row sink is modelled in the graph and demanded (d27),
  the registration ORDER is fixed (d28), and the salt must be UNPREDICTABLE, not merely
  fresh — a counter fails; V-E g11/x1 are now EXECUTED (66-bashlane-probe.md: the judge's
  bash lane is DEAD at the executor, probed by driving the real _tool_bash seam — box=None
  the single cause); V-F the cross-leg salt half is Demand{form: waiver} w3 (unexercisable
  — the adversarial leg has no ticket tools); V-G JUDGE_REQUEST_LIMIT=45 is ledger claim
  g20, and skills/ticket/SKILL.md's status vocabulary gets the executable pin d29.
  Auto-repairs: the d23 fixture rebuilt so a conforming implementation passes (cold C1);
  Fork A's retry-class half asserted with zero store attempts (cold C4); the five blind
  non-discriminating assertions rewritten to bind the behavior their comments claim; the
  "concurrent" test renamed to the sequential property it actually pins.

ROUND 3 (76-verify-r2-resolutions.md — the round-2 cold findings, all auto-repairs of
decided intent, none re-decided):
  C5 Fork E applied to BOTH read tools — the LIST path gets its own open-breaker honor
  test (immediate failed result, NO transport attempt: test_store_breaker_open_blocks_
  list_path), and the malformed-list breaker trip is driven ALONE so the contribution is
  independently attributable to the list call (no sibling get to hide behind); C6a d16
  now pins the teaching INSTRUCTION, not a floating phrase — one sentence coupling the
  cached surface (cached/gather_raw) to "context, never confirmation", plus the
  confirmation-denial half ("only the live … read" / "the store confirmed") — with the
  explicit note that the BEHAVIORAL half is instruction-level, not suite-enforced (Fork
  D at the only altitude this surface admits); d28 asserts the insertion POSITION via a
  source-order census over register_tools' presence table beside the judge-leg
  projection (CR-m1); d23's list-fault fallback is scoped to the list call's own
  appended result (CR-m2); the graph's x4 handoff entry is carried as
  executed-probe-owed, split from the g11/x1 resolution record (CR-m3).

ROUND 4 (#684 — the non-discriminating screening assertions the adversarial implementer and
finalize's PR-#678 review both flagged; the honest implementation was already correct on F2/F3,
so those two are test-only tightenings):
  F1 the key screen is now a GRAMMAR instead of a seven-token blacklist a lazier
  implementation could trim to exactly the sampled rows, and the parametrize set pins the
  characters that set omitted entirely — `#`/`&`/`=`/backtick/internal space and, the
  request-reshaping vector, whitespace and CR/LF. The grammar is NOT a constant in the
  judge's code: it is the ticket system's REQUIRED `TICKET_KEY_PATTERN` config value
  (d30), read through the same `verbs=` registry seam the store is read through, because
  what a key looks like is a fact about the deployed store, not about this consumer — and
  a store that declares none FAILS CLOSED AND LOUD (no read, an infra row, a breaker
  contribution) rather than screening against a built-in guess. That relocation also
  settles #672's "clean non-ASCII flows opaquely": the question moved to whoever describes
  the environment, and THIS environment declares an ASCII grammar, so `SOC-λ42` now
  refuses here while a store that mints accented keys says so in its pattern. Free of cost
  either way: a key this store cannot mint is a key it cannot hold, so refusing one forfeits
  no readable ticket. #684 also closed the reader/writer encoding asymmetry this screen used
  to stand in for — `get_ticket` now percent-encodes the key into the path as
  `ticket_writer` always has (pinned in test_ticket_adapter.py), so no key value can reshape
  the request even unscreened, and the screen is DEFENSE IN DEPTH: what it still buys is
  retry-class feedback, a store never asked for an impossible key, and a clean audit trail.
  F2 the two `served OR faulted` whole-response disjunctions
  (d24/d23) became CONJUNCTIONS on the list call's own response — the good sibling is served
  in the SAME response the non-closed/self items are excluded from, so faulting the whole
  listing no longer passes a per-ITEM demand (it would gut O1's precedent search). F3 the
  self-key payload screen is parametrized over the field carrying the key
  (resolution/key/nested comment), so a screen scoped to `summary` — or to the top level —
  fails. Plus the salt nit: the delimiter lookalike is now a prior bind's ACTUAL rendered
  frame salt, so a reused or derivable salt fails where `!= "deadbeef"` could not.

Fakes inject faults; they never classify. Fault content cites the ledger claim that observed
it on the real dependency: UpstreamFault exit-1 refusals are c2/g5 (executed), the exit-2
infra classes are c4/g8 (executed), the ``open|in_progress|closed`` store enum is the Fork D
probe (executed, playground/ticket-server/app.py:27), the outgoing status=closed pin is c3/g6
(executed). The fake registry enters through the SAME injection idiom as #611's FakeVerbs —
`verbs=` handed to the entry point — never monkeypatch.setattr.

Premise → test map (phase-C dispositions conservation; consensus premises not listed under
their own name land inside the named test):

  key_not_found_vs_wrong_status / status_third_lifecycle_state / response_omits_status
      -> test_nonclosed_refusal_is_one_business_fault_class (parametrized)
  list_malformed_store_response / get_response_shape_mismatch
      -> test_list_closed_tickets_malformed_store_response
  envelope_delimiter_lookalike / carries_model_directed_language
      -> test_delimiter_lookalike_and_model_directed_text_stay_inert
  list_no_filters_supplied -> test_tool_result_envelope (the filterless list drive)
  filter_crafted_to_cross_the_closed_boundary -> test_tool_schemas_have_no_status_or_require_closed
      (request half) + test_list_response_non_closed_item_dropped_or_faulted (response half)
  list_result_empty -> test_list_closed_tickets_result_empty
  get_without_a_prior_list_call -> test_malformed_key_model_retry (well-formed-key control:
      get stands alone on any schema-clearing non-self key)
  key_repeated_identical_calls / two_reads_disagree / cited_ticket_enriched_between
      -> test_repeated_reads_are_fresh_live_and_unreconciled
  cited_seed_state_changes_between_sample_and_confirm
      -> test_cited_seed_instruction_survives + test_cached_open_payload_beside_live_refusal
      (phase-F correction: the map pointed at test_repeated_reads_…, which asserts nothing
      about a cited seed or a confirm; the premise's content lives in these two)
  concurrent_closed_ticket_calls_in_one_turn -> test_two_ticket_calls_one_turn_rows_independent
      (renamed at the F round: the drive cannot establish that the two calls OVERLAP —
      sequential execution produces the same observables — so the name stops overclaiming;
      what it pins is per-call independence of verb call / row / payload path)
  ticket_flips_state_between_list_and_get -> test_ticket_flips_state_between_list_and_get
  ticket_status_transitions_around_the_read -> DROPPED, see the graph's handoff.drops
      (phase-F correction: no assertion in the flip test pins one-check-per-call granularity
      or the absent settled-for-the-run guarantee)
  concurrent_legs_no_toolset_bleed / repeated_builds_do_not_accumulate /
  wiring_bit_does_not_leak / per_leg_toolset_exact_beyond_the_new_bit
      -> test_adversarial_leg_has_no_ticket_tools (phase-F note: the three builds there are
      SEQUENTIAL — what is exercised is the frozen-base replace() mechanism that makes bleed
      impossible, not a concurrent drive)
  same_case_judged_a_second_time / each_leg_gets_its_own_salt
      -> test_same_case_judged_second_time_fresh_salt_persistent_audit (the PER-BIND half,
      now including UNPREDICTABILITY — a counter salt fails the assertion, V-D); the
      "not derivable ACROSS LEGS" half is w3, Demand{form: waiver} (V-F: an examined
      decline — unexercisable through this delta, the adversarial leg has no ticket tools)
  taught_tool_names_match_registered_names / no_surface_teaches_the_tool_to_a_leg_that_lacks_it
      -> test_teaching_surfaces_teach_tool_not_bash
  key_pathologically_long / key_non_ascii -> test_malformed_key_model_retry (controls)
  filter_values_with_shell_and_url_metacharacters -> test_bodies_hardcode_require_closed
      (label/q ride opaquely: list_tickets urlencodes them — #672 recorded this as a chosen
      ASYMMETRY against Fork A's key screen; since #684 encodes the key too, the two paths
      are symmetric and the screen is defense in depth)
  status_case_or_whitespace_variant / response_contains_duplicate_key
      -> test_list_response_non_closed_item_dropped_or_faulted
  case_own_ticket_state_at_judgment_time -> test_case_own_key_refused_at_tool_boundary
  oversized_ticket_payload_or_result_set -> test_oversized_payload_bounded_view_and_capture_row
  cached_open_payload_beside_live_refusal -> test_cached_open_payload_beside_live_refusal
  judged_cases_own_ticket_already_closed -> test_case_own_key_refused_at_tool_boundary
  closed_ticket_content_names_the_open_ticket -> test_closed_ticket_naming_self_key_refused
  list_response_contains_non_closed_item -> test_list_response_non_closed_item_dropped_or_faulted
  store_breaker_open_when_judge_reads -> test_store_breaker_open_when_judge_reads
  repeated_store_failures_across_one_judge_run -> test_repeated_store_failures_across_one_judge_run
  ticket_tool_call_in_flight_when_run_cut_off -> test_control_flow_exceptions_propagate (Fork F)
  operator_policy_cli_after_the_demo_scope_removal -> test_operator_policy_cli_after_demo_scope_removal
  registration_reaches_every_benign_call_site -> test_closed_ticket_registration_reaches_every_benign_call_site
  key_wrong_json_type (silent branch) -> test_malformed_key_model_retry

Recorded, deliberately NOT suite expectations (converged-on-silence, unrevised — inherited
verb-body/config behavior this change does not own): list label/q empty-string handling,
label+q combination semantics, q pathologically long, config-knob resolution timing.
Waivers (no test, recorded in the graph): w1 ``ticket_store.access[query-tool]``,
w2 ``ticket_store.access[subprocess-cli]``, w3 the cross-leg salt half (V-F).
"""
from __future__ import annotations

import ast
from dataclasses import replace
from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")  # CI installs the runtime extra; skip otherwise

from defender.learning.pipeline.judge.engine_pydantic import JUDGE_DEF  # noqa: E402
from defender.runtime.agent_definition import ToolSet  # noqa: E402
from defender.runtime.verbs import VerbContext  # noqa: E402
from defender.tests.e2e._replay_harness import DEFENDER, VerbRecorder  # noqa: E402
from defender.tests._closed_ticket_672 import (  # noqa: E402
    BIT,
    CASE,
    DONE,
    OTHER_KEY,
    TOOL_GET,
    TOOL_LIST,
    _case,
    _drive,
    _get,
    _get_calls,
    _list,
    _list_calls,
    _ticket_registry,
    _wiring,
)

pytestmark = pytest.mark.e2e


def test_benign_leg_registers_closed_ticket_tools(tmp_path):
    """[d1_benign_registration] The benign judge leg's built agent registers exactly the two
    closed-ticket tools (list_closed_tickets + get_closed_ticket) beside its read/bash pair,
    carried by the closed_tickets ToolSet bit set per-leg from JudgeWiring.closed_ticket_read
    on the stage-build replace seam — JUDGE_DEF's frozen static default keeps the bit off,
    and flipping the wiring bit off removes both tools through the same seam.

    # rejected: N6 — presence is a ToolSet bit on the built definition, never a conditional
    # in a tool body; extending `defender-policy show` stays out of scope.
    """
    rec = VerbRecorder()
    run = _drive(tmp_path, [DONE], registry=_ticket_registry(rec))
    assert run.tool_names() == {"bash", "read_file", TOOL_GET, TOOL_LIST}

    # The carrier is the wiring bit, not the direction name: same benign wiring, bit off →
    # the tools are absent from the model-visible roster.
    off = replace(_wiring(tmp_path), closed_ticket_read=False)
    run_off = _drive(
        tmp_path, [DONE], registry=_ticket_registry(VerbRecorder()),
        case=_case(tmp_path, name=CASE + "-off"), wiring=off,
    )
    assert TOOL_GET not in run_off.tool_names()
    assert TOOL_LIST not in run_off.tool_names()

    # x6's premise, extended to the new bit: every ToolSet bit defaults False, so the frozen
    # JUDGE_DEF cannot carry the tools statically — only the per-leg replace turns them on.
    assert getattr(ToolSet(), BIT, None) is False
    assert getattr(JUDGE_DEF.tools, BIT, None) is False


def test_adversarial_leg_has_no_ticket_tools(tmp_path):
    """[d2_adversarial_absent] The adversarial judge leg's built agent schema contains no
    closed-ticket tool — absence by registration (closed_tickets.domain.distinguished[false]
    exercised directly), even when a benign leg was built FIRST from the same frozen
    JUDGE_DEF in the same process: each build starts from the frozen base via a fresh
    replace(), so nothing accumulates and the wiring bit cannot leak across builds. Beyond
    the new bit the two legs' toolsets are IDENTICAL (read + bash). Positive control: the
    benign build through the very same seam registers both tools exactly once.

    # rejected: N3 — no runtime direction check; the adversarial property is absence by
    # registration.
    """
    benign1 = _drive(tmp_path, [DONE], registry=_ticket_registry(VerbRecorder()),
                     case=_case(tmp_path, name=CASE + "-b1"))
    assert {TOOL_GET, TOOL_LIST} <= benign1.tool_names()  # positive control (d1's seam)

    adv = _drive(tmp_path, [DONE], registry=_ticket_registry(VerbRecorder()),
                 case=_case(tmp_path, name=CASE + "-adv"), benign=False)
    assert TOOL_GET not in adv.tool_names()
    assert TOOL_LIST not in adv.tool_names()
    # Per-leg toolset exact beyond the new bit: read+bash identical on both legs.
    assert adv.tool_names() == {"bash", "read_file"}

    benign2 = _drive(tmp_path, [DONE], registry=_ticket_registry(VerbRecorder()),
                     case=_case(tmp_path, name=CASE + "-b2"))
    names = [t.name for t in benign2.script.tool_defs]
    assert names.count(TOOL_GET) == 1  # no accumulation across builds
    assert names.count(TOOL_LIST) == 1


def test_tool_schemas_have_no_status_or_require_closed(tmp_path):
    """[d3_schema_closed_by_construction] The model-facing schemas expose exactly {key} on
    get_closed_ticket and exactly {label, q} on list_closed_tickets — no require_closed, no
    status parameter on either: closed-only is unreachable by construction, never
    model-chosen (x8 grounds the underlying verb signatures; the crafted-filter premise's
    request half — no filter value can name a status because no status slot exists).

    # rejected: N5 — no write verb; the adapter surface stays read-only. M1 — two tools,
    # deliberately no operation discriminator parameter.
    """
    run = _drive(tmp_path, [DONE], registry=_ticket_registry(VerbRecorder()))
    defs = {t.name: t for t in run.script.tool_defs}
    get_props = set(defs[TOOL_GET].parameters_json_schema.get("properties", {}))
    list_props = set(defs[TOOL_LIST].parameters_json_schema.get("properties", {}))
    assert get_props == {"key"}
    assert list_props == {"label", "q"}
    for t in defs.values():
        props = set(t.parameters_json_schema.get("properties", {}))
        assert "require_closed" not in props
        assert "status" not in props


def test_no_query_tool_on_judge_legs(tmp_path):
    """[d19_no_query_tool_on_judge] Neither judge leg registers the generic `query` tool —
    the closed-ticket capability arrives only as the dedicated closed-only tools, so
    require_closed can never become a model-chosen parameter with a default (the exact
    fail-open shape the Fork D probe measured on gather's route). Positive control: d1 —
    the benign leg's roster is non-empty through the same build seam."""
    benign = _drive(tmp_path, [DONE], registry=_ticket_registry(VerbRecorder()))
    adv = _drive(tmp_path, [DONE], registry=_ticket_registry(VerbRecorder()),
                 case=_case(tmp_path, name=CASE + "-adv19"), benign=False)
    assert "query" not in benign.tool_names()
    assert "query" not in adv.tool_names()
    assert benign.tool_names()  # control: the roster capture channel is not blind


def test_closed_ticket_tools_registration_order(tmp_path):
    """[d28_registration_order] (V-D — brief F3's order half; ROUND 3: the assertion now
    pins the two tools' INSERTION POSITIONS, closing CR-m1's altitude gap) register_tools
    documents a FIXED registration order (bash, read_file, write_file, edit_file,
    forward_check, lesson_read, template_search, query — tools.py:511, one flat presence
    table including the deferred tail it composes); the two closed-ticket tools enter that
    order at the TAIL, after query, as list_closed_tickets then get_closed_ticket, so the
    model-visible roster order is deterministic and the pre-existing ordering tests in the
    change's blast radius stay stable. Two halves, because no agent that exists can
    OBSERVE the whole sequence (a judge leg carries none of write_file..query, so every
    post-read_file position projects identically — CR-m1): (1) a source-order census over
    the presence table pins the closed_tickets guard's position — dead LAST, after the
    query guard — so an implementation registering the pair anywhere earlier FAILS; (2)
    the driven benign judge leg pins the pair's model-visible order — exactly
    [bash, read_file, list_closed_tickets, get_closed_ticket], a SEQUENCE assertion where
    d1's roster check deliberately compares sets — so list-before-get is observed on a
    real agent."""
    # (1) The source-order census: the ToolSet presence-table guard sequence, walked in
    # execution order (register_tools' body, splicing in any local helper it composes —
    # today the deferred tail lives in _register_deferred_tools).
    tree = ast.parse((DEFENDER / "runtime" / "tools.py").read_text(encoding="utf-8"))
    funcs = {n.name: n for n in tree.body if isinstance(n, ast.FunctionDef)}

    def guard_bits(fn_name: str, seen: frozenset) -> list[str]:
        out: list[str] = []
        for stmt in funcs[fn_name].body:
            for node in ast.walk(stmt):
                if (isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name)
                        and node.value.id == "tools"):
                    out.append(node.attr)
                elif (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                        and node.func.id in funcs and node.func.id not in seen):
                    out.extend(guard_bits(node.func.id, seen | {node.func.id}))
        return out

    bits = guard_bits("register_tools", frozenset({"register_tools"}))
    assert bits == ["bash", "read", "write", "forward_check", "lesson_read",
                    "template_search", "query", BIT], (
        f"register_tools' presence-table order is {bits} — the closed_tickets guard must "
        "enter the fixed order at the TAIL, after query"
    )

    # (2) The judge-leg projection: the pair's order on the model-visible roster.
    run = _drive(tmp_path, [DONE], registry=_ticket_registry(VerbRecorder()))
    assert [t.name for t in run.script.tool_defs] == [
        "bash", "read_file", TOOL_LIST, TOOL_GET,
    ], "the pair must project as list before get on the judge leg's roster"


def _called_names(tree: ast.AST) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            f = node.func
            if isinstance(f, ast.Name):
                names.add(f.id)
            elif isinstance(f, ast.Attribute):
                names.add(f.attr)
    return names


def test_closed_ticket_registration_reaches_every_benign_call_site():
    """[d22_registration_reaches_every_call_site] Static census (§7 gate obligation): the
    live benign-leg driver — learning_loop via its subagents carrier — funnels through the
    identical invoke_judge → judge_fn → stage-build call, with NO bypass build, so the
    closed_tickets registration wired from JudgeWiring.closed_ticket_read reaches every
    call site the moment it reaches one. Paired with d1/d2's per-leg behavior checks — the
    census picks the subjects; the drive tests observe the effect.

    #791 stopped the two frozen-case eval drivers (`run_judge_ab`, `judge_equivalence`)
    judging, because the shared judge prompts were rewritten off a two-column comparison
    their inputs predate; both have since been retired outright, so the census subjects are
    exactly the funnel that reaches the live judge."""
    files = {
        "learning_loop": DEFENDER / "learning" / "loop.py",
        "subagents": DEFENDER / "learning" / "core" / "subagents.py",
    }
    trees = {}
    for name, p in files.items():
        assert p.is_file(), f"census subject vanished: {p}"
        trees[name] = ast.parse(p.read_text(encoding="utf-8"))

    # The funnel exists: the loop's judge carrier (subagents) CALLS invoke_judge.
    assert "invoke_judge" in _called_names(trees["subagents"])
    # learning_loop reaches it via its re-export/import (the subagents carrier).
    assert "invoke_judge" in files["learning_loop"].read_text(encoding="utf-8")

    banned = {"build_stage_agent", "build_judge_agent", "build_agent_core", "Agent"}
    for name, tree in trees.items():
        called = _called_names(tree)
        assert "_run_judge_pydantic" not in called, (
            f"{name} calls the engine directly, bypassing invoke_judge's wiring thread"
        )
        assert not (called & banned), f"{name} builds a judge agent outside the one seam"

    # The bit rides the Direction specs both eval drivers and the loop source wiring from.
    from defender.learning.core.directions import ADVERSARIAL, BENIGN
    assert BENIGN.judge_wiring.closed_ticket_read is True
    assert ADVERSARIAL.judge_wiring.closed_ticket_read is False


# ═════════════════════════════════════════════════════════════════════════════
# B. The seam and the outbound payload
# ═════════════════════════════════════════════════════════════════════════════


def test_tools_drive_verbs_in_process_via_deps(tmp_path):
    """[d13_in_process_host_side] The tools execute the ticket verb bodies in-process on the
    host — a VerbContext built from ctx.deps (the judge's run identity: its learning run
    dir, its tree, a run-scoped env mapping), off the event loop — so the registry injected
    through the entry point's `verbs=` seam is what EVERY drive observes: no subprocess, no
    box (the judge's deps carry the inert BoxExecutor, which refuses on first use — a drive
    that reached it could not have produced this success view).

    # rejected: N1 — no network egress through the box (stays --network=none); N4 — the
    # gather-side VERBS registry and the six CLI-less adapters are untouched.
    """
    rec = VerbRecorder()
    run = _drive(tmp_path, [_get(OTHER_KEY), DONE], registry=_ticket_registry(rec))
    (call,) = _get_calls(rec)
    assert isinstance(call.ctx, VerbContext)
    assert Path(call.ctx.run_dir) == run.lrd          # the judge's OWN run identity
    assert Path(call.ctx.defender_dir).name == "defender"
    assert isinstance(call.ctx.env, dict)
    assert "TKT-CONTENT-777" in run.all_text          # the fake's payload is what came back


def test_bodies_hardcode_require_closed(tmp_path):
    """[d4_body_pins_closed] The tool bodies call the existing verb bodies in-process with
    require_closed=True HARD-CODED on both verbs — observed on the captured inbound verb
    payload, the facet's invariant, not on the fake's canned response: get sends exactly
    {key, require_closed=True}; list sends require_closed=True with NO status value, and its
    label/q filters ride to the verb OPAQUELY (shell/URL metacharacters included — the
    #672 called this a chosen asymmetry — Fork A screens `key` while label/q ride
    list_tickets' urlencoding; #684 encoded the key path too, so both are now encoded and
    the key screen is defense in depth, pinned end-to-end in test_ticket_adapter.py). Under
    require_closed=True the real verb body pins the outgoing store query to status=closed
    and refuses a non-closed body — executed-probed as c2/c3/g5/g6 and pinned in
    test_ticket_adapter.py; this test pins the composition's judge-side half."""
    rec = VerbRecorder()
    ugly_label, ugly_q = "a;b|c d", "$(reboot) & ../%2e"
    run = _drive(
        tmp_path,
        [_get(OTHER_KEY), _list(label=ugly_label, q=ugly_q), DONE],
        registry=_ticket_registry(rec),
    )
    assert run.out.strip()
    (g,) = _get_calls(rec)
    assert g.params == {"key": OTHER_KEY, "require_closed": True}
    (ls,) = _list_calls(rec)
    assert ls.params["require_closed"] is True
    assert ls.params["status"] is None            # never model-chosen, never tool-invented
    assert ls.params["label"] == ugly_label       # opaque pass-through, verbatim
    assert ls.params["q"] == ugly_q
