# shuffle-premises: copy 1 of 3, seed='6311' — premises in randomized order.
# The order is deliberate noise (anti-anchoring); do not infer meaning from it.
# Phase C synthesis — issue 631, base 483b5809
# Deduplicated premise set from five lens frontiers (30-premises-{author,dependency,
# input-surface,lifecycle,concurrency}.md). 99 lens premises in, 79 kept out (63
# standalone + 16 merges of 36 lens premises). See 40-premises.md for the full
# conservation accounting, the merged probe-obligation list (PO1-PO38), forks, and
# red flags. Each function below is a signature + situation docstring — no
# assertions; the answerer leaf fills in the assertion per premise.
#
# Trailing comments per premise:
#   # origin: <lens[, lens...]>        which lens(es) raised this premise
#   # fork: ...                        carried verbatim from the source frontier(s)
#   # probe: see POn[, POm]            mechanism fact this premise depends on


# ============================================================================
# The kill's downstream — consumers of a truncated run
# ============================================================================

def test_killed_run_flows_into_the_post_run_steps():
    """The budget kill ends the loop and run_investigation returns normally, so the caller's
    post-run steps execute over a run dir the run never finished filling — what must be
    observable?"""
    # origin: author


def test_killed_run_without_a_report_reaches_the_learning_enqueue():
    """A run killed at tail exhaustion produced no report.md, and the enqueue-for-learning
    step runs anyway on the same path a completed run takes."""
    # origin: author
    # fork: enqueue-and-let-validation-reject vs suppress-the-enqueue-for-a-killed-run — this
    # outcome is a known decision, and it is the boundary between the runtime and the loop.
    # probe: see PO6.


def test_learning_scores_a_budget_truncated_investigation():
    """The judging path receives a run whose investigation stopped because enforcement stopped
    it, not because the defender reasoned its way there."""
    # origin: author
    # fork: whether a budget-terminated run is marked as such for downstream scoring at all.


def test_cross_check_over_a_truncated_narration():
    """The trip lands after some leads have table rows but before the narration names them, and
    the structural cross-check runs over that state."""
    # origin: author


def test_case_ticket_closes_on_a_run_that_stated_no_disposition():
    """The case-history ticket was opened before the run and its close step runs after a kill
    that left no disposition to close with."""
    # origin: author
    # probe: see PO7.


def test_visualization_of_a_run_dir_the_kill_truncated():
    """The run's rendering step runs over a run dir missing artifacts a completed run has."""
    # origin: author


# ============================================================================
# Which limb trips, and the tail it opens
# ============================================================================

def test_wall_clock_trip_and_the_report_window():
    """The wall-clock cap trips while tool_calls sits far below N, and MAIN has not yet written
    its report."""
    # origin: author
    # fork: whether the tail band exists on the clock limb at all, and if so what opens it —
    # M1 refuses at wall_clock_timeout, M4 ends the tail at wall_clock_timeout + grace.


def test_spawn_cap_trips_alone():
    """max_subagent_spawns is reached while both the count and the clock are far from their
    caps."""
    # origin: author
    # fork: whether a spawn trip stops only `gather` or opens the tail for everything.


def test_trip_arrives_during_the_tail_from_a_different_limb():
    """The tail is open because the count limb tripped, and the clock limb crosses while MAIN is
    partway through writing."""
    # origin: author


def test_cap_is_crossed_while_a_long_call_is_still_in_flight():
    """The run's longest-running single call is still executing when the elapsed time it
    will eventually report crosses the wall-clock cap — during that window, is the run's
    state "tripped" or not, and who could tell?"""
    # origin: lifecycle


# ============================================================================
# Clock origin, state-file presence, and recreation
# ============================================================================

def test_state_file_absent_before_any_call():
    """the very first tool call of a run finds no state file at all — is this the normal
    cold-start case or one instance of a broader "missing state" situation that also covers
    the recreation cases below?"""
    # origin: lifecycle


def test_first_enforcement_check_precedes_any_accounting_write():
    """The very first tool call of a run reaches the enforcing tool_execute check before
    update_budget_locked has ever written budget.json for this run_dir — not merely a missing
    started_at, the whole file may be absent. The check fires at a seam that precedes any
    completed call's accounting write."""
    # origin: author + input-surface (merge of test_first_enforcement_read_precedes_any_accounting_write,
    # test_budget_state_read_before_any_write_has_ever_occurred)
    # fork: whether the enforcing reader may create the state it enforces on — the timestamp
    # it mints becomes the origin of the cap it is checking.
    # probe: see PO4.


def test_run_spends_time_before_its_first_tool_call():
    """A run's wall-clock anchor is written at tool-call time, not at process start — a model
    that reasons through several full-context round trips, or simply reasons for a long
    stretch, before ever calling a tool has already spent wall-clock time the run's own
    accounting has not yet started counting."""
    # origin: author + lifecycle (merge of test_run_spends_its_first_minutes_before_any_tool_call,
    # test_first_tool_call_after_a_long_silent_stretch)


def test_run_dir_reused_carries_a_prior_runs_counters():
    """An operator (or a retried invocation) starts a run against a run_dir that already
    contains a budget.json with nonzero tool_calls and/or subagent_spawns from a prior run,
    rather than a fresh run_dir — the new run's first tool call inherits counters it did not
    accrue."""
    # origin: author + input-surface (merge of test_run_dir_reused_by_a_second_run,
    # test_run_dir_has_a_leftover_budget_json_from_a_prior_run)
    # fork: whether run_dir reuse is a supported scenario at all, or budget.json's identity
    # facet (keyed one-per-run_dir) makes this premise out of scope by construction.
    # fork: whether a second invocation against an existing run_dir is meant to inherit or
    # reset the prior attempt's counters — the design is silent on re-run/resume semantics
    # entirely (flagged by the lifecycle lens's red flags, not written as its own premise
    # there pending a probe; folded into this premise so the fork is not lost).
    # probe: see PO30.


def test_state_file_recreated_before_any_cap_has_tripped():
    """The run's budget-tracking file is absent and then recreated partway through a run that
    has not yet crossed any cap — rather than continuously present from the run's first tool
    call — so its start-of-run timestamp is not the run's actual start. What, if anything,
    distinguishes this reseed from a cold start?"""
    # origin: dependency + lifecycle (merge of test_budget_file_recreated_mid_run_restarts_the_clock,
    # test_state_file_recreated_before_any_cap_has_tripped)
    # fork: whether a mid-run reseed should be treated identically to a cold start, or
    # flagged as a distinct event — this is the caveat's core open decision.
    # probe: see PO28.


def test_state_file_recreated_after_a_cap_has_already_tripped():
    """the run has already crossed a cap once, and the state file backing that observation
    is then missing and reseeded — does the run's memory of having tripped survive the
    reseed, given nothing about "tripped" is recorded anywhere but the counters themselves?"""
    # origin: lifecycle
    # fork: the caveat's case named directly by M4 — silently undoing an already-observed
    # trip.


def test_state_file_recreated_inside_the_bounded_tail():
    """the reseed happens while the run is inside its post-trip bounded window — what bounds
    that window once the clock backing it has been reset out from under it?"""
    # origin: lifecycle
    # fork: whether the tail's bound is allowed to depend on a clock that can restart.


def test_started_at_is_present_but_malformed():
    """budget.json exists and is read at every call, but the specific started_at field the
    wall clock is computed from holds a value that is present yet not a numeric timestamp — a
    string, null, or otherwise unparseable type — distinct from the field being absent
    outright. The existing (KeyError, ValueError) swallow around the wall-clock arm now sits
    on a code path where its silence gates whether a tool call proceeds, rather than only
    producing a warning."""
    # origin: dependency + lifecycle + input-surface (merge of
    # test_malformed_started_at_meets_the_enforcing_wall_clock,
    # test_state_file_has_unreadable_timestamp_rather_than_missing_one,
    # test_budget_json_started_at_has_the_wrong_type)
    # fork: "missing" and "malformed" are not obviously the same situation — an author could
    # reasonably treat only one of them as the caveat's target.
    # probe: see PO18, PO29.


def test_system_clock_moves_during_the_run():
    """The host's wall-clock time steps forward or backward between the timestamp that anchors
    the cap and the moment the cap is evaluated."""
    # origin: author
    # probe: see PO10.


# ============================================================================
# Counting and spawn accounting
# ============================================================================

def test_refused_gather_and_the_spawn_counter():
    """A gather refused for budget never dispatches a subagent, and the refusal still reaches the
    accounting hook that carries the spawn branch."""
    # origin: author
    # probe: see PO2.


def test_budget_counters_against_the_trace_after_many_refusals():
    """A run ends having refused far more calls than it executed, and two artifacts count its tool
    activity — the budget state and the projected trace."""
    # origin: author
    # fork: whether the refusals are meant to be visible in the trace, invisible, or labelled.
    # probe: see PO11.


def test_stderr_warnings_during_a_refusal_loop():
    """The accounting path still runs on each refused call, on a run already past its cap."""
    # origin: author


def test_warning_threshold_and_the_enforcement_predicate_disagree():
    """The 75% warning and the stop decision read the same counters through two separate
    predicates."""
    # origin: author


def test_extended_refusal_only_tail_never_advances_the_count():
    """After the trip, the model issues nothing but stopped tools — no executed call advances
    tool_calls toward N + 10. Across an arbitrarily long stretch of such calls, what (if
    anything) about the run's recorded state changes on each one, and what eventually ends the
    stretch?"""
    # origin: author + lifecycle (merge of test_refusal_only_tail_never_advances_the_count,
    # test_extended_run_of_calls_that_never_advance_the_call_count)


def test_concurrent_gather_burst_overshoots_the_spawn_cap():
    """MAIN's model turn issues more `gather` calls in one batch than max_subagent_spawns
    allows, and pydantic-ai schedules them as concurrent tasks — each sibling's tool_execute
    check reads the shared pool before any sibling in the same burst has committed its own
    increment (each dispatch is counted before any of the dispatched work has actually drawn
    on the pool). What, if anything, bounds how far subagent_spawns can be driven past the cap
    by the size of a single burst?"""
    # origin: concurrency + lifecycle (merge of test_concurrent_gather_burst_overshoots_the_spawn_cap,
    # test_several_dispatches_issued_together_before_any_of_them_act)
    # fork: subagent_spawns carries no tail band analogous to tool_calls' N+10 — is a burst
    # overshoot here accepted slack or a violation the mechanism must prevent even under
    # concurrency?
    # probe: see PO33.


def test_concurrent_gather_burst_overshoots_the_tool_call_cap():
    """The same one-turn burst of parallel `gather` dispatches also counts toward tool_calls
    (each gather call increments both counters) — what does the tool_calls axis observe when
    N siblings' checks all read the pool before any of their own increments land?"""
    # origin: concurrency


def test_subagent_dispatched_into_an_already_stopped_pool():
    """a subagent is dispatched, and counted as a dispatch, at a moment when the pool it
    joins has already crossed a cap — does that subagent get to do any work at all before its
    very first call is refused, or does its entire working life begin already stopped?"""
    # origin: lifecycle
    # probe: see PO33.


# ============================================================================
# The report MAIN is told to write
# ============================================================================

def test_tail_write_rejected_by_the_write_gate():
    """MAIN spends tail calls on report writes that the invlang schema gate rejects, having been
    instructed by the refusal message to write its report now."""
    # origin: author


def test_kill_lands_between_two_report_writes():
    """The report is written across more than one call and the tail is exhausted partway
    through."""
    # origin: author


def test_model_ignores_the_refusal_and_keeps_planning():
    """The refusal message is the model's only notice of the stop, and the model continues issuing
    stopped tools instead of writing."""
    # origin: author
    # probe: see PO8.


# ============================================================================
# Composition — seams this design shares rather than adds
# ============================================================================

def test_enforcement_seam_raises_an_unexpected_error():
    """Something other than the budget kill goes wrong inside the new enforcement seam — a
    malformed budget state, an unreadable file, an unresolvable posture."""
    # origin: author
    # fork: fail-open (run continues unenforced) vs fail-closed (run dies) — and the answer may
    # differ with the flag off, where today's guard makes budget faults non-fatal.
    # probe: see PO3.


def test_flag_off_run_still_traverses_the_new_seam():
    """Enforcement is off in production, and every tool call of every agent still passes through
    the seam the enforcement was added at."""
    # origin: author


def test_kill_exception_reaches_uncaught_driver_handling():
    """the tail-exhaustion kill exception is raised from within the same hook body whose
    prior behavior was wrapped in a broad exception guard added specifically so that budget
    accounting could never itself break a run."""
    # origin: dependency
    # probe: see PO16.


def test_kill_raised_inside_a_gather_crosses_two_handlers():
    """The tail exhausts on a call made from inside a GATHER subagent's own execution, where a
    handler broadened to catch a different subagent-abort condition (UnexpectedModelBehavior,
    widened by M7 from UsageLimitExceeded only) and a shared, named CONTROL_FLOW_EXCEPTIONS
    list — with two separate `except` consumer sites — both sit somewhere between the raise
    site and the run-level catch."""
    # origin: author + dependency (merge of test_kill_raised_inside_a_gather_meets_the_widened_handler,
    # test_kill_exception_inside_a_gather_subagent_crosses_two_handlers)
    # probe: see PO17.


def test_query_capture_and_budget_refusal_wrap_the_same_call():
    """A single `query` tool call that the budget stops, and the capability that would
    otherwise record a row for that call, both wrap the identical execute-time seam for that
    one call."""
    # origin: author + dependency (merge of test_two_capabilities_wrap_the_same_call,
    # test_query_capture_and_budget_refusal_wrap_the_same_call)


def test_sibling_locked_files_in_the_same_tool_call_window():
    """within the handling of one tool call, two different per-run JSON files — each
    guarded by its own call into the same locking primitive — are each read, modified,
    and written by two different hooks."""
    # origin: dependency
    # probe: see PO14 (open).


# ============================================================================
# Posture and exemption from enforcement
# ============================================================================

def test_unenforced_agent_spends_the_enforced_pool():
    """An agent (or run stage) exempt from the stop still makes tool calls that increment the
    counters an enforced agent or sibling stage is stopped by — does an unenforced actor's own
    activity ever count against a pool an enforced actor has to live within?"""
    # origin: author + lifecycle (merge of test_unenforced_agent_spends_the_enforced_pool,
    # test_a_stage_whose_own_posture_is_unenforced_still_writes_into_a_shared_pool)
    # fork: shared-pool-regardless vs exempt-from-spending-too.
    # probe: see PO5.


def test_agent_constructed_with_no_declared_posture():
    """An agent (or hook factory caller) is constructed through a path that carries no
    posture declaration for the enforcement decision to read at all — the real third
    `_make_hooks` call site under `experiments/` builds its Agent by hand and holds no
    AgentDefinition. Across that agent's entire working life, what does the run's state say
    about whether it is enforced?"""
    # origin: author + dependency + input-surface + lifecycle (merge of
    # test_agent_built_without_declaring_a_posture, test_experiment_caller_missing_posture_carrier,
    # test_make_hooks_called_with_no_agent_definition, test_agent_instance_with_no_declared_posture_at_all)
    # fork: (dependency's framing) RF2 — whether a caller with no posture bit to read fails
    # loudly (a required parameter with nothing to supply it) or silently inherits a default
    # is an explicit, unresolved seam choice, not mine to answer.
    # fork: (input-surface's framing) RF2/FF2-FF3, already routed to the post-D human batch —
    # required-parameter TypeError at that call site vs a safe default that runs the harness
    # unenforced (fail-open under the hostile-model axiom). Restated here as the
    # input-surface framing of the same open seam choice, not a new one.
    # fork: (lifecycle's framing) this is a known open seam choice (routed forward, not
    # decided here) — fail loud at construction versus a silent default, and the two read
    # very differently over a run's whole lifetime.
    # (echoed, not reflagged, by the author lens as RG8.)


def test_learning_stage_bound_and_shared_pool_trip_together():
    """a learning-loop stage's own independent per-stage bound and the shared MAIN/GATHER
    budget pool are both live over the course of one run, and a call happens to land near
    both thresholds at once."""
    # origin: dependency


def test_posture_bit_visible_inside_the_hook_closure():
    """an agent's declared budget-posture bit is read at some point on the path from
    agent construction through to a single tool call being evaluated, and those two
    moments are not the same moment."""
    # origin: dependency


def test_docs_describe_the_shipped_posture():
    """The flag ships off while the prose describes the mechanism the flag would enable."""
    # origin: author


def test_same_tool_name_on_two_agents():
    """A tool name that is tail on MAIN is core on GATHER, and both agents call it in the same
    run."""
    # origin: author


def test_lead_cut_short_by_the_trip_is_read_by_main():
    """A gather subagent's own tools start being refused partway through a lead, and its summary
    reaches MAIN alongside summaries from leads that finished."""
    # origin: author
    # probe: see PO9.


# ============================================================================
# The flag's own input surface, and its reach across process boundaries
# ============================================================================

def test_enforce_flag_unrecognized_token():
    """DEFENDER_BUDGET_ENFORCE is set to a token that is neither a recognized truthy nor
    falsy value for env_bool (e.g. "maybe") — what must be observable at startup?"""
    # origin: input-surface


def test_enforce_flag_whitespace_and_case_variants():
    """DEFENDER_BUDGET_ENFORCE is set with surrounding whitespace or non-canonical casing
    (" True ", "YES") rather than the exact recognized token — what must be observable?"""
    # origin: input-surface
    # probe: see PO25.


def test_enforce_flag_empty_string():
    """DEFENDER_BUDGET_ENFORCE is set to the empty string, distinct from being unset
    entirely — what must be observable, and does it match the unset case or diverge?"""
    # origin: input-surface


def test_enforcement_flag_diverges_across_a_process_boundary():
    """the enforcement flag is set once near the top of a run's process chain, and a
    later hop in that same chain — a re-exec into a different interpreter, or a
    subprocess an orchestration layer launches on the run's behalf — reads the
    environment on its own, independently of the hop that set it."""
    # origin: dependency
    # probe: see PO12.


def test_ci_never_sets_the_enforcement_flag():
    """the exact command CI runs to execute the unit-test suite carries no explicit
    setting of the enforcement flag, either true or false."""
    # origin: dependency
    # probe: see PO19.


def test_bash_child_env_carries_or_drops_the_flag():
    """a bash tool call's child process receives an environment built by filtering the
    calling agent's own environment, and the enforcement flag's presence in that filtered
    copy is exactly what a script running inside that child process would observe."""
    # origin: dependency
    # probe: see PO20.


def test_flag_reaches_a_child_process_that_starts_its_own_run():
    """The enforcement flag is inherited by processes the run spawns, including any that begin a
    run of their own."""
    # origin: author
    # probe: see PO12, PO13.


# ============================================================================
# The on-disk budget.json — malformed input surface
# ============================================================================

def test_budget_json_is_corrupted_on_disk():
    """budget.json exists but its bytes are not valid JSON — e.g. truncated by a process
    killed mid-write — when the enforcing path next reads it."""
    # origin: input-surface
    # probe: see PO23.


def test_budget_json_missing_the_subagent_spawns_key():
    """An on-disk budget.json predates M3's spawn-cap wiring and lacks the
    subagent_spawns key entirely — the schema-drift case, not the value-is-zero case."""
    # origin: input-surface
    # probe: see PO24.


def test_budget_json_counters_are_negative_or_non_integer():
    """budget.json's tool_calls or subagent_spawns holds a negative integer, a float, or a
    string when read by the enforcing path — on-disk state that does not match the shape
    only this code is supposed to write."""
    # origin: input-surface
    # fork: budget.json's access facet types this via as trust: derived — is malformed
    # on-disk state in scope for this change at all, or is "only our own writer touches this
    # path" the boundary of what we defend?


# ============================================================================
# The injected `limits` seam — a new, test-only input surface
# ============================================================================

def test_injected_limits_missing_a_key():
    """The test seam's limits dict, threaded into check_budgets, omits one of the three
    cap keys (e.g. no max_subagent_spawns) rather than supplying all three."""
    # origin: input-surface
    # fork: is completeness the seam's own contract to enforce, or a caller obligation the
    # spec leaves unchecked — N1 only commits to "no operator config", not to validating
    # what a test injects.


def test_injected_zero_cap_means_disabled_not_immediate_trip():
    """The test seam injects exactly 0 for one of the three caps — the boundary value FF15
    already names as disabling the accounting-side ratio warning. Read against the
    deny/short-circuit arm rather than the warning arm: does the domain's documented falsy
    member switch the entire check off, or does a caller supplying the boundary value meant
    to trip on the very next call instead get "disabled"?"""
    # origin: dependency + input-surface (merge of test_injected_zero_limit_means_disabled_not_immediate,
    # test_injected_limits_zero_cap)
    # probe: see PO21.


def test_injected_limits_negative_cap():
    """The test seam injects a negative value for one of the three caps — a value below
    the domain's stated refinement (non-negative), reachable only because N1's carve-out
    is the first seam that lets any caller choose the number at all."""
    # origin: input-surface


def test_injected_limits_non_integer_value():
    """The test seam injects a non-integer value (a float, or a string) for a cap the
    config-knob table types as int — the wrong-type case, distinct from zero and negative."""
    # origin: input-surface


def test_gather_own_request_limit_races_the_shared_pool():
    """within a single gather dispatch, the nested agent's own per-dispatch request
    ceiling and the shared run-wide budget pool are both approaching their limits over
    the same sequence of calls, and either could be the one to end the dispatch first."""
    # origin: dependency


def test_replay_harness_without_injected_limits_uses_production_values():
    """a caller of the replay/injection seam that supplies no limits, and a caller of the
    same seam that does supply injected ones, drive the identical underlying entry point
    through the identical optional-argument shape."""
    # origin: dependency


# ============================================================================
# The call stream reaching the short-circuit seam
# ============================================================================

def test_short_circuited_call_carries_invalid_tool_args():
    """A call to a budget-stopped tool arrives at the tool_execute short-circuit carrying
    args that would fail that tool's own argument schema (missing a required field, wrong
    type) — does the refusal fire regardless, or does something upstream reject the call
    on shape grounds first?"""
    # origin: input-surface
    # probe: see PO26.


def test_same_budget_stopped_tool_reissued_twice_in_one_turn():
    """The model emits two calls to the same budget-stopped tool within a single model
    turn — not across turns/retries — matching register_gather_tool's own documented
    instruction to dispatch sibling leads in parallel; both calls reach the short-circuit
    before either's ToolReturnPart returns."""
    # origin: input-surface


# ============================================================================
# Dependency-specific structural premises
# ============================================================================

def test_new_spawn_arm_assertions_coexist_with_the_retired_name_assertion():
    """a test module that already asserts the retired dispatch names contribute nothing
    to the spawn counter gains new assertions about the live counter's deny behavior,
    sharing the same fixtures and run-dir setup as the existing ones."""
    # origin: dependency


def test_unregistered_toolset_bit_reaches_the_tier_function():
    """a bit is present on the tool-capability declaration without (yet) having a
    corresponding arm in the dispatch that turns declared bits into registered tool
    names, while the tail/core classification is still asked to place whatever set of
    tool names it is actually handed."""
    # origin: dependency


def test_two_consumers_construct_the_budget_path_independently():
    """more than one piece of code that needs the run's budget-tracking file's location
    builds that path itself, with no single shared accessor either of them goes through."""
    # origin: dependency
    # probe: see PO22.


# ============================================================================
# Concurrency — admission races at or near the cap
# ============================================================================

def test_last_remaining_slot_is_claimed_by_more_than_one_concurrent_caller():
    """Several sibling GATHER subagents (or a call arriving at the exact threshold count)
    each read a budget snapshot showing the pool close to or exactly at its cap, and each
    decides independently whether it may proceed — more than one of them proceeds on that
    reading before any of their own increments has committed. What is supposed to happen to
    the call(s) that should have been the one refused, and does the boundary land the same
    way for every concurrent reader?"""
    # origin: dependency + concurrency + lifecycle (merge of
    # test_concurrent_gathers_race_the_shared_trip_point,
    # test_last_slot_under_a_cap_is_claimed_by_more_than_one_concurrent_caller,
    # test_call_landing_exactly_on_the_threshold_value)
    # probe: see PO15, PO37.


def test_more_than_one_concurrent_call_independently_detects_the_trip():
    """MAIN and several concurrently-running siblings each recompute "tripped" (including
    tail exhaustion specifically) against the one shared pool at close to the same moment,
    each seeing counters the others are also updating — with no persisted trip record, does
    each of them land on the same answer, and what happens when more than one caller reaches
    the conclusion that the run should end?"""
    # origin: lifecycle + concurrency (merge of
    # test_multiple_agents_independently_observe_the_same_trip,
    # test_more_than_one_concurrent_call_independently_detects_tail_exhaustion)


def test_intra_agent_parallel_calls_race_the_same_shared_check():
    """A single agent instance's one model turn (MAIN or one GATHER
    subagent) issues several tool calls that pydantic-ai executes as
    concurrent tasks against the one shared budget.json — not a
    cross-subagent race, but a same-instance one. Does the ordering the cap
    comparison assumes still hold when the calls that are supposed to
    precede or follow the cap are, in fact, simultaneous?"""
    # origin: concurrency
    # probe: see PO35.


def test_call_checked_before_the_trip_commits_its_effect_after_the_pool_has_tripped():
    """A call's tool_execute check passes while the pool is still under the
    cap. Before that call's own after_tool_execute increment commits, a
    concurrent sibling's increment trips the pool. The first call finishes
    and its effect lands anyway. Is a call that was legitimately admitted at
    check-time allowed to still commit after the run has, in the interim,
    become tripped by a sibling?"""
    # origin: concurrency


def test_late_committing_sibling_increment_lands_inside_mains_tail_window():
    """A GATHER sibling's tool call was checked and admitted pre-trip, but
    its increment commits only after MAIN has already entered the
    N-to-N+10 tail band reserved for its own file-I/O report-writing calls.
    Does that late, sibling-sourced increment consume tail-band capacity
    MAIN's own tail-tier calls were counted on?"""
    # origin: concurrency
    # fork: whether a GATHER-sourced increment landing during MAIN's tail
    # window is treated as eating into that window, or the tail band is
    # sized to be indifferent to which agent's calls fill it.


# ============================================================================
# Concurrency — accounting integrity and message delivery
# ============================================================================

def test_concurrent_refusals_of_the_same_stopped_tool_do_not_cross_attribute_accounting():
    """Two concurrently-executing calls to the same budget-stopped tool —
    one from MAIN, one from a GATHER sibling, or two GATHER siblings against
    each other — are both refused at the execute seam at close to the same
    instant. Does each refused call's own non-increment stay scoped to that
    call, or can concurrent refusals of the same tool interfere with one
    another's accounting?"""
    # origin: concurrency


def test_every_concurrently_refused_call_receives_its_own_permanence_message():
    """Multiple callers refused at the same seam within the same short
    window — not one caller re-issuing serially, but several callers
    refused concurrently — each need M1b's message (permanence, what
    remains, write the report now). Does concurrency change whether every
    one of those simultaneous refusals carries the full message, or could
    only the first-scheduled one see it?"""
    # origin: concurrency


def test_query_capture_ordering_holds_independently_for_every_concurrent_query_call():
    """M11 pins the budget hook ahead of QueryCapture in the capability
    chain for a single call. When several `query` calls from concurrent
    GATHER siblings are in flight together, does that per-call ordering
    guarantee hold independently for every one of them, or could shared
    state in the hook chain let one call's ordering leak into another's?"""
    # origin: concurrency


def test_concurrent_increments_to_budget_json_are_neither_lost_nor_duplicated_under_contention():
    """Many concurrently-executing tool calls across MAIN and several
    GATHER siblings all reach the point of committing their increment to
    budget.json within a narrow window of each other, all serialized by the
    same flock. Does every one of those increments survive intact, or can
    high contention lose or double-count one under real concurrent load?"""
    # origin: concurrency
    # probe: see PO36.


def test_wall_clock_elapsed_is_read_consistently_during_a_concurrent_increment():
    """One concurrently-scheduled call's tool_execute check needs to read
    budget.json's elapsed wall-clock time at the same instant another
    call's locked increment is being written. Does the concurrent reader
    see a consistent pre- or post-increment snapshot, or something torn
    between the two?"""
    # origin: concurrency


def test_concurrent_readers_disagree_on_the_recreated_clock_origin():
    """budget.json is absent, or was just recreated, at the moment several concurrently-
    executing tool calls (MAIN and a sibling) each independently read or reseed the shared
    pool to check the wall clock. Does every concurrent checker in that window agree on when
    the run's clock began, or can siblings disagree about elapsed time from the same missing
    timestamp — and whose reseed does the run's clock end up anchored to?"""
    # origin: concurrency + lifecycle (merge of
    # test_concurrent_checks_observe_different_started_at_after_a_recreated_budget_json,
    # test_two_processes_both_reseed_the_state_file_at_once)


# ============================================================================
# The kill instant, shutdown, and sibling fate
# ============================================================================

def test_artifact_state_at_the_exact_kill_instant():
    """the run ends because a cap's tail is exhausted — at that instant, what is already
    durable on disk versus still in flight (a write mid-call, a log entry mid-append), and
    does the run's own shutdown sequence know the difference?"""
    # origin: lifecycle
    # probe: see PO16, PO34.


def test_sibling_subagents_still_in_flight_when_the_kill_fires():
    """One or more concurrently-scheduled sibling calls — a GATHER subagent mid-run, a long
    bash call — have neither completed nor had their result logged when the tail-exhaustion
    kill fires and unwinds the run. What becomes of them: awaited to a stopping point, cut off
    mid-call, or left running past the point their parent's own life has ended — and what is
    left in the trace and the queries table for the calls that were still executing?"""
    # origin: concurrency + lifecycle (merge of
    # test_kill_unwinds_the_run_while_sibling_calls_are_still_in_flight,
    # test_sibling_subagents_still_running_when_the_run_ends)
    # fork: does the kill wait for in-flight siblings to reach a boundary before the run
    # ends, or is "unwind immediately, whatever is on disk survives" (the design's own
    # framing for the single-caller case) equally the intended answer when other callers
    # are mid-flight?
    # probe: see PO32.


def test_the_shutdown_write_itself_fails():
    """the very write meant to preserve the run's artifacts at the moment enforcement ends
    the run fails on its own terms (a full disk, a permission error, whatever the write's
    normal failure modes are) — what happens to a run whose safety net breaks exactly when
    it is needed?"""
    # origin: lifecycle
    # fork: best-effort (log and move on) versus something louder — the design does not say,
    # and the two answers leave very different amounts of evidence behind.
    # probe: see PO34.


def test_the_same_refusal_repeats_across_a_long_stretch_of_the_run():
    """a model keeps re-issuing the same stopped tool well past any point where a single
    refusal would have made the situation clear — across that stretch, does the run's own
    running history of the conversation keep accumulating an identical outcome each time, and
    does anything about the run's state distinguish the first refusal from the fiftieth?"""
    # origin: lifecycle


# ============================================================================
# FOLLOW-UP RGX1 — the budget-accounting write itself fails mid-run
# ----------------------------------------------------------------------------
# Strong-author follow-up (phase B/C boundary). Distinct from
# `test_the_shutdown_write_itself_fails` (the FINAL artifact-preservation write, at the
# kill instant) and from `test_budget_json_is_corrupted_on_disk` (bytes ALREADY malformed
# when read). This region is the run's own per-call accounting write failing while the run
# is still going — the write enforcement newly makes load-bearing, where accounting-only
# made it merely lossy.
# ============================================================================

def test_accounting_write_fails_on_one_call_before_any_cap_trips():
    """A completed tool call's own accounting write fails on its own terms — the run dir is
    full, or not writable, or the write's normal failure modes fire — while the run is far
    from every cap and nothing has tripped. The call itself did real work; the record of it
    did not land."""
    # origin: author-followup (RGX1)
    # fork: fail-open (the call's work stands, the count is silently lost) vs fail-closed
    # (a run whose accounting cannot be written is a run that cannot be enforced) — the
    # design says nothing, and the two answers differ only once enforcement is on.
    # probe: see PO39, PO40.


def test_accounting_write_fails_only_once_and_then_recovers():
    """The accounting write fails on a single call and succeeds on every call before and
    after it — a transient failure, not a standing condition. The run continues past it with
    one call's worth of spend unrecorded."""
    # origin: author-followup (RGX1)


def test_accounting_write_fails_for_the_rest_of_the_run():
    """The condition that broke the accounting write does not clear: from some call onward,
    every subsequent accounting write fails too. The run keeps making tool calls, and its
    recorded spend stops advancing while its actual spend does not."""
    # origin: author-followup (RGX1)
    # fork: whether a run that has permanently lost its ability to account is meant to keep
    # running unenforced, stop, or be marked — the count limb can no longer reach any cap,
    # so this is the shape in which enforcement silently disappears from a live run.


def test_accounting_write_fails_on_the_very_call_that_would_have_tripped_the_cap():
    """The increment that fails to land is precisely the one that would have carried a
    counter across its cap. The call ran; the crossing is not on disk; the next call reads a
    pool that is one short of tripping."""
    # origin: author-followup (RGX1)
    # probe: see PO40.


def test_accounting_write_fails_during_the_post_trip_tail():
    """A cap has already tripped and the run is inside its bounded tail, where the count limb
    is one of the two things that ends it. Inside that window, the accounting writes stop
    landing."""
    # origin: author-followup (RGX1)
    # fork: whether the tail is allowed to be bounded by the clock limb alone once the count
    # limb has been silently frozen — the same question `tail_band_ends_on_either_limb`
    # answers for refusals, arriving here by a different door.


def test_enforcement_reads_succeed_while_accounting_writes_fail():
    """The run's enforcement checks keep reading budget state successfully — the file is
    there and parses — while the writes that were supposed to advance it are failing. The
    reader has no way to distinguish "this run has spent little" from "this run's spending
    stopped being recorded"."""
    # origin: author-followup (RGX1)
    # probe: see PO41.


def test_the_failing_accounting_write_leaves_the_state_file_damaged():
    """The accounting write fails partway rather than cleanly — the run's own writer is what
    leaves budget.json truncated, empty, or half-written, and the same run then reads back
    what its own failed write left behind. Distinct from finding pre-existing corruption
    written by something else."""
    # origin: author-followup (RGX1)
    # probe: see PO42.


def test_accounting_write_fails_before_the_state_file_ever_exists():
    """The failure lands on the run's first accounting write, so budget.json is never brought
    into existence at all, and every enforcement check for the remainder of the run finds no
    state rather than stale state."""
    # origin: author-followup (RGX1)
    # fork: this collapses into the cold-start situation
    # (`test_first_enforcement_check_precedes_any_accounting_write`) unless the run
    # distinguishes "not written yet" from "could not be written" — whether it must is the
    # open decision.


def test_accounting_write_cannot_acquire_its_serialization_at_all():
    """The failure is upstream of the write: the run cannot take the exclusive hold that
    serializes budget.json updates in the first place — the run dir is read-only, or the
    process cannot open the file — so the read-modify-write never begins, as opposed to
    beginning and failing at the write."""
    # origin: author-followup (RGX1)
    # probe: see PO43.


def test_accounting_write_fails_for_one_concurrent_caller_while_siblings_succeed():
    """Several concurrently-executing calls across MAIN and its GATHER siblings all commit
    accounting for the same pool in the same window, and exactly one of them fails to write
    while the others land. The pool's recorded value afterwards reflects some of that window's
    calls and not others."""
    # origin: author-followup (RGX1)
    # probe: see PO39.


def test_spawn_accounting_fails_after_the_subagent_is_already_dispatched():
    """A `gather` dispatch is admitted and the subagent begins its own working life; the
    accounting write that was supposed to record that dispatch against the spawn counter is
    the one that fails. The subagent exists and is spending; the pool does not know it was
    spawned."""
    # origin: author-followup (RGX1)
    # probe: see PO40.


def test_accounting_write_fails_with_enforcement_off_and_with_it_on():
    """The identical accounting-write failure occurs on a run with enforcement off and on a
    run with it on. Under the off posture the loss is accounting-only; under the on posture
    the same lost write is what a stop decision would have been computed from."""
    # origin: author-followup (RGX1)
    # fork: whether the two postures are entitled to different observable outcomes for one
    # underlying fault, or the write's failure handling must be posture-independent the way
    # accounting itself is.


def test_the_accounting_write_and_the_shutdown_write_fail_from_one_cause():
    """The condition that breaks the run's per-call accounting write — the disk, the
    permissions, the run dir itself — is the same condition that will break the
    artifact-preserving write at the end of the run. The mid-run symptom is the advance
    warning for the shutdown one, and both fall in the same run."""
    # origin: author-followup (RGX1)
    # probe: see PO34, PO44.


def test_the_run_dir_stops_being_writable_partway_through_the_run():
    """It is not one file that fails but the shared root: the run dir becomes unwritable or
    disappears mid-run, so the accounting write, the request log, the trace, and MAIN's own
    report writes are all failing from the same moment onward."""
    # origin: author-followup (RGX1)
    # fork: whether an unwritable run dir is a budget-enforcement concern at all or a
    # separate runtime failure the budget path should merely not make worse — the enforcing
    # posture is what puts a stop decision downstream of it.
    # probe: see PO44.


# ============================================================================
# FOLLOW-UP RGX2 — two independent kill mechanisms sharing one run
# ----------------------------------------------------------------------------
# Strong-author follow-up (phase B/C boundary). The circuit breaker's run-wide abort and
# the budget kill are separate mechanisms that end the same run, keyed on the same run dir,
# with sibling state files under the same serialization primitive (PO14, still open: is
# that hold per-file or broader). No lens premise covers their interaction.
# ============================================================================

def test_both_kills_become_eligible_in_the_same_window():
    """The circuit breaker's run-wide abort condition and the budget's tail exhaustion both
    become true within the same narrow window of one run — neither strictly precedes the
    other by any margin the run controls."""
    # origin: author-followup (RGX2)
    # fork: whether the run is required to have a defined precedence between its two kill
    # mechanisms at all, or "whichever is observed first wins" is the intended answer.
    # probe: see PO45.


def test_the_other_kill_fires_while_the_budget_tail_is_open():
    """The budget has already tripped and told MAIN the stop is permanent and to write its
    report now; MAIN is inside the tail window that promise depends on when the circuit
    breaker's run-wide abort fires and ends the run from a different direction."""
    # origin: author-followup (RGX2)
    # fork: whether the tail band's promise of a report window survives an unrelated kill, or
    # the tail is only ever guaranteed against the mechanism that opened it.


def test_the_budget_kill_fires_while_the_other_mechanism_is_mid_shutdown():
    """The reverse ordering: the connectivity abort has begun unwinding the run and the
    budget's own kill becomes eligible on a call that is still in flight during that unwind."""
    # origin: author-followup (RGX2)
    # probe: see PO46.


def test_two_different_kills_are_raised_by_two_concurrent_callers():
    """One concurrently-executing caller reaches the budget kill's condition while a sibling
    reaches the connectivity abort's, and both raise into the same run's unwinding at once —
    two distinct end-the-run signals in flight together rather than one."""
    # origin: author-followup (RGX2)
    # probe: see PO46, PO47.


def test_the_run_records_one_cause_when_two_were_true():
    """The run ends and whatever it leaves behind for a later reader — the trace, the summary
    it returns, the state files — has to describe why. Both mechanisms were eligible; the
    record is written once."""
    # origin: author-followup (RGX2)
    # fork: whether a reader must be able to tell that both were eligible, or naming the one
    # that fired is the whole obligation — this is the "one masks the other's evidence" case
    # and it is a reporting decision, not a mechanism one.


def test_both_shutdown_paths_write_the_same_run_dir_artifacts():
    """Each kill mechanism has its own end-of-run handling, and both of those paths write into
    the same run dir — the trace, the request log, the summary. Both mechanisms fire in one
    run and each path does whatever it does to those files."""
    # origin: author-followup (RGX2)
    # fork: exactly-once, twice, or one path suppressed — the design specifies the budget
    # kill's shutdown against a run where it is the only kill.
    # probe: see PO47.


def test_the_two_state_files_are_mutated_at_the_same_instant_by_the_two_mechanisms():
    """budget.json and circuit_breaker.json are siblings keyed on one run dir and serialized
    by one shared primitive. Within one narrow window each is being read-modify-written — one
    by the accounting path, one by the connectivity recorder — for two different calls."""
    # origin: author-followup (RGX2)
    # probe: see PO14 (open — per-file or broader), PO48.
    # note: `test_sibling_locked_files_in_the_same_tool_call_window` (dependency) covers the
    # two writes inside ONE call's handling under normal operation; this is the concurrent,
    # two-caller framing, and it is the one that matters if the hold is broader than per-file.


def test_a_kill_becomes_eligible_while_the_shared_serialization_is_held():
    """The condition that ends the run is reached at a moment when the run is inside its
    serialized read-modify-write of one of the two state files — the decision to stop and the
    exclusive hold on the run's shared state overlap."""
    # origin: author-followup (RGX2)
    # probe: see PO48.


def test_connectivity_failures_spend_the_budget_pool():
    """A dependency the run queries is down, so the run makes call after call that fails on
    connectivity. Each of those failing calls is also a tool call against the shared pool.
    The breaker is accumulating toward its own threshold and the budget is accumulating
    toward its caps off the same sequence of failures."""
    # origin: author-followup (RGX2)
    # probe: see PO49.


def test_the_budget_stop_prevents_the_breaker_from_ever_tripping():
    """The environment is genuinely broken, but the budget stops the tool the run would have
    diagnosed that through before enough failures accumulate for the connectivity mechanism to
    reach its own threshold. The run ends on spend, and the connectivity evidence the run
    dir carries is whatever was gathered before the stop."""
    # origin: author-followup (RGX2)
    # fork: whether a budget stop masking an environment failure is an accepted cost or
    # something the run must still surface — the two mechanisms diagnose different faults and
    # only one of them gets to report.


def test_a_budget_refused_call_names_a_system_the_breaker_tracks():
    """A call refused for budget was addressed to a system whose connectivity record the run
    keeps. The call never reached that system, and that system's record is what a later reader
    — or the breaker's own gate on the next call — consults."""
    # origin: author-followup (RGX2)
    # probe: see PO50.


def test_an_already_tripped_breaker_changes_the_shape_of_budget_spend():
    """The connectivity mechanism has already tripped for one system earlier in the run, so
    calls to it now return immediately instead of doing work. The budget's count limb and its
    wall-clock limb advance at very different relative rates for the rest of that run than
    they would have."""
    # origin: author-followup (RGX2)
    # fork: whether cheap short-circuited calls are meant to count against the tool-call cap
    # the same as real work — the same question `refused_calls_not_counted` settles for the
    # budget's own refusals, unsettled for the other mechanism's.


# ============================================================================
# The enforced actor's own authoring region contains the enforcement state
# (strong-author follow-up — routed from 45-dispositions.md red flag 6)
# ============================================================================

def test_the_enforced_actor_authors_the_region_holding_its_own_limit_state():
    """The actor whose spending the limit bounds holds a general authoring capability over the
    region that also holds the record the limit is computed from. Nothing about the authoring
    capability distinguishes the artifacts the actor is meant to produce from the record that
    decides whether it may keep producing them."""
    # origin: author-followup (RF6)
    # probe: see PO51, PO53.


def test_the_counters_are_returned_to_their_starting_values_mid_run():
    """Partway through a run, the record the limit is read from is replaced wholesale with one
    that reads as a run that has just begun — every count at its starting value and the origin
    freshly minted — authored by the actor the limit binds."""
    # origin: author-followup (RF6)
    # probe: see PO51, PO55.


def test_only_the_clock_origin_is_rewritten_and_the_counts_left_intact():
    """The record is rewritten in one field only: the origin the elapsed-time limb measures
    from moves forward, while every count is left exactly as the run's own writer left it. A
    later reader sees counts that match the run's real activity."""
    # origin: author-followup (RF6)
    # fork: whether a single-field rewrite is a distinguishable situation from a wholesale
    # replacement at all, or whether both collapse into one obligation — the two limbs fail
    # separately and are bounded by different things.


def test_only_the_counts_are_rewritten_and_the_clock_origin_left_intact():
    """The mirror of the single-field rewrite: the counts are returned to values below the
    limit while the origin the elapsed-time limb measures from is left untouched, so the limb
    the design relies on to bound a refusal-only stretch is the only one still advancing."""
    # origin: author-followup (RF6)


def test_the_state_is_rewritten_from_inside_the_bounded_tail():
    """The run has already crossed a limit and is inside the bounded window it gets to produce
    its conclusion. The capability that window exists to fund — authoring files — is the same
    capability that reaches the record bounding the window."""
    # origin: author-followup (RF6)
    # fork: whether the tail's grant must be narrowed to the artifact it exists for, or whether
    # a tail that can extend itself is accepted — this is the sharpest instance in the region
    # and it sits precisely where the design's own guarantee lives.
    # probe: see PO51, PO56.


def test_the_state_is_rewritten_just_before_the_limit_would_be_reached():
    """The rewrite lands while the run is still under every limit, so no limit is ever crossed,
    no stop is ever decided, and no bounded window ever opens. Nothing downstream of the
    enforcement decision is ever entered."""
    # origin: author-followup (RF6)


def test_the_rewrite_repeats_every_time_a_limit_is_approached():
    """Not one rewrite but a standing practice: every time the run nears a limit, the record is
    returned to a permissive state, for as long as the run continues. The universal the design
    states — that no run consumes unbounded resource while enforcement is on — is what this
    situation is asked against."""
    # origin: author-followup (RF6)
    # fork: whether an actor that is assumed hostile is in scope for this obligation at all, or
    # whether the universal is scoped to a merely-runaway actor — the issue's own threat axiom
    # says the former and no demand currently says either.


def test_the_actor_reads_the_state_its_own_limit_is_computed_from():
    """Before authoring anything, the actor consults the record the limit is read from. Whether
    it can time an action against its own remaining allowance, rather than acting blind, is what
    this asks."""
    # origin: author-followup (RF6)
    # fork: whether read exposure is part of the region to close or whether only the authoring
    # side is — closing one and not the other are materially different postures.
    # probe: see PO54.


def test_the_state_is_rewritten_while_the_runs_own_writer_holds_its_serialization():
    """The actor's authoring path and the run's own accounting writer reach the same record.
    One of them coordinates with other writers of that record; whether the other does is what
    this situation turns on, and the two land at the same instant."""
    # origin: author-followup (RF6)
    # probe: see PO55.


def test_the_state_is_authored_before_the_runs_own_writer_ever_creates_it():
    """The record does not exist yet — no call has been accounted. The actor authors it first,
    with an origin and counts of its own choosing, so the run's own writer finds an existing
    file rather than creating one."""
    # origin: author-followup (RF6)
    # fork: this is the same seam an already-marked premise reaches from the accident side
    # (a cold-start check originating the state it enforces against); whether the deliberate
    # case is the same obligation or a distinct one is a decision, not a reading.


def test_the_actor_authors_a_well_formed_but_untrue_state():
    """The bytes are valid, every field is present and of the right type, and nothing about the
    record is malformed — it simply does not describe what the run actually spent. Every
    existing situation about this record's contents describes damage rather than authorship."""
    # origin: author-followup (RF6)
    # fork: whether a plausible-but-false record is the same obligation as a damaged one — the
    # trust-boundary lean that closes the damaged cases ("only the run's own writer reaches
    # this path") is exactly the premise this situation denies, so it must not settle both.


def test_the_sibling_stop_mechanisms_state_sits_in_the_same_region():
    """The other mechanism that can end a run keeps its own record in the same region, under
    the same authoring capability, reached the same way. Whether the region has one exposed
    record or a class of them is what this asks."""
    # origin: author-followup (RF6)
    # fork: whether a carve-out names one artifact or the class of enforcement-bearing state —
    # naming one leaves the sibling open and leaves the next such record open by default.
    # probe: see PO51.


def test_the_audit_record_is_authored_by_the_actor_it_records():
    """The durable record a later reader consults to establish what the run actually did sits
    in the same region under the same authoring capability as the enforcement state. Every
    situation whose answer is "it must be observable afterwards" rests on that record."""
    # origin: author-followup (RF6)
    # probe: see PO51.


def test_the_second_agent_cannot_author_the_shared_state_the_first_can():
    """The two actors that spend from the same shared pool hold different authoring
    capabilities: the one that can drain the pool fastest holds none over the region, while the
    one holding the bounded reporting window holds a general one."""
    # origin: author-followup (RF6)
    # fork: whether this asymmetry is a deliberate part of the posture or an accident of which
    # agent happens to need to produce files.
    # probe: see PO52.


def test_the_enforcement_decision_is_taken_after_the_state_changed_under_it():
    """A call's enforcement decision and a rewrite of the record that decision reads land in
    the same window — the decision may consult the record before or after the rewrite, and
    whether it consults it at all per call or holds an earlier reading is what this turns on."""
    # origin: author-followup (RF6)
    # probe: see PO57.


def test_the_ending_limb_reads_the_same_rewritten_state_as_the_refusing_limb():
    """The path that refuses a call and the path that ends the run outright both derive from
    the same record. Whether a rewrite that defeats one also defeats the other, or whether the
    ending path holds state of its own, is what this asks."""
    # origin: author-followup (RF6)
    # probe: see PO58.


def test_the_protection_cited_for_the_switch_is_the_boundary_of_the_region():
    """The posture switch is argued unreachable partly because the actor's authoring is
    confined to a region. The record the enforcement decision reads is inside that region. What
    the confinement is and is not evidence for is the situation."""
    # origin: author-followup (RF6)
    # fork: whether the existing negative obligation about the switch is widened to cover the
    # state, or whether a second obligation is minted alongside it — the two produce different
    # tests and only one of them keeps the switch assertion honest.


def test_a_legitimate_artifact_write_still_succeeds_under_the_narrowing():
    """Whatever narrowing closes the region, the actor still has to produce the artifacts it
    exists to produce, inside the same region, including the one it writes in its bounded final
    window."""
    # origin: author-followup (RF6)
    # fork: what the actor legitimately authors besides its named conclusions — a narrowing
    # keyed on artifact shape is cheap and already used elsewhere in the tree, but only if the
    # legitimate set is actually that shape.
    # probe: see PO56.


def test_the_refusal_of_the_state_write_is_observable_to_the_actor():
    """The actor attempts the write and the attempt does not take effect. Whether that arrives
    as something the actor can see and act on, or as a silently discarded write, is what a test
    would have to stand on — a carve-out asserted only as a configuration fact is not a
    situation any run enters."""
    # origin: author-followup (RF6)
    # fork: refuse-the-write-visibly vs accept-and-ignore vs treat-the-attempt-as-a-signal —
    # a known decision with three live branches and no default.
