# Novel-fork adjudication manifest — fixture 631 (15 premises)

### P1: test_accounting_write_cannot_acquire_its_serialization_at_all
Situation: The failure is upstream of the write: the run cannot take the exclusive hold that
    serializes budget.json updates in the first place — the run dir is read-only, or the
    process cannot open the file — so the read-modify-write never begins, as opposed to
    beginning and failing at the write.

### P2: test_accounting_write_fails_on_the_very_call_that_would_have_tripped_the_cap
Situation: The increment that fails to land is precisely the one that would have carried a
    counter across its cap. The call ran; the crossing is not on disk; the next call reads a
    pool that is one short of tripping.

### P3: test_budget_json_missing_the_subagent_spawns_key
Situation: An on-disk budget.json predates M3's spawn-cap wiring and lacks the
    subagent_spawns key entirely — the schema-drift case, not the value-is-zero case.

### P4: test_connectivity_failures_spend_the_budget_pool
Situation: A dependency the run queries is down, so the run makes call after call that fails on
    connectivity. Each of those failing calls is also a tool call against the shared pool.
    The breaker is accumulating toward its own threshold and the budget is accumulating
    toward its caps off the same sequence of failures.

### P5: test_enforce_flag_empty_string
Situation: DEFENDER_BUDGET_ENFORCE is set to the empty string, distinct from being unset
    entirely — what must be observable, and does it match the unset case or diverge?

### P6: test_enforce_flag_whitespace_and_case_variants
Situation: DEFENDER_BUDGET_ENFORCE is set with surrounding whitespace or non-canonical casing
    (" True ", "YES") rather than the exact recognized token — what must be observable?

### P7: test_injected_limits_negative_cap
Situation: The test seam injects a negative value for one of the three caps — a value below
    the domain's stated refinement (non-negative), reachable only because N1's carve-out
    is the first seam that lets any caller choose the number at all.

### P8: test_intra_agent_parallel_calls_race_the_same_shared_check
Situation: A single agent instance's one model turn (MAIN or one GATHER
    subagent) issues several tool calls that pydantic-ai executes as
    concurrent tasks against the one shared budget.json — not a
    cross-subagent race, but a same-instance one. Does the ordering the cap
    comparison assumes still hold when the calls that are supposed to
    precede or follow the cap are, in fact, simultaneous?

### P9: test_query_capture_ordering_holds_independently_for_every_concurrent_query_call
Situation: M11 pins the budget hook ahead of QueryCapture in the capability
    chain for a single call. When several `query` calls from concurrent
    GATHER siblings are in flight together, does that per-call ordering
    guarantee hold independently for every one of them, or could shared
    state in the hook chain let one call's ordering leak into another's?

### P10: test_same_budget_stopped_tool_reissued_twice_in_one_turn
Situation: The model emits two calls to the same budget-stopped tool within a single model
    turn — not across turns/retries — matching register_gather_tool's own documented
    instruction to dispatch sibling leads in parallel; both calls reach the short-circuit
    before either's ToolReturnPart returns.

### P11: test_same_tool_name_on_two_agents
Situation: A tool name that is tail on MAIN is core on GATHER, and both agents call it in the same
    run.

### P12: test_the_budget_kill_fires_while_the_other_mechanism_is_mid_shutdown
Situation: The reverse ordering: the connectivity abort has begun unwinding the run and the
    budget's own kill becomes eligible on a call that is still in flight during that unwind.

### P13: test_the_failing_accounting_write_leaves_the_state_file_damaged
Situation: The accounting write fails partway rather than cleanly — the run's own writer is what
    leaves budget.json truncated, empty, or half-written, and the same run then reads back
    what its own failed write left behind. Distinct from finding pre-existing corruption
    written by something else.

### P14: test_two_different_kills_are_raised_by_two_concurrent_callers
Situation: One concurrently-executing caller reaches the budget kill's condition while a sibling
    reaches the connectivity abort's, and both raise into the same run's unwinding at once —
    two distinct end-the-run signals in flight together rather than one.

### P15: test_visualization_of_a_run_dir_the_kill_truncated
Situation: The run's rendering step runs over a run dir missing artifacts a completed run has.
