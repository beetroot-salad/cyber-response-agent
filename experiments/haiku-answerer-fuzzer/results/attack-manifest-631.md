# Adversarial re-judge manifest — fixture 631 (14 JUNK verdicts under attack)

### J1: test_accounting_write_cannot_acquire_its_serialization_at_all
Situation: The failure is upstream of the write: the run cannot take the exclusive hold that
    serializes budget.json updates in the first place — the run dir is read-only, or the
    process cannot open the file — so the read-modify-write never begins, as opposed to
    beginning and failing at the write.
Judge's JUNK citation: D4 governs "accounting-write failure" by outcome category (isolated fails open / sustained is an environment fault, detected via NF4's consecutive-failure count + first-failure stamp); a failure to acquire the flock is still a failure to complete the update and feeds the same detection state, and an enforcing read that cannot proceed fails closed per D9 — the where-in-the-RMW distinction yields no different observable.
Observed reader spreads (independent panels, arm-stripped):
  - C1/C3 lean toward settled (the write fails/raises, propagates to the except-Exception guard); C2 explicitly hedges whether the failure is observable or silent

### J2: test_accounting_write_fails_on_the_very_call_that_would_have_tripped_the_cap
Situation: The increment that fails to land is precisely the one that would have carried a
    counter across its cap. The call ran; the crossing is not on disk; the next call reads a
    pool that is one short of tripping.
Judge's JUNK citation: D4 states this case verbatim — "One failure costs one call of overshoot (the counter is monotonic; the next call re-crosses and trips)." The observable (one call of overshoot, then trip) is fixed.
Observed reader spreads (independent panels, arm-stripped):
  - C1/C3 state settled (the trip is not observed, next call reads stale-below-cap state); C2 hedges — NOTE: resolved by isolated_accounting_write_failure_fails_open, which confirms the "one call of overshoot, next call re-crosses and trips" reading, answering C2's hedge

### J3: test_connectivity_failures_spend_the_budget_pool
Situation: A dependency the run queries is down, so the run makes call after call that fails on
    connectivity. Each of those failing calls is also a tool call against the shared pool.
    The breaker is accumulating toward its own threshold and the budget is accumulating
    toward its caps off the same sequence of failures.
Judge's JUNK citation: Connectivity-failed calls are executed tool calls (F3(b) exempts only budget short-circuits, not executions that error), so they count toward the pool, and D5/D6 settle the breaker/budget interaction as decoupled first-fires-wins.
Observed reader spreads (independent panels, arm-stripped):
  - C1/C3 state settled (failed queries still increment tool_calls, both mechanisms accumulate off the same failures); C2 hedges whether connectivity failures count at all

### J4: test_enforce_flag_empty_string
Situation: DEFENDER_BUDGET_ENFORCE is set to the empty string, distinct from being unset
    entirely — what must be observable, and does it match the unset case or diverge?
Judge's JUNK citation: M9 commits the flag to the existing `env_bool` mechanism (`driver.py:351`, `DEFENDER_COMPACTION`); empty-string handling is fixed by that named function, not a design choice left open.
Observed reader spreads (independent panels, arm-stripped):
  - C1 asserts empty string is treated the same as unset; C2/C3 leave it unclear (falsy vs fatal)

### J5: test_enforce_flag_whitespace_and_case_variants
Situation: DEFENDER_BUDGET_ENFORCE is set with surrounding whitespace or non-canonical casing
    (" True ", "YES") rather than the exact recognized token — what must be observable?
Judge's JUNK citation: Same as P5 — M9 pins the flag to `env_bool`, whose treatment of " True "/"YES" is determined by the existing function, so there are not two shippable readings.
Observed reader spreads (independent panels, arm-stripped):
  - C1/C2 assert a settled answer (case-insensitive recognized tokens, whitespace raises); C3 hedges that the doc doesn't specify

### J6: test_injected_limits_negative_cap
Situation: The test seam injects a negative value for one of the three caps — a value below
    the domain's stated refinement (non-negative), reachable only because N1's carve-out
    is the first seam that lets any caller choose the number at all.
Judge's JUNK citation: D9 already decided injected out-of-range caps: "An injected cap of 0 trips immediately rather than reading as 'disabled'"; a negative cap makes M1's `count >= limit` comparison always true and fails D9's validation, so it trips immediately under either mechanism — one observable.
Observed reader spreads (independent panels, arm-stripped):
  - C1/C3 assert the mechanism settles it (comparison always false, limb silently disabled); C2 leaves accepted-vs-falsy-vs-error unclear

### J7: test_intra_agent_parallel_calls_race_the_same_shared_check
Situation: A single agent instance's one model turn (MAIN or one GATHER
    subagent) issues several tool calls that pydantic-ai executes as
    concurrent tasks against the one shared budget.json — not a
    cross-subagent race, but a same-instance one. Does the ordering the cap
    comparison assumes still hold when the calls that are supposed to
    precede or follow the cap are, in fact, simultaneous?
Judge's JUNK citation: NF1 (D1 reopened) resolves single-turn concurrent fan-out — "the increment path re-checks the pool and refuses to commit an effect whose cap has since tripped," bounding overshoot by in-flight concurrency ("a hostile 200-call turn has 199 refused at commit"), which is exactly this same-instance race.
Observed reader spreads (independent panels, arm-stripped):
  - C1 asserts settled (ordering not guaranteed, same as cross-agent race); C2/C3 leave it open

### J8: test_query_capture_ordering_holds_independently_for_every_concurrent_query_call
Situation: M11 pins the budget hook ahead of QueryCapture in the capability
    chain for a single call. When several `query` calls from concurrent
    GATHER siblings are in flight together, does that per-call ordering
    guarantee hold independently for every one of them, or could shared
    state in the hook chain let one call's ordering leak into another's?
Judge's JUNK citation: M11's guarantee is a static capability-registration order (`_make_hooks` prepended ahead of QueryCapture, `driver.py:205-209`) applied identically within every call's own execution path; there is no per-call ordering state to leak, so concurrency cannot break it — mechanism-level noise about a structural property.
Observed reader spreads (independent panels, arm-stripped):
  - copy2 and copy3 state "yes, structurally" (per-instance construction-time ordering holds independently across concurrent siblings); copy1 hedges that the doc "doesn't explicitly confirm" this under concurrency

### J9: test_same_budget_stopped_tool_reissued_twice_in_one_turn
Situation: The model emits two calls to the same budget-stopped tool within a single model
    turn — not across turns/retries — matching register_gather_tool's own documented
    instruction to dispatch sibling leads in parallel; both calls reach the short-circuit
    before either's ToolReturnPart returns.
Judge's JUNK citation: F3(a) short-circuit-only + F3(b) short-circuited calls do not increment `tool_calls`, probed at "14 consecutive short-circuits with zero retry accumulation, run completing normally"; two calls in one turn both short-circuit to M1b's ToolReturnPart with no increment and no retry.
Observed reader spreads (independent panels, arm-stripped):
  - copy2 states "yes, with reasonable confidence" (both same-turn calls independently reach and are denied); copy1 and copy3 hedge that the doc doesn't explicitly resolve the ordering/race

### J10: test_same_tool_name_on_two_agents
Situation: A tool name that is tail on MAIN is core on GATHER, and both agents call it in the same
    run.
Judge's JUNK citation: M1's tier function keys on agent+tool — `tail` for read/write/edit "(MAIN only)" and "Every GATHER tool is `core`, including `read_file`" — so a name that is tail on MAIN and core on GATHER is explicitly resolved; each call gets its own agent's tier.
Observed reader spreads (independent panels, arm-stripped):
  - C1 implies each agent's tier is independent ("withdrawn at the tier's limit, not the other's"); C2/C3 correctly describe a single tier keyed by tool name, defaulting to core when ambiguous | impact: a test could wrongly assert per-agent dual limits instead of one shared tier-by-name | rec: go with C2/C3 — matches demand tier_is_total + tier_census

### J11: test_the_budget_kill_fires_while_the_other_mechanism_is_mid_shutdown
Situation: The reverse ordering: the connectivity abort has begun unwinding the run and the
    budget's own kill becomes eligible on a call that is still in flight during that unwind.
Judge's JUNK citation: D5/D6 resolve overlapping kills as "First-fires-wins, neither kill knows about the other," and D6 pins by test that "exactly one shutdown path writes the run-dir artifacts" — the budget kill becoming eligible during another mechanism's unwind is that first-fires-wins/single-shutdown case.
Observed reader spreads (independent panels, arm-stripped):
  - C1/C3 lean settled (first-to-catch/first-unwound wins); C2 hedges whether the budget kill is even checked during breaker unwinding

### J12: test_the_failing_accounting_write_leaves_the_state_file_damaged
Situation: The accounting write fails partway rather than cleanly — the run's own writer is what
    leaves budget.json truncated, empty, or half-written, and the same run then reads back
    what its own failed write left behind. Distinct from finding pre-existing corruption
    written by something else.
Judge's JUNK citation: D4 covers the write failure and D9 covers the read-back — "validate and fail closed on the enforcing path / malformed counters trip"; a mid-run truncated/half-written file also loses D2's previously-present sentinel ("absent-after-present = the file was replaced" → trip), so both mechanisms converge on trip regardless of who caused the damage.
Observed reader spreads (independent panels, arm-stripped):
  - C1 assumes damage is the default outcome of a failed write; C3 argues the write is essentially atomic under flock and damage requires a mid-write process kill; C2 hedges between them | impact: whether the design must defend against self-inflicted corruption from its own writer, versus only externally-corrupted files | rec: not resolved by a named demand among those reviewed — recommend confirming 

### J13: test_two_different_kills_are_raised_by_two_concurrent_callers
Situation: One concurrently-executing caller reaches the budget kill's condition while a sibling
    reaches the connectivity abort's, and both raise into the same run's unwinding at once —
    two distinct end-the-run signals in flight together rather than one.
Judge's JUNK citation: D5/D6 — "First-fires-wins, neither kill knows about the other," with D6 guaranteeing "exactly one shutdown path writes the run-dir artifacts, pinned by a test" — directly settles two distinct end-the-run signals raised concurrently.
Observed reader spreads (independent panels, arm-stripped):
  - C1/C3 lean settled (first handler/first in stack unwind wins, one exception suppressed or chained); C2 hedges whether both are caught or both propagate

### J14: test_visualization_of_a_run_dir_the_kill_truncated
Situation: The run's rendering step runs over a run dir missing artifacts a completed run has.
Judge's JUNK citation: The design's downstream-handling obligation for a killed run is D8 (mark `truncated_by: "budget"`, runtime skips the learning enqueue); a visualization/rendering step is not an obligation of #631, and S2/C5 already accept run dirs may lack artifacts (investigation.md absent even in normal runs) — out-of-scope component noise, not an outcome this design underdetermines.

REAL 1 / JUNK 14
Observed reader spreads (independent panels, arm-stripped):
  - C1 states it flatly (viz renders over whatever's missing); C2/C3 hedge on whether viz tooling is required to handle truncation specially
