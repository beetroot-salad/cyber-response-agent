P1 test_accounting_write_cannot_acquire_its_serialization_at_all
VERDICT: JUNK
CITE: D4 governs "accounting-write failure" by outcome category (isolated fails open / sustained is an environment fault, detected via NF4's consecutive-failure count + first-failure stamp); a failure to acquire the flock is still a failure to complete the update and feeds the same detection state, and an enforcing read that cannot proceed fails closed per D9 — the where-in-the-RMW distinction yields no different observable.

P2 test_accounting_write_fails_on_the_very_call_that_would_have_tripped_the_cap
VERDICT: JUNK
CITE: D4 states this case verbatim — "One failure costs one call of overshoot (the counter is monotonic; the next call re-crosses and trips)." The observable (one call of overshoot, then trip) is fixed.

P3 test_budget_json_missing_the_subagent_spawns_key
VERDICT: REAL
CITE: A run-start file predating M3's spawn wiring lacks both the counter key and D2's run-scoped sentinel; D2 routes an absent marker to "genuine cold start" (benign re-init, no trip), while D9's "validate and fail closed on the enforcing path / malformed counters trip" routes a missing required counter to a fail-closed trip — neither is ordered over the other for this migration case, and both readings ship.

P4 test_connectivity_failures_spend_the_budget_pool
VERDICT: JUNK
CITE: Connectivity-failed calls are executed tool calls (F3(b) exempts only budget short-circuits, not executions that error), so they count toward the pool, and D5/D6 settle the breaker/budget interaction as decoupled first-fires-wins.

P5 test_enforce_flag_empty_string
VERDICT: JUNK
CITE: M9 commits the flag to the existing `env_bool` mechanism (`driver.py:351`, `DEFENDER_COMPACTION`); empty-string handling is fixed by that named function, not a design choice left open.

P6 test_enforce_flag_whitespace_and_case_variants
VERDICT: JUNK
CITE: Same as P5 — M9 pins the flag to `env_bool`, whose treatment of " True "/"YES" is determined by the existing function, so there are not two shippable readings.

P7 test_injected_limits_negative_cap
VERDICT: JUNK
CITE: D9 already decided injected out-of-range caps: "An injected cap of 0 trips immediately rather than reading as 'disabled'"; a negative cap makes M1's `count >= limit` comparison always true and fails D9's validation, so it trips immediately under either mechanism — one observable.

P8 test_intra_agent_parallel_calls_race_the_same_shared_check
VERDICT: JUNK
CITE: NF1 (D1 reopened) resolves single-turn concurrent fan-out — "the increment path re-checks the pool and refuses to commit an effect whose cap has since tripped," bounding overshoot by in-flight concurrency ("a hostile 200-call turn has 199 refused at commit"), which is exactly this same-instance race.

P9 test_query_capture_ordering_holds_independently_for_every_concurrent_query_call
VERDICT: JUNK
CITE: M11's guarantee is a static capability-registration order (`_make_hooks` prepended ahead of QueryCapture, `driver.py:205-209`) applied identically within every call's own execution path; there is no per-call ordering state to leak, so concurrency cannot break it — mechanism-level noise about a structural property.

P10 test_same_budget_stopped_tool_reissued_twice_in_one_turn
VERDICT: JUNK
CITE: F3(a) short-circuit-only + F3(b) short-circuited calls do not increment `tool_calls`, probed at "14 consecutive short-circuits with zero retry accumulation, run completing normally"; two calls in one turn both short-circuit to M1b's ToolReturnPart with no increment and no retry.

P11 test_same_tool_name_on_two_agents
VERDICT: JUNK
CITE: M1's tier function keys on agent+tool — `tail` for read/write/edit "(MAIN only)" and "Every GATHER tool is `core`, including `read_file`" — so a name that is tail on MAIN and core on GATHER is explicitly resolved; each call gets its own agent's tier.

P12 test_the_budget_kill_fires_while_the_other_mechanism_is_mid_shutdown
VERDICT: JUNK
CITE: D5/D6 resolve overlapping kills as "First-fires-wins, neither kill knows about the other," and D6 pins by test that "exactly one shutdown path writes the run-dir artifacts" — the budget kill becoming eligible during another mechanism's unwind is that first-fires-wins/single-shutdown case.

P13 test_the_failing_accounting_write_leaves_the_state_file_damaged
VERDICT: JUNK
CITE: D4 covers the write failure and D9 covers the read-back — "validate and fail closed on the enforcing path / malformed counters trip"; a mid-run truncated/half-written file also loses D2's previously-present sentinel ("absent-after-present = the file was replaced" → trip), so both mechanisms converge on trip regardless of who caused the damage.

P14 test_two_different_kills_are_raised_by_two_concurrent_callers
VERDICT: JUNK
CITE: D5/D6 — "First-fires-wins, neither kill knows about the other," with D6 guaranteeing "exactly one shutdown path writes the run-dir artifacts, pinned by a test" — directly settles two distinct end-the-run signals raised concurrently.

P15 test_visualization_of_a_run_dir_the_kill_truncated
VERDICT: JUNK
CITE: The design's downstream-handling obligation for a killed run is D8 (mark `truncated_by: "budget"`, runtime skips the learning enqueue); a visualization/rendering step is not an obligation of #631, and S2/C5 already accept run dirs may lack artifacts (investigation.md absent even in normal runs) — out-of-scope component noise, not an outcome this design underdetermines.

REAL 1 / JUNK 14
