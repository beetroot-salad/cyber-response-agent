# Adversarial re-judge verdicts — fixture 631 (attacking 14 JUNK verdicts)

Method: for each premise, tried to exhibit two implementations both consistent with the
design doc + the shipped handoff record that diverge observably on exactly the premise's
situation, and to show the judge's citation fails to exclude one. Grounded against the
shipped code (hooks/budget_enforcer.py, runtime/driver.py, _env.py at base 483b5809) where
a mechanism claim was load-bearing.

---

J1 test_accounting_write_cannot_acquire_its_serialization_at_all
VERDICT: FLIPPED
WHY: Impl A wraps the whole locked read-check-write (including flock/file acquisition) in the
failure-detection path, so an inability to acquire feeds `accounting_failure_state` and a
sustained read-only dir trips the environment-fault `BudgetKill`; Impl B (which the shipped
`account_call` actually is) wraps only `_write_budget_atomic` in `except OSError` — the
`read_budget`/flock acquisition sits OUTSIDE it, so an acquire-side failure propagates to
driver.py:121's `except Exception` ("budget accounting skipped") and never advances the
detection count, failing open forever. The citation asserts "a failure to acquire the flock
... feeds the same detection state," an implication the doc does not make: the D4/NF4 demands
govern "accounting-WRITE failures," and the premise's whole distinction (the RMW never begins)
is exactly the case the shipped code leaves undetected.

J2 test_accounting_write_fails_on_the_very_call_that_would_have_tripped_the_cap
VERDICT: UPHELD
WHY: `isolated_accounting_write_failure_fails_open` states the observable verbatim — one call
of overshoot, then the next call re-crosses and trips — and the counter's monotonicity makes
this deterministic; the shipped `account_call` matches (a failed atomic write leaves the old
count, the next call reads one-short and re-crosses). Fail-closed-on-isolated is excluded by
the demand's fail-open scope and fail-open-forever is excluded by the sustained limb, so a
single isolated failure has exactly one shippable outcome.

J3 test_connectivity_failures_spend_the_budget_pool
VERDICT: UPHELD
WHY: `failed_calls_still_counted` is a named demand discharged by this exact test and pins
that a connectivity-failed call still executed and still increments; the shipped `account_call`
carries `exit_code` and documents "accounting is unconditional on OUTCOME." Any doc-consistent
impl must count it, so C2's "do they count at all" hedge has one answer, and the
breaker/budget interaction is the decoupled first-fires-wins of D5 — no divergent impl survives.

J4 test_enforce_flag_empty_string
VERDICT: UPHELD
WHY: M9 commits the flag to the pre-existing `env_bool` (unchanged since #455, present at base
483b5809), whose `_FALSE_TOKENS` explicitly contains `""` — so `""` returns False and the run
is unenforced, observationally identical to unset (also False). Both readings the panels
floated ("falsy" vs "fatal") cannot both be doc-consistent, because a compliant impl MUST use
the named function, and it puts `""` in the false bucket, not the unrecognized/fatal one. The
citation genuinely pins it; the C2/C3 hedge is a guess refuted by the function the doc names.

J5 test_enforce_flag_whitespace_and_case_variants
VERDICT: UPHELD
WHY: The same `env_bool` does `raw.strip().lower()` before matching, so " True " -> "true" ->
True and "YES" -> "yes" -> True — whitespace-insensitive and case-insensitive, and neither
raises. There is one shippable reading because any doc-consistent impl calls this exact
function; the panels' "whitespace raises" reading is contradicted by the code the citation
correctly points to.

J6 test_injected_limits_negative_cap
VERDICT: FLIPPED
WHY: The only cap-domain member any demand pins is [0] (`injected_zero_cap_trips_immediately`),
and `malformed_counter_trips` governs counter VALUES, not caps; the "non-negative" domain note
is a refinement, not an enforced cap-validation. Impl A uses the bare `count >= max_tool_calls`
comparison (as shipped `should_refuse` does) so a negative cap is always crossed and trips
immediately; Impl B satisfies the literal [0] demand with `if cap == 0: trip; elif cap > 0 and
count >= cap: trip` and lets a negative cap fall through as silently disabled (fail open) —
mirroring the incumbent `cap <= 0 -> None` shape. Both satisfy every demand yet diverge, and
the readers' "comparison disabled, limb silently off" reading is exactly Impl B; the citation's
"fails D9's validation" overstates a validation the spec pins only for 0.

J7 test_intra_agent_parallel_calls_race_the_same_shared_check
VERDICT: UPHELD
WHY: Two demands jointly close it — `concurrent_increments_neither_lost_nor_duplicated` (bound
at the composition frame, flock per-file not per-caller) and `effect_not_committed_after_its_
pool_trips` (commit-time re-check refuses to land an effect past the trip). The shipped
`account_call` enforces both via an in-process `_ACCOUNT_LOCK` plus a commit re-check, so a
same-instance fan-out is handled identically to the cross-agent race: overshoot bounded by
in-flight concurrency, no increment lost. No doc-consistent impl escapes both demands.

J8 test_query_capture_ordering_holds_independently_for_every_concurrent_query_call
VERDICT: UPHELD
WHY: M11's ordering is a static capability-registration order (`_make_hooks` prepended ahead of
QueryCapture at construction, driver.py:205), applied identically inside every call's own path;
there is no per-call ordering state, so there is nothing for one concurrent call to leak into
another. Any doc-consistent impl builds the capability list once at construction (the handoff's
own drop rationale), so the ordering property holds structurally under concurrency. The
open no-torn-row obligation is the FILE-integrity question, not the hook-ordering question this
premise asks.

J9 test_same_budget_stopped_tool_reissued_twice_in_one_turn
VERDICT: UPHELD
WHY: `reissue_costs_no_retries` (no special-casing, no retry accumulation, driven well past ten
re-issues) plus `refused_calls_not_counted` pin the observable: each same-turn call independently
short-circuits to M1b's ToolReturnPart with no increment and no retry. Because the refusal path
touches no counter (writes nothing to budget.json), the two calls are commutative and ordering
is irrelevant to the accounting/retry outcome the premise centers on; F3(a)/F3(b) exclude any
divergent handling of the second call.

J10 test_same_tool_name_on_two_agents
VERDICT: UPHELD
WHY: `tier_is_per_tool_and_agent` is a named demand for this exact test, and the shipped `tier`
keys on `(tool_name, role)`: MAIN's read_file is tail, GATHER's read_file is core, in one run.
The rival "single tier keyed by name, defaulting to core" reading would demote MAIN's file I/O
out of the tail band, breaking O2 — which `tier_census`'s cross_check explicitly names the WRONG
repair — so it is not a doc-consistent impl. Both compliant impls give MAIN N+10 and GATHER N;
no divergence survives.

J11 test_the_budget_kill_fires_while_the_other_mechanism_is_mid_shutdown
VERDICT: FLIPPED
WHY: D5/D6 pin "decoupled, first-fires-wins" and "exactly one shutdown path writes," but neither
pins WHICH mechanism's mark lands when the budget kill becomes eligible during the breaker's
unwind. Impl A treats the breaker's already-caught RunAborted as the terminator (`truncated_by`
stays None, run enqueued for learning); Impl B lets the decoupled budget kill fire during the
unwind and land in `except BudgetKill`, stamping `truncated_by="budget"` and suppressing the
learning enqueue. Both satisfy D5/D6 (one writer) yet diverge on `truncated_by` and enqueue —
precisely C2's "is the budget kill even checked during breaker unwinding" hedge, an ordering the
doc's decoupling leaves undefined.

J12 test_the_failing_accounting_write_leaves_the_state_file_damaged
VERDICT: FLIPPED
WHY: No demand pins the enforced writer's atomicity. Impl A does an in-place truncate+write (the
incumbent `update_json_locked` shape), so a partial failure leaves budget.json truncated and the
read-back trips via D9/D2; Impl B (the shipped `_write_budget_atomic` = temp + os.replace) leaves
the last-good file intact on failure, so there is NO self-inflicted damage and the run continues
on valid state. The code comment itself notes "an in-place r+ would silently succeed" — i.e. the
two writer choices behave differently. The citation assumes damage occurs and then both
mechanisms trip; it fails to exclude the atomic impl where no damage is produced at all. The
manifest's own note ("not resolved by a named demand") is correct.

J13 test_two_different_kills_are_raised_by_two_concurrent_callers
VERDICT: FLIPPED
WHY: P6/`kill_own_exception_caught` probed the collapse-to-one shape only for two SAME-type
budget kills; for a budget kill and a breaker abort raised concurrently the doc pins no tie-break.
Impl A has the budget kill win the race -> `except BudgetKill` -> `truncated_by="budget"` ->
learning suppressed; Impl B has RunAborted win -> `except RunAborted` -> `truncated_by=None` ->
run enqueued for learning. Both satisfy D6 (one path writes) and D5 (decoupled, "neither knows
about the other," which explicitly admits a nondeterministic winner), so the observable
(`truncated_by` + enqueue) is genuinely underdetermined. The handoff even flags the single-
exception shape as version-dependent and untested for the cross-type case.

J14 test_visualization_of_a_run_dir_the_kill_truncated
VERDICT: UPHELD
WHY: No #631 demand touches the rendering/visualization step; D8's downstream obligation is
scoped to the `truncated_by` mark and the learning-enqueue skip (which the runtime owns), not to
`scripts/visualize/`. A #631 implementation adds the mark and the enqueue guard and does not
modify rendering, so viz behavior is invariant across compliant impls — and S2/C5 establish that
run dirs already lack artifacts on normal runs, so viz's tolerance of missing files is a
pre-existing, already-fixed property. The premise is about a component the design does not
govern, not an outcome the design underdetermines.

---

FLIPPED 5 / UPHELD 9
