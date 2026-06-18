# Per-loop, invlang-based context compaction (Phase B)

**Status:** design. Implements Phase B of
`runtime-pydanticai-migration.md` (lines 222-234). Phase A (engine swap,
history passed through unmodified) is functionally aligned and signed off
— this is the green light per that doc's parity gate.

## What this is

At each **investigation loop boundary**, rewrite the main agent's message
history down to the committed invlang frontier (`investigation.md`) plus
the current loop's working turns, dropping the now-redundant gather
Task-return summaries and superseded predict/analyze prose of resolved
loops. The frontier is the authoritative carry-over; raw evidence stays
behind the gather wall, recoverable on demand (see §Recovery).

"Loop" = one PLAN→GATHER→ANALYZE round, the unit invlang already names:
the `:L findings [id|loop|...]` column and the `## GATHER (loop N)` /
`## ANALYZE (loop N)` markdown headers (`skills/invlang/SKILL.md:7-8`).

## Mechanism — freeze per loop, not per request

The migration doc says "rewrite before each model request." That's the
**hook site**, not the **trigger**. Recomputing on every request keyed to
`investigation.md` content would change the prefix mid-loop (gather
appends observations as the loop runs) and bust the cache every turn.

Instead: compact **only at loop increments, then freeze**. Within a loop
we're back to today's append-only shape — which already caches well — and
we pay the rewrite (one cache-creation) once per loop.

`ProcessHistory` / `before_model_request` hook in `runtime/driver.py`
(the `agent.iter()` seam, `driver.py:7-9`) holds:

- `_frozen_prefix` — the synthetic compacted preamble (see §Kept/Dropped),
  byte-stable for the whole loop.
- `_freeze_index` — count of real history messages absorbed into the prefix.
- `_frozen_at_loop` — the loop number the prefix was built at.

Per call:

```
current_loop = detect_loop()                      # §Detection
if current_loop == _frozen_at_loop:
    return _frozen_prefix + real_history[_freeze_index:]   # cache hit
else:                                              # loop advanced
    _frozen_prefix = build_prefix()                # from current investigation.md
    _freeze_index  = len(real_history)             # absorb everything so far
    _frozen_at_loop = current_loop
    reset_observe_cursors()                        # observe.py:28-30
    return _frozen_prefix                          # one cache-creation
```

Before the first increment (loop 1) nothing is compacted — identical to
Phase A. A single-loop investigation therefore never compacts, which is
correct (nothing redundant yet). The cut at `_freeze_index` lands on a
completed request/response boundary, so no `tool_use`/`tool_return` pair
is orphaned (an assertion at the cut enforces this; bail to fallback if
it would be — §Failure).

## Kept / dropped

`_frozen_prefix` =

1. **Orientation message** (real message 0: alert summary, lessons,
   workspace map, invlang catalog) — verbatim. Bonus: moving it into the
   frozen prefix lets it cache at 1h instead of its current 5m tail slot.
2. **Synthetic frontier message** (user role): the full current
   `investigation.md` rendered in a fenced ```invlang block, plus a
   pointer line per resolved lead → its persisted summary path (§Recovery).

Dropped (absorbed, not re-emitted): resolved-loop gather Task-return
summaries and superseded predict/analyze turns. The invlang validator
enforces **append-only** on `investigation.md`
(`hooks/invlang_validate.py`), so the file at loop N already contains the
full accumulated frontier of loops 1..N — committed vertices, edges,
hypothesis transitions (`:T`), authz verdicts. We re-read the whole file;
no per-loop stitching, and committed state can never be lost across loops.

**The bet:** the structured frontier is a sufficient distillation of the
prose gather summaries it replaces. §Validation is designed to detect when
it isn't.

## Recovery — persist gather summaries to disk

Today gather's prose summary lives **only** in the message history
(`runtime/tools.py:327,384`); the on-disk artifacts (`gather_raw/`) are
walled off from the main loop by `block_main_loop_raw_access.py`, whose
own remedy is "re-dispatch gather." Re-dispatch is an expensive recovery
path for a detail dropped by compaction.

So we add a **PostToolUse hook** (extend `tag_tool_results.py`, which
already intercepts the gather Task return) that writes the wrapped summary
to `{run_dir}/gather_summaries/{lead_id}.md`. Then a dropped detail is
recovered with a cheap `Read`, not a re-dispatch.

- **Location:** outside `gather_raw/`, so the block hook (keyed on the
  literal `gather_raw` marker) permits the main-loop Read with no hook
  edit.
- **Trust:** this is compatible with the #264 isolation invariant — we
  persist the **summary** (the sanitized record the main loop already
  consumes), never raw payloads. The persisted copy is stored
  **pre-wrapped with the salted untrusted marker** so a later Read returns
  tagged content; compaction must not become a way to launder
  attacker-influenced text into trusted context.
- **Testing posture:** for the A/B work we let the main loop re-read these
  freely. Whether to keep that surface open long-term is a follow-up
  decision, gated on whether the frontier proves a sufficient distillation.

## Cache layout

Slot budget works out exactly. Today (`driver.py:51-68`):
`instructions(1h) + tools(1h) + automatic tail(5m)` = 3 of Anthropic's 4
slots. The compacted-frontier `CachePoint()` takes the **one free slot**
at 1h:

```
[instructions 1h] [tools 1h] [orientation + frontier 1h ← CachePoint] [current-loop tail 5m]
```

All 4 slots full; no room to sub-segment the frontier (fine). The frozen
prefix is byte-stable across a loop → cache-creation once at the
increment, cache-read for every other turn in the loop. Within-loop turns
append into the 5m tail exactly as in Phase A.

## Loop-change detection

Signal: parse `investigation.md`, take `max(lead.loop)` over the `:L`
rows. When it exceeds `_frozen_at_loop`, the loop advanced. Preferred over
file-mtime or phase-header scraping because it's derived from the
validator-guarded committed artifact, it's exactly the unit we compact on,
and it degrades into the §Failure fallback when the parse fails.

Detection fires both the prefix recompute **and** the observe-cursor reset
(`observe.py:28-30` — the cursors assume append-only history; rewriting it
without resetting them corrupts the live `llm_requests.jsonl` trace).

## Failure handling

Compaction is deterministic (frontier selection, not model summarization),
so failure modes are narrow and testable:

- `investigation.md` parse/validate failure
- can't determine the current loop number
- the cut would orphan a `tool_use`/`tool_return` pair
- degenerate: the "compacted" prefix isn't actually smaller

On any: **return the original, unmodified history for this request** —
correctness preserved, savings forgone. Fallback is **sticky for the
failing boundary but re-attempted at the next** (never permanently
disabled). Emit a **structured compaction-outcome event** (not just a
printed warning) so the validation harness can report fallback frequency —
silent fallback would quietly erode the very savings this feature exists
for. Kill switch `DEFENDER_COMPACTION=off` runs Phase-A behavior (needed
anyway to produce the A/B baseline).

## Validation (A/B)

Acceptance is **two** numbers per the migration doc: token savings **and**
unchanged dispositions on the same fixtures. The available artifacts let us
climb a cost-ordered ladder — cheapest, most diagnostic step first.

**Baseline material on hand:** 5 recorded Phase-A runs under
`/tmp/defender-runs/` carry full `llm_requests.jsonl` + `tool_trace.jsonl`
(best: `opt-verify-xtier-6f2d77e`, 344 request lines). They ran against the
**live** playground-v2 stack, so they are a *reference*, not a drift-free
A-leg. No fixture-replay mode exists; `run_pai.py` (the PydanticAI driver)
hits the stack live. Toggle is `DEFENDER_COMPACTION=off|on`, same alert,
same invocation.

0. **Offline dry-run (no API, no stack).** Compaction is a pure
   history-rewrite, so replay the builder + loop-detection over a recorded
   `llm_requests.jsonl` and compute the hypothetical per-loop prefix sizes.
   Validates the mechanism on real histories and yields a first *mechanical*
   savings number at zero cost. It cannot show trajectory divergence (the
   agent may behave differently with compacted context) — that's step 1.
   Implemented: `scripts/compaction_dryrun.py` over `runtime/compaction.py`.

   **Step-0 result (5 recorded Phase-A runs, each 1–2 loop boundaries):**
   message-history payload **−35% to −55%**; estimated total prompt tokens
   **−26% to −38%** (token < history because the ~7.3–8.6k-token system+tools
   preamble is fixed). The chars/token the harness regresses out is stable at
   **2.9–3.1** across runs, and the regressed system+tools overhead matches
   `driver.py`'s "SKILL ~9K tokens" note — two independent signs the estimate
   is sound. Lower than the migration doc's modeled 51–64% because these runs
   have few loop boundaries (1–2); savings rise with loop count, as the
   2-boundary run (−55% history) shows. The recorded input is ~90% cache_read,
   so *billed* savings concentrate on cache-creation + a longer-lived cache,
   not the raw token delta — but the context-window headroom is the full delta.
1. **N=1 live, read the transcript.** Run one alert through `run_pai.py`
   twice back-to-back, `DEFENDER_COMPACTION` off then on (both fresh, so
   the A and B legs see the same current stack — don't use the older
   recorded runs as the A-leg). Don't trust a single disposition/token
   number — read the compacted run and watch for the real failure signal:
   does the agent start **re-dispatching gather or re-reading persisted
   summaries to recover detail it used to hold in context**, or conclude
   differently? Visible by reading, invisible in the aggregate.
   **Step-1 result (N=1, ssh-pivot alert, 2026-06-18):** FAILED — compaction
   induced a fatal trajectory divergence. Phase A (off) completed clean
   (disposition `malicious`, 7 leads dispatched once each, 21 requests). Phase B
   (on) froze at the loop-1→2 boundary, then **re-dispatched the active loop-2
   leads `l-004`/`l-005` 17 times** until the gather tool hit its 10-retry cap
   and crashed. The agent never used the `gather_summaries/` re-read path (0
   reads). Diagnosis: the freeze fires on `:L` loop *increment*, i.e. the moment
   loop 2 is *planned* — while loop 2's leads are still unresolved. The synthetic
   frontier then advertises `l-004`/`l-005` as planned-with-no-results, and the
   agent re-gathers them (their fresh summaries were in the live tail) instead of
   reasoning from the tail or re-reading the persisted summary. Root cause: the
   design's assumption that "loop N's gathers are resolved when loop N+1 is
   planned" is false — `max(:L loop)` fires too early, compacting mid-stride.
   (N=1 caveat: model nondeterminism not fully excluded, but the clean control,
   the loop localized exactly to the freeze boundary, and the unused recovery
   path make compaction the clear cause.) Also: disposition drifted vs. the
   recorded `inconclusive` even on Phase A — stack/model drift since the Jun-15
   recording, so the recorded runs are not a disposition oracle; Phase A is.

2. **Iterate** the kept/dropped boundary if the read shows over-compaction.
   **Done (commit cc85516):** `fold_boundary` folds only loops *below* the active
   (highest-planned) loop — settled regardless of dead-end leads — plus the active
   loop once itself resolved; `_frontier_through` trims the rendered frontier to
   the folded loops so the active loop never enters the frozen snapshot; the
   framing message now says the listed leads are DONE (don't re-dispatch).
   22 unit tests pass. **Live re-validation PENDING:** the re-run (`ab-sshpivot-B2`)
   was aborted by the circuit breaker when the playground VPS went unreachable
   mid-run (`ssh … port 22: Connection timed out`); compaction never engaged
   (0 freezes — the run never reached a resolved loop), so it's inconclusive.
   Re-run arm B once the stack is back up.
3. **Scale** to the fixture set only once N=1 looks directionally right;
   report the A→B token delta and the disposition-parity table. A
   **fixture-replay mode** (serve recorded `gather_raw/` payloads instead of
   hitting the stack) is the clean way to remove drift from the quantitative
   deltas here — deferred to this step, not built up front.

## Live-integration bug (found 2nd A/B, post-fix)

The resolved-boundary fix killed the re-dispatch crash, but the next live arm B
looped to the 60-request limit with **flat input tokens** (14,556 every request
after the first freeze) — the agent re-read `alert.json` 45× and re-oriented
forever. Root cause (proven with a TestModel probe — processor saw message counts
`[1,3,3,3,3,3,3]`, flat): **PydanticAI's history processor persists/accumulates
its own output** — each call receives `[previously-returned messages + new
turns]`, NOT the full append-only canonical the design assumed. So a stateful
`freeze_index` into the original history is invalid after the first freeze: the
history collapses to `[orientation, frontier]`, `freeze_index` exceeds its
length, `tail` is always empty, and every request re-sends just the prefix,
dropping the agent's new work → infinite re-orientation.

**Fix direction (not yet implemented):** marker-based incremental processing —
locate the frontier sentinel in the received (accumulated) history, keep
everything after it as the live tail, and re-render the frontier from
`investigation.md`. The pure `compaction.py` logic is sound (22 tests); only the
live wiring's freeze-index model is wrong. `compaction.py`'s `compact()` and the
offline dry-run still assume a growing canonical, which is correct for the
*offline* replay but not for the *live* processor — the two need different
drivers over the same primitives (`fold_boundary`, `_frontier_through`,
`render_frontier_message`).

## Status after the stateless redesign (3rd A/B)

The marker-based stateless processor is committed and offline-proven (regression
test simulates PydanticAI's accumulation and asserts the tail grows; 23 tests).
Live `ab3-B`: completed `malicious`/high (matches the `ab2-A` baseline), **no
re-dispatch loop, no crash, and input tokens grow normally** (11442→39262, vs the
pre-fix flat 14,556) — confirming the accumulation bug is dead and the processor
is harmless when dormant. **But `ab3-B` was a single-loop run** (concluded after
loop 1), so `fold_boundary` never crossed a boundary and compaction **did not
fire** (0 freezes — correct: nothing to fold in a one-loop investigation).

**Remaining validation gap:** a *live multi-loop* run where a freeze actually
fires AND the run completes with matching disposition + measured token savings.
Loop count is nondeterministic on this alert (baseline got 4 loops, ab3-B got 1);
catching a multi-loop trajectory may take a couple of runs, or a fixture that
reliably needs ≥2 loops. This is the "scale" rung of the ladder.

## Live freeze validated (4th A/B, Falco alert)

Ran the richer `v2-falco-suspicious-network-tool` alert (more likely multi-loop)
through both arms. **Milestone: compaction fired live AND the run completed
cleanly** — the first run to do both (prior attempts crashed, looped, or stayed
dormant). Arm B (on): 3 loops, 54 requests, finished with a coherent
`inconclusive` report. The input-token trace shows the textbook compaction
signature — grows, **dips at the freeze** (26,874 → 20,682), then grows again —
i.e. the fold dropped the settled loop and the tail is preserved. So the
mechanism works end-to-end.

**But this A/B does NOT measure the payoff** — it's confounded by trajectory
nondeterminism:
- Arm A (off): `malicious`/high, 2 loops, 20 requests, 525k prompt tokens.
- Arm B (on): `inconclusive`/medium, 3 loops, 54 requests, 2.08M prompt tokens.

B used ~4× the tokens because it did ~2.7× more work (deeper investigation), not
because compaction is inefficient — a single nondeterministic pair can't isolate
compaction's per-request saving. Disposition also diverged (malicious vs
inconclusive), but B's inconclusive came from a *deeper* investigation (it found
the external IP was the sole SSH operator across 38 prior logins, then flagged 3
verification gaps) — that reads as nondeterministic depth, not compaction-induced
info loss. Minor yellow flag: leads l-001–l-004 were each dispatched twice (mild
re-gather, not the old pathological loop).

**Verdict:** the fix is validated at the mechanism level (fires + completes +
tail preserved). The quantitative token-saving and disposition-parity numbers
require the **scale rung** — either N>1 runs to average out nondeterminism, or
(cleaner) a deterministic fixture-replay harness that serves recorded gather
payloads so A and B run the identical trajectory.

## Post-mortem on the 4th A/B — the freeze backfired (two fixes)

Reading the recorded trace (`tool_trace.jsonl` + per-request `usage`) instead of
the headline numbers showed the freeze was **net-negative**, not merely
unmeasured. The freeze fired once at request **r12** (prompt 32,209 → 12,587),
and the agent's very next move was to *restart*: it re-read `alert.json` +
`SKILL.md` (r12), rewrote ORIENT+PLAN from scratch (r15), **re-dispatched the
already-gathered loop-1 leads l-001–l-004** (r16), then re-read 5 gather
summaries (r26–r27) and the full `investigation.md` (r32). Prompt climbed to
**66k by r54** — well above Arm A's 37k peak — plus a cache bust at r39
(re-created 43k). The agent pulled the folded context straight back in. Two
distinct defects, each reproduced from the recorded run:

1. **Premature freeze on a transient draft (root cause).** At r11 the agent
   drafted loop 2's `:L` plan row while loop 1 still had **no results**
   (`resolved={1: False, 2: False}`). The old `fold_boundary` ("fold everything
   strictly below the active loop") returned 1 and froze the **empty** loop 1 —
   so the agent was asked to continue from a loop folded out from under it, and
   re-did it. **Fix:** fold only the *contiguous run of fully-resolved loops
   strictly below the active loop*. Now r11–r14 return `fold=0` (verified by
   replaying the recorded writes); the freeze can only fire once an earlier loop
   is committed *and* a later one has opened. This also subsumes the old
   "never fold the sole/active loop" intent.

2. **Frontier was a pointer dump, not a continuation.** The frozen message
   listed each completed lead's on-disk summary path ("read its summary instead
   of re-running it") — which read as a to-do list; the agent dutifully re-read
   them, re-inflating context. **Fix:** reframe as a continuation — the folded
   loops are COMPLETE, the inlined invlang is authoritative, "do NOT re-dispatch,
   re-read, or re-derive" — and **stop advertising the disk paths**. The
   summaries still persist on disk (debug / genuine last resort), just unlinked
   from the frontier.

Regression tests pin both: `test_fold_boundary_does_not_fold_unresolved_loop_below_drafted_loop`
(the r11 scenario) and `test_fold_boundary_never_folds_the_active_loop`; the
refreeze test now requires a *later loop to open*, not merely the current one to
resolve.

## 5th + 6th A/B — restart fixed; one residual re-orientation (credits ran out)

**5th A/B (`ab5-falco-B`, fixes 1+2):** the restart is gone. Vs the broken 4th
run: alert/SKILL read only at the open (not mid-run), each lead dispatched once
(no re-dispatch), **zero** gather-summary re-reads, 26 requests vs 54, correct
`malicious`/high. At the old bug spot (loop 2 drafted over an unresolved loop 1,
here r19) `fold_boundary` correctly returned 0. **But the freeze never fired** —
loop 1's lead l-004 dead-ended, and "fold only when *all* leads resolved" let one
dead-end block the whole loop, so `fold` stayed 0 all run. Real investigations
routinely dead-end a lead, so that rule neutered the feature.

**Fix 3 (commit `fa7c078`):** fold a below-active loop once it has **≥1 committed
finding** (`any`, not `all`) — a bare drafted-ahead plan still has zero (bug stays
fixed), but a worked loop folds dead-ends and all (the original design's intent).

**6th A/B (`ab6-falco-B`, fixes 1+2+3):** the freeze **fires cleanly**. At the
loop-1→loop-2 boundary (t13→t14) the prompt dropped 29,328 → 14,118 (−15,210),
the frontier sentinel is present in the sent request, and the run made forward
progress — 10 leads across 3 loops, **no** lead re-dispatch, **no** summary
re-reads. Baseline `ab5-falco-A` (off): `malicious`/high, 30 requests, ~1.20M
cumulative prompt tokens, 8 leads.

**Residual artifact (not yet fixed):** right after the freeze (t14) the agent
re-read `alert.json` + the **invlang** `SKILL.md`. Confirmed freeze-caused — the
baseline reads them only at the open, never again. Root cause: both were loaded
as *orientation-phase tool-returns* (t01), which the freeze folds; the preserved
prefix is `[orientation message 0, frontier]`, and neither carries the raw alert
nor the invlang block spec, so the agent re-fetches them to keep writing invlang.
Much milder than the old full restart (no re-plan/re-dispatch/re-derive), but it
partially eats the saving and would recur once per freeze. Candidate fixes:
(a) embed the invlang spec + raw alert in the persistent context (agent
`instructions` or orientation message 0) so a fold can't drop them — the proper
fix; (b) accept it as a cheap one-time re-read per freeze; (c) a frontier nudge
("alert + invlang spec unchanged; don't re-read") — risky, may suppress a genuine
need. **Unresolved**: needs a live run to validate, but the first-party API key's
**credits were exhausted** by these three runs (the 6th crashed mid-investigation
on `400 credit balance too low`, before REPORT — billing, not a code bug).

**Net:** the restart (the costly failure) is fixed and the freeze now fires at a
genuine boundary with a clean ~15k dip. One residual mild re-orientation remains,
and a real token-saving / disposition-parity number still needs the scale rung
(N>1 or the deterministic fixture-replay harness) — plus a credit top-up.

## Implementation status

Built and tested (branch `worktree-per-loop-compaction`):

- **Pure core** — `runtime/compaction.py`: `detect_loop`, freeze-per-loop
  `compact()` (passthrough / froze / reused / fallback), size accounting,
  `apply_writes`. Unit tests: `tests/test_compaction.py`.
- **Offline harness** — `scripts/compaction_dryrun.py` (validation ladder
  step 0; results above).
- **Recovery hook** — `tools._persist_gather_summary` writes the wrapped
  summary to `{run_dir}/gather_summaries/{lead_id}.md` from `_run_gather`.
  No `permission.py` change needed: `decide_read` blocks only `gather_raw/`,
  and `is_untrusted_read` keys on `gather_raw/`/`alert.json`, so the pre-wrapped
  copy is readable and stays tagged (no double-wrap).
- **Live wiring** — `driver.py`: `ProcessHistory(_make_compaction_processor())`
  added to the **main** agent only, behind `DEFENDER_COMPACTION` (default
  **off** → Phase A byte-identical; set `on`/`1`/`true` to enable). The
  processor dumps the canonical history, runs `compact`, and re-validates a
  rewrite back to message objects; failures fall back to the full history.
  `observe.py` self-rebaselines its streaming cursor when the history shrinks
  at a freeze. Glue tests: `tests/test_compaction_driver.py`.
  - *Gotcha pinned in code:* the history-processor's first param must be
    annotated `RunContext[...]` — pydantic-ai detects the ctx-taking variant by
    annotation, not name; an unannotated `ctx` is silently called arg-short.

Not yet done: the live N=1 A/B run (ladder step 1) — needs the playground-v2
stack and API spend.

## Open decisions

- Keep the main-loop read of `gather_summaries/` open past the A/B phase,
  or re-close it once the frontier proves a sufficient distillation?
- Frontier = `investigation.md` only (current choice) vs. also folding in
  the two tables. Start strict; let a disposition flip force the question.
