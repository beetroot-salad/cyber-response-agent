## Intent + design — blocking budget under a flag

Compiled from discussion, then revised against a cold review. Probed claims at the bottom — four of them changed the design, and one is recorded `refuted`.

### Intent

**Obligations**

- **O1 (operator).** When enforcement is on, a run cannot exceed its per-run caps without the system taking a deliberate action. Warnings on stderr do not satisfy this — that is accounting, the state this issue opens against. *Qualified deliberately:* the flag ships off in production (M9), so this obligation is discharged in CI/eval now and in production when the default flips.
- **O2 (operator).** When a cap trips, the MAIN loop gets a bounded opportunity to write its report before the run ends. Scoped to MAIN: GATHER holds no write tool (`driver.py:296`), so there is nothing to degrade *to* there.
- **O3 (operator).** The caps bound MAIN plus every GATHER subagent as one pool — not each agent separately.
- **O4 (operator).** The wall-clock cap is ~20 min, down from today's 1800s. *Stakeholder-requested tightening*, recorded as its own obligation rather than smuggled into O1 — the cold review correctly flagged it as a mechanism serving nothing.
- **O5 (operator).** The post-trip tail is bounded by a number we can state, not merely "eventually."
- **O6 (developer).** The enforcement path is *executed* routinely — not merely enabled. Turning the flag on in CI exercises nothing on its own: C6's data has real runs at 10-26 tool calls against a cap of 200, so the deny branch would never be reached. See M12.
- **O7 (reader).** `budget_enforcer.py`'s docstring and threat-model class 7 describe what the code does, in whichever state the flag leaves it.

**Explicit non-obligations**

- **N1.** The caps do **not** become configurable *by an operator*. `DEFAULT_LIMITS` stays inline and single-default; the flag governs *posture*, not tuning. (The issue says this outright.) O4 is a one-time value change, not a configurability seam. **Carve-out, required by O6:** a *test* seam is not an operator overlay. `check_budgets(budget, limits)` already takes limits as a parameter; the driver resolves `DEFAULT_LIMITS` at the boundary and threads it inward, which is `defender/CLAUDE.md`'s own sanctioned shape ("a single DI/test seam that *owns* its default"). No env var, no file, no per-signature layering — the thing N1 exists to prevent.
- **N2.** No token or cost cap. Wall clock stays the indirect proxy for spend. The issue's third gotcha asks whether that is the right proxy — deliberately out of scope, worth a separate issue.
- **N3.** **The learning-loop agents are out of scope for deny-and-kill.** They keep accounting only. `_make_hooks` is the single shared hook factory and `build_agent_core` is reached by `_pydantic_stage.py:67`, so an ungated deny would silently extend enforcement to the actor, judge, oracle, lead author, and both curators. The curator runs a one-PR-per-batch transaction under a writer lease; killing it mid-transaction is a failure mode nothing here asks for, and those stages already carry their own `request_limit` + `wall_clock_timeout` (`_pydantic_stage.py:77-81`). Deny and kill are gated to MAIN and GATHER.
- **N4.** `gather` gets no per-call stopwatch. It is a nested agent with its own `GATHER_REQUEST_LIMIT = 40`; #304 records a legitimate 6-dimension lead needing ~26 turns, so a 2–3 min timer would cut real work.
- **N5.** Not addressed: whether every `query` transport actually sets the inner timeout that `query_tool.py:439-445` calls mandatory. Real gap, different work — separate issue.
- **N7.** **There is no second enforcement path to flip.** The issue says "Neither path enforces them," but the `claude -p` path is not unenforcing — it is *uninvoked*. That runtime and its `run-settings.json` hook wiring were retired (`defender/CLAUDE.md:17-24`); `budget_enforcer.py` survives only as the budget *logic* `driver.py:49` imports. Its `main()`/stdin/exit-code entrypoint was dead code exercised only by its own test, and **is now deleted** — along with the `"Task"/"Agent"` spawn names from the retired dispatch, which no registered tool answers to any more. See C13.
- **N6.** No out-of-band wall-clock watchdog. Detection stays at a tool-call boundary; see M6 for the honest bound. Filed alongside N5.

### Design

- **M1 — withdraw the tool, don't deny it** (discharges O1, O2). The trip's primary mechanism is the `prepare_tools` hook, which filters the toolset offered on each model request. Post-trip, the expensive tools are simply **not offered**. This is the correction that makes O2 dischargeable at all — see the failure it avoids below.

  ```
  tier(tool)  = "tail"  for read_file / write_file / edit_file   (MAIN only)
                "core"  otherwise                                (DEFAULT — fail closed)
  limit(tier) = N + 10  for "tail"
                N       for "core"
  withdraw tool from the offered set when  budget.tool_calls >= limit(tier(tool))
                                        or budget.subagent_spawns >= max_subagent_spawns  (tool == gather)
                                        or elapsed >= wall_clock_timeout
  ```

  `tier` is **total by construction** — the default arm is `core`, the restrictive one. A tool added to either ToolSet inherits the tight cap rather than falling off a lookup table; there is no `KeyError` path into `before_tool_execute`, which `tool_manager.py:341`'s `except (ValidationError, ModelRetry)` would not catch. A test pins the census (C4) so a new tool is a deliberate tiering decision, not a silent one.

  No trip *state* — no `tripped` flag, no state machine, just comparisons against counters. Concurrent gathers all mutate `budget.json` under `flock`, so a "reset the budget on trip" would be a read-modify-write race where two leads each observe the trip and each reset. Static thresholds cannot race.

  **Why withdrawal rather than denial.** A budget deny is *permanent*, unlike a permission deny — "pick another command" is not available, the tool is gone for the rest of the run. A model whose plan is "dispatch the next lead" re-issues `gather`, is denied, re-issues. MAIN is built with `retries=DEFAULT_TOOL_RETRIES` = 10 (`driver.py:216`), so the 11th consecutive denial raises `UnexpectedModelBehavior` — and `run_investigation` catches only `UsageLimitExceeded` and `RunAborted` (`driver.py:550-558`, "Let any other error stay loud"), so it escapes past `observe.write_trace` and `logger.close()`. **The run dies without writing its trace** — precisely the "hard stop mid-investigation loses the artifacts" outcome this issue argues against, reached through the mechanism chosen to avoid it. Withdrawal removes the retry loop entirely: there is nothing to retry against.

  **`before_tool_execute` stays as a backstop**, denying via `ModelRetry` if a withdrawn tool is somehow called (a stale tool call from a request prepared before the trip). C1 shows that denial bypasses `after_tool_execute`, so `driver.py:121`'s `except Exception` guard — the issue's first gotcha — cannot swallow it. **The guard needs no change.** The backstop is one-shot per tool by construction: after the trip the tool is no longer offered, so consecutive denials of the same tool cannot accumulate toward the retry ceiling.

  **The tiers, over the real census (C4).** MAIN holds `bash`/`read_file`/`write_file`/`edit_file` plus the layered `gather`; GATHER holds `bash`/`read_file`/`template_search`/`query`. **Every GATHER tool is `core`, including `read_file`** — GATHER has no write tool, so a read-only tail buys it no artifact while spending the shared pool and extending the wall clock. GATHER stops at N; the tail is MAIN's alone. This closes the pool-drain hole: `tools_gather.py:523` instructs the model to dispatch sibling leads in parallel, so a `tail`-tiered `read_file` in GATHER would let N concurrent subagents consume the 10-call window before MAIN reaches its report.

  The tier table is what bounds the tail in **cost**, not just in count. A tool-agnostic threshold would let the last 10 calls each be a `gather` dispatch — a nested agent with its own 40-request loop — bounded in length, unbounded in spend. Restricting the tail to MAIN's file I/O makes it cheap by construction.

- **M1b — the deny/withdrawal message is part of the design, not the implementation.** `check_budgets` warnings go to `print(..., file=sys.stderr)` (`driver.py:119-120`) and never enter the message history, so **the model never sees them**. "Warn, then degrade" describes an operator tailing stderr, not the only party that can actually degrade. The model's sole notice is the backstop `ModelRetry` text and the shrinking toolset, so the text is load-bearing and specified here: it must say the withdrawal is **permanent**, name what remains available, and instruct the model to write its report now. A message that reads like a transient failure invites exactly the retry storm M1 exists to prevent.

- **M2 — gate on an `AgentDefinition` bit, not on `role`** (discharges N3). `tools.py:145-150` states the convention outright: *"Per-agent gate policy is DATA, not a role branch: the gate keys on `deps.policy` … `role` remains only as an identity label."* A role branch in the shared factory would also fail **open** — every future agent silently defaults to unenforced. A declared bit makes budget posture something a new agent must state. Accounting stays unconditional; withdrawal and kill read the bit.
- **M3 — caps: wall clock ~20 min (O4), `N = 200`, spawns enforced.** All three now have a deny arm in M1's rule — `max_subagent_spawns` was previously described as "a third independent trip" while nothing read it.

  **`N = 200` is a deliberate hold, not a measurement (supersedes C6's deferral).** It is today's `max_tool_calls`, kept unchanged. Two reasons. First, C6 could not justify *any* number from six spawn-free runs, and inventing one would be worse than keeping the incumbent. Second, holding N fixed means switching enforcement on changes **only the posture, not the threshold** — so any behavior difference observed is attributable to enforcement rather than to a retuned cap, which is what makes the CI/eval rollout (M9 + M12) readable as an experiment.

  **Consequence, stated plainly: at `N = 200` the tool-call cap does not bind in production.** C6's runs land at 10-26 calls. The caps that will actually trip are the wall clock (20 min) and spawns (40) — in that likely order. The tool-call limb is a backstop against a runaway loop, not the control bounding spend; nobody should read `N = 200` as the latter. Refining it needs the gather-era data C6 still lacks, and is expected.
- **M4 — the tail carries a wall clock** (discharges O5). The call-count tail alone does not bound duration: C2 shows the retry counter is **per-tool and resets on any success**, and C1 makes backstop denials free, so the `N → N+10` band can be walked arbitrarily slowly, bounded only by the remaining `DEFAULT_REQUEST_LIMIT = 60` — each a full-context model round-trip. So the tail ends at `tool_calls >= N + 10` **or** `elapsed > wall_clock_timeout + grace_seconds`. Checkable at the same seam: `started_at` and `tool_calls` live in one `budget.json` object (`budget_enforcer.py:36-42`) and `check_budgets` already computes `elapsed` from that field. **Caveat:** `started_at` is `setdefault`-backfilled (`budget_enforcer.py:50`), so a recreated `budget.json` silently restarts the clock. Today that costs a warning; under M4 it costs the enforcement — the backfill must not mask a missing timestamp on a path that now denies.
- **M5 — tail exhausted ⇒ kill the run, through a caught exception.** The idiom exists: `RunAborted` (`circuit_breaker.py:89-99`) is raised from a hook and caught at `driver.py:553`, which writes the partial trace exactly like the request-limit path. The budget kill takes the same shape and **must be added to that catch** — a new exception type not on it lands back in the uncaught-crash failure M1 describes. It must also stay off `query_tool.CONTROL_FLOW_EXCEPTIONS` handling (`query_tool.py:79-86`) and out of `_run_gather`'s widened handler (M7), or it gets recorded as a query fault instead of killing the run. Whatever is on disk survives; C5 is the honest limit on how much that is worth.
- **M6 — the stated bound**, two quantities that must not be conflated. *Detection latency*: the caps are checked at a tool-call boundary and the longest executing call is bash at `_BASH_TIMEOUT_S = 120` (C8), so a trip is observed within **cap + 2 min**. *Tail*: M4's grace clock, bounded independently. Total ≈ **22 min + grace** — with `grace_seconds = 120` (proposed, matching `_BASH_TIMEOUT_S`'s order of magnitude and ample for ~10 file-I/O calls plus their model round-trips), a stated worst case of **~24 min**. O4's "~20 min" therefore means "withdrawal at 20 min, observed within 22, killed at 20 + grace" — not "the run ends at 20 minutes."
- **M7 — GATHER stops clean rather than aborting the run** (discharges O2's scoping). `_run_gather` catches only `UsageLimitExceeded` (`tools_gather.py:485`); an `UnexpectedModelBehavior` from the nested `gagent.run` propagates out of the `gather` tool body and kills the run with no report. Withdrawal (M1) makes this far less reachable, but the handler is still the right belt-and-braces: catch it alongside `UsageLimitExceeded` and convert to the same measurement-shaped string, so MAIN reads an incomplete lead and reasons on.
- **M8 — one whole-run budget pool** (discharges O3). Already true — `budget.json` is keyed by run dir and `_make_hooks` binds it for MAIN and GATHER alike (`driver.py:107-110`). Recorded, not built. Consequence pre-trip: an expensive lead spends MAIN's budget. Post-trip the pool is no longer shared for the tail, because M1 tiers every GATHER tool as `core`.
- **M9 — `DEFENDER_BUDGET_ENFORCE`, off for interactive dev, on in CI/eval** (discharges O6 jointly with M12). `env_bool` is the existing mechanism (`driver.py:351`, `DEFENDER_COMPACTION`).
- **M10 — docstring + threat-model class 7 rewritten to match** (discharges O7). Three edits, not one: class 7's body (`threat-model.md:179-187`), **the open question at `:222-223`** ("Flip to blocking, or accept accounting and say so here?") which this design closes, and `DEFAULT_LIMITS`' inline comment (`budget_enforcer.py:31`), which still reads `30 min` against O4's 20. Note the #631 cleanup commit already rewrote class 7's body and added a docstring line — *"The sole consumer is `runtime/driver.py`'s `after_tool_execute` hook"* — which M1 invalidates by adding `prepare_tools` and `before_tool_execute` consumers. That sentence is part of this edit.
- **M11 — pin the capability ordering** (discharges O1's integrity flank). `_make_hooks` is prepended ahead of `QueryCapture` (`driver.py:205-209`), so a backstop deny on `query` raises before `QueryCapture.wrap_tool_execute` (`query_tool.py:275`) — no queries-table row for a call that never ran. Without this the enforcement mechanism corrupts the queries table, which is why it belongs to O1 rather than floating free.
- **M12 — an e2e test that actually crosses the cap** (discharges O6). Flipping the flag in CI exercises nothing while runs land at 10-26 calls against a cap of 200. The hermetic replay suite drives a run with injected low limits through the `limits` parameter `check_budgets` already takes (N1's carve-out), and asserts the observable outcome: expensive tools withdrawn, report still written, trace on disk. This is what makes the issue's "observed, not asserted" real; without it, M9 ships a branch no test has executed.

*Background:* `bash` already carries `_BASH_TIMEOUT_S = 120` (C8), inside the 2–3 min range discussed, so the per-call-timeout thread resolves to N4 + N5 and no new mechanism.

### Security dive — fires

Asset touched: the run's compute/spend budget, and the run's artifacts. Enumerated from assets, as negative universals:

- **S1.** No run may consume unbounded tool calls, subagent spawns, or wall clock when enforcement is on. Discharged by M1+M3+M4+M5 — withdrawal plus a positive control (kill), not a guard alone. All three limbs have a deny arm in M1's rule; an earlier revision enforced only `tool_calls` while claiming the spawn cap was "a third independent trip." Discharge means a path census, and M1's tier function is total by construction rather than a lookup over the census, so the discharge does not lapse when a tool is added.
- **S2.** No trip may leave MAIN's artifacts unwritten. **Discharged only partly, and less than first drafted.** C5 came back *refuted*: `investigation.md` is written by model tool calls under a SKILL.md instruction, not by an enforced mechanism, and the one real non-test run-dir set on this box has no `investigation.md` at all. Under this issue's own axiom (model is attacker-controlled) a hostile model can simply not write, and M5 then kills a run with nothing in it. **Accepted residual:** the budget's job is bounding spend, and "attacker declines to produce a report" is not a resource-exhaustion failure. Recorded so it is not mistaken for a covered case.
- **S3.** Enforcement must not be disableable by the model. The flag is an env var read in-process; MAIN's bash lane is `shell=False` with no env-mutating grant, and writes are clamped to `run_dir` (`_main_write_shape`, `driver.py:260-264`). Probed as reachability — C7, `unrefuted`, which is that kind's ceiling.

### Scale dive — fires weakly, and the earlier reason for skipping it was false

An earlier revision declined this dive on the grounds that the check rides "an already-existing locked read-modify-write." That is wrong: the existing read-modify-write is in `after_tool_execute` (`driver.py:113-123`). M1's seams — `prepare_tools` and `before_tool_execute` — do **no** I/O today, so enforcement adds a new `budget.json` read per model request and per tool call, contended by concurrent gathers under the same `flock`.

Typed claim: the added cost is one `flock`-guarded read of a small JSON file per request, against a path that already performs one such read-modify-write per tool call and spends seconds in model round-trips. Expected to be negligible, but that is a claim about a **new** cost, not the absence of one. No benchmark run — deferred honestly rather than asserted. If `prepare_tools` fires per request rather than per tool call, cache the read within a request.

```yaml
claims:
  - id: C1
    kind: behavior
    claim: A ModelRetry raised in before_tool_execute skips after_tool_execute, so the driver's `except Exception` budget guard cannot swallow the denial — and denied calls are invisible to the counter that lives there.
    probe: probe_retry.py — deny-then-succeed against FunctionModel, recording which calls reached the after_tool_execute hook.
    probe_kind: executed
    observed: "B1 deny-then-succeed: COMPLETED, after_tool_execute fired for ['work','work'] — the 2 successful calls, never the denied one."
    verdict: holds
  - id: C2
    kind: behavior
    claim: pydantic-ai resets a tool's retry counter on success, and the counter is per-tool — so a retry budget bounds only *consecutive* denials of the *same* tool.
    probe: same script — deny,ok,deny,ok at max_retries=1.
    probe_kind: executed
    observed: "COMPLETED. Two non-consecutive denials survive a limit of 1, so the counter reset on the intervening success. Abort message in C3 names a single tool, so the counter is per-tool."
    verdict: holds
  - id: C3
    kind: behavior
    claim: Consecutive denials past max_retries abort with UnexpectedModelBehavior.
    probe: same script — deny,deny at max_retries=1 (control for C2).
    probe_kind: executed
    observed: "ABORTED UnexpectedModelBehavior: Tool 'work' exceeded max retries count of 1."
    verdict: holds
  - id: C4
    kind: census
    claim: The in-scope agents' full registered-tool sets are exactly those in M1's table, and forward_check is not among them.
    probe: read every ToolSet(...) declaration and the register_tools dispatch.
    probe_kind: search
    observed: "MAIN ToolSet(read,bash,write) driver.py:276 + layered gather; GATHER ToolSet(read,bash,template_search,query) driver.py:296. forward_check/lesson_read appear ONLY on CORPUS_AUTHOR (curator_engine.py:276), asserted at test_forward_check_tool.py:1269. Registration dispatch at tools.py:473-571."
    verdict: holds
  - id: C5
    kind: census
    claim: investigation.md is written incrementally during the run, so a kill at grace exhaustion preserves partial artifacts.
    probe: read SKILL.md's instruction, then enumerated the real non-test run dirs for the artifact.
    probe_kind: search
    observed: "SKILL.md:374 instructs 'grows append-only' — an instruction to the model, not an enforced property. The only real non-test run-dir set on this box (experiments/gather-verifiable-code-289/runs/*) contains summary.md and gather_summary.md but NO investigation.md at all. That is counter-evidence, not absent evidence. Re-typed from `behavior` to `census`: the probe that settled it enumerated run dirs, which is what this claim actually rests on."
    verdict: refuted
  - id: C6
    kind: census
    claim: Observed tool-call counts justify a specific cap.
    probe: read every non-test budget.json on the box.
    probe_kind: search
    observed: "n=6, all from experiments/gather-verifiable-code-289 (2026-06-16). tool_calls 10-26 against a cap of 200. But subagent_spawns=0 in ALL SIX — none exercised the gather path, the expensive one. Sample cannot support a number."
    verdict: deferred
  - id: C7
    kind: reachability
    claim: The model cannot disable enforcement at runtime by setting DEFENDER_BUDGET_ENFORCE.
    probe: read the flag's read site against the model's available grants; not adversarially executed.
    probe_kind: read
    observed: "env_bool reads os.environ in-process (_env.py:56-70). MAIN's bash lane is shell=False with no env-mutating grant; writes clamp to run_dir (driver.py:260-264). Probe-kind is below what this claim's kind wants — recorded rather than rounded up."
    verdict: unrefuted
  - id: C8
    kind: referential
    claim: bash already carries a per-call timeout in the 2-3 min range, and it sets the detection bound in M6.
    probe: read tools.py.
    probe_kind: read
    observed: "_BASH_TIMEOUT_S = 120 at tools.py:44, applied at :289, raising ModelRetry on expiry at :292."
    verdict: holds
  - id: C9
    kind: referential
    claim: An outer wall-clock timeout on query was deliberately removed and must not be reinstated as a wrapper.
    probe: read query_tool.py.
    probe_kind: read
    observed: "query_tool.py:439-445 — asyncio.wait_for cancels the await, not the thread, so a hung verb leaks a thread and synthesizes an exit-124 row reporting a kill that never happened. 'The transport's own inner timeout is the real one, and it is mandatory.'"
    verdict: holds
  - id: C10
    kind: referential
    claim: wrap_tool_execute is the seam for pre-execute denial.
    probe: introspected the Hooks registration surface; read query_tool.py's usage.
    probe_kind: executed
    observed: "REFUTED AS STATED, and the first correction was itself imprecise. `hooks.on` exposes no attribute NAMED wrap_tool_execute — but the wrap-style seam DOES exist on the registry, registered as `tool_execute`; AbstractCapability's method of that name (query_tool.py:275) is the capability-side form. So it is the name that was wrong, not the seam's existence. The conclusion stands: before_tool_execute ('may only return args or raise', query_tool.py:287) suffices for the backstop deny, and prepare_tools is the seam M1 actually turns on."
    verdict: refuted
  - id: C11
    kind: behavior
    claim: An UnexpectedModelBehavior raised inside a gather subagent propagates out of the gather tool body and kills the run.
    probe: read _run_gather's exception handling against C3's verified abort type.
    probe_kind: read
    observed: "tools_gather.py:485 catches UsageLimitExceeded ONLY, converting it to a measurement-shaped string. UnexpectedModelBehavior — C3's verified outcome for consecutive denials — has no handler on that path. Not executed end-to-end; typed honestly as read. NOTE: the same unexecuted reasoning applied one level up on MAIN, where run_investigation catches only UsageLimitExceeded and RunAborted (driver.py:550-558); executing this probe would likely have surfaced that crash before a reviewer did. It remains the cheapest un-executed claim here — probe_retry.py already builds a FunctionModel agent with a before_tool_execute deny, and nesting one inside a tool body would settle it."
    verdict: unrefuted
  - id: C12
    kind: referential
    claim: The shared hook factory installs on the learning-loop agents, so an ungated deny would extend enforcement to them.
    probe: traced build_agent_core's callers.
    probe_kind: search
    observed: "_make_hooks is the only hook factory (driver.py:107), installed at driver.py:205; build_agent_core is called from _pydantic_stage.py:67 (every learning stage) plus driver.py:326/464. Those stages carry their own bounds at _pydantic_stage.py:77-81."
    verdict: holds
  - id: C14
    kind: behavior
    claim: Consecutive denials on MAIN raise UnexpectedModelBehavior past the run's exception handling, losing the trace — the failure M1's withdrawal design exists to avoid.
    probe: read run_investigation's handlers against C3's verified abort type and MAIN's configured retry ceiling.
    probe_kind: read
    observed: "MAIN is built with retries=DEFAULT_TOOL_RETRIES=10 (driver.py:216, :76), so the 11th consecutive denial of one tool raises UnexpectedModelBehavior (C3, executed). run_investigation catches ONLY UsageLimitExceeded and RunAborted (driver.py:550-558) with the comment 'Let any other error stay loud', so it escapes past observe.write_trace (:560) and logger.close() (:561). Handler set read directly; the end-to-end raise was not driven — typed as read, not executed."
    verdict: unrefuted
  - id: C13
    kind: census
    claim: The claude -p enforcement path is retired, so there is one enforcement path rather than two.
    probe: searched every settings.json for hook wiring; traced all references to the module.
    probe_kind: search
    observed: "No PostToolUse/PreToolUse wiring in any settings.json. defender/CLAUDE.md:17-24 states the legacy claude -p runtime and its run-settings.json wiring were retired and the hooks/ modules are 'imported as plain libraries, not wired as hooks'. The only non-test reference to budget_enforcer is driver.py:49, importing DEFAULT_LIMITS/check_budgets/update_budget_locked. Its main() was reachable only from its own test. Precedent: spec_graph_647.yaml:314 records tag_tool_results_main as already 'DELETED (never wired)'. The dead entrypoint has since been removed; defender suite green at 2141 passed / 11 skipped."
    verdict: holds
```

**What review and probes changed.** A cold review of the first draft returned eight findings; all were reconciled. The material ones: the deny list was a partition of MAIN's tools, not of the tool census — corrected in M1 and pinned by C4. Enforcement would have silently reached eight agents including transactional curators — scoped out in N3/M2 on C12. A trip inside `gather` hard-aborted the run with no report, the opposite of the chosen posture — M7, on C11. C5 was mis-typed and mis-verdicted; it is now `refuted`, and S2 states the residual it leaves. Earlier, C10 refuted the seam originally named, and C1 reversed the grace-counting decision — denials cannot count, because they never reach the counter.

**Revised after a second cold review.** The first posted revision would have shipped the failure it was written to prevent: it denied expensive tools via `ModelRetry`, and because a budget deny is permanent, a model re-issuing `gather` would hit MAIN's 10-retry ceiling and raise `UnexpectedModelBehavior` past `run_investigation`'s handlers — killing the run without writing its trace (C14). M1 is now built on `prepare_tools` **withdrawal**, with the deny kept only as a backstop. Also corrected: the spawn cap had no deny arm while M3 claimed it was "a third independent trip"; GATHER's `read_file` sat in the tail tier, letting parallel subagents drain the window MAIN needs for its report; the tier table had no default arm, so a newly added tool would fall through to an uncaught `KeyError` in a hook; M2 gated on `role` against `tools.py:145-150`'s stated data-not-role-branch convention; the scale dive declined on a false premise (the new seams do no I/O today, so enforcement adds a read rather than riding an existing one); and O6 was undischargeable, since flipping the flag in CI executes no deny branch while runs land at 10-26 calls against a cap of 200 — now M12, using the `limits` parameter as N1's explicit test-seam carve-out.

**Retracted since first posting.** An earlier revision carried an *M10 — both existing paths flip together*, on the premise that the `claude -p` hook was a live second enforcement path. C13 refutes that: it is retired, and its entrypoint is now deleted. The design has one path.

**Constants — settled.** `N = 200` (M3, a deliberate hold at the incumbent value, not a measurement) and `grace_seconds = 120` (M6). Neither is blocked on the gather-era runs C6 wanted: M12's harness injects its own limits, so the enforcement path is exercised without the production number being right. Refining `N` on real data is expected follow-up, and the design is written so that refinement is a one-line change to `DEFAULT_LIMITS` rather than a re-derivation.

**Ready for implementation.** No open constants and no unreconciled review findings. The one claim worth executing before or during implementation is C11 — the cheapest remaining probe, and the same failure mode as C14, which a reviewer found rather than a probe.

