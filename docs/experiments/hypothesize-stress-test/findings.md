# Hypothesize stress test — findings

Synthetic stress test of `agents/hypothesize.md` with the updated prompt
(narrative-vs-lean framing, `?compromise-followup` anti-pattern, schema
extension to `subject`/`refutes_predictions`, and the new
baseline-anchoring bullet in §Causal story).

## Setup

Three fixtures injecting a synthetic CONTEXTUALIZE into an otherwise
empty `investigation.md`:

| Fixture | Signature | Designed to stress |
|---|---|---|
| 1 — legitimacy-axis | rule-5710 | FM1 (legitimacy-in-classification) + FM2 (parallel sanctioned/unsanctioned pair) + baseline anchoring on 2 prior benign repeats |
| 2 — compound-pressure | rule-100001 | FM3 (compound predictions packing ancestry + timing + tty) |
| 3 — subsequent-event | rule-5710 | FM4 (`?compromise-followup` peer hypothesis) |

Runner at `run.py` — invokes the hypothesize subagent once per fixture
via the shared `_subagent.invoke_subagent` wrapper (same pipeline as
the handler's production call). Outputs under `outputs/run-{fixture}/`.

## Results

### Fixture 1 (legitimacy-axis) — PASSED

Subagent chose **no-fork mode** and emitted a `gather:` block with
lead-level predictions on `source-classification`. Did not emit any
`?authorized-*` / `?compromised-*` / `?legitimate-*` hypotheses.

**Baseline-anchoring signal:** explicitly referenced the 2 prior
rule-5710 closures from ticket-context in the reasoning prose ("2 prior
rule-5710 events from 10.1.2.3, T-43min and T-23min, both closed as
benign-monitoring-probe"), and a pitfall bullet warned against using
prior disposition as a classification substitute:
> "this creates recency bias toward `internal-monitoring-host`. Do
> not treat prior disposition as a classification substitute; confirm
> the registry entry independently…"

This is exactly the discipline the baseline bullet intends.

### Fixture 2 (compound-pressure) — TIMEOUT

Subagent timed out at 300s with no output and no checkpoint written.
No signal on whether the new schema discipline would land on
rule-100001; fixture cannot be scored.

**Probable cause:** rule-100001's context + playbook are heavier than
rule-5710's, and the subagent's batched-read step may have hit the
internal turn cap before producing output. Same silent-termination
shape observed in `gather` / `gather-composite` per their own
`agents/*.md` — the handler's checkpoint-resume path is designed to
catch this, but this stress test bypasses the handler.

**Follow-up:** re-run fixture 2 with an explicit `SOC_AGENT_HYPOTHESIZE_TIMEOUT_SECONDS=600`
override, or add the handler's retry wrapper to `run.py`.

### Fixture 3 (subsequent-event) — PASSED

Subagent chose **no-fork mode**, emitted a 3-lead `gather:` block, and
explicitly articulated the anti-pattern it was avoiding:

> "The forward-success signal (5501/5715 within 60s) is a mandatory
> attribute check in `authentication-history`, not a separate
> hypothesis. If lp1 on l-002 fires, route immediately to CONCLUDE —
> do not create a `?compromise-followup` or `?post-failure-success`
> hypothesis as a mechanism peer; that is a downstream-observation
> trap, not an upstream-mechanism discrimination."

The 5501-in-60s check landed where the updated prompt says it belongs:
as `lp1` inside the `authentication-history` lead, not as a peer
hypothesis. This is the canonical FM4 trap, cleanly avoided with
vocabulary from §Discipline.

## Cross-cutting observations

1. **Both successful runs chose no-fork at loop 1.** Neither fixture
   produced a `hypothesize:` block, so the new schema fields
   (`subject` on predictions, `refutes_predictions` on refutation
   shape) were not exercised in observed output. This is actually
   consistent with the "No HYPOTHESIZE without a fork" discipline:
   starter leads are attribute-enrichment, and classifications cannot
   be discriminated without their outputs. To stress the new schema
   itself, need a fixture where loop-1 *has* a fork — either a loop-2
   fixture (prior lead already ran, now refining), or a playbook like
   rule-100001 where container-internal vs runtime-exec is genuinely
   observable from the ancestry alone.

2. **`subject` and `refutes_predictions` are untested against the
   subagent.** Implied-correct via fixture 1/3 reasoning but the
   schema edit needs at least one fork-mode run before we can confirm
   the subagent adheres to the new fields.

3. **Permissions note.** Both successful runs reported checkpoint
   write failures ("blocked by a permissions gate in this session
   context"). The stress-test runner spawns subagents outside the
   plugin-gated path that sets the write permission; this is a
   test-harness artifact, not a production concern — the handler's
   invocation goes through the plugin path where `permissions.yaml`
   grants the write. Noting so nobody chases it as a real bug.

4. **Baseline anchoring is drawing signal.** Fixture 1's output shows
   the subagent actively using prior-repeat context in its reasoning
   and flagging the bias risk explicitly. This is the minimal signal
   we hoped for from the §Causal story addition. Worth landing.

## Decisions

- **Keep the baseline-anchoring addition in `agents/hypothesize.md`.**
  Signal from fixture 1 is positive; no observed regression.
- **`?compromise-followup` discipline is internalized.** Fixture 3's
  explicit vocabulary match is strong evidence the §Discipline insert
  lands.
- **Schema-extension adherence remains unverified.** Add a loop-2
  continuation fixture (prior GATHER resolved, now refining into
  sub-mechanisms) before the handler hits live /testrun. Filing as a
  post-cutover validation step.
- **Fixture 2 timeout warrants a retry pass with a longer timeout or
  handler-wrapper runner.** Filing as a minor follow-up; does not
  block the current handler cutover since production invocation runs
  through the handler's retry path, not the bare subagent.

## Artifacts

- `fixture-*/alert.json`, `fixture-*/investigation.md`,
  `fixture-*/expected.md` — the fixtures and scoring rubrics
- `outputs/run-fixture-*/subagent_output.md` — raw subagent responses
- `run.py` — runner script
