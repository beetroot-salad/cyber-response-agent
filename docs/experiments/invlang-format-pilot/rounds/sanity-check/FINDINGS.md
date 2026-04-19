# Sanity Check — Findings

## Pipeline status

- **`render_prior.py`**: works. All 12 Case 1 + Case 2 × depth × arm
  combinations render without error. See `README.md` in this directory.
- **`run_arm.py`**: authored but blocked on `claude -p` authentication
  — CLI is not logged in and `ANTHROPIC_API_KEY` is unset. The
  subprocess path is correct (composes system prompt, stages a temp
  run_dir, invokes the model) — just needs an auth step before batch
  runs.
- **In-session subagent invocation**: succeeded. Ran Case 1 shallow ×
  Arm A through a general-purpose Agent subagent loaded with the
  hypothesize subagent's instructions. Output saved as
  `output-case1-shallow-A.md`.

## Substantive finding — gold labels need revision

At the shallow cut (CONTEXTUALIZE only), the subagent emitted a
**`gather:` block, not a `hypothesize:` block**. This is contract-
compliant per `/workspace/soc-agent/agents/hypothesize.md`:

> No HYPOTHESIZE without a fork. Enter only when ≥ 2 competing
> classifications have predictions that diverge on already-observable
> fields. If the discriminating data is not yet known, emit a GATHER
> block with lead-level predictions.

The subagent's reasoning: at CONTEXTUALIZE, the only observables are
the alert fields (which are compatible with every playbook
hypothesis); the discriminating data (attempt cadence, follow-up
success, username diversity) is not yet in hand. So it routed to
GATHER-with-lead-level-predictions rather than commit to a hypothesis
frontier.

**Implication for the case-yaml gold schema.** The current gold block
assumes the subagent emits HYPOTHESIZE and lists `expected_hypothesis_set`
as the primary assertion. But at shallow cuts, the subagent can
legitimately skip HYPOTHESIZE and emit GATHER directly. We need to:

1. Allow the gold block to be **EITHER** a HYPOTHESIZE shape (expected
   hypothesis set + selected lead + assessment) **OR** a GATHER shape
   (lead-level predictions + selected lead + no hypothesis assertion).
2. For cuts where the subagent is *likely* to route to GATHER (e.g.,
   CONTEXTUALIZE with no archetype-scan fork), prefer the GATHER gold
   shape — and score "did the subagent correctly skip HYPOTHESIZE" as
   a methodology signal.
3. For cuts where a fork IS observable (e.g., ANALYZE_L1 with loop-1
   evidence), expect HYPOTHESIZE.

This actually *strengthens* the experiment — routing behavior (when
to HYPOTHESIZE vs GATHER) is itself a methodology decision the two
format arms may handle differently.

## Output quality (one-trial observation)

The selected lead (`authentication-history`) matches the gold
next-lead-set in case.yaml. The lead-level predictions are
well-formed: three outcomes each mapped to a `read_as` tag and an
`advance_to` target, covering the forward-success axis (compromise)
and the cadence-shape axis (benign vs noisy). Pitfalls are concrete
and non-generic.

The subagent used 6 tool calls and 46,349 total tokens for one trial.
At that rate, ~162 trials would burn ~7.5M tokens — tractable but not
trivial. Arm A trials may run cheaper than Arm B since the prior is
already structured; worth measuring once we're running at scale.

## Next actions

1. Revise `case.yaml` gold schema to support both HYPOTHESIZE and
   GATHER outcomes (Case 1 + Case 2 to be updated).
2. Rework Case 7 (see `cases/case-rule550-ssh-persistence/REWORK_NEEDED.md`).
3. Solve `run_arm.py` auth — either log in the CLI once or set
   `ANTHROPIC_API_KEY`. Once solved, batch-run the remaining 11 Case 1
   + Case 2 combinations and compare Arm A vs Arm B outputs manually
   before writing the scorer.
