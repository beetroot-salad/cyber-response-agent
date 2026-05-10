# Validation v2 summary — predict-haiku-story-shapeM

After iteration 1 fixes: no-fence rule + divergence-axis taxonomy on proposed-B. N=1 per arm, same fixture. Wall-clock: current 128s, proposed-A 94s, proposed-B 89s.

## Per-arm reads

### current (sonnet + env context)

- 4 sentences each. Mutually exclusive on **three axes**: signing distribution (uniform CA vs heterogeneous), name-pattern stability (structured step-suffix vs non-templated), and cadence baseline (90-day established for h-001, no prior episodes for h-002).
- Names env-anchored facts: `LegalSupport-EvLoader-Users` AD group, `90-day established baseline`, `80–250 children / 10–50 distinct images` count range.
- No fence violation. Strong reference output, slightly tighter than v1.

### proposed-A (haiku + env context)

- 3 sentences each. **No fence violation** (fence rule worked).
- **Regression on discriminator naming.** v1's proposed-A named `Acme Legal Software CA` and signing distribution as the diagnostic axis. v2's proposed-A does NOT name signing distribution at all. Stories diverge softly on "structured naming conventions used by batch-processing tools" (h-001) vs "iterative payload generation where each spawned process receives a distinct identifier" (h-002) — both about naming, neither cites the signing axis the env-quirk doc explicitly flagged as the load-bearing discriminator.
- Hypothesis names are still reasonable (`?office-addin-batch-processor` vs `?macro-payload-generator`), parent_class differs on each, but the load-bearing observable from env context didn't make it into the story prose.
- **Implication: arm A's first-run quality was lucky.** With env context, Haiku sometimes grounds the discriminator and sometimes doesn't. Single-trial signal is insufficient to characterize this.

### proposed-B (haiku + no env + relative descriptions + divergence-axis taxonomy)

- 3 sentences each. No fence violation.
- **Mutual exclusivity is improved over v1's proposed-B but still inadequate.** v1's two hypotheses were both about iteration loops with `parent_class: office-application-host`. v2's two hypotheses are distinguishable mechanism classes (`?payload-staging-dropper` vs `?batch-document-auxiliary-processing`) — but BOTH still carry `parent_class: office-application-host`, and neither story names a divergence axis from the canonical taxonomy.
- The 6-axis instruction ("pick from signing distribution / name-pattern stability / cadence / lineage shape / content entropy / distinct-artifact breadth, name the value under each mechanism") was not followed. h-001 mentions entropy and "unique or obfuscated" naming; h-002 doesn't name an opposing axis value.
- **The relative-description approach is not landing.** Two different prompt formulations have produced two different failure modes (v1: same mechanism class; v2: different classes but no axis grounding). No evidence the prompt iteration is converging.

## Headline

The two iterations together change the picture:

1. **Arm A is the only viable Haiku candidate, but its variance on the load-bearing discriminator is the open question.** v1 named signing distribution; v2 didn't. 1 vs 1 across two single-trial runs is uninformative — we need 3–5 more trials of arm A on this fixture to see whether grounding the discriminator is reliable or coin-flippy.

2. **Arm B is probably dead in this form.** Two prompt iterations, two failures with different shapes. Telling Haiku to "stay at mechanism-class abstraction AND fork on a named axis from this list" doesn't produce arm-A-quality stories. There may be a more directive shape (e.g., a structured "axis: <chosen>; opposing-values: A=<...>, B=<...>" preamble before the story) but that's a substantive redesign rather than another nudge.

3. **Env-context fetching is the right next workstream IF arm A holds up.** Per the earlier note, extending CONTEXTUALIZE to surface alert-relevant env context as a structured `environment_context:` field in the prologue is the cleanest path — PREDICT reads it from the investigation tag, no new tool calls.

## Recommended next move

Run 5 more trials of **proposed-A only** on the same fixture. Score each on:
- Does the story name a load-bearing observable axis from the env-quirk doc (signing distribution / name-pattern stability / cadence baseline / count-range membership)?
- Are the two stories mutually exclusive on at least one such axis?
- Is the env-anchored grounding (CA name / AD group / baseline range) present or absent?

If ≥4/5 pass, arm A is reliable enough to act on — start the env-context-fetching workstream.
If ≤2/5 pass, arm A is too variable — story authoring stays on Sonnet.
3/5 → run 5 more.

This is cheap (~8 min wall-clock for 5 trials) and answers the only remaining question that matters for the disposition of this experiment.

Skip further iteration on arm B until and unless we want to revisit the structured-axis-preamble redesign.
