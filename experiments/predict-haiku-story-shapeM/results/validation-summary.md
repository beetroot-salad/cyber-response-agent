# Validation summary — predict-haiku-story-shapeM

N=1 per arm on `shapeM-winword-burst-quirky`. Wall-clock: current 171s, proposed-A 102s, proposed-B 89s.

## Per-arm reads

### current (sonnet + env context) — reference

- Shape M; 2 hypotheses; 4 sentences each; mutually exclusive on **signing distribution** and **name pattern stability** (the two roles where the env-quirk doc says EvidenceLoader and macro-droppers diverge).
- Both stories name the load-bearing discriminator explicitly (`Acme Legal Software CA` uniform signing for h-001; "absent or heterogeneous code-signing with no recurring enterprise CA" for h-002).
- No output-spec violations. No fences.
- Candidate naming: uses `EvidenceLoader`, `ksilva`, `Acme Legal Software CA` — env-context-allowed and load-bearing.

### proposed-A (haiku + env context)

- Shape M; 2 hypotheses; 3 sentences each; mutually exclusive on the same two roles as current (signing + naming pattern).
- Substantively close to current — slightly less concrete refutation framing on h-002 ("typically lack a structured naming convention and are unsigned or self-signed") but the discriminator is still named.
- **Output-spec violation**: wraps the entire envelope in a ` ``` ` fence. Harness says "no prose framing, no fences." Parser would reject.

### proposed-B (haiku + no env + relative descriptions)

- Shape M; 2 hypotheses; 3 sentences each. **No fences are not the only structural issue here — the substantive issue is mutual-exclusivity collapse.**
- Both hypotheses share `parent_class: office-application-host` and the stories describe near-identical mechanisms: h-001 is a "macro-iterating-child-spawner" and h-002 is a "batch-automation-child-spawner". Both spawn one child per enumerated item from the same parent class.
- Neither story names a load-bearing discriminating observable. The closest thing in h-001 is "moderate naming entropy (3.12) consistent with deterministic macro-driven construction" — but that's a general property, not a divergence axis. h-002 mentions "the 38 distinct child images and 142 total child count reflect the combination of batch size and pipeline-stage diversity" — also descriptive, not divergent.
- **The two arms-A discriminators (signing distribution + name-pattern stability) are absent.** Haiku without env context did not invent the right divergence axes — it stayed at mechanism-class abstraction so faithfully that it lost the fork.
- **Output-spec violation**: ` ``` ` fences, same as A.

## Verdict on validation

The experiment is well-formed. The N=1 signal is strong enough to act on:

1. **Both Haiku arms violate the no-fence output spec.** Trivial prompt fix ("Do not wrap your output in code fences. Emit dense blocks at the top level of stdout.") needed before any scale-up.

2. **Arm proposed-A is plausibly competitive with current.** The trim is sufficient and Haiku follows it; with env context, it finds the right discriminators. Worth scaling up.

3. **Arm proposed-B as currently written fails the mutual-exclusivity criterion.** "Stay at mechanism-class abstraction" without naming a *divergence-axis taxonomy* makes Haiku write two stories about the same mechanism. The relative-description block needs to actively prompt for a divergence axis (e.g., "name one observable axis on which the two stories diverge: cadence, naming pattern, signing distribution, lineage shape, content entropy, or a similar role-named property"). Without that nudge, Haiku has nothing to fork on.

## Recommended next moves (in order of cheapness)

1. **Fix the fence violation** in the harness: add an explicit "Do not wrap output in code fences" line to the §Output format section. Re-run all three arms (validation only).
2. **Iterate proposed-B's relative-description block** to enumerate divergence-axis candidates. Re-run only proposed-B against the same fixture; compare against the current proposed-B output.
3. Only after (1) and (2): consider scale-up to N=10.

Stopping here per "minimal A/B for repro" — do not auto-launch scale-up. Per-arm outputs are at `runs/validation/<arm>/trial-1/stdout.txt`.
