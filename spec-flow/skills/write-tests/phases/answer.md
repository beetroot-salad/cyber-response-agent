# Phase C — answer the premises (step 4)

## Topology

Sequence; the premise is a question, the assertion is its answer, and the spread of independent answers *is* the ambiguity measurement.

- **(a) Synthesis leaf** (Sonnet, low effort): inputs = the five `30-premises-*.md` frontiers. Outputs: `40-premise-file.py` (a real Python file — the shuffle CLI consumes it) plus the sidecar frontier `40-premises.md` carrying the frontmatter and digest.
- **(b) Shuffle — spine-run CLI, never an agent**: `shuffle-premises 40-premise-file.py --copies 3` (on PATH) writes ~3 seeded permutations to a temp directory and prints the per-copy order for the record. Keep copies out of the suite directory and never commit them — a lingering copy matches pytest's `test_*.py` glob and shadows the real tests in `check_binds`'s scan. **Never ask an agent to shuffle:** models don't randomize — they return correlated or identity orders, silently restoring the positional artifact the shuffle removes; a position shared across copies manufactures false consensus.
- **(c) ~3 answerer leaves** (identical, Sonnet, low effort), one per copy. Inputs per leaf: the intent+design doc, `10-brief.md`, and **that leaf's copy only** — never another's copy or answers, never the lens frontiers; anchoring kills the measurement. The dispatch prompt restates this isolation ban explicitly and states the output format in full — a leaf left to infer the format goes looking for another leaf's output as its example. Identical because this tier is redundancy, not diversity (the diversity was the lenses); shallow because the work is transcription, not derivation. Scale up only when a specific premise's spread is too thin to classify.
- **(d) Judge leaf** (Opus): inputs = the doc's intent section, the answered copies, `40-premise-file.py`, `20-demands.md`. Output: `45-dispositions.md`. One leaf carries both the lineup and the correctness check — its charge orders the reading (intent before copies) and binds the ratchet that makes the merge safe. **Not collapsible, including in reduced mode** — a converged set no strong intent-anchored reader has examined must never reach the human.

## Charge — the synthesis leaf

Dedup the lenses' premises by **bound address plus concrete fault** (schema.md's address forms; a domain member, a payload shape, an interleaving — not test name, not loose prose similarity), merge duplicates, and write them into a single **premise-only test file**: each a signature + situation docstring, no assertions. Gaps — a premise only one lens raised — are the norm and kept: a lens seeing what others structurally can't is the lens working. Name any fault no lens owned under `## Red flags` (the orchestrator routes it to a strong-author follow-up). This dedup is alignment, never fork detection — lenses are engineered against overlap, so two of them landing the same premise is luck, not a signal. Carry every `# fork:` marker through verbatim, and roll the five frontiers' probe obligations into one deduplicated list in the sidecar frontier.

Frontier inventory: `{premises: n, forks_flagged: n, probe_obligations: n}`, `inputs` echoing all five lens counts — every lens premise resolves to a kept premise or a named merge; counts in equal counts out.

## Charge — an answerer

You receive one premise file: signatures and situation docstrings, no assertions. For **every** premise, fill in the assertion: given the doc and the situation, *what does the doc say must be observable here?* — written as the test's assertion, in intent-space. Answer from the doc and the brief, not from guesses about what code will do; where the doc genuinely doesn't say, write that ("unclear whether…") rather than inventing an outcome — a hedge is data. Write your answered copy beside the input copy.

## Charge — the judge

**Read the intent section first and form your own reading of each contested outcome before opening any answered copy** — you anchor to the doc, not to the answerers' framings; an examiner who reads the copies first confirms instead of measures. Then line up the assertions for each premise across the answered copies and classify:

- **Consensus** — the same outcome across answerers. The test's expected value; record it with provenance ("3/3 converged").
- **Fork** — materially different outcomes. The payoff: a real ambiguity, localized to one premise by measurement instead of collision luck.
- **Silent branch** — one answerer hedges or omits while another states an outcome as settled. The dangerous kind — it looks resolved from inside any single reading. Routes as a fork.

**The ratchet — the fork set only grows.** A materially different spread routes to §7 regardless of your own reading: never resolve a fork by deciding one copy is simply right, however confident your reading — that is suppressing the measurement, and the demotion is invisible downstream. You may **promote** a converged entry to the fork list, and must examine every consensus entry for exactly that: convergence is not correctness — shared priors converge on shared blind spots, and your independent reading is the one instrument that catches an answer that is actually a decision, wrong against intent, or pinned at a different altitude than its premise asked. A premise flagged `# fork:` in phase B goes to the fork list regardless of agreement. **Every premise leaves with a recorded disposition** — a consensus assertion bound for the suite, a fork or silent branch for the human, or a drop with its named reason — written down, never held in anyone's head: the premise that silently vanishes between the answered set and the demand list is the one loss no downstream check can see, and phase F reconciles the counts. Write the **fork section for a cold relay**: per fork — the situation, the actual answer spread verbatim, the implementation impact, and a recommendation with rationale. The orchestrator relays that section to the human verbatim; what it omits, the human never sees.

Frontier inventory: `{consensus: n, forks: n, silent_branches: n, promotions: n, drops: n}` with `inputs` echoing the premise count — consensus, forks, silent branches, and drops must sum to it; `promotions` counts the consensus entries you moved to the fork list, so the examination leaves a trace even when it moves nothing.
