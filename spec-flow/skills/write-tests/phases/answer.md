# Phase C — answer the premises (step 4)

The premise is a question; the assertion is its answer. Phase B's lenses (diverse, one sample each) asked the questions; this phase has identical readers (redundant, sampled) answer them, and the spread of answers *is* the ambiguity measurement — agreement is the expected value with provenance, disagreement is a fork. Five dispatches in sequence; only the shuffle runs on the spine (it is a CLI call, and its output is file paths).

## (a) Synthesis leaf (Sonnet, low effort) → `40-premise-file.py`

Inputs: the five `30-premises-*.md` frontiers. Dedup the premises by **bound address plus concrete fault** (schema.md's address forms; a domain member, a payload shape, an interleaving — not test name, not loose prose similarity), merge duplicates, and write them into a single **premise-only test file**: each a signature + situation docstring, no assertions. Gaps — a premise only one lens raised — are the norm and kept: a lens seeing what others structurally can't is the lens working. Name any fault no lens owned in `red_flags` (the orchestrator routes it to a strong-author follow-up). This dedup is alignment, never fork detection — lenses are engineered against overlap, so two of them landing the same premise is luck, not a signal. Carry every `# fork:` marker through verbatim, and roll the five frontiers' probe obligations into one deduplicated list in the header. Inventory: `{premises: n, forks_flagged: n, probe_obligations: n}`, with `inputs` echoing all five lens counts — every lens premise resolves to a kept premise or a named merge; counts in equal counts out.

## (b) Shuffle — spine-run CLI, never an agent

The orchestrator runs `shuffle-premises 40-premise-file.py --copies 3` (the plugin ships it on PATH) — it writes ~3 copies, each a seeded permutation of the same premises (identical names, reordered), and prints the per-copy order for the record. The copies land in a temp directory by default; keep them out of the suite directory and never commit them — a lingering copy matches pytest's `test_*.py` glob and shadows the real tests' docstrings in `check_binds`'s scan. **Never ask an agent to shuffle:** models don't randomize — they return correlated or identity orders — and a fake shuffle silently restores the positional artifact this step exists to remove. With the whole set visible to each answerer, order is the anti-anchoring control: a sibling premise must not prime an answer through its position, and a position shared across copies is what would otherwise manufacture false consensus.

## (c) Answerer leaves (~3, identical, Sonnet, low effort) — one per copy

Identical because this tier is redundancy, not diversity (the diversity was the lenses), and shallow because the work is transcription of the doc's answer, not derivation: the spread saturates fast (measured spreads were identical at three and four answerers over a 74-premise pool). Scale up only when a specific premise's spread is too thin to classify. Inputs per leaf: the intent+design doc, `10-brief.md`, and **that leaf's copy only** — no answerer sees another's copy, another's answers, or the lens frontiers; anchoring kills the measurement. Fill in **the assertion for every premise in your copy**: given the doc and the situation, *what does the doc say must be observable here?*, written as the test's assertion in intent-space. Write your answered copy beside the input copy.

## (d) Classifier leaf → `45-dispositions.yaml`

Inputs: the ~3 answered copies, `40-premise-file.py`, `20-demands.yaml`. Line up the assertions for each premise and classify:

- **Consensus** — the same outcome across answerers. The test's expected value; record it with provenance ("3/3 converged").
- **Fork** — materially different outcomes. The payoff: a real ambiguity, localized to one premise by measurement instead of collision luck.
- **Silent branch** — one answerer hedges ("unclear whether…") or omits the assertion while another states an outcome as settled. The dangerous kind — it looks resolved from inside any single reading. Routes as a fork.

A premise flagged `# fork:` in phase B goes to the fork list regardless of agreement. **Every premise leaves with a recorded disposition** — a consensus assertion bound for the suite, a fork or silent branch for the human, or a drop with its named reason — written down, never held in anyone's head: the premise that silently vanishes between the answered set and the demand list is the one loss no downstream check can see, and phase F reconciles the counts. Write the **fork section for a cold relay**: per fork — the situation, the actual answer spread verbatim, the implementation impact, and a recommendation with rationale. The orchestrator reads this section in full and relays it via AskUserQuestion; what the section omits, the human never sees. Inventory: `{consensus: n, forks: n, silent_branches: n, drops: n}` with `inputs` echoing the premise count — the four must sum to it.

## (e) Strong cold pass (frontier model) — over the converged set

Convergence is not correctness; shared priors converge on shared blind spots. A frontier-model leaf reads the *full* consensus set from `45-dispositions.yaml` against the intent section and marks any consensus answer that is actually a decision, wrong against intent, or pinned at the wrong altitude — each marked entry moves to the fork list (the leaf updates the dispositions frontier and its counts). This pass is **not optional and not collapsible**: the one run that skipped it went straight from answerers to the human with a converged set nobody strong had read. In reduced mode (SKILL.md, "Scale") the copies and answerers collapse — this pass does not.
