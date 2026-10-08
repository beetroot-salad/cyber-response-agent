# Phase C — answer, probe, judge (step 4)

## Topology

Three leaves in sequence. Writing each premise's answer down is the specification act; checking the answers' is-facts against reality and the answers' oughts against intent are the two nets behind it.

- **(a) Answerer leaf** (Sonnet, low effort): inputs = the `30-premises-*.md` frontiers, the intent+design doc, `10-brief.md`. Merges the lenses' premises and answers them in one pass. Outputs: `40-premise-file.py` (merged premises, no assertions — the record of what was asked), `42-answers.py` (the same file with assertions), and the sidecar frontier `40-premises.md`, which carries the deduplicated probe-obligation list.
- **(b) Probe leaf** (Sonnet, high effort): inputs = `40-premises.md`'s probe obligations, `42-answers.py`, `10-brief.md`. Runs every probe obligation now — the lenses' and the answerer's — and marks each answer it confirms or overturns. Output: `44-probes.md`. Skip it, recording `probes: 0` in the judge's digest, when the obligation list is empty.
- **(c) Judge leaf** (Opus, xhigh effort): inputs = the doc's principles and intent sections, `42-answers.py`, `40-premise-file.py`, `44-probes.md`, `20-demands.md`, `10-brief.md`. Output: `45-dispositions.md`. **Not collapsible, in any mode.**
- After an amendment (SKILL.md §7), the answerer and judge re-run on the existing premise file against the amended design; the judge's frontier then also names the clusters the amendment dissolved.

Run the probes *before* the judge, not after the graph: in the runs measured, the probes that overturned answers (a forged pointer called settled, a planted FIFO, hostile labels passing the loader) were minted here and ran only phases later, after work had been built on the answers they overturned. Answer escalation — re-answering hedged premises with shuffled copies on other models — is retired: across two measured runs it re-read 269 premises and changed zero routings, while its cheapest model failed often enough to need an Opus redo.

Keep premise and answer files out of the suite directory and never commit them — a lingering one matches pytest's `test_*.py` glob and shadows the real tests in `check_binds`'s scan.

## Charge — the answerer

Two jobs in one pass, in this order, and the order matters: merge before you answer, so you answer each situation once.

**Merge.** Dedup the lenses' premises by **bound address plus concrete fault** (schema.md's address forms; a domain member, a payload shape, an interleaving — not test name, not loose prose similarity). Gaps — a premise only one lens raised — are the norm and kept. Name any fault no lens owned under `## Red flags` (the orchestrator routes it to a strong-author follow-up). Carry every `# fork:` marker through verbatim, and roll the lenses' probe obligations into one deduplicated list in your frontier. Write the merged premise-only file (signatures + situation docstrings, no assertions) before filling anything in — the judge reads it against your answers.

**Answer.** For **every** premise, fill in the assertion: given the doc and the situation, *what does the doc say must be observable here?* — written as the test's assertion, in intent-space. Answer from the doc and the brief, not from guesses about what code will do. Where your answer rests on a fact about existing code or a dependency that neither the brief nor the ledger settles, add it to the probe-obligation list with the premise ids it decides.

**Hedging is a first-class output, not a failure.** Where the doc genuinely doesn't say, write "unclear whether…" and name the competing readings. The judge examines every hedge; swallowing one by picking the more plausible reading leaves no trace a choice was made.

## Charge — the probe leaf

You settle is-questions, nothing else. For each probe obligation, run the instrument its kind demands (rules.md, "Probed claims"; a `behavior` fact is settled only by an executed probe — a throwaway run over the input types the boundary admits — never by reading the code) and record `{id, premises, probe, probe_kind, observed, verdict}`. Then, per premise the obligation named, say whether the observation **confirms**, **overturns**, or **does not bear on** the answer in `42-answers.py` — quote the answer and the observation side by side. Do not rewrite answers and do not judge intent; an overturned answer is the judge's to re-classify. A probe that reveals a bug on main is a red flag even when no premise asked about it.

## Charge — the judge

**Read the principles and intent sections first and form your own reading of each contested outcome before opening any answered file** — you anchor to the doc, not to the answerer's framing. You are the only intent-anchored reader between one answerer and the human.

Classify every premise:

- **Settled** — answered, no hedge, no `# fork:` marker, not overturned by a probe, and your own reading agrees. The test's expected value; record it with provenance ("single reading, judge-examined").
- **Fork** — the answerer hedged, a `# fork:` marker was carried, or your reading materially differs from the answerer's. Record each competing reading.
- **Dropped** — with its named reason (duplicate of #n; out of scope per a stated non-obligation).

**Probes outrank readings on is-questions.** An answer `44-probes.md` overturned is not settled however plausible it reads: re-answer it from the observation if the doc then decides it, or make it a fork. Where an answer's divergence from your reading rests on an unprobed mechanism-level fact — an exception class, a locking guarantee — mint a probe obligation (`route: re-ground`) for the orchestrator to dispatch before the dissolve pass; never settle it from your own sense of plausibility.

**Promotion is your primary net.** Examine **every** settled entry for an answer that is actually a *decision* someone made, wrong against intent, or pinned at a different altitude than its premise asked — and promote it to the fork list. A single reading has no convergence to be wrong about; nothing else stands between it and the suite.

**Cluster the forks.** Group forks that are one decision into a cluster — the same question asked through different situations — and grade each cluster **material** (the readings imply a different data model, a different set of bound addresses or surfaces, or a different observable outcome at a stated obligation; when unclear, material) or **non-material**. Write the **fork section for a cold relay**: per cluster — the situation, its member premises, the readings verbatim, the implementation impact, and a recommendation with rationale. The dissolve leaf and the orchestrator read that section; what it omits, the human never sees.

**Every premise leaves with a recorded disposition** — settled, in a cluster, or dropped with its reason — written down, never held in your head. State the per-disposition counts in your digest, computed over your file.
