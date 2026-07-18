---
name: write-tests
description: "Use once a design is settled enough to become the contract the code must satisfy — after discuss-issue has posted the intent+design doc, and before any implementation exists — to turn that design into the executable spec (end-to-end tests bound to a spec-coverage graph) the code is then written against. Kick back to discuss-issue if intent itself is still unsettled."
argument-hint: "[design doc path or issue #]"
effort: xhigh
---

# Write tests

The spec is the e2e test suite bound to a spec-coverage graph; *tests green* is meant to mean *code follows intent*. Translating a natural-language design into that executable form has three distinct failure modes, and the flow is one lane per mode:

- **Language lane — ambiguity.** Ambiguity is the one failure genuinely unique to natural language: a single sentence, two defensible readings (an executable spec reads exactly one way). Enumerators interpret the doc into situations, in intent-space, never guessing what code does; independent readers then answer each situation's outcome, and the ambiguity is found by *measurement* — a divergence across those readings localizes the fork, instead of one author silently picking a reading.
- **Reality lane — the world as it is.** Completeness and correctness are *not* natural-language failures — a test suite drops a case or asserts a falsehood just as easily as prose. What is mechanizable is grounding every is-question in executed reality: throwaway probes answer what a primitive raises, who writes a file, whether a value is constructible. Fault menus come from observed behavior, never priors — a test whose fault model came from the same prior as the code is a correlated error, green by construction.
- **Ought lane — the genuine forks.** The human answers the forks the language lane surfaces, and only those.

Nothing in between gets to guess: an enumerator's opinion about an exception type is not evidence, and a probe's output is not a decision. Two cross-checks then keep the *translation* honest without inventing a new oracle: **conservation** (questions generated from the doc and the same questions from the tests alone, diffed — a reading that lost an obligation or invented scope surfaces as a mismatch) and the **gate rules** (the known blind-spot shapes computed over the graph — HAZOP guide-words walked over the structure, so each pit is *computed* from the topology rather than remembered, which fails exactly when the written-down lesson is the one needed). One residue stays uncovered, and is named rather than papered over: the reality lane closes the is-questions the spec *cites*, but which questions to ask at all is bounded by recall. *Green* means the resolved, cited demands hold — never a guarantee the right questions were all asked, and never that the code is correct: the human PR review is still essential. And the suite must be an **independent** encoding of intent — grounded in existing reality (sibling code, real tool semantics), never in assumptions about what the not-yet-written target will do.

Input is discuss-issue's **intent+design doc**: typed obligations (stakeholder-indexed, non-obligations included), mechanisms naming the obligations they discharge, and a `claims:` block of already-probed assumptions this flow inherits into its ledger. If the design arrives untyped — a bare issue, a flat doc — derive the sections (a leaf's job) and post them back before starting, and kick back to discuss-issue when intent itself is unsettled. A typed doc with an empty or missing `claims:` block is still usable — claims then enter at grounding and extraction (rules.md, "Probed claims"); kick back for unsettled intent, not for a missing sweep.

The **project profile** — `.claude/spec-flow.json` in the repo you are working in — carries what this skill deliberately does not hardcode: the test harness, the injection idioms CI enforces, how to invoke the spec_graph checks, and the danger lens. Read it before dispatching anything; if it is missing, run `/spec-flow:init` first.

## The orchestrator contract

**You are a scheduler, not a worker.** Your job is dispatch, monitoring, retry, routing, and the human seam — nothing else. Every producing phase runs as a leaf under a **phase contract** in `phases/` and exits by writing a **frontier file**; the next phase's leaves read that file from disk and proceed. You hold digests, not content.

This is a measured budget, not a style rule: runs where leaf reports returned inline, the orchestrator read the references itself, and the artifact was typed into context peaked above 400k tokens of spine context — with the genuine human dialogue under 10k of it. The frontier discipline keeps the spine small, and it buys two more things for free: **every phase boundary is a checkpoint** (a dead session resumes at the last frontier instead of re-running grounding and enumeration — a loss paid twice in one day before this contract existed), and **every frontier is a forced cold handoff** (a next phase that cannot proceed from the file alone has found an incomplete frontier *now*, not at the final baton).

The spine owns exactly four things; everything else is a leaf:

1. **Dispatch, monitor, retry.** Thin prompts (below). A slow or stalled leaf is resumed or replaced, never absorbed — folding its work inline spends exactly the context the fan-out protects, and serially, forfeiting the parallelism too. A leaf that returns garbage is re-dispatched with the defect named, not patched over in-context. If a phase seems too small to dispatch, it is small enough to be cheap as a leaf; dispatch it anyway and keep the spine clean.
2. **The human seam** (§7). Forks, holes, refutations, waiver candidates — relayed from frontier files, decided by the human, recorded to a resolutions frontier.
3. **Residue routing.** The gate's typed residue and the verify phase's findings are routed — to leaves for re-grounding, to §7 for decisions — routed, never resolved in your own voice.
4. **Deviation decisions.** Reduced mode, decomposition, early exit, degraded-model fallbacks — each recorded in `handoff.deviations`.

**Dispatch protocol.** A leaf prompt is a pointer, not a payload: the phase contract path, the worktree path, the input frontier paths, the output frontier path, and the per-dispatch parameters (lens name, copy index). The contract file carries the doctrine; do not restate it into the prompt — five enumerators re-fed the same inline charge is 15k tokens of pure duplication. The references (`references/schema.md`, `references/rules.md`) are read by the leaves their phase contracts name — **the orchestrator reads neither.**

**Return protocol.** A leaf's inline return is its frontier's `digest` block only (≤15 lines) — status, inventory counts, red flags, and the file path. Everything else lives in the file.

**Spot-read rule.** You may read a frontier's header and a bounded sample (~40 lines) to verify a leaf stayed in its lane — an enumerator writing outcomes into premises, a gate leaf hand-waving a spend-point — and you read *in full* only the two sections written for you: a residue frontier's routing entries and a dispositions frontier's fork section. What you must never do is absorb enough content to start answering judgment calls yourself: **every judgment-call outcome routes to §7, none is self-answered** — a self-answered outcome measures nothing, and the one escaped bug of this skill's first week traces to exactly that move (a star-import "accepted gap" self-dispositioned into a drops note instead of asked as a fork; the human, asked minutes later about a weaker waiver, overrode it). A declined obligation is recorded as `Demand {form: waiver}` — an examined no, never a silence in `handoff.drops`.

**Inline probing and debugging are producing work.** A failing baseline, a stale environment, a "quick verification" grep — dispatch a leaf. The measured cost of one inline worktree bisection was 34k tokens of Bash output on the spine.

## Frontiers

All working frontiers live in `<worktree>/.spec-flow/frontiers/`. Add `.spec-flow/` to the worktree's `.git/info/exclude` (not the repo's `.gitignore` — the final diff must not carry plumbing). The two deliverables — the suite and `spec_graph_<slug>.yaml` — are *not* frontiers: they live at their final committed paths, and their phases write a small digest frontier beside the real artifact.

Every frontier begins with a YAML header:

```yaml
frontier:
  phase: <A|B|C|D|E|F, plus the dispatch's own name for fan-out phases>
  status: complete | design-refuted | blocked
  inputs: [{path: <frontier consumed>, inventory_echo: {<its counts, as consumed>}}]
  inventory: {<category>: <count>, ...}   # claims, flagged_facts, premises, forks, demands — whatever the phase produces
  red_flags: ["<anything the orchestrator or the human must see>", ...]
  digest: |
    <the ≤15 lines the leaf returned inline, verbatim>
```

**Conservation is the header's job.** Each consuming phase echoes the inventories it consumed and accounts for them in its own output: counts in equal counts out, per category, with every drop named. This is the same conservation move the mechanical gate runs at the suite's edges (rules.md, "Suite verification"), pushed to *every* boundary — each internal handoff is a new place for the premise that silently vanishes, and a frontier pipeline without conservation would multiply that hole rather than close it. The verify phase re-walks the whole chain (phases/verify.md).

**Checkpoint and resume.** On start (§0), scan the frontiers directory. Resume at the first phase whose frontier is missing, `blocked`, or stale against its inputs; never re-run a phase whose frontier is `complete` and whose inputs are unchanged. A restart that re-derives a completed frontier is the waste this mechanism exists to end.

**Early exit — design-refuted.** Any phase that refutes the design's own ground — its census, its mechanism set, the premise under demand #0 — sets `status: design-refuted` and stops. The orchestrator halts the pipeline **before the next dispatch**: post the correction to the issue, and put the choice to the human (§7, immediately): revise the doc (kick back to discuss-issue) or proceed with the corrections folded in. A refuted story is frequently the run's single most valuable finding; enumerating against a doc just proven partly false is the failure this seam ends — both prior occurrences needed a human interrupt that this rule replaces.

## Phase map

| Phase | Steps | Dispatches | Contract | Frontier(s) |
|---|---|---|---|---|
| 0 | worktree + resume scan | spine | — | — |
| A | 1–2 ground ∥ extract | grounding leaf (Explore-shaped) ∥ extraction leaf (frontier model) | phases/ground-extract.md | `10-brief.md`, `20-demands.yaml` |
| B | 3 enumerate | 4 lensed Sonnet leaves + 1 unlensed frontier strong author | phases/enumerate.md | `30-premises-<lens>.md` ×5 |
| C | 4 answer | synthesis (Sonnet, low) → `shuffle-premises` (spine, CLI) → ~3 identical Sonnet-low answerers → classifier leaf → frontier cold pass | phases/answer.md | `40-premise-file.py`, `45-dispositions.yaml` |
| D | 5–6 graph + gate | assembler leaf (frontier model) → gate leaf | phases/graph-gate.md | `spec_graph_<slug>.yaml` + `50-graph-digest.md`, `60-residue.yaml` |
| §7 | 7 human seam | spine (AskUserQuestion) | — | `70-resolutions.md` |
| E | 8 author | one frontier-model author leaf | phases/author.md | the suite + `80-author-digest.md` |
| F | 9 verify | mechanical-gate leaf, blind conservation reader, cold reconciler (frontier model) | phases/verify.md | `90-verification.md` |
| 10 | hand off | spine | — | — |

Ordering constraints the scheduler enforces: B's five leaves **block on A's finished brief** — ungrounded enumeration invents scary-sounding inputs that map to nothing; don't launch them early to save minutes. The early-exit check runs after A (and after any later frontier that flips to `design-refuted`). C's answerers see only their own shuffled copy — never each other, never the lens files. §7 runs after D so the gate's residue reaches the human in the same sitting as the forks; F's findings route back through §7, never straight into the diff. If A's grounding leaf overruns, dispatch a *fresh* probe-backed grounding leaf to produce the brief — never derive it on the spine; reconcile the two when the slow one lands.

Models are named in the phase contracts and are not economizable where they say frontier model (Opus-class): a blind A/B found the cross-cutting, grounding-dependent faults capability-dominated — the lenses miss them at any skill quality. If a frontier-model leaf genuinely cannot be spawned, run the best derivation you can and **record in `handoff.deviations` that the unknown-unknown region ran degraded**.

## 0. Worktree, hygiene, resume

Write the spec in a **dedicated git worktree** — confirm you are on one before starting, create one if not. The deliverable is a tests + spec_graph diff (§10); an isolated worktree keeps it off the main checkout and clean to hand off. **Reused-worktree hygiene:** a worktree from a prior life carries stale `.venv`, `__pycache__`, `.pytest_cache` that corrupt the baseline — clean them or verify the baseline green *before* phase A (a leaf's job if anything looks off; one stale venv cost ten minutes of spine debugging and sixteen spurious failures). Then run the resume scan (Frontiers, above) and enter the phase map at the first incomplete phase.

## Scale and decomposition

Scale the ceremony to the delta. When the design touches no shared sink, removes nothing, and yields only a handful of demands: run two lenses plus the strong author in B, collapse C's copies-and-answerers (the synthesis leaf answers its own premise file — and every judgment-call outcome still routes to §7 as a fork; self-answered outcomes measure nothing), and keep the graph to the touched neighborhood — recording the reduced mode in `handoff.deviations`. The gate always runs; over a small graph it is cheap. Reduced mode collapses *dispatch counts*, never the frontier files or their conservation headers — the checkpoint chain is not ceremony.

At the other end: when a design is too large to spec in one clean pass, decide *where* to cut it into several **before** phase A — each piece its own frontier chain. A bad cut splits a correctness property across dispatches so each reads green while the whole breaks; **references/decomposition.md** carries the test for a sound cut plus the execution-context and interface-grounding checks the demand tests alone don't cover. Read it when splitting; a single-pass spec doesn't need it.

## 7. Resolve with the human

Surface together, highest implementation-impact first (AskUserQuestion, your recommendation first): the forks and silent branches (C's dispositions frontier), the design holes and obligation-minted demands (D's residue frontier), the **refuted claims** (design corrections — the design said X, the probe shows Y), any **load-bearing claim no available probe can settle**, and F's findings when this seam re-opens for them. Relay each fork from its frontier's fork section — the phase contracts require that section written rich enough for a cold relay (the answer spread, the implementation impact, a recommendation with rationale), because a thin spine cannot reconstruct what the file omits. This is where human attention earns its keep: a handful of genuine decisions that dictate what the code must do — the is-questions were reality's to answer and are already in the ledger.

Record every outcome in `70-resolutions.md`, conservation-counted against the incoming forks and residue. A declined obligation is `Demand {form: waiver}` in the artifact — an examined no, never a silence. If the #0 provisional reading flipped, re-run C's classification against the resolved shape before dispatching E — the author must never receive answers written against a rejected contract. The resolved demand list — design-extracted, enumeration-derived, and obligation-minted alike — is the spec.

## 10. Hand off

Deliver the diff and the note.

**The diff** is **tests + spec_graph only** — the suite with `spec_graph_<issue-or-slug>.yaml` beside it (demands, structure, gate record, claims ledger, and a `handoff:` block recording forks and resolutions, holes, waivers, refuted and deferred claims, drops, nullstub passes, and deviations). Its `base:` field is the commit the spec forked from, so write-code-from-spec's gate can find its range. The frontiers directory stays untracked and uncommitted. Commit the diff **before the implementation exists** — write-code-from-spec refuses to start otherwise, and a spec phase that never ran discretely can't bite. Green means the resolved demands hold, not that the code is correct.

**The note** is the baton to a *cold* write-code-from-spec — a fresh session that never saw this one, reachable only through the issue thread, so post it there with the `handoff` skill. It records what the diff can't: the branch and base commit, the forks the human resolved and which reading they picked, anything that ran degraded, and the single next action. Write it **for the implementer, not the reviewer** — `finalize` deliberately meets the code cold, and a reviewer who has read the rationale confirms it instead of testing it.
