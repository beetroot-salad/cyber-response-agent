---
name: write-tests
description: "Use once a design is settled enough to become the contract the code must satisfy — after discuss-issue has posted the intent+design doc, and before any implementation exists — to turn that design into the executable spec (end-to-end tests bound to a spec-coverage graph) the code is then written against. Kick back to discuss-issue if intent itself is still unsettled."
argument-hint: "[design doc path or issue #]"
effort: xhigh
---

# Write tests

The spec is the e2e test suite bound to a spec-coverage graph; *tests green* is meant to mean *code follows intent*. Translating a natural-language design into that form has three failure modes, and the flow is one lane per mode: **language** (ambiguity — found by measurement, a divergence across independent readings, never one author silently picking), **reality** (every is-question answered by an executed probe, never a prior — fault menus come from observed behavior), and **ought** (the human answers the forks the language lane surfaces, and only those). Nothing in between gets to guess. The phase contracts in `phases/` enact the lanes; this file is the scheduler's charge. Two limits stay named: *green* means the resolved, cited demands hold — never that the right questions were all asked, and never that the code is correct (the human PR review is still essential) — and the suite must be an **independent** encoding of intent, grounded in existing reality, never in assumptions about the not-yet-written target.

Input is discuss-issue's **intent+design doc**: typed obligations, mechanisms naming the obligations they discharge, and a `claims:` block of already-probed assumptions this flow inherits. If it arrives untyped, derive the sections (a leaf's job) and post them back before starting; kick back to discuss-issue when intent itself is unsettled — for that, not for a missing claims sweep. The **project profile** (`.claude/spec-flow.json`) carries what this skill refuses to hardcode — harness, injection idioms, spec_graph checks, danger lens; read it before dispatching anything, and run `/spec-flow:init` first if it is missing.

## The orchestrator contract

**You are a scheduler, not a worker.** Every producing phase runs as a leaf under a phase contract and exits by writing a **frontier file**; the next phase's leaves read that file from disk and proceed. You hold digests, not content. This is a measured budget, not a style rule — runs that returned leaf reports inline, read the references on the spine, and typed the artifact into context peaked above 400k tokens of spine context with under 10k of it human dialogue — and the frontier discipline buys two more things: every phase boundary is a **checkpoint** (a dead session resumes there instead of re-deriving), and every frontier is a **forced cold handoff** (an incomplete one is found at its boundary, not at the final baton).

The spine owns exactly four things; everything else is a leaf:

1. **Dispatch, monitor, retry.** A slow or stalled leaf is resumed or replaced, never absorbed; a bad return is re-dispatched with the defect named, not patched inline. A phase too small to dispatch is small enough to be cheap as a leaf; dispatch it anyway.
2. **The human seam** (§7).
3. **Residue routing** — the gate's residue and the verify findings are routed (to leaves for re-grounding, to §7 for decisions), never resolved in your own voice.
4. **Deviation decisions** — reduced mode, decomposition, early exit, degraded-model fallbacks — each recorded in `handoff.deviations`.

**Dispatch protocol.** A leaf prompt is a pointer, not a payload: contract path **and charge section name**, worktree path, input frontier paths, output frontier path, per-dispatch parameters (lens name, copy index). The contract carries the doctrine — don't restate it. Each contract has two audiences, split by section: its `## Topology` block — always the first section, ≤20 lines — is the spine's (dispatch list, order, models, per-leaf inputs/outputs; read it with `Read`'s `limit` or a `Grep` on the heading with `-A` — the cap is a context budget, not a secrecy boundary, so glimpsing a charge's first lines is harmless), and the `## Charge — <role>` sections below it are the leaves'. The references are read by the leaves their charges name; **the orchestrator reads neither the charges nor the references.**

**Return protocol.** A leaf's inline return is its frontier's `## Digest` section, verbatim, and nothing else — no trailing summary, no restated inventory; everything else lives in the file.

**Spot-read rule.** Read a frontier's frontmatter and `## Red flags` plus a bounded sample (~40 lines) to verify a leaf stayed in its lane; read *in full* only the two sections written for you — a residue frontier's routing entries and a dispositions frontier's fork section. Never absorb enough content to start answering judgment calls yourself: **every judgment-call outcome routes to §7, none is self-answered** — the one escaped bug of this skill's first week was a self-dispositioned "accepted gap" the human would have overridden. A declined obligation is `Demand {form: waiver}` — an examined no, never a silence in `handoff.drops`.

**Inline probing and debugging are producing work.** A failing baseline, a stale environment, a "quick verification" grep — dispatch a leaf.

## Frontiers

Working frontiers live in `<worktree>/.spec-flow/frontiers/`; add `.spec-flow/` to the worktree's `.git/info/exclude` (not the repo's `.gitignore`). The two deliverables — the suite and `spec_graph_<slug>.yaml` — are not frontiers: they live at their final committed paths, with a small digest frontier beside them.

A frontier is a **markdown file**: every consumer is an LLM — the next phase's leaves, the cold reconciler, a human peeking mid-run — so the payload is prose and fenced data blocks, not schema. Exactly one sliver is machine-read (the resume scan, the conservation walk, the planned `spec-graph frontiers` lint), and that sliver is **YAML frontmatter** in the repo's one frontmatter grammar — never a fenced code block, which breaks on backticks inside values (this contract's own smoke run tripped on exactly that):

```
---
phase: <A|B|C|D|E|F, plus the dispatch's own name for fan-out phases>
status: complete | design-refuted | blocked
inputs: [{path: <basename of the consumed frontier>, inventory_echo: {<its counts, as consumed>}}]
inventory: {<category>: <count>, ...}   # claims, flagged_facts, premises, forks, demands — whatever the phase produces
---
```

Body, in order: `## Digest` — the ≤15 lines the leaf returns inline, verbatim; `## Red flags` — anything the orchestrator or the human must see (omit when empty); then the payload. Producer/consumer pairing is by full filename — the numeric prefix orders the chain for readers, it is not an identity (five `30-*` files share one prefix). A frontier whose payload cannot be a markdown file — phase C's `40-premise-file.py` must stay a real Python file for the shuffle CLI — gets a **sidecar**: `40-premises.md` carries the frontmatter and digest, and the payload file sits beside it.

**Conservation is the frontmatter's job**: each phase echoes the inventories it consumed and accounts for them in its output — counts in equal counts out, every drop named. Each internal handoff is a new place for the premise that silently vanishes; the frontmatter closes that hole and phase F re-walks the whole chain.

**Checkpoint and resume.** On start (§0), scan the frontiers directory; resume at the first phase whose frontier is missing, `blocked`, or stale against its inputs. Never re-run a phase whose frontier is `complete` on unchanged inputs.

**Early exit — design-refuted.** Any phase that refutes the design's own ground — its census, its mechanism set, the premise under demand #0 — sets `status: design-refuted` and stops. Halt **before the next dispatch**: post the correction to the issue and put the choice to the human (§7, immediately) — revise the doc (kick back to discuss-issue) or proceed with the corrections folded in. A refuted story is frequently the run's most valuable finding; enumerating against a doc just proven partly false is the failure this seam ends.

## Phase map

| Phase | Steps | Dispatches | Contract | Frontier(s) |
|---|---|---|---|---|
| 0 | worktree + resume scan | spine | — | — |
| A | 1–2 ground ∥ extract | grounding leaf (reader posture) ∥ extraction leaf (frontier model) | phases/ground-extract.md | `10-brief.md`, `20-demands.md` |
| B | 3 enumerate | 4 lensed Sonnet leaves + 1 unlensed frontier strong author | phases/enumerate.md | `30-premises-<lens>.md` ×5 |
| C | 4 answer | synthesis (Sonnet, low) → `shuffle-premises` (spine, CLI) → ~3 identical Sonnet-low answerers → classifier leaf → frontier cold pass | phases/answer.md | `40-premise-file.py` + `40-premises.md`, `45-dispositions.md` |
| D | 5–6 graph + gate | assembler leaf (frontier model) → gate leaf | phases/graph-gate.md | `spec_graph_<slug>.yaml` + `50-graph-digest.md`, `60-residue.md` |
| §7 | 7 human seam | spine (AskUserQuestion) | — | `70-resolutions.md` |
| E | 8 author | one frontier-model author leaf | phases/author.md | the suite + `80-author-digest.md` |
| F | 9 verify | mechanical-gate leaf, blind conservation reader, cold reconciler (frontier model) | phases/verify.md | `90-verification.md` |
| 10 | hand off | spine | — | — |

Scheduler-enforced constraints: B's five leaves **block on A's finished brief**; the early-exit check runs after A and after any later `design-refuted` flip. C's answerers see only their own shuffled copy. §7 runs after D so the gate's residue reaches the human with the forks; F's findings route back through §7, never straight into the diff. If A's grounding leaf overruns, dispatch a *fresh* probe-backed grounding leaf — never derive the brief on the spine — and reconcile when the slow one lands. Models are named in the contracts and are not economizable where they say frontier model; if one genuinely cannot be spawned, run the best derivation available and **record in `handoff.deviations` that the unknown-unknown region ran degraded**.

## 0. Worktree, hygiene, resume

Work in a **dedicated git worktree** — confirm before starting, create if not; the deliverable is a tests + spec_graph diff (§10) and stays off the main checkout. A reused worktree carries stale `.venv`/`__pycache__`/`.pytest_cache` that corrupt the baseline — clean them or verify the baseline green before phase A (a leaf's job if anything looks off). Then run the resume scan and enter the phase map at the first incomplete phase.

## Scale and decomposition

Scale the ceremony to the delta. Small delta (no shared sink, nothing removed, a handful of demands): two lenses plus the strong author in B, and collapse C's copies-and-answerers (the synthesis leaf answers its own premise file — every judgment-call outcome still routes to §7; C's cold pass never collapses) — record the reduced mode in `handoff.deviations`. The gate always runs; the frontier files and their conservation headers are never collapsed — the checkpoint chain is not ceremony. Too large for one clean pass: decide *where* to cut **before** phase A, each piece its own frontier chain — **references/decomposition.md** carries the test for a sound cut; read it when splitting.

## 7. Resolve with the human

Surface together, highest implementation-impact first (AskUserQuestion, your recommendation first): the forks and silent branches (C), the design holes and obligation-minted demands (D), the **refuted claims** (design corrections), any load-bearing claim no available probe can settle, and F's findings when this seam re-opens. Relay each fork from its frontier's fork section — written there for a cold relay; a thin spine cannot reconstruct what the file omits. This is where human attention earns its keep: a handful of genuine decisions that dictate what the code must do — the is-questions were reality's to answer and are already in the ledger.

Record every outcome in `70-resolutions.md`, conservation-counted against the incoming forks and residue. A declined obligation is `Demand {form: waiver}`. If the #0 provisional reading flipped, re-run C's classification against the resolved shape before dispatching E — the author must never receive answers written against a rejected contract. The resolved demand list — design-extracted, enumeration-derived, and obligation-minted alike — is the spec.

## 10. Hand off

**The diff** is **tests + spec_graph only** — the suite with `spec_graph_<issue-or-slug>.yaml` beside it (demands, structure, gate record, claims ledger, `handoff:` block); its `base:` field is the fork commit. The frontiers directory stays untracked. Commit **before the implementation exists** — write-code-from-spec refuses to start otherwise, and a spec phase that never ran discretely can't bite.

**The note** is the baton to a *cold* write-code-from-spec, reachable only through the issue thread — post it there with the `handoff` skill: branch and base commit, the forks the human resolved and which reading they picked, anything that ran degraded, the single next action. Write it **for the implementer, not the reviewer** — `finalize` deliberately meets the code cold.
