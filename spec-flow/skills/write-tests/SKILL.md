---
name: write-tests
description: "Use once a design is settled enough to become the contract the code must satisfy — after discuss-issue has posted the intent+design doc, and before any implementation exists — to turn that design into the executable spec (end-to-end tests bound to a spec-coverage graph) the code is then written against. Kick back to discuss-issue if intent itself is still unsettled."
argument-hint: "[design doc path or issue #]"
effort: medium
---

# Write tests

The spec is the e2e test suite bound to a spec-coverage graph; *tests green* is meant to mean *code follows intent*. Translating a natural-language design into that form has three failure modes, and the flow is one lane per mode: **language** (what the design leaves undecided — surfaced as premises and judged against intent, never one author silently picking), **reality** (every is-question answered by an executed probe, never a prior — fault menus come from observed behavior), and **ought** (the human decides what the language lane surfaces, and only that). Nothing in between gets to guess. The phase contracts in `phases/` enact the lanes; this file is the scheduler's charge. Two limits stay named: *green* means the resolved, cited demands hold — never that the right questions were all asked, and never that the code is correct (the human PR review is still essential) — and the suite must be an **independent** encoding of intent, grounded in existing reality, never in assumptions about the not-yet-written target.

**Where the value is.** Measured over the October runs, the decisions that most improved designs were never a fork picked from a menu: they were the human rejecting a batch of forks and asking for the design call that dissolves them — a threat model, "fail closed, loud, fast", one owner per path. The phases that produced the rest were grounding's executed probes (refuted design claims), extraction (most material forks, before any lens ran), re-grounding probes (answers overturned by reality), the judge's clustering, and the cold reconciler. The flow is built around those; the redundancy tiers that changed no routing (answer escalation, five lenses, count echoes, a separate blind pass nobody read) are gone, and the dissolve step the human kept doing by hand is now a phase.

Input is discuss-issue's **intent+design doc**: **principles** (threat model and failure posture), typed obligations, mechanisms naming the obligations they discharge, and a `claims:` block of already-probed assumptions this flow inherits. If it arrives untyped, derive the sections (a leaf's job) and post them back before starting; kick back to discuss-issue when intent itself is unsettled — for that, not for a missing claims sweep. The **project profile** (`.claude/spec-flow.json`) carries what this skill refuses to hardcode — harness, injection idioms, spec_graph checks, danger lens, standing principles; read it before dispatching anything, and run `/spec-flow:init` first if it is missing.

## The orchestrator contract

**You are a scheduler, not a worker.** Every producing phase runs as a leaf under a phase contract and exits by writing a **frontier file**; the next phase's leaves read that file from disk and proceed. You hold digests, not content — never a leaf report inline, never a reference read on the spine, never the artifact typed into context. Every phase boundary is a **checkpoint** (a dead session resumes there instead of re-deriving), and every frontier is a **forced cold handoff** (an incomplete one is found at its boundary, not at the final baton).

The spine owns exactly five things; everything else is a leaf:

1. **Dispatch, monitor, retry.** A slow or stalled leaf is resumed or replaced, never absorbed; a bad return is re-dispatched with the defect named, not patched inline. A phase too small to dispatch is small enough to be cheap as a leaf; dispatch it anyway.
2. **Fan-out.** When a phase splits into parallel workers (phase E's writers), *you* dispatch them, from the plan a leaf wrote — never a leaf that spawns its own workers and polls for them: only the spine is woken when a background agent finishes, so a nested orchestrator spends its time in sleep loops.
3. **The human seam** (§7).
4. **Residue routing** — probe obligations, the gate's residue, and the verify findings are routed (to leaves for probing, to §7 for decisions), never resolved in your own voice.
5. **Deviation decisions** — reduced mode, decomposition, early exit, lens choice, degraded-model fallbacks — each recorded in `handoff.deviations`.

**Dispatch protocol.** A leaf prompt is a pointer, not a payload: contract path **and charge section name**, `references/frontier.md` (the file shape every leaf writes), worktree path, input frontier paths, output frontier path, per-dispatch parameters (lens name, slice), and the return line (self-check, then the digest — below). **Never point a leaf at this file** — its doctrine is the spine's, and a leaf that reads it spends its first ten minutes on the scheduler's job; whatever a leaf needs is in its charge or the references its charge names. Each contract has two audiences, split by section: its `## Topology` block — always the first section, ≤20 lines — is the spine's (dispatch list, order, models, per-leaf inputs/outputs; read it with `Read`'s `limit` or a `Grep` on the heading with `-A`), and the `## Charge — <role>` sections below it are the leaves'. **The orchestrator reads neither the charges nor the references.**

**Return protocol.** A leaf's inline return is its frontier's `## Digest` section, verbatim, and nothing else. The ≤15-line digest cap binds Opus leaves too. **Before returning, the leaf runs `spec-graph frontiers <dir> --only <file>` on every frontier it wrote and repairs each finding itself, returning only on exit 0** — the dispatch prompt's return line says so. The spine's boundary run stays the net.

**Spot-read rule.** Read a frontier's frontmatter and `## Red flags` plus a bounded sample (~40 lines) to verify a leaf stayed in its lane; read *in full* only the sections written for you — the dissolve frontier's tensions, a dispositions frontier's fork section, a residue frontier's routing entries. Never absorb enough content to start answering judgment calls yourself: **every judgment-call outcome routes to §7, none is self-answered.** A declined obligation is `Demand {form: waiver}` — an examined no, never a silence in `handoff.drops`.

**Inline probing and debugging are producing work.** A failing baseline, a stale environment, a "quick verification" grep — dispatch a leaf.

## Frontiers

Working frontiers live in `<worktree>/.spec-flow/frontiers/`; add `.spec-flow/` to the worktree's `.git/info/exclude` (not the repo's `.gitignore`). The two deliverables — the suite and `spec_graph_<slug>.yaml` — are not frontiers: they live at their final committed paths, with a small digest frontier beside them.

A frontier is a **markdown file** read by LLMs, opening with YAML frontmatter — `phase`, `status` (`complete | design-refuted | blocked`), `inputs` (the frontier filenames it consumed) — then `## Digest` (≤15 lines, the leaf's inline return), `## Red flags` (omit when empty), then the payload. `references/frontier.md` is the template leaves follow. A payload that cannot be markdown (a premise file) gets a markdown **sidecar** carrying the frontmatter and digest, with the payload beside it. The numeric prefix orders the chain for readers; pairing is by full filename.

The frontmatter is for **checkpoint and resume**, not accounting: `inputs` is what makes a frontier detectably stale when an input changes. Counts are optional payload, never reconciled across files — the per-file count echoes this flow used to carry caught bookkeeping slips and never a dropped item; the drops that mattered were found by the cold reconciler's trail walk (phase F), which is where conservation now lives.

**Checkpoint and resume.** On start (§0), run `spec-graph frontiers <dir> --resume`; it names the first frontier that is blocked, stale against its inputs, or unparseable — resume there (a `design-refuted` frontier is a deliberate halt: route it to §7, don't re-enter past it). The tool classifies only frontiers that exist, so cross-check against the phase map: a frontier the map expects that is absent on disk is the resume point. Never re-run a phase whose frontier is `complete` on unchanged inputs. Run `spec-graph frontiers <dir>` at every phase boundary.

**Early exit — design-refuted.** Any phase that refutes the design's own ground — its census, its mechanism set, the premise under demand #0 — sets `status: design-refuted` and stops. Halt **before the next dispatch**: post the correction to the issue and put the choice to the human (§7, immediately) — revise the doc (kick back to discuss-issue) or proceed with the corrections folded in. A refuted story is frequently the run's most valuable finding.

## Phase map

| Phase | Steps | Dispatches | Contract | Frontier(s) |
|---|---|---|---|---|
| 0 | worktree, principles, resume | spine | — | `00-principles.md` (only when asked) |
| A | 1–2 ground ∥ extract | grounding leaf (Opus) ∥ extraction leaf (Opus) | phases/ground-extract.md | `10-brief.md`, `20-demands.md` |
| B | 3 enumerate | strong author (Opus) ∥ 2–3 lensed leaves (Sonnet) | phases/enumerate.md | `30-premises-<lens>.md` |
| C | 4 answer, probe, judge | answerer (Sonnet) → probe leaf (Sonnet; skipped when nothing to probe) → judge (Opus) | phases/answer.md | `40-premise-file.py` + `40-premises.md`, `42-answers.py`, `44-probes.md`, `45-dispositions.md` |
| C′ | 5 dissolve | dissolve leaf (Opus) | phases/dissolve.md | `47-dissolve.md` |
| §7 | 6 decide | spine (AskUserQuestion) | — | `70-resolutions.md` |
| D | 7 graph + gate | assembler (Opus) → gate (Sonnet) → probe leaf if the residue asks | phases/graph-gate.md | `spec_graph_<slug>.yaml` + `75-graph-digest.md`, `76-residue.md`, `78-gate-resolutions.md` |
| E | 8 author | survey leaf (Opus) → writer leaves ×N (Opus, spine-dispatched) → integrator (Opus) | phases/author.md | `80-survey.md`, `82-writer-<slice>.md`, the suite + `88-author-digest.md` |
| F | 9 verify | mechanical gate (Sonnet) → blind reader (Sonnet) → cold reconciler (Opus) → at most one repair | phases/verify.md | `90-mechanical.md`, `91-blind.md`, `92-reconciliation.md`, `94-repair.md` |
| 10 | hand off | spine | — | — |

Scheduler-enforced constraints: B blocks on A's finished brief; the early-exit check runs after A and after any later `design-refuted` flip. **The graph is built after §7**, on the decided design — built before, it was voided by the decisions it preceded. F's findings route back through §7, never straight into the diff. If A's grounding leaf overruns, dispatch a *fresh* probe-backed grounding leaf — never derive the brief on the spine — and reconcile when the slow one lands. Models **and efforts** are named in the contracts; dispatch each leaf at its contract-named effort — the skill's own `effort: medium` is the spine's budget, and a leaf left to inherit it runs degraded. If a contract-named model cannot be spawned, run the best derivation available and record the degraded region in `handoff.deviations`.

## 0. Worktree, principles, resume

Work in a **dedicated git worktree** — confirm before starting, create if not; the deliverable is a tests + spec_graph diff (§10) and stays off the main checkout. A reused worktree carries stale `.venv`/`__pycache__`/`.pytest_cache` that corrupt the baseline — clean them or verify the baseline green before phase A (a leaf's job if anything looks off).

**Principles.** Every fork is judged against the threat model and failure posture — the design doc's principles block, on top of the profile's `conventions.principles`. If neither states them, ask the human now, once (AskUserQuestion: what is trusted, what is not, what is *not* assumed hostile; the failure posture), and record the answer in `00-principles.md` (a frontier: `phase: 0-principles`) and in the issue thread — not in `70-resolutions.md`, which would read as a finished §7 to a resumed run. Never derive them: twice a run reached §7 without them and the human had to stop it to state them, after the forks they would have dissolved had already been enumerated and answered.

Then run `spec-graph frontiers <worktree>/.spec-flow/frontiers --resume` and enter the phase map where it says. A chain begun under the earlier phase map (graph and gate at `50-`/`60-`, before §7) finishes under that map — check out the plugin commit it started on — or restarts at phase A; never splice the two maps.

## Scale and decomposition

Scale the ceremony to the delta. A small delta (no shared sink, nothing removed, a handful of demands) runs B as the strong author plus the danger lens only, and C′ is skipped when the judge reports two or fewer material clusters — record either in `handoff.deviations`. The judge, the gate, the cold reconciler, and the frontier files are never collapsed. Too large for one clean pass: decide *where* to cut **before** phase A, each piece its own frontier chain — **references/decomposition.md** carries the test for a sound cut; read it when splitting.

## 7. Decide with the human

**Lead with tensions, not forks.** The human's attention is the scarcest input in the flow, and the runs measured how it was being spent: twenty to fifty questions per run, the recommendation taken 87–92% of the time — ratification, not decision — while the decisions that mattered arrived when the human rejected the batch and asked what single design call would dissolve it. `47-dissolve.md` has already asked that question. Put to the human, in this order:

1. **Tensions** — each a root cause shared by a group of material forks, with the dissolving design call the dissolve leaf proposes, the principle it rests on, what it dissolves, and what it costs (what the code must then carry, what it forecloses). Options: adopt the call, adopt a variant, or keep the forks and decide them one by one. The dissolve leaf *proposes*; only the human disposes.
2. **Outside the threat model** — the forks the dissolve leaf found exist only to handle a condition the principles don't call for. One question: drop them (each becomes a `rejected:` non-obligation), or name the ones to keep.
3. **Remaining material forks**, highest implementation-impact first, your recommendation first — plus the refuted claims (design corrections), obligation-minted demands from extraction, and any load-bearing claim no available probe can settle.

A fork is **material** when its readings imply a different *data model*, a different *set of bound addresses or surfaces*, or a different *observable outcome at a stated obligation*; when it is genuinely unclear, it is material. Everything else **auto-resolves to the judge's recommendation**, recorded in `70-resolutions.md` and `handoff.forks` with `resolved_by: auto` — decided, not dropped, and visible to the merge-gate human. **Every option states its trade-off** — bare labels make the human pick on wording; the seam exists so they pick on consequence. Relay each item from its frontier, written there for a cold relay. Aim for one or two AskUserQuestion rounds; a third means the dissolve pass missed a root cause — say so, rather than keep asking.

Record every outcome in `70-resolutions.md`: the principles in force (profile, doc, `00-principles.md`), each tension's ruling, the dropped-as-outside-the-threat-model list, each fork's reading, verbatim free text where the human wrote it. A declined obligation is `Demand {form: waiver}`. The resolved demand list — design-extracted, enumeration-derived, and obligation-minted alike — is the spec.

**When a ruling amends the design** (a tension adopted, a free-text redesign), write the amendment to `.spec-flow/design-amendments.md`, post it to the issue, and re-enter at C against the amended design — do not restart the chain:

- **Keep A and B.** The brief is facts about today's code, which an amendment does not change; the premise file is situations, most of which still apply. Re-enter with a probe leaf for any is-claim the amendment newly rests on, and a strong-author follow-up only for mechanisms the amendment introduces that no premise covers.
- **Re-answer and re-judge the existing premise file** under the amendment: the judge marks clusters the amendment dissolves, re-classifies what it changes, and surfaces new interactions. Re-dissolve only if new material forks remain.
- **If the #0 provisional reading flipped**, this re-judge is mandatory before anything downstream — the author must never receive answers written against a rejected contract.

A finding that the design is wrong at its root — not amendable by a ruling — is a kick back to discuss-issue, not an amendment written here.

## 10. Hand off

**The diff** is **tests + spec_graph only** — the suite, plus `spec_graph_<issue-or-slug>.yaml` in the profile's spec corpus (demands, structure, gate record, claims ledger, `handoff:` block); its `tests:` field names the suite it derives and its `base:` field is the fork commit. The frontiers directory stays untracked. Commit and push the spec branch **before the implementation exists** — verify the remote branch contains the commit before posting the handoff. Write-code-from-spec refuses to start otherwise, and a spec phase that never ran discretely can't bite.

**The note** is the baton to a *cold* write-code-from-spec, reachable only through the issue thread — post it there with the `handoff` skill: branch and base commit, the principles and the tensions the human ruled, the forks resolved and which reading was picked, the auto-resolutions and the gate-minted obligations (`gate.obligations`) for the merge-gate human to scan, anything that ran degraded, the single next action. Write it **for the implementer, not the reviewer** — `finalize` deliberately meets the code cold.
