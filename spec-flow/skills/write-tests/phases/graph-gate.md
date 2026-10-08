# Phase D — materialize the graph, run the gate (step 7)

## Topology

- Runs **after §7**, on the decided design: built before, the graph modelled readings the human then rejected (one run's 170 demands were voided by its own §7; another's never took the amendment). The orchestrator routes the residue afterwards; it produces none of this.
- **Assembler leaf** (Opus, xhigh effort): inputs = `10-brief.md`, `20-demands.md`, `45-dispositions.md`, `47-dissolve.md` (when written), `70-resolutions.md`, `.spec-flow/design-amendments.md` if any. Outputs: `spec_graph_<slug>.yaml` at its final committed path in the spec corpus (the profile's `specGraph.artifacts`), carrying `tests:` — the repo-relative suite directory it derives — plus `75-graph-digest.md`.
- **Gate leaf** (Sonnet, high effort — the R1–R5 and R7 triggers are computed by `spec-graph gate`, so this leaf annotates and judges rather than re-derives): inputs = the assembled artifact, `70-resolutions.md`. Outputs: the gate record written into the artifact, plus `76-residue.md`.
- Routing: test obligations are minted into the graph without a question (recorded in `gate.obligations`, which the handoff note lists for the merge-gate human); `route: re-ground` items go to a probe leaf (phases/answer.md, "Charge — the probe leaf"), whose results the gate leaf folds in on resume; **new** design holes and waiver candidates go to a short second human round, recorded by the spine in `78-gate-resolutions.md` — skipped, with no file, when there are none.

## Charge — the assembler

Read **references/schema.md** (the graph language) and **references/rules.md**, "The artifact" (the file's shape), before starting.

Resolve every `binds:` target. Resolution is what pulls boundaries, facets, and edges into the graph — at spec time the delta *is* demand-implied structure; change kinds (add/remove/modify) are assigned from the design, not from a code diff (rules.md, "Procedure"). Fill every invariant field or set it to `unknown` — an `unknown` is a finding, never a silent null. Then attach the grounded neighborhood from the brief: the co-writers, sibling constraints, and consumers that reality imposes and no demand asked for.

**Reconcile names before the join:** grounding, demand extraction, and the dispositions' address derivations coin ids and axis names independently — unify boundary ids (key by role+origin) across all three coining passes, and declare every axis once in the artifact's `axes:` list; a `key_axes`/`interpolates` member outside that list is an R0 finding. Seed the `claims:` block with every claim the three input frontiers raised, inherited entries keeping their ids.

Digest: demand, claim, boundary, and `unknown` counts. Every demand, claim, settled assertion, and §7 ruling from the inputs is present in the artifact or named as a drop — apply each ruling as the human worded it, and model nothing an adopted tension dissolved.

## Charge — the gate leaf

Read **references/rules.md** in full. The rules are **guaranteed question-generators**: a lens *might* ask the two-writer collision question; the rule makes sure it is asked, every run — and for R1–R5 plus R7 the asking is now mechanical. Start with:

```
spec-graph gate <artifact> --residue
```

That prints every slot-computed firing (rule, element, reason) plus the R0 formal findings (dangling addresses, unregistered axes, unheard `unknown`s). Your work is what the tool cannot do: write each firing's **witness** (the concrete element and the missing demand, one sentence), classify its route into the typed residue below, and run the three **judgment halves** the tool only demands entries for — R0's bidirectional prose reconciliation (a normative design sentence binding no element; a delta element tracing to no sentence), R5's tightening/safe-by-construction extension, and R6's chooser/sanitizer walk over every rendered sink. Do not re-derive the computed triggers by hand, and do not trim the tool's list — a firing you disagree with is a `fired: false` that must cite its claim, never a deletion.

Record each rule's outcome — fired or clean — in the artifact's `gate.evaluated`: a rule with no entry reads as skipped, and the cold reconciler cannot tell a quiet rule from a forgotten one. Before writing the frontier, re-run `spec-graph gate <artifact>` (no flag) — it must exit clean or every remaining finding must be a residue entry you routed on purpose.

**Every spend-point cites its claim.** A `fired: false`, a waiver's rationale, a pre-discharge credit, a `binds_waivers`/`exercise_waivers`/`actor_waivers` entry, or a hole resolved as "not reachable / cannot be built unsafe" closes only by citing a ledger claim id of the matching kind with an executed probe (rules.md, "Probed claims") — a plausible sentence in one of those slots is exactly what hardens a blind spot into a green suite. Reachability claims are break-attempts and only ever `unrefuted`; a design that needs the universal *confirmed* routes to a safe-by-construction demand instead — enforced, not believed. A spend-point whose claim does not exist yet becomes a probe obligation in the residue, not a citation-shaped sentence.

Write the residue **typed** (definitions in rules.md; one hit can take more than one route), one entry per hit with the route pre-labelled, because the orchestrator routes this file without re-deriving it:

- **Test obligations** → minted as executable demands — kind and binds from the rule's obligation, witness prose included (it seeds the test's docstring in phase E); recorded in `gate.obligations` for the merge-gate human, not asked.
- **Design holes** → the human, but only holes §7 did not already rule on: check `70-resolutions.md` and `45-dispositions.md` first and cite the cluster or ruling that covers a hole instead of re-raising it (in the measured runs every hole the gate raised was already a cluster). But mark fact-shaped `unknown`s (a knob's default, a key read off the resource — anything an agent can look up) `route: re-ground` — the orchestrator dispatches a lookup leaf first; §7 is for decisions, not lookups.
- **Pre-discharged rules** → credited in the artifact; listed for the record, not for routing.
- **Waiver candidates** → the second human round, each with the claim it rests on.

Digest: obligation, new-hole, re-ground, waiver-candidate, and pre-discharged counts, with every rule accounted for in `gate.evaluated`.
