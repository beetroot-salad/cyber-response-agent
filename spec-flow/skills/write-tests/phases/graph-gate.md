# Phase D — materialize the graph, run the gate (steps 5–6)

## Topology

- Two leaves in sequence. The orchestrator routes the residue afterwards; it produces none of this — assembly is a leaf's job, never the spine's.
- **Assembler leaf** (Opus, xhigh effort): inputs = `10-brief.md`, `20-demands.md`, `45-dispositions.md`. Outputs: `spec_graph_<slug>.yaml` at its final committed path (the profile's `specGraph.artifacts` names the directory — it is a deliverable, not plumbing) plus `50-graph-digest.md`.
- **Gate leaf** (Sonnet — the R1–R5 triggers are computed by `spec-graph gate`, so this leaf annotates and judges rather than re-derives; Opus here re-buys what the tool already knows): inputs = the assembled artifact. Outputs: the gate record written into the artifact, plus `60-residue.md`.

## Charge — the assembler

Read **references/schema.md** (the graph language) and **references/rules.md**, "The artifact" (the file's shape), before starting.

Resolve every `binds:` target. Resolution is what pulls boundaries, facets, and edges into the graph — at spec time the delta *is* demand-implied structure; change kinds (add/remove/modify) are assigned from the design, not from a code diff (rules.md, "Procedure"). Fill every invariant field or set it to `unknown` — an `unknown` is a finding, never a silent null. Then attach the grounded neighborhood from the brief: the co-writers, sibling constraints, and consumers that reality imposes and no demand asked for.

**Reconcile names before the join:** grounding, demand extraction, and the dispositions' address derivations coin ids and axis names independently — unify boundary ids (key by role+origin) across all three coining passes, and declare every axis once in the artifact's `axes:` list; a `key_axes`/`interpolates` member outside that list is an R0 finding. Seed the `claims:` block with every claim the three input frontiers raised, inherited entries keeping their ids.

Digest-frontier inventory: `{demands: n, claims: n, boundaries: n, unknowns: n}`, `inputs` echoing all three input counts — every demand, claim, and consensus assertion from the inputs is present in the artifact or named as a drop.

## Charge — the gate leaf

Read **references/rules.md** in full. The rules are **guaranteed question-generators**: a lens *might* ask the two-writer collision question; the rule makes sure it is asked, every run — and for R1–R5 the asking is now mechanical. Start with:

```
spec-graph gate <artifact> --residue
```

That prints every slot-computed firing (rule, element, reason) plus the R0 formal findings (dangling addresses, unregistered axes, unheard `unknown`s). Your work is what the tool cannot do: write each firing's **witness** (the concrete element and the missing demand, one sentence), classify its route into the typed residue below, and run the three **judgment halves** the tool only demands entries for — R0's bidirectional prose reconciliation (a normative design sentence binding no element; a delta element tracing to no sentence), R5's tightening/safe-by-construction extension, and R6's chooser/sanitizer walk over every rendered sink. Do not re-derive the computed triggers by hand, and do not trim the tool's list — a firing you disagree with is a `fired: false` that must cite its claim, never a deletion.

Record each rule's outcome — fired or clean — in the artifact's `gate.evaluated`: a rule with no entry reads as skipped, and the cold reconciler cannot tell a quiet rule from a forgotten one. Before writing the frontier, re-run `spec-graph gate <artifact>` (no flag) — it must exit clean or every remaining finding must be a residue entry you routed on purpose.

**Every spend-point cites its claim.** A `fired: false`, a waiver's rationale, a pre-discharge credit, a `binds_waivers`/`exercise_waivers`/`actor_waivers` entry, or a hole resolved as "not reachable / cannot be built unsafe" closes only by citing a ledger claim id of the matching kind with an executed probe (rules.md, "Probed claims") — a plausible sentence in one of those slots is exactly what hardens a blind spot into a green suite. Reachability claims are break-attempts and only ever `unrefuted`; a design that needs the universal *confirmed* routes to a safe-by-construction demand instead — enforced, not believed. A spend-point whose claim does not exist yet becomes a probe obligation in the residue, not a citation-shaped sentence.

Write the residue **typed** (definitions in rules.md; one hit can take more than one route), one entry per hit with the route pre-labelled, because the orchestrator routes this file without re-deriving it:

- **Test obligations** → to be minted as executable demands — kind and binds from the rule's obligation, witness prose included (it seeds the test's docstring in phase E); the human reviews the minted list at §7.
- **Design holes** → §7, the human. But mark fact-shaped `unknown`s (a knob's default, a key read off the resource — anything an agent can look up) `route: re-ground` — the orchestrator dispatches a lookup leaf first; §7 is for decisions, not lookups.
- **Pre-discharged rules** → credited in the artifact; listed for the record, not for routing.
- **Waiver candidates** → §7.

Residue inventory: `{obligations: n, holes: n, re_grounds: n, waiver_candidates: n, pre_discharged: n}` with every rule accounted for in `gate.evaluated`.
