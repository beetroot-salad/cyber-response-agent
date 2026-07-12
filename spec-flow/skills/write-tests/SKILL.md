---
name: write-tests
description: "Turn an approved design into an executable spec — a demand list bound to a spec-coverage graph, realized as end-to-end tests, so 'tests green' means 'code follows intent.' Gate rules over the graph compute the known blind-spot shapes instead of relying on the author to remember them. Use after a design is approved and before the implementation is written — the tests + spec_graph are the spec the code is coded against, and the tests+spec_graph-only diff is the reviewable artifact."
argument-hint: "[design doc path or issue #]"
effort: xhigh
---

# Write tests

The demand list is the spec; the e2e tests are its executable form. A natural-language design fails three ways — **ambiguity** (two defensible readings), **incompleteness** (a case it never mentions), **incorrectness** (code that diverges from it) — and this flow instruments all three: independent enumeration plus diffing catches ambiguity (steps 3–4), the spec-coverage graph and its gate rules *compute* the known incompleteness shapes (steps 5–6), and the binding suite catches incorrectness (step 8). The known blind-spot shapes — an unread outbound payload, a shared-sink collision, an undersampled config domain, a missing parity row, an orphaned consumer — are detected by rules over the graph rather than carried in the author's head: prose lessons fail exactly when recall fails (#534 shipped two bug classes whose lessons were already written down, via #533).

Two limits stay in view. Tests pin **observable behavior**: green means the resolved demands hold, not that the code is correct — the human PR review is still essential. And the suite must be an **independent** encoding of intent: grounded in existing reality (sibling code, real tool semantics), never in assumptions about what the not-yet-written target will do.

Two references carry the depth; read each when the flow first needs it: **references/schema.md** (the graph language — layers, facets, addresses, slot discipline) before step 1 — its "Extraction contract" defines the grounding brief — and **references/rules.md** (the gate rules, the spec_graph artifact) before step 5.

The **project profile** — `.claude/spec-flow.json` in the repo you are working in — carries what this skill deliberately does not hardcode: the test harness to build on, the injection idioms the project's CI enforces, how to invoke the spec_graph checks, and the project's danger lens (step 3's fourth slot). Read it before step 3. If it is missing, run `/spec-flow:init` first; the flow below assumes it.

Scale the ceremony to the delta. When the design touches no shared sink, removes nothing, and yields only a handful of demands, run two lenses plus the strong author, align the stubs yourself (step 4 collapsed), and keep the graph to the touched neighborhood — recording the reduced mode in the artifact's `handoff.deviations`. The gate rules always run; over a small graph they are cheap.

## 0. Work in a dedicated worktree

Write the spec in a **dedicated git worktree** — confirm you are on one before starting, and create one if not. The deliverable is a tests + spec_graph diff (step 10); an isolated worktree keeps it off the main checkout and clean to hand off.

## 1. Launch grounding first

One shared **Explore agent**, launched before anything else — it is slow and shared, and step 2 (which needs only the design) runs while it works. The lensed enumerators of step 3 **block on the finished brief**: ungrounded enumeration is precisely the failure mode step 3 warns about, so don't launch them early to save minutes. Its output is the structure-layer *neighborhood* the change will attach to — prompt the agent from schema.md's "Extraction contract", not from memory of it, and require the brief to say, per shared root and removed verb, *how* each writer and consumer list was established (the search it ran): extraction completeness is the gate's single point of failure — an element the brief misses is invisible to every rule (schema.md). Include the change's **execution contexts** in that census — not just in-process callers but the CLI/harness/eval entrypoints that re-run it, since a subprocess re-exec can relocate a `PATHS`-style constant the guards trust; `check_actors` (step 9) is the mechanical net under the execution-context slice of this hole, but only for contexts the brief thought to reach. Facts only, no judgments — the brief is the one thing the ensemble deliberately shares: facts anchor far less than framings, and a fact left to one enumerator's initiative is a coverage lottery.

## 2. Extract demands — the spec proper

Read the design. Every normative sentence becomes a demand — `{kind, form, outcome: {nl: "<full sentence>"}, binds: [<addresses>]}` — or is explicitly classified background; a sentence may not fall in between. Mark a demand `form: test` unless you are deliberately deferring it to prose (`form: clause`) — a clause does not discharge a gate obligation (rules.md), so the downgrade is a recorded choice, never a default. The **return-value contract is demand #0**: resolve it before anything else — every scenario's assertions depend on it, and left unpinned each author invents a different result shape. When the design's own return sentence is ambiguous, #0 is itself the first fork: pin a provisional reading, flag it, and carry it to step 7 — never let each author resolve it silently. Addresses follow schema.md's address forms; don't force a doubtful target to resolve — a dangling address is R0's job to flag, not yours to paper over.

## 3. Enrich adversarially — independently, cheap

The design is silent about most of what can go wrong; enumeration supplies the missing demands. The catalog is a fault taxonomy, not a happy-path list: dependency errors (transient, permanent, timeout, malformed response), bad input (empty, missing, malformed, duplicate), partial failure, ordering, re-run / idempotency, output-side I/O failure.

Fan out **4 cheap, independent enumerators** (e.g. Haiku), **one lens each** — independence comes from perspective, not sampling; identical prompts converge on the same blind spots. Three lenses are near-universal: **dependency** (what each dependency can do to you), **input surface** (empty, missing, malformed, duplicate), and **lifecycle/state** (re-run / idempotency, crash-resume, partial failure, ordering). The fourth slot goes to the design's danger zone: **adversarial input** (well-formed on purpose — the input that slips past the obvious check), **environment/resource** (disk full, permissions, missing or malformed config, quotas, clock), or **concurrency**, promoted out of lifecycle when the design admits parallel invocation. The profile's `conventions.dangerLens` names the project's standing default — take it unless *this* change's danger zone is plainly elsewhere. Prompt every enumerator to an **actively adversarial** posture: the job is to *break* the contract — find the input, spelling, ordering, or path that slips past the obvious implementation. Adversarial-and-grounded is the pairing that pays: anchored to the step-1 brief, the lens enumerates faults the surface actually admits; ungrounded, it invents scary-sounding inputs that map to nothing. Each enumerator emits **test stubs — signature + docstring, no body:**

```python
def test_transient_enrich_error():
    """one enrich() raises a transient error → event skipped, others written, ProcessResult.failed == 1"""
    # rejected: retry with backoff; abort the whole batch
    ...
```

Stubs are demand candidates: the docstring names the fault (a domain member, a payload, an interleaving) and the expected observable outcome; the addresses it implies are extracted in step 4. When the outcome is a judgment call, a `# rejected: <alternative>` comment names the branch(es) not taken — without it, a silently-chosen branch leaves no trace it was ever a choice.

Include the strong author as one derivation — **unlensed**, on a **frontier model (Opus); do not economize here.** A blind A/B over this skill's prose-lens predecessor found the cross-cutting, grounding-dependent faults capability-dominated — the finding attaches to this enrichment step, which survives here structurally unchanged: cheap lenses miss them at any skill quality, and only a frontier backstop recovers them reliably. The graph rules (step 6) compute the *known* pit shapes; the strong author covers the unknown ones and the misclassified seams — the two mechanisms are complements, not substitutes. The strong author is also explicitly charged with the brief's edges: hunt for elements the grounding pass may have missed (a co-writer, a consumer, a surface the brief looks thin on) — an element absent from the graph is invisible to every rule, and this derivation is the only net under that hole. If a frontier author genuinely cannot be spawned (budget, availability), do not silently substitute a weaker one: run the best derivation you can, and **record in the artifact's `handoff.deviations` that the unknown-unknown region ran degraded** — the reviewer's attention shifts to exactly that region.

## 4. Diff by address

A separate agent — cheap is fine; the job is alignment, not authorship — first derives each stub's implied address(es) (schema.md's address forms; coin ids by role+origin), then aligns the stubs by **bound address plus concrete fault** (a domain member, a payload shape, an interleaving — not by test name, not by loose prose similarity) and classifies each. Running collapsed (no budget for a diff agent), do the alignment yourself, but only after *all* stubs are collected, and record the deviation in `handoff.deviations`:

- **Fork** — same address, materially different expected outcome. The payoff: a real ambiguity, made visible.
- **Silent branch** — one author flags the fault open (a hedge, a `# rejected:`); another states one outcome as settled. The dangerous kind — it looks resolved from inside any single suite.
- **Gap** — an address only one author bound. Under lensed enumeration gaps are the norm — a lens seeing what others structurally can't is the lens working.
- **Consensus** — same outcome across every author who bound the address. Auto-accept — *unless* the strong author or a `# rejected:` marks it a decision; peers guessing the same obvious branch is not evidence the branch is right.

**Lens-completeness check:** name any fault no lens owned and any region no lens covered, and route those to the strong author's derivation. A fork only the strong author raised is the backstop working, not an anomaly.

## 5. Materialize the address space

Resolve every `binds:` target. Resolution is what pulls Boundaries, facets, and edges into the graph — at spec time the delta *is* demand-implied structure; change kinds (add/remove/modify) are assigned from the design, not from a code diff (rules.md, "Procedure"). Fill every invariant field or set it to `unknown` — an `unknown` is a finding, never a silent null. Then attach the grounded neighborhood from step 1: the co-writers, sibling constraints, and consumers that reality imposes and no demand asked for. **Reconcile names before the join:** grounding and demand extraction coin ids and axis names independently — unify boundary ids (key by role+origin) and declare every axis once in the artifact's `axes:` list; a `key_axes`/`interpolates` member outside that list is an R0 finding. The result is the `spec_graph_<issue-or-slug>.yaml` artifact (rules.md, "The artifact").

## 6. Run the gate

Execute every rule in rules.md over the join of demands × structure, and record each rule's outcome — fired or clean — in the artifact's `gate.evaluated`: a rule with no entry reads as skipped, and the reviewer cannot tell a quiet rule from a forgotten one. The residue is **typed** (definitions in rules.md; one hit can take more than one route):

- **Test obligations** → mint each as an executable demand — kind and binds from the rule's obligation, outcome from its witness — and add it to the list step 7 reviews; the artifact links obligation to demand via `discharged_by`.
- **Design holes** → step 7, the human. But re-ground fact-shaped `unknown`s first (a knob's default, a key read off the resource — anything an agent can look up): step 7 is for decisions, not lookups.
- **Pre-discharged rules** → credit them; don't re-litigate.
- **Waiver candidates** → step 7.

## 7. Resolve with the human

Surface the forks and silent branches (step 4) together with the design holes and obligation-minted demands (step 6), highest implementation-impact first (AskUserQuestion, your recommendation first). This is where human attention earns its keep: a handful of decisions that dictate what the code must do. Gaps: auto-accept the uncontroversial, fork the judgment calls. A declined obligation is recorded as `Demand {form: waiver}` in the artifact — an examined no, never a silence. If the #0 provisional reading flipped, re-derive before step 8: restate every stub and demand outcome minted under the provisional shape in the resolved shape — the author must never receive outcomes written against a rejected contract. The resolved demand list — design-extracted, enrichment-derived, and obligation-minted alike — is the spec.

## 8. Author the binding suite

One strong author turns the resolved demands into the real suite. Survey the project's existing test machinery first and build on it — a harness that already fakes the dependencies is the starting point, so a new scenario is a few lines of data, not fresh plumbing; the profile's `tests.harness` names it. Then:

- **Declarative fault-injection fakes** — one fake per dependency, driven by a data fault-spec (`fail_on`, `raise_after`, `malformed`, `delay`). The fake injects faults **only** — it never classifies or decides policy. Fakes enter through the entry point's injection seams (a deps parameter, a constructor argument), never by monkey-patching an attribute out from under the target — the profile's `tests.idioms` records what the project's CI enforces here. If the design gives a dependency no seam, the seam is part of the contract — pin it as a demand.
- **Fakes record what they receive.** A payload (`kind: shape`) demand asserts on the *captured inbound payload* against the facet's invariants — the obligation carries the assertion content (rules.md R1) — not on the fake's canned response. A fake that only returns answers leaves the entire outbound channel unpinned.
- **One test per executable demand**, driving the **real entry point** against the fakes; assert observable outcomes only — output contents, return value, raised errors, recorded seam calls.
- **Every `kind: negative` demand is paired with its positive control** — on the same address, under the complementary condition (schema.md) — proof the mechanism fired and the observation channel can see the difference. The control takes the shape of the negative: for a redaction, the same bytes *are* returned through the sanctioned path; for a denied action, the allowed variant succeeds; for an absent artifact, the substitute workflow demonstrably completes. And a negative binds **every surface the content could reach** — each of the actor's out-edges (outputs, traces, error messages), not just the obvious one; an unbound surface is exactly where the leak ships. A bare negative passes vacuously (`assert secret not in out` is also green when `out` is empty).

## 9. Gate mechanically

Reject or repair any test that fails these — they are what makes a test bind, not style:

- The file **parses**, and every import except the not-yet-written target resolves. The target's import failing is the expected red; do not repair it by committing skeleton source.
- **AST check: every test calls the target symbol** — directly, via a helper in the same file whose body does, or by driving an object a call to the target returned (constructor → handle counts; a test that touches neither the target nor anything it produced tests nothing). Repair by inlining the call, never by loosening the check. And no test asserts only against a value its own body computed — the expected side of every assertion traces to the demand or a fixture, never to a re-implementation of the target's logic.
- **Assertions sit at observable seams; fakes inject faults, not policy.** Reject a fake that classifies or decides (any branching beyond returning its spec'd fault) and any assertion that reaches into internals.
- **Every executable demand has its test; every gate obligation is discharged** — by a demand or a recorded waiver — in the artifact, and every rule has its `gate.evaluated` entry.
- **Every negative has its paired positive control**, and binds (or explicitly waives) each of its actor's out-edges.
- **The spec_graph checks pass** — `spec-graph binds <artifact>` and `spec-graph actors <artifact> --base <base>`. (`spec-graph` is on your PATH: the plugin ships it. It finds its own scripts and a PyYAML interpreter; you do not configure either.) `check_binds` flags a concept threaded in a demand's `outcome` prose (`salt=deps.salt`) but absent from its `binds` — an assertion step 8's test then silently drops: **bind the concept** so the test must assert it, or record a conscious `binds_waivers:` entry. `check_actors` derives from the CODE — not the design — every CLI/harness/eval entrypoint that drives a changed module, especially a **subprocess re-exec that relocates a `PATHS`-style anchor constant onto a different tree**, and flags any the graph's `actors` don't model: model the context as an actor — modelling it surfaces its hidden axes, which is where the bug hides — or `actor_waivers:` an out-of-scope one, but never silence a re-exec driver to go green. These cover the prose⊄binds and execution-context slices; the input-partition slice (a guard's invalid domain modelled as one bucket) is NOT graph-mechanizable — it wants property-based / mutation testing at impl time (write-code-from-spec §2).
- **Formal slots validate** against schema.md's closed vocabularies: no free text in a query-evaluated slot, no assertion depending on an `nl:` slot. (The closed-vocabulary slot check stays hand-checked until the rest of the #537 linter lands; record in `handoff.deviations` that this slice was manual.)

## 10. Hand off

Deliver two things: the diff, and the note.

**The diff** is **tests + spec_graph only**: the suite with `spec_graph_<issue-or-slug>.yaml` beside it. The artifact's `handoff:` section carries the record — the forks and how they were resolved, the holes and waivers, the deviations (degraded author, collapsed diff, manual slot check, reduced small-delta mode) — and its `base:` field records the commit the spec branch forked from, so write-code-from-spec's gate can find its range. Commit it and get it reviewed **before the implementation exists** — write-code-from-spec refuses to start otherwise. That process gate is the precondition for everything above: #527 and #534 both co-committed tests+impl in one change, and #534 shipped bug classes whose lessons were already encoded — no spec text bites in a phase that isn't run. Green means the resolved demands hold: the guardrail that lets the later review/refactor phase move aggressively, not a proof of correctness.

**The note** is the baton. `write-code-from-spec` starts *cold* — a fresh session that never saw this one — and the issue thread is the only channel between you, so end by running the `handoff` skill against the issue (it posts the note as an issue comment). The artifact records *what the spec says*; the note records what a fresh implementer cannot recover by reading the diff: the branch and the base commit the spec forked from, the forks the human resolved and which reading they picked, anything that ran degraded, and the single next action. One dense paragraph — the handoff skill's own discipline applies.

Write it **for the implementer, not the reviewer.** `write-code-from-spec` reads it; `review` deliberately does not. A reviewer who has read why every choice was made is anchored by that rationale and will confirm it rather than test it — the review's whole value is meeting the code cold. Keep the reasoning in the note and the artifact, where the implementer needs it, and let the review find what it finds.
