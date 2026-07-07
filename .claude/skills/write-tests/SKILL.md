---
name: write-tests
description: "Turn an approved design into an executable spec — a demand list bound to a spec-coverage graph, realized as end-to-end tests that pin the observable behavior the design promises, so 'tests green' means 'code follows intent.' Extract demands from the design, enrich them with independent adversarial enumerators, materialize the address space they bind to, and run gate rules that COMPUTE the known blind-spot shapes (unread payloads, shared-sink collisions, undersampled domains, missing parity, orphaned consumers) instead of relying on the author to remember them. Use after a design is approved and before the implementation is written — the tests + spec_graph are the spec the code is coded against, and the tests+spec_graph-only diff is the reviewable artifact."
argument-hint: "[design doc path or issue #]"
---

# Write tests

The demand list is the spec; the e2e tests are its executable form. A natural-language design fails three ways — **ambiguity** (two defensible readings), **incompleteness** (a case it never mentions), **incorrectness** (code that diverges from it) — and this flow instruments all three: independent enumeration plus diffing catches ambiguity (steps 3–4), the spec-coverage graph and its gate rules *compute* incompleteness (steps 5–6), and the binding suite catches incorrectness (step 8). The known blind-spot shapes — an unread outbound payload, a shared-sink collision, an undersampled config domain, a missing parity row, an orphaned consumer — are detected by rules over the graph, never carried in the author's head: prose lessons fail exactly when recall fails (#527 and #534 each shipped bug classes whose lessons were already written down).

Two limits stay in view. Tests pin **observable behavior**: green means the resolved demands hold, not that the code is correct — the human PR review is still essential. And the suite must be an **independent** encoding of intent: grounded in existing reality (sibling code, real tool semantics), never in assumptions about what the not-yet-written target will do.

Two references carry the depth; read each when the flow first needs it: **references/schema.md** (the graph language — layers, facets, addresses, slot discipline) before step 2, and **references/rules.md** (gate rules R0–R5, the spec_graph artifact) before step 5.

## 0. Work in a dedicated worktree

Write the spec in a **dedicated git worktree** — confirm you are on one before starting, and create one if not. The deliverable is a tests + spec_graph diff (step 10); an isolated worktree keeps it off the main checkout and clean to hand off.

## 1. Launch grounding first

One shared **Explore agent**, launched before anything else — it is slow and shared, and step 2 (which needs only the design) runs while it works. The lensed enumerators of step 3 **block on the finished brief**: ungrounded enumeration is precisely the failure mode step 3 warns about, so don't launch them early to save minutes. Its output is the structure-layer *neighborhood* the change will attach to (schema.md, "Extraction contract"): every shared root the change touches with **all** its writers (path templates and the axes they interpolate); every sibling surface with the constraints it enforces; the consumers of anything the design removes — found by reading the prompts and call-sites that invoke the removed verb (a prompt line reading "grep, not index" names a consumer of grep), never by a signature grep; the real semantics of every external tool the entry point drives (run its `--help`, read its docs — priors don't count); and every config knob with its domain, default, and documented alternatives. Facts only, no judgments — the brief is the one thing the ensemble deliberately shares: facts anchor far less than framings, and a fact left to one enumerator's initiative is a coverage lottery.

## 2. Extract demands — the spec proper

Read the design. Every normative sentence becomes a demand — `{kind, outcome: {nl: "<full sentence>"}, binds: [<addresses>]}` — or is explicitly classified background; a sentence may not fall in between. The **return-value contract is demand #0**: resolve it before anything else — every scenario's assertions depend on it, and left unpinned each author invents a different result shape. When the design's own return sentence is ambiguous, #0 is itself the first fork: pin a provisional reading, flag it, and carry it to step 7 — never let each author resolve it silently. Addresses follow schema.md's address forms; don't force a doubtful target to resolve — a dangling address is R0's job to flag, not yours to paper over.

## 3. Enrich adversarially — independently, cheap

The design is silent about most of what can go wrong; enumeration supplies the missing demands. The catalog is a fault taxonomy, not a happy-path list: dependency errors (transient, permanent, timeout, malformed response), bad input (empty, missing, malformed, duplicate), partial failure, ordering, re-run / idempotency, output-side I/O failure.

Fan out **4 cheap, independent enumerators** (e.g. Haiku), **one lens each** — independence comes from perspective, not sampling; identical prompts converge on the same blind spots. Three lenses are near-universal: **dependency** (what each dependency can do to you), **input surface** (empty, missing, malformed, duplicate), and **lifecycle/state** (re-run / idempotency, crash-resume, partial failure, ordering). The fourth slot goes to the design's danger zone: **adversarial input** (the default in this repo — alert data is attacker-influenced by definition, and malicious input is well-formed on purpose), **environment/resource** (disk full, permissions, quotas, clock), or **concurrency**, promoted out of lifecycle when the design admits parallel invocation. Prompt every enumerator to an **actively adversarial** posture: the job is to *break* the contract — find the input, spelling, ordering, or path that slips past the obvious implementation. Adversarial-and-grounded is the pairing that pays: anchored to the step-1 brief, the lens enumerates faults the surface actually admits; ungrounded, it invents scary-sounding inputs that map to nothing. Each enumerator emits **test stubs — signature + docstring, no body:**

```python
def test_transient_enrich_error():
    """one enrich() raises a transient error → event skipped, others written, ProcessResult.failed == 1"""
    # rejected: retry with backoff; abort the whole batch
    ...
```

Stubs are demand candidates: the docstring names the fault (a domain member, a payload, an interleaving) and the expected observable outcome; the addresses it implies are extracted in step 4. When the outcome is a judgment call, a `# rejected: <alternative>` comment names the branch(es) not taken — without it, a silently-chosen branch leaves no trace it was ever a choice.

Include the strong author as one derivation — **unlensed**, on a **frontier model (Opus); do not economize here.** A blind A/B over this skill found the cross-cutting, grounding-dependent faults capability-dominated: cheap lenses miss them at any skill quality, and only a frontier backstop recovers them reliably. The graph rules (step 6) compute the *known* pit shapes; the strong author covers the unknown ones and the misclassified seams — the two mechanisms are complements, not substitutes. If a frontier author genuinely cannot be spawned (budget, availability), do not silently substitute a weaker one: run the best derivation you can, and **say in the handoff record that the unknown-unknown region ran degraded** — the reviewer's attention shifts to exactly that region.

## 4. Diff by address

A separate agent — cheap is fine; the job is alignment, not authorship — aligns the stubs by **bound address plus fault member** (not by test name, not by prose fault description) and classifies each. Running collapsed (no budget for a diff agent), do the alignment yourself, but only after *all* stubs are collected, and note the deviation in the handoff:

- **Fork** — same address, materially different expected outcome. The payoff: a real ambiguity, made visible.
- **Silent branch** — one author flags the fault open (a hedge, a `# rejected:`); another states one outcome as settled. The dangerous kind — it looks resolved from inside any single suite.
- **Gap** — an address only one author bound. Under lensed enumeration gaps are the norm — a lens seeing what others structurally can't is the lens working.
- **Consensus** — same outcome across every author who bound the address. Auto-accept — *unless* the strong author or a `# rejected:` marks it a decision; peers guessing the same obvious branch is not evidence the branch is right.

**Lens-completeness check:** name any fault no lens owned and any region no lens covered, and route those to the strong author's derivation. A fork only the strong author raised is the backstop working, not an anomaly.

## 5. Materialize the address space

Resolve every `binds:` target. Resolution is what pulls Boundaries, facets, and edges into the graph — at spec time the delta *is* demand-implied structure; there is no code to diff. Fill every invariant field or set it to `unknown` — an `unknown` is a finding, never a silent null. Then attach the grounded neighborhood from step 1: the co-writers, sibling constraints, and consumers that reality imposes and no demand asked for. The result is the `spec_graph.yaml` artifact (rules.md, "The artifact").

## 6. Run the gate

Execute rules.md R0–R5 over the join of demands × structure. The residue is **typed** — route each kind to its resolver instead of flattening everything into "write more tests":

- **Test obligations** (each carries derivable assertion content from the formal facets) → step 8.
- **Design holes** (an `unknown` invariant, an unresolvable address, a substitute that structurally can't discharge its survival demand) → step 7, the human.
- **Pre-discharged rules** (the design already stated it and step 2 extracted it) → credit them; don't re-litigate.
- **Waiver candidates** → step 7.

## 7. Resolve with the human

Surface the forks and silent branches (step 4) together with the design holes (step 6), highest implementation-impact first (AskUserQuestion, your recommendation first). This is where human attention earns its keep: a handful of decisions that dictate what the code must do. Gaps: auto-accept the uncontroversial, fork the judgment calls. A declined obligation is recorded as `Demand {form: waiver}` in the artifact — an examined no, never a silence. The resolved demand list is the spec.

## 8. Author the binding suite

One strong author turns the resolved demands into the real suite. Survey the project's existing test machinery first and build on it — a harness that already fakes a dependency (e.g. `defender/tests/e2e/_replay_harness.py`: a new scenario is a few lines of `Turn(...)`, not fresh plumbing) is the starting point. Then:

- **Declarative fault-injection fakes** — one fake per dependency, driven by a data fault-spec (`fail_on`, `raise_after`, `malformed`, `delay`). The fake injects faults **only** — it never classifies or decides policy. Fakes enter through the entry point's injection seams (a deps parameter, a constructor argument), never `monkeypatch.setattr` — this repo's CI ratchets new setattr sites (`scripts/lint/lint_monkeypatch.py`). If the design gives a dependency no seam, the seam is part of the contract — pin it as a demand.
- **Fakes record what they receive.** A payload (`kind: shape`) demand asserts on the *captured inbound payload* against the formal facet — `roles-disjoint-sources`, `all-slots-bound` — not on the fake's canned response. A fake that only returns answers leaves the entire outbound channel unpinned; that is the #534 dual-prompt escape.
- **One test per executable demand**, driving the **real entry point** against the fakes; assert observable outcomes only — output contents, return value, raised errors, recorded seam calls.
- **Every `kind: negative` demand is paired with its positive control** — proof the mechanism fired and the observation channel can see the difference. The control takes the shape of the negative: for a redaction, the same bytes *are* returned through the sanctioned path; for a denied action, the allowed variant succeeds; for an absent artifact, the substitute workflow demonstrably completes. A bare negative passes vacuously (`assert secret not in out` is also green when `out` is empty).

## 9. Gate mechanically

Reject or repair any test that fails these — they are what makes a test bind, not style:

- The file **parses**, and every import except the not-yet-written target resolves. The target's import failing is the expected red; do not repair it by committing skeleton source.
- **AST check: every test calls the target symbol** — directly, via a helper in the same file whose body does, or by driving an object a call to the target returned (constructor → handle counts; a test that touches neither the target nor anything it produced tests nothing). Repair by inlining the call, never by loosening the check.
- **Every executable demand has its test; every gate obligation is discharged** — by a demand or a recorded waiver — in the artifact.
- **Every negative has its paired positive control.**
- **Formal slots validate** against schema.md's closed vocabularies: no free text in a query-evaluated slot, no assertion depending on an `nl:` slot. (Hand-checked until a `spec_graph` linter exists — tracked in #537; say in the handoff that this check was manual.)

## 10. Hand off

Deliver a **tests + spec_graph-only diff**: the suite, `spec_graph.yaml` beside it, and a short record of the forks, holes, and waivers resolved. Commit it and get it reviewed **before the implementation exists** — write-code-from-spec refuses to start otherwise. That process gate is the precondition for everything above: #527 and #534 both co-committed tests+impl in one change, and both shipped bug classes whose lessons were already encoded — no spec text bites in a phase that isn't run. Green means the resolved demands hold: the guardrail that lets the later review/refactor phase move aggressively, not a proof of correctness.
