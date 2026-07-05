---
name: write-tests
description: "Turn an approved design into an executable spec — end-to-end tests that pin the observable behavior the design promises, so 'tests green' means 'code follows intent.' Independently enumerate failure modes as cheap test stubs, diff them to surface the ambiguities a human must resolve, then author one binding, seam-bound suite that drives the real entry point against declarative fault-injection fakes. Use after a design is approved and before the implementation is written — the tests are the spec the code is coded against, and the tests-only diff is the reviewable artifact."
argument-hint: "[design doc path or issue #]"
---

# Write tests

The e2e tests are the spec. Natural-language design is ambiguous; this phase converts it into something executable, so "tests green" means "the code follows intent." Run it after the design is approved and before the implementation exists — the tests are written against the contract, not mirrored from code that isn't there yet.

Two limits stay in view throughout. Tests pin **observable behavior**: green means the enumerated behavior holds, not that the code is correct — the human PR review is still essential. And because the suite is written before the code, it must be an **independent** encoding of intent; the moment it silently assumes what the code will do, it stops being a spec and becomes a mirror.

Write the suite in a **dedicated git worktree** — confirm you are on one before starting, and create one if not. The deliverable is a tests-only diff (step 7); an isolated worktree keeps it off the main checkout and clean to hand off.

## 1. Frame the target

Restate the contract under test: the entry-point signature, its dependencies, and the observable surface — outputs written, return value, raised errors, side effects.

Pin the **return-value contract first — it is decision #0.** If the design left it unspecified, resolve it before anything else; every scenario's assertions depend on it. Left unpinned, each author invents a different result shape and nothing aligns.

**Ground the frame in what already exists.** The independence rule bars assuming what the *not-yet-written target* will do — not learning how the world it runs in behaves; those are different, and conflating them leaves the catalog full of *plausible* faults instead of *real* ones. Establish two kinds of ground truth before enumerating. The actual signature and enforced rules of existing code the change extends or must reach **parity** with — read it, don't infer it (e.g. what `decide_read` already denies, before a second read surface lands beside it). And the real behavior of any external tool or library the entry point drives — how it *actually* parses its input and fails — established by launching an **Explore agent** or reading its docs, never enumerated against your prior of the tool (a security gate over `jq` argv has to be built against how jq actually bundles flags, not how you assume it does). Grounding in already-shipped code and real tool semantics is mandatory; only assuming the *target's* future choices is the mirror trap.

## 2. Enumerate failure modes — independently, cheap

The catalog is a fault taxonomy, not a happy-path list: dependency errors (transient, permanent, timeout, malformed response), bad input (empty, missing, malformed, duplicate), partial failure, ordering, re-run / idempotency, and output-side I/O failure.

That taxonomy is **addition-shaped** — faults injected into behavior the code performs. When the design instead **subtracts or restricts** a capability (drops a surface, tightens a scope, removes a default), add two rows the injection lenses structurally miss. **Safe-by-construction:** if a field's default is safe for some callers and unsafe for a security-critical one, pin that the critical caller *cannot be constructed in the unsafe state* — assert the constructor raises, not merely that it behaves when configured right. **Orphaned consumers:** enumerate every existing workflow that ran through the removed surface — including the non-obvious ones a signature search won't surface: read the prompts and call-sites that invoked the removed verb (a prompt line reading "grep, not index" names a consumer of grep) — and pin that each still completes via its substitute. A suite that tests only the new restriction ships silent regressions of everything the old surface quietly served.

Fan out **4 cheap, independent enumerators** (e.g. Haiku), **one lens each** — independence comes from perspective, not just sampling; identical prompts converge on the same blind spots. Three lenses are near-universal: **dependency** (what each dependency can do to you), **input surface** (empty, missing, malformed, duplicate), and **lifecycle/state** (re-run / idempotency, crash-resume, partial failure, ordering). The fourth slot goes to whichever lens the design's shape makes most dangerous: **adversarial input** (the default in this repo — alert data is attacker-influenced by definition, and malicious input is well-formed on purpose), **environment/resource** (disk full, permissions, missing or malformed config, quotas, clock), or **concurrency**, promoted out of lifecycle when the design admits parallel invocation. Weight the set toward the design's danger zones: across the two authoring runs that shaped this skill, every fork a lensed ensemble recovered over an identical one came from the **lifecycle/side-effect** and **numeric-boundary** lenses — where ordering, aliasing, and off-by-one branches hide — while the dependency and input lenses mostly reproduced what a generic prompt already finds. The universal three earn their place on coverage; expect the incremental *fork* recovery to come from the danger-zone lens you add for this design. Prompt every enumerator to an **actively adversarial** posture: its job is to *break* the contract — find the input, spelling, ordering, or path that slips past the obvious implementation — not to catalog the faults a correct implementation already handles. Adversarial-and-grounded is the pairing that pays: grounded in the real tool and the sibling code (§1), an adversarial lens enumerates the bundled flag or the parity gap the surface actually admits; ungrounded, the same lens only invents scary-sounding inputs that map to nothing. Each enumerator emits **test stubs only — signature + docstring, no body:**

```python
def test_transient_enrich_error():
    """one enrich() raises a transient error → event skipped, others written, ProcessResult.failed == 1"""
    # rejected: retry with backoff; abort the whole batch
    ...
```

The docstring names the injected fault and the expected observable outcome. Stubs are the right altitude: no body means they can't drift into re-implementing the logic, they parse trivially, and each *is* a catalog row in the exact shape the author later fills. Independence is the whole point — decorrelated derivations catch blind spots a single author rationalizes away.

When a stub's outcome is a judgment call, carry a `# rejected: <alternative>` comment naming the branch(es) not taken. This is the decision channel. Without it, a silently-chosen branch leaves no trace it was ever a choice, and the diff cannot tell a real agreement from the authors independently guessing the same obvious branch.

Include the strong author as one of the derivations — not as garnish. The strong author stays **unlensed** — the generalist that catches what the narrow lenses structurally can't. In the authoring run that shaped this skill, the cheap peer ensemble converged on the majority branch and manufactured false consensus exactly where the non-obvious branch was the right one; the strong author is the derivation best placed to take and name that minority branch. Expect the cheap ensemble to surface forks where the outcome word differs or someone hedges — don't count on it to surface a fork that survives only as the road not taken.

## 3. Diff to surface ambiguity

A separate agent compares the stubs, aligned by **injected fault** (not by test name), and classifies each fault:

- **Fork** — same fault, materially different expected outcome across authors. This is the payoff: a real ambiguity, made visible.
- **Silent branch** — one author's docstring flags the fault as open (a hedge, or a `# rejected:` line); another states one outcome as settled. The dangerous kind — it looks resolved from inside any single suite.
- **Gap** — a fault only one author thought of. Candidate addition to the union. Under lensed enumeration gaps are the norm, not a smell — a lens seeing what the others structurally can't is the lens working.
- **Consensus** — same expected outcome across every author who enumerated the fault. Auto-accept — *unless* the strong author's derivation or a `# rejected:` line marks the fault as a decision, in which case treat it as a fork despite the agreement. Peers guessing the same obvious branch is not evidence the branch is right.

**Lens-completeness check.** Because each lens sees only its region, a cross-cutting fault can fall *between* lenses and be missed by the whole cheap ensemble — in both authoring runs one such item (a dependency-error-classification question; a `replay_incompatible` case) slipped every lens and was caught only by the unlensed strong author. So the diff names, explicitly, any fault no lens owned and any region no lens covered, and routes those to the strong author's derivation or a follow-up lens. A fork only the strong author raised is the backstop working, not an anomaly.

One region counts as uncovered until checked by name: **any resource class reachable through more than one surface** — a file both the read tool and a bash reader can open, a value both an API and a CLI can set. Grounding (§1) makes each surface legible on its own, but *parity is a separate step*: enumerate the constraints the **established** surface enforces (denylist, clamp, confine, rate-limit) and pin, as an explicit **parity row**, that the **new** surface enforces every one of them. A constraint pinned on one surface but silently absent on its sibling is the canonical fail-open — and it hides precisely because each surface, read alone, looks correct.

## 4. Resolve forks with the human

Surface the forks — silent branches are forks, just harder-won — highest implementation-impact first, and resolve them (AskUserQuestion, your recommendation first). This is where human attention is spent and where it earns its keep: a handful of decisions that dictate what the code must do. Gaps join the catalog: auto-accept a gap whose outcome is uncontroversial, treat it as a fork when the outcome is a judgment call. Consensus scenarios pass through untouched. The resolved catalog is the spec.

## 5. Author the binding suite

One strong author turns the resolved catalog into the real suite. Survey the project's existing test machinery first and build on it — a harness that already fakes a dependency (e.g. `defender/tests/e2e/_replay_harness.py`: "a new scenario is a few lines of `Turn(...)` against this harness, not a fresh copy of the plumbing") is the starting point; write fresh fakes only for dependencies it doesn't cover. Then:

- **Declarative fault-injection fakes** — one fake per dependency, driven by a data fault-spec (`fail_on`, `raise_after`, `malformed`, `delay`). Faults are data, not bespoke per-test mocks. The fake injects faults **only** — it never classifies or decides policy; that is the job of the code under test, and a fake that decides has smuggled in the answer. Fakes enter through the entry point's injection seams (a deps parameter, a constructor argument), never `monkeypatch.setattr` — this repo's CI ratchets new setattr sites (`scripts/lint/lint_monkeypatch.py`). If the design gives a dependency no seam, the seam is part of the contract — pin it back in step 1.
- **One test per resolved scenario**, driving the **real entry point** against the fakes.
- **Assert observable outcomes only** — output contents, return value, raised errors, recorded seam calls. Never reach into internals.
- **Guarded negative assertions.** Any design clause phrased as "must not" — a confinement, a dropped capability, an idempotency guarantee — needs a test that pins the *absence*: the denied content never appears in observable output via **any** surface; the skipped item was not written; the re-run did not double-write. Positive-only suites drift toward "the allowed path works" and leave the forbidden path unpinned — which is how a fail-open ships green. But a bare negative passes vacuously (`assert secret not in out` is also green when `out` is empty or the fake never ran), so pair every negative with a **positive control** that proves the mechanism fired and the content was real and leakable — the same bytes *are* returned through the sanctioned path — so the negative fails for the right reason.

## 6. Gate before handing off

Reject or repair any test that fails these. They are not style — they are what makes a test bind:

- The file **parses**, and every import except the not-yet-written target resolves. The target's import failing is the expected red before the implement phase; do not repair it by committing skeleton source — the deliverable stays a tests-only diff.
- Every test **actually calls the target symbol.** No test that re-implements the logic in its own body, and no test that asserts on a value it constructed itself. A cheap author will happily produce a full-looking suite that never calls the target and therefore tests nothing — gate against it mechanically (AST check: each test calls the entry point directly, or via a helper in the same file whose body does — repair a failure by inlining the call, never by loosening the check).
- Assertions sit at observable seams; fakes inject faults, not policy. A negative ("must not") assertion carries a positive control, or it passes vacuously and binds nothing.

## 7. Hand off

Deliver the suite as a **tests-only diff** — the reviewable spec artifact — plus a short record of the forks resolved and how. This is what the implement phase codes against and what the human reviews *as the spec*. Green means the enumerated behavior holds: it is the guardrail that lets the later review/refactor phase move aggressively, not a proof of correctness.
