---
name: write-tests
description: "Turn an approved design into an executable spec — end-to-end tests that pin the observable behavior the design promises, so 'tests green' means 'code follows intent.' Independently enumerate failure modes as cheap test stubs, diff them to surface the ambiguities a human must resolve, then author one binding, seam-bound suite that drives the real entry point against declarative fault-injection fakes. Use after a design is approved and before the implementation is written — the tests are the spec the code is coded against, and the tests-only diff is the reviewable artifact."
argument-hint: "[design doc path or issue #]"
---

# Write tests

The e2e tests are the spec. Natural-language design is ambiguous; this phase converts it into something executable, so "tests green" means "the code follows intent." Run it after the design is approved and before the implementation exists — the tests are written against the contract, not mirrored from code that isn't there yet.

Two limits stay in view throughout. Tests pin **observable behavior**: green means the enumerated behavior holds, not that the code is correct — the human PR review is still essential. And because the suite is written before the code, it must be an **independent** encoding of intent; the moment it silently assumes what the code will do, it stops being a spec and becomes a mirror.

## 1. Frame the target

Restate the contract under test: the entry-point signature, its dependencies, and the observable surface — outputs written, return value, raised errors, side effects.

Pin the **return-value contract first — it is decision #0.** If the design left it unspecified, resolve it before anything else; every scenario's assertions depend on it. Left unpinned, each author invents a different result shape and nothing aligns.

## 2. Enumerate failure modes — independently, cheap

The catalog is a fault taxonomy, not a happy-path list: dependency errors (transient, permanent, timeout, malformed response), bad input (empty, missing, malformed, duplicate), partial failure, ordering, re-run / idempotency, and output-side I/O failure.

Fan out **4 cheap, independent enumerators** (e.g. Haiku), **one lens each** — independence comes from perspective, not just sampling; identical prompts converge on the same blind spots. Three lenses are near-universal: **dependency** (what each dependency can do to you), **input surface** (empty, missing, malformed, duplicate), and **lifecycle/state** (re-run / idempotency, crash-resume, partial failure, ordering). The fourth slot goes to whichever lens the design's shape makes most dangerous: **adversarial input** (the default in this repo — alert data is attacker-influenced by definition, and malicious input is well-formed on purpose), **environment/resource** (disk full, permissions, missing or malformed config, quotas, clock), or **concurrency**, promoted out of lifecycle when the design admits parallel invocation. Each enumerator emits **test stubs only — signature + docstring, no body:**

```python
def test_transient_enrich_error():
    """one enrich() raises a transient error → event skipped, others written, ProcessResult.failed == 1"""
    # rejected: retry with backoff; abort the whole batch
    ...
```

The docstring names the injected fault and the expected observable outcome. Stubs are the right altitude: no body means they can't drift into re-implementing the logic, they parse trivially, and each *is* a catalog row in the exact shape the author later fills. Independence is the whole point — decorrelated derivations catch blind spots a single author rationalizes away.

When a stub's outcome is a judgment call, carry a `# rejected: <alternative>` comment naming the branch(es) not taken. This is the decision channel. Without it, a silently-chosen branch leaves no trace it was ever a choice, and the diff cannot tell a real agreement from the authors independently guessing the same obvious branch.

Include the strong author as one of the derivations — not as garnish. The strong author stays **unlensed**: the generalist that catches what the narrow lenses structurally can't, carrying one cross-cutting brief — hunt **silent failures**, the faults whose path-of-least-resistance implementation swallows them (an error caught-and-logged while the run still reports success; partial output that looks complete). In the authoring run that shaped this skill, the cheap peer ensemble converged on the majority branch and manufactured false consensus exactly where the non-obvious branch was the right one; the strong author is the derivation best placed to take and name that minority branch. Expect the cheap ensemble to surface forks where the outcome word differs or someone hedges — don't count on it to surface a fork that survives only as the road not taken.

## 3. Diff to surface ambiguity

A separate agent compares the stubs, aligned by **injected fault** (not by test name), and classifies each fault:

- **Fork** — same fault, materially different expected outcome across authors. This is the payoff: a real ambiguity, made visible.
- **Silent branch** — one author's docstring flags the fault as open (a hedge, or a `# rejected:` line); another states one outcome as settled. The dangerous kind — it looks resolved from inside any single suite.
- **Gap** — a fault only one author thought of. Candidate addition to the union. Under lensed enumeration gaps are the norm, not a smell — a lens seeing what the others structurally can't is the lens working.
- **Consensus** — same expected outcome across every author who enumerated the fault. Auto-accept — *unless* the strong author's derivation or a `# rejected:` line marks the fault as a decision, in which case treat it as a fork despite the agreement. Peers guessing the same obvious branch is not evidence the branch is right.

## 4. Resolve forks with the human

Surface the forks — silent branches are forks, just harder-won — highest implementation-impact first, and resolve them (AskUserQuestion, your recommendation first). This is where human attention is spent and where it earns its keep: a handful of decisions that dictate what the code must do. Gaps join the catalog: auto-accept a gap whose outcome is uncontroversial, treat it as a fork when the outcome is a judgment call. Consensus scenarios pass through untouched. The resolved catalog is the spec.

## 5. Author the binding suite

One strong author turns the resolved catalog into the real suite. Survey the project's existing test machinery first and build on it — a harness that already fakes a dependency (e.g. `defender/tests/e2e/_replay_harness.py`: "a new scenario is a few lines of `Turn(...)` against this harness, not a fresh copy of the plumbing") is the starting point; write fresh fakes only for dependencies it doesn't cover. Then:

- **Declarative fault-injection fakes** — one fake per dependency, driven by a data fault-spec (`fail_on`, `raise_after`, `malformed`, `delay`). Faults are data, not bespoke per-test mocks. The fake injects faults **only** — it never classifies or decides policy; that is the job of the code under test, and a fake that decides has smuggled in the answer. Fakes enter through the entry point's injection seams (a deps parameter, a constructor argument), never `monkeypatch.setattr` — this repo's CI ratchets new setattr sites (`scripts/lint/lint_monkeypatch.py`). If the design gives a dependency no seam, the seam is part of the contract — pin it back in step 1.
- **One test per resolved scenario**, driving the **real entry point** against the fakes.
- **Assert observable outcomes only** — output contents, return value, raised errors, recorded seam calls. Never reach into internals.

## 6. Gate before handing off

Reject or repair any test that fails these. They are not style — they are what makes a test bind:

- The file **parses**, and every import except the not-yet-written target resolves. The target's import failing is the expected red before the implement phase; do not repair it by committing skeleton source — the deliverable stays a tests-only diff.
- Every test **actually calls the target symbol.** No test that re-implements the logic in its own body, and no test that asserts on a value it constructed itself. A cheap author will happily produce a full-looking suite that never calls the target and therefore tests nothing — gate against it mechanically (AST check: each test calls the entry point directly, or via a helper in the same file whose body does — repair a failure by inlining the call, never by loosening the check).
- Assertions sit at observable seams; fakes inject faults, not policy.

## 7. Hand off

Deliver the suite as a **tests-only diff** — the reviewable spec artifact — plus a short record of the forks resolved and how. This is what the implement phase codes against and what the human reviews *as the spec*. Green means the enumerated behavior holds: it is the guardrail that lets the later review/refactor phase move aggressively, not a proof of correctness.
