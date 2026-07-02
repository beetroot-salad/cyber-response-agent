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

Fan out **3 cheap, independent enumerators** (e.g. Haiku — cheap enough that a third instance is worth it for the extra decorrelation). Each emits **test stubs only — signature + docstring, no body:**

```python
def test_transient_enrich_error():
    """one enrich() raises a transient error → skip? retry? abort? — and ProcessResult.???"""
```

The docstring names the injected fault and the expected observable outcome. Stubs are the right altitude: no body means they can't drift into re-implementing the logic, they parse trivially, and each *is* a catalog row in the exact shape the author later fills. Independence is the whole point — decorrelated derivations catch blind spots a single author rationalizes away. Have the strong author enumerate too, so there are ≥2 derivations to diff.

## 3. Diff to surface ambiguity

A separate agent compares the stubs, aligned by **injected fault** (not by test name), and classifies each fault:

- **Fork** — same fault, materially different expected outcome across authors. This is the payoff: a real ambiguity, made visible.
- **Silent branch** — one author flagged the fault as open; another hard-coded one outcome as if settled. The dangerous kind — it looks resolved from inside any single suite.
- **Gap** — a fault only one author thought of. Candidate addition to the union.
- **Consensus** — same expected outcome everywhere. Auto-accept; no human input needed.

## 4. Resolve forks with the human

Surface the forks, highest implementation-impact first, and resolve them (AskUserQuestion, your recommendation first). This is where human attention is spent and where it earns its keep: a handful of decisions that dictate what the code must do. Consensus scenarios pass through untouched. The resolved catalog is the spec.

## 5. Author the binding suite

One strong author turns the resolved catalog into the real suite:

- **Declarative fault-injection fakes** — one fake per dependency, driven by a data fault-spec (`fail_on`, `raise_after`, `malformed`, `delay`). Faults are data, not bespoke per-test mocks. The fake injects faults **only** — it never classifies or decides policy; that is the job of the code under test, and a fake that decides has smuggled in the answer.
- **One test per resolved scenario**, driving the **real entry point** against the fakes.
- **Assert observable outcomes only** — output contents, return value, raised errors, recorded seam calls. Never reach into internals.

## 6. Gate before handing off

Reject or repair any test that fails these. They are not style — they are what makes a test bind:

- The file **parses** and imports cleanly.
- Every test **actually calls the target symbol.** No test that re-implements the logic in its own body, and no test that asserts on a value it constructed itself. A cheap author will happily produce a full-looking suite that never calls the target and therefore tests nothing — gate against it mechanically (AST check: the entry point appears as a call in each test).
- Assertions sit at observable seams; fakes inject faults, not policy.

## 7. Hand off

Deliver the suite as a **tests-only diff** — the reviewable spec artifact — plus a short record of the forks resolved and how. This is what the implement phase codes against and what the human reviews *as the spec*. Green means the enumerated behavior holds: it is the guardrail that lets the later review/refactor phase move aggressively, not a proof of correctness.
