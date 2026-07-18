# Phase B — enumerate situations (step 3)

## Topology

- Five parallel leaves, dispatched only after `10-brief.md` is `complete`. Inputs for all: the intent+design doc, `10-brief.md`, `20-demands.md`. Each writes `30-premises-<lens>.md` (the strong author: `30-premises-author.md`).
- **4 lensed enumerators** (Sonnet), one lens each as a dispatch parameter: **dependency**, **input surface**, **lifecycle/state**, and a fourth from the design's danger zone — adversarial input, environment/resource, or concurrency; the profile's `conventions.dangerLens` is the standing default unless *this* change's danger zone is plainly elsewhere.
- **1 strong author** (frontier model, unlensed) — not economizable: a blind A/B found the cross-cutting, grounding-dependent faults capability-dominated; the lenses miss them at any skill quality. If it genuinely cannot be spawned, run the best derivation available and record the degraded unknown-unknown region in `handoff.deviations`.
- Dispatch prompt names the charge sections: every leaf takes "Charge — every enumerator" plus its role section.

## Charge — every enumerator

The design is silent about most of what can go wrong; you supply the missing situations. The catalog is a fault taxonomy, not a happy-path list: dependency errors (transient, permanent, timeout, malformed response), bad input (empty, missing, malformed, duplicate), partial failure, ordering, re-run / idempotency, output-side I/O failure.

Take an **actively adversarial** posture — find the input, ordering, or path that slips past the obvious implementation — and enumerate against the **intent section as well as the design**: a design that narrowed a surface-general obligation to three enumerated surfaces is exactly where the fourth surface never enters the space. Anchor to the brief: grounded, you enumerate faults the surface actually admits; ungrounded, you invent scary-sounding inputs that map to nothing.

Work the **language lane only**, and write **the premise, not its answer.** Emit **premise stubs — a test signature + a docstring stating the *situation* only, no intended outcome and no body** — in intent-space. The outcome is the next phase's to measure; writing it pre-answers your own question and destroys the measurement.

```python
def test_transient_enrich_error():
    """one enrich() call fails transiently while its siblings succeed — what must be observable?"""
    # fork: skip-and-continue vs abort-the-batch — this outcome is a known decision
```

A premise that names a mechanism-level fact — an exception class, a primitive's return shape, what existing code does — has left its lane: strip the fact into a **probe obligation** listed in your frontier and keep the situation. The one exception: a fact that belongs to the *not-yet-written target* (how it signals failure, what it returns) has no probe to run — that is demand #0's territory or a human fork, never a probe obligation. The fault menu is reality's to supply (phase E), not yours to guess. When a premise's outcome is a known judgment call, mark it `# fork:` so phase C routes it to the human regardless of how the answerers land — a silently-chosen branch otherwise leaves no trace it was ever a choice.

Frontier inventory: `{premises: n, probe_obligations: n, forks_flagged: n}`, `inputs` echoing the brief's `flagged_facts` count (state which facts fed a premise of yours — phase F's conservation walks this edge), and a `## Red flags` entry for anything that smelled like a design hole while enumerating.

## Charge — a lensed enumerator

Your dispatch names your lens; hold it. Independence comes from perspective, not sampling — identical prompts converge on the same blind spots, so your value is enumerating what only your lens sees. A premise only you raise is the norm and the point, not an error.

## Charge — the strong author

You are unlensed: the net under the unknown-unknown region, the complement of both the lenses and the gate rules — the graph rules compute the *known* pit shapes; you cover the unknown ones and the misclassified seams. You are also explicitly charged with the brief's edges: hunt for elements the grounding pass may have missed — a co-writer, a consumer, a surface the brief looks thin on — because an element absent from the graph is invisible to every rule, and this derivation is the only net under that hole. List every suspected brief gap in your frontier's `## Red flags` section.
