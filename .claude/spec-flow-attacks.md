# Attack deck

Append-only. One entry per exploit shape that carried a real bug past a committed suite in this repo — appended by `finalize` from an artifact-proven tracer attribution, replayed by `write-code-from-spec`'s adversarial implementer against every future spec. Entries record *shapes*, phrased to transfer across specs ("assert shape, not substance, on serialization demands"), never this-bug specifics alone and never doctrine.

Entry format:

```
## <date> · PR #<n> — <exploit shape, one line>
- **violated**: <demand id or design-doc clause, quoted>
- **exploit**: <how it greened — enough to re-attempt>
- **killed by**: <what the fix asserts, or "open">
```

## 2026-07-21 · PR #678 — a catch-all fault demand discharged at ONE seam; fault the other seams the guarded value crosses
- **violated**: `d7_unmapped_fault_enveloped` — "an unmapped `BaseException` → the fault-class envelope (write a row, never delete one) … never unwinds out of `agent.iter()`" (`closed_ticket_tool.py:38-40`; `spec_graph_672-closed-ticket-tool.yaml:152`).
- **exploit**: the discharging test injects the fault INSIDE the callee — the verb body, via the fake's `("raise", RuntimeError(...))` outcome — after a clean dependency resolution. Resolve the dependency OUTSIDE the guarded `try` (here `verbs.verbs(SYSTEM)[verb]`, which lazily imports the adapter and can `KeyError`/`ImportError`/`SystemExit`); the resolution fault then unwinds the stage with no row and no breaker record, and the suite stays green because every fake resolves cleanly. Generic replay: for any "any fault of class X → the safe envelope" demand, inject X at EACH seam the guarded value crosses around the `try` — dependency lookup/resolution/import, setup, teardown — not only inside the call.
- **killed by**: resolution moved inside the fault seam (`_run_verb`); regression `test_registry_resolution_fault_recorded_not_unwound`; and — the **mechanical net** — CI gate `scripts/lint/lint_unguarded_verb_dispatch.py`, which deterministically fails a subscripted `registry.verbs(system)[verb]` dispatch resolved outside a fault `try` (modules with a pydantic-ai capability catch-all exempt). The prose replay above is the cross-spec net for the adversarial implementer; the gate is the deterministic in-repo one — belt and suspenders, since a gate is cheap where the replay only shifts the odds.
