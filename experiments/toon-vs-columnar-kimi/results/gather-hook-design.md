# A gather-side re-encoding hook, for payloads whose shape we do not own

## Why the 200-trial verdict does not settle this

That run measured `current` (columnar) vs TOON and returned **−6.7%**, below the 10% bar. But
`current` only exists because we own `elastic_adapter.esql_payload` and fixed the shape at the
source (#842). An external adapter or an MCP server hands us whatever it likes — commonly an
array of row objects — and there is no source to fix.

Three-way, identical content, 40 payloads, real `kimi-k2.6` tokenizer:

| encoding | tokens | bytes | vs dictrow | vs columnar |
|---|---|---|---|---|
| `dictrow` (unowned external shape) | 52,446 | 137,492 | — | +36.8% |
| `columnar` (ours, source-side fix) | 38,335 | 88,077 | **−26.9%** | — |
| `toon` | 35,578 | 79,456 | **−32.2%** | −7.2% |

**For an unowned source, TOON is −32.2% — comfortably over the bar.** The verdict differs by
deployment, and the owned case is the one where TOON has least to add.

Critically, the `columnar` middle row is **not reachable generically**: producing it requires
knowing that `columns` names `values` in this particular schema. TOON's §9.3 tabular detection
infers uniformity from the data itself, so it needs no per-source knowledge. That is the whole
argument for a library over a bespoke transform.

## But blanket re-encoding is wrong

Measured over the 110 non-ES|QL recorded payloads ≥500 B — nested docs, listings, the class that
best proxies unknown MCP output:

- **28 of 110 get BIGGER under TOON**
- byte delta p10 / p50 / p90 = **−31.7% / −1.9% / +5.9%**

The median payload gains essentially nothing and the tail costs bytes. The win is concentrated
entirely in the uniform-tabular subset. This matches the published finding that TOON ranks last
on deeply nested data — its list-form fallback is not a compact format, it is YAML with counts.

## Design

**Conditional, decided per payload, with no knowledge of the source.**

1. At the `payload_view.render` boundary — the module that already owns the model-visible view.
   **View only; the persisted payload stays JSON** (#834 constraint N2), so `defender-sql`
   reducers are untouched and the hook is reversible.
2. Encode the payload both ways. Emit TOON **only if it beats the JSON view by a margin**
   (≥10% tokens, matching the bar this experiment used); otherwise pass JSON through unchanged.
3. **Round-trip assert before substituting**: `toons.loads(toons.dumps(x)) == x`. Verified to
   hold on an adversarial value carrying a newline, a comma and an embedded quote. A payload that
   fails the assert is emitted as JSON — never as a best-effort re-encoding.

**The cost gate doubles as an accuracy gate.** TOON's size win and its accuracy safety come from
the *same* condition — uniform tabular structure. A payload that does not win on size is, by the
same property, the nested kind where the published accuracy losses concentrate. One threshold
excludes both risks, which is why the gate should be a measured margin and not a shape heuristic.

## Library, not a custom implementation

- The generic work a bespoke transform would have to do — infer uniformity, tabularize, fall back
  when a column holds arrays — **is** §9.3. Reimplementing it is reimplementing TOON.
- The escaping rules are security-critical: the payload is untrusted, and a value must never
  author row structure. `py-toon-format` 0.1.0, a published package, **emits a literal newline
  inside a row** — exploitable from an attacker-controlled `cmdline`. If a shipped implementation
  got this wrong, a hand-rolled one written under delivery pressure plausibly would too.
- `toons` 0.7.0 (Rust) was probed spec-compliant on every hazard in our corpus: `null` literal,
  escaped newline, quoted numeric-looking strings, quoted delimiters, correct list-form fallback.

Cost of the dependency: a Rust extension module in the gather path, and a format whose Python
ecosystem is immature enough that three of four packages were unusable. The round-trip assert is
what makes that dependency safe to hold — it converts an encoder bug into a fallback, not a
silent corruption.

## Open, not decided here

- **Accuracy on non-tabular payloads is unmeasured by us.** The gate is designed to avoid that
  path; it has not been tested that it always does.
- **Over-ceiling payloads still unhandled.** `payload_view.walk` is a JSON structural walk with
  no TOON equivalent. The hook as designed applies to payloads that pass whole; a truncating
  TOON view is a separate piece of work.
- **`glm-5.2` untested.** It reads reports rather than raw payloads, but the hook is model-agnostic
  and the claim should not be assumed to transfer.
