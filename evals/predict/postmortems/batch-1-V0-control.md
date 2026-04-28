# Batch 1 post-mortem — V0 (control)

**Matrix:** V0 × 5 cases × 3 reps = 15 cells. Wall: 478s @ parallelism 4. 15/15 ok, 0 failures.

**Aggregate score:** 0.636 (rubric D1+D2+D3+D4+D5+D7+D8a, weighted).

## Per-dimension baseline

| Dim | Score | Read |
|---|---|---|
| D1 shape | 0.467 | Wrong shape on 2 of 5 cases (003, 004); partial on 005 |
| D2 lead | 0.067 | Picks expected lead on only 1 of 15 cells |
| D3 structural | 1.000 | Envelopes always parse |
| D4 count | 1.000 | Hypothesis count matches when shape is right |
| D5 forbidden | 0.333 | Pattern fires on 10 of 15 cells |
| D7 auth contract | 1.000 | Contract present on the one shape-A case |
| D8a pred quality | 0.989 | Predictions are falsifiable + non-tautological |

## Per-case behavior

### case-001 (5710 loop 1, expected E) — score 0.743, shape correct 3/3

All three reps land Shape E correctly. Lead choice diverges across reps: `source-classification` / `source-reputation` / `authentication-history`. Only rep-3 picks the rubric's expected lead. **V0 has high lead-choice variance on enrichment cases.** Whether this reflects a real PREDICT problem or rubric over-specification is open — `source-classification` is a defensible cheapest-discriminator move given the alert shape.

D5 fires on `baseline_value_leak` — the lp* `if` text contains the literal IP `172.22.0.10`. **Detector calibration issue:** the IP is the alert's own srcip being classified, not a PREDICT-time guess at GATHER's output. The rubric's value-leak rule is intended to catch *predicted* values, not references to alert fields. All variants hit this consistently, so it doesn't bias variant ranking — but flag for D5 calibration in a follow-on.

### case-002 (5710 loop 2, expected A) — score 0.733, shape correct 3/3

All three reps land Shape A with one hypothesis carrying an authorization_contract. Hypothesis names converge: `?registered-monitoring-probe` (2x), `?registered-monitoring-triple` (1x). Lead choice mixed: rep-3 picks `approved-monitoring-sources` (the expected anchor lead); reps 1-2 pick `source-classification` (a more general scoping move).

### case-003 (100110 loop 1, expected M) — score 0.500, shape WRONG 3/3

**All reps default to Shape E** with NXDOMAIN-sampling leads (`nxdomain-query-cluster`, `client-dns-query-log`, `dns-nxdomain-sample`). V0 does not recognize the alert as warranting a mechanism fork on per-process concentration + qname entropy. Reverts to "fetch more samples first." This is a **default-bias-too-strong** failure — the alert genuinely supports an M shape with diverging predictions, but V0 collapses to E.

Variant target: V1 (frontier classifier) and V3 (frontier-first deliberation) should help by forcing the agent to name the open question explicitly before defaulting to enrichment.

### case-004 (100001 loop 1, expected E — the run-#44 reproduction) — score 0.615, shape WRONG 3/3

**All three reps emit Shape A with a single mechanism-fork hypothesis on a null parent_pname field:** `?operator-host-exec`, `?underlying-host-exec`, `?operator-runtime-exec`. Names vary; pathology is identical — V0 invents a story on the unknown rather than emitting a Shape E lead to refill the gap. This is **the exact run-#44 cascade trigger reproduced 3/3 times in the controlled fixture.**

The convergence across reps (~3 different names, identical mechanism-fork shape) confirms the failure is a discipline pattern, not random sampling. Variants targeting unknown-as-first-class should differentiate strongly here.

### case-005 (5710 loop 3, expected E or A on upstream) — score 0.590, shape correct 1/3

Rep-1 lands Shape E correctly with `monitoring-tool-audit` lead probing the upstream actor. **Reps 2-3 emit Shape M with two peer hypotheses** on the same vertex — `?monitoring-system-is-the-actor` + `?credentials-used-outside-registered-actor`. This is the **sideways-pivot-after-`++` anti-pattern** (case-005's specifically-named forbidden pattern): the prior loop already graded the current edge `++`, so loop 3 should attach to the upstream vertex, not litigate a peer for the confirmed one. 2/3 reps fail this, with peers that look like an integrity-vs-authorization split (the invoker-identity anti-pattern in disguise).

## Failure-mode summary

| Failure | Cases hit | Reps hit | Variant target |
|---|---|---|---|
| Default to E on real M (no mechanism-fork recognition) | 003 | 3/3 | V1 frontier classifier; V3 frontier-first deliberation |
| Mechanism-spiral on null discriminator (run #44 shape) | 004 | 3/3 | V1 (classifier should mark "what is parent?" as edge-extension question requiring lead-refill, not story); V2 (unknowns slot for the open question); V3 (frontier listing should expose the gap before shape commit) |
| Sideways pivot after `++` | 005 | 2/3 | V1 (slot discipline should route loop 3 to attribute on confirmed vertex or new upstream-edge-extension); V3 (frontier-first should name the upstream question) |
| Lead-choice noise on E cases | 001 | 2/3 | Not a variant target — likely rubric over-specification |

## Reproducibility signal

Within-V0 variance: shape consensus 100% on cases 001/002/003/004; only case-005 splits (1 E vs 2 M). When V0 is wrong, it's wrong in a *consistent* way (same hypothesis-pattern across reps), which means variant comparisons against V0 are more about discipline gates than about coin-flip noise. Good baseline noise floor.

## Setup gates this baseline reveals

- D5 calibration: `baseline_value_leak` regex flags references to alert-field IPs in lp* text. Doesn't bias variant ranking but inflates the "violations" count. Track for follow-on; do not fix mid-experiment (would change scoring under V0's feet).
- D2 lead expected_oneof lists may be too narrow for E-shape cases. The rubric assumes one canonical lead; in practice V0 picks defensible alternates. Either widen the oneof set after batch review or weight D2 down — but again, do not change mid-experiment.

## What to watch in batches 2-4

- **V1's containerd worked example bias** — if V1 picks containerd-shaped vertex inferences on case-004 even though the case's expected output is Shape E (no containerd vertex pre-inferred in the fixture), variant may overfit the example.
- **V2's `unknowns[]` field acceptance** — does the agent emit it consistently, or treat it as decorative? Empty unknowns[] across all V2 cells = the slot didn't activate.
- **V3's frontier-first prose** — lightest-touch variant; if it doesn't move case-003 / case-004 / case-005 from V0's failures, prose-only nudges aren't enough.

## Next: launch Batch 2 (V1 frontier classifier × 5 × 3)
