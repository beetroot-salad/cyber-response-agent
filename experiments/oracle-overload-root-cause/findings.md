# Oracle overload: root-cause reassessment of PR #247

**Date:** 2026-06-06
**Fixture:** `live-falco-nettool-1` (v2 `Falco: suspicious network tool` — an adversarial story whose `nc` probe hides in the `svc.monitoring` health-check shape; the missed gap is the probe destination `172.18.0.24` + an SSH login from that unregistered host).
**Model:** Haiku 4.5 (per-lead probe) / Sonnet 4.6 (single-call A/B), via `claude -p`.

## TL;DR

PR #247 attributed the single-call oracle's **projection overload** (out-of-envelope events placed in a lead) to the *generative-while-seeing-all-leads structure* and replaced it with a two-stage **footprint → deterministic router**. A multi-round probe shows two distinct things:

1. **A large part of the oracle's failures were input contamination, not structure** — the prose `goal` drove fabrication-to-fill, and concrete timestamps embedded in `what_to_summarize` drove wrong-time events. Both are fixable with a deterministic `what_to_summarize` sanitizer + dropping the goal. This is real and worth shipping.
2. **But input cleaning does NOT fix overload.** A controlled single-call A/B (original vs sanitized inputs, everything else held constant) shows **no overload reduction** (A ≈ 3.3, B ≈ 4.7 overloaded events/run, n=3 each). Overload is eliminated only by **decomposition** — running the oracle per-lead, where each isolated instance correctly emits `[]` for state/lookup leads. The router (or per-lead isolation) is load-bearing; the sanitizer is complementary, not a substitute.

**Net:** keep the decomposition. Add the sanitizer + the tightened per-lead prompt as complementary quality fixes. Do not retire #247 in favor of "feed the old oracle our context" — that was the tempting simplification, and it's falsified below.

---

## Origin

PR #247 ("learning: judge query surface, actor grounding, effort knob (+ deterministic oracle router, unwired)") split the oracle into:
- **Stage A (footprint LLM):** enumerate the attack's telemetry footprint, lead-agnostic.
- **Stage B (deterministic router, `_oracle_router.py`):** place each footprint event under the leads whose structured filter it satisfies — pure containment, no QL parsing. Overload "impossible by construction."

The PR's stated motivation: prose discipline could not stop the single-call generative oracle from smuggling out-of-envelope events into the nearest lead ("Sonnet overloaded; Haiku over-dumped to `uncovered`"). The router also produces an `uncovered` bucket and is vendor-neutral via `scripts/lead_filters.py` (template reverse-alignment).

The question this experiment asked: **was overload really caused by the generative structure, or by the inputs we were feeding it?** If the latter, the heavy router (+ template reverse-parsing) may be more than the problem required.

## Method

Two phases.

**Phase 1 — per-lead/per-query generative probe (7 rounds, Haiku).** Reimplement the oracle as one LLM call per lead (and per query), iterating the prompt. Harness: `harness/build_prompts_r*.py`. Scored on: redirect **canary** (story says no redirect fires — does it fabricate one?), bypass-event recall (the SSH from `172.18.0.24`), `<noise>`-marker use, format discipline, timestamp behavior.

**Phase 2 — decisive single-call A/B (Sonnet).** Resurrect the *actual* old oracle (`harness/sys_old.txt`, recovered from git `f74ec6e~1:defender/learning/oracle.md`) and change exactly one variable:
- **A:** original goal-laden lead descriptions + concrete timestamps (reproduces #247).
- **B:** `goal` dropped + timestamps stripped from `what_to_summarize` (`sanitize_wtc`).
Same exemplars, same single-call all-leads structure, same model (Sonnet 4.6) / effort (low). Harness: `harness/build_oldoracle_ab.py`; overload scored by `harness/detect_overload.py` (data-source-family mismatch + events emitted into state/lookup leads). n=3 each.

## Results

### Phase 1 — what input cleaning fixed (per-lead, promptable)

| Round | Change | Result |
|---|---|---|
| 1 | per-lead, goal+summarize | fabrication-to-fill (phantom `nc`), lead-4 envelope violation |
| 2 | tightened discipline | format fixed on the easy case, but **over-abstained** — dropped the bypass SSH (false negative) |
| 3 | per-query, **goal dropped** + `<noise>` marker | **fabrication-to-fill fixed** (redirect → `[]`); bypass events recovered; per-query coverage inconsistency |
| 4 | per-lead, `what_to_characterize` only (no goal) | **redirect canary passed**; lead-4 correctly `[]`; timestamp fab-to-fill persisted (from query windows) |
| 5 | + timestamp rule, consolidated examples | timestamp rule helped lead 1; **verbose `Why:` example block leaked as essays** (format regression); rule over-fired (dropped `nc`) |
| 6 | remove `Why:` block; **anchored `<alert-time>` placeholders** | **5/5 clean format**; placeholders adopted; canary holds. Residual: one concrete `14:08:43` |
| 7 | + deterministic `what_to_characterize` timestamp **sanitizer** | the `14:08:43` was lifted from a `what_to_summarize` item presupposing a `curl` event the story lacks; sanitizing it → `<alert-time>`, consistent across leads |

**Promptable vs structural (per-lead):**
- *Fixed by prompting/sanitizing:* presupposed-event fabrication, over-abstention, lookup-lead recognition, timestamp-guess fabrication (→ placeholders), the concrete-timestamp contamination, format discipline (~80–90%, run-to-run flicker).
- *Structural (per-lead can't fix):* cross-lead event identity, multi-event completeness, the `uncovered` loss (accepted as a product decision).

The `14:08:43` diagnostic (`evidence/out6_5.yaml` vs the variant runs) proved the last concrete-timestamp fabrication was **input contamination**, not the model inventing it — strip/relativize concrete clock times in `what_to_summarize` and it falls back to `<alert-time>`, consistent with the other leads.

### Phase 2 — the decisive test: does input cleaning fix overload?

Single-call oracle, one variable (input sanitization), n=3, Sonnet:

| Condition | cross-source-smuggle | state-lead fabrication | **total overload / run** | events/run |
|---|---|---|---|---|
| **A** — original goal+timestamps | 2.0 | 1.3 | **3.3** | 11.0 |
| **B** — sanitized | 3.0 | 1.7 | **4.7** | 11.7 |

**No reduction — B is marginally higher (within noise).** In both conditions the overload is concentrated in the **state/lookup leads**: pos 3 (`host-state.*`, no event stream) and pos 4 (`cmdb.*` lookups) get fabricated events every run. The genuine **event** leads (1, 2, 5) stayed in-envelope in both — so on this fixture the dominant overload flavor is *fabricating events for non-event-stream leads*, and it is identical with or without input cleaning.

Contrast with Phase 1: the **per-lead** oracle (rounds 4–7) emits `[]` for leads 3 and 4 — because each isolated instance sees only its own (lookup) queries and recognizes "no event stream → no events." The decomposition removes the overload; input cleaning does not.

> Caveat: this fixture did not strongly stress #247's exact reported case (a distinct-container sidecar smuggled into the alert-container event-lead); the event leads were clean in both conditions. The reproduced-and-measured overload here is state/lookup-lead fabrication. Either way the directional conclusion holds: **input cleaning ≠ overload fix**, and decomposition is what eliminates the overload that does manifest.

## Conclusion

1. **#247's router is doing real work that input cleaning cannot replace.** The decomposition (deterministic router, or per-lead LLM) is the load-bearing mechanism against overload. Keep it.
2. **The input-contamination finding is still valuable and shippable** — independent of the router debate. A deterministic `what_to_summarize` sanitizer (drop goal / strip concrete clock times → `<alert-time>`) removes fabrication-to-fill and wrong-timestamp events. It belongs upstream of *whatever* oracle path is used.
3. **The router-vs-per-lead-LLM choice is a real trade**, not a free win for either:
   - Router: overload impossible *by construction*, free deterministic matching, produces `uncovered`, consistent event identity — at the cost of `lead_filters.py` template reverse-parsing for vendor-neutrality.
   - Per-lead LLM: simpler to reason about, no QL machinery, recognizes lookup leads — but costs N thinking-heavy LLM calls (~86% of per-lead cost is thinking; see cost note below), loses `uncovered` and cross-lead identity, and is probabilistic (real n=1 variance observed at temperature 1).

## Adjacent findings (recorded so they aren't re-derived)

- **Cost is ~86% output/thinking**, not input. Per-lead Haiku run: ~$0.08/lead, of which input-side is ~14% (and that's already mostly cache-priced — uncached input was ~8 tokens/lead). Prompt caching + CLAUDE.md/`--bare` removal address at best ~10–13% combined (almost all from cross-call caching of the shared system+story prefix, which `claude -p` cannot do; ~1–2% from CLAUDE.md removal, which is cheap cache-read). **The only real cost lever is `--effort`/thinking.**
- **Thinking control:** Haiku 4.5 uses the classic `thinking: {enabled, budget_tokens}` / `{disabled}` API (not `effort` — `effort` 400s on Haiku). `claude -p` exposes neither, so thinking is uncontrollable through the CLI. The SDK is the only lever.
- **Temperature:** `claude-haiku-4-5` *accepts* `temperature`/`top_p`/`top_k` (the "removed → 400" rule is Opus-4.7+-only). `claude -p` has no temperature flag; the SDK does. The observed run-to-run variance (leads 3/4 flipping format on byte-identical inputs; lead 5 empty 1/6) is consistent with temp-1 sampling — `temperature=0` via the SDK should largely remove it (not the structural failures).
- **One SDK port unlocks all three** (temperature=0, thinking control, cross-call caching). The production loop drives these subagents through `claude -p` (`_loop_subagents._run_claude`), so it shares all three limitations — an argument for the `SdkSubagents` adapter already contemplated in that seam's docstring.
- **Methodology:** n=1 per cell is too noisy to read prompt deltas — leads 3/4 flipped clean↔FENCE on identical inputs. Large effects (goal-prose toxicity; the sanitizer; the A/B overload result) reproduce; finer format/completeness deltas need n>1. (A measurement bug in a first-pass classifier nearly produced a false "sanitizer breaks output" regression — re-scored before reporting.)

## Artifacts

- `harness/sys_old.txt` — the recovered old oracle prompt (git `f74ec6e~1`).
- `harness/build_oldoracle_ab.py` — single-call A/B builder (`sanitize_wtc`, scrubbed-exemplar logic).
- `harness/detect_overload.py` — overload scorer (data-source-family mismatch + state-lead fabrication).
- `harness/build_prompts_r6.py` / `_r7.py` — final per-lead prompt (SYSTEM6) + the `what_to_characterize` sanitizer.
- `harness/sys6.txt` — final per-lead oracle prompt (3-way output, anchored `<placeholder>` timestamps, consolidated example).
- `evidence/oldA_*.jsonl`, `evidence/oldB_*.jsonl` — the decisive A/B raw runs.
- `evidence/out6_*.yaml` — final per-lead projections (round 6).

(Working fixtures were under `/tmp/oracle-v2-probe`; the load-bearing subset is copied here since `/tmp` is ephemeral.)
