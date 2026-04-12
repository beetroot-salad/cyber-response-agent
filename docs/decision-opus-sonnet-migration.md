# Decision: Main Agent Model Migration (Opus → Sonnet)

**Date:** 2026-04-12
**Status:** Proposed — pending empirical validation
**Context:** Run #9 cost split: Opus main $1.86 (82%), Sonnet ticket-context $0.29, Haiku screen+precedent $0.13. Total $2.28. Main-agent Opus dominates cost.

---

## Two Approaches

### Approach 1: Sonnet main + mandatory Opus consultations

Sonnet runs the investigation loop. Opus is called as a reasoning-only subagent at structurally-enforced decision points. Hooks block state transitions without a recorded consultation.

**Mandatory consultation points:**
- HYPOTHESIZE→GATHER — "Which lead is most diagnostic given these hypotheses?"
- ANALYZE decision — "Is the adversarial hypothesis genuinely refuted? Loop or conclude?"
- Pre-CONCLUDE — "Does the evidence support this disposition?"

**Enforcement:** `write_state.py` checks `tool_audit.jsonl` for a recorded Opus consultation before allowing gated transitions (same pattern as `check_ticket_context_spawned`).

### Approach 2: Lean Opus main + delegated subtasks

Opus stays as the main agent. Cost reduction comes from offloading mechanical work: hook-based CONTEXTUALIZE preload (Stage 1), Sonnet report drafter (Stage 2), existing Sonnet/Haiku subagents.

---

## Cost Estimates

Anchored on run #9 ($2.28 total, full investigation with SCREEN no-match, 2 loops) and run #7 ($0.63, SCREEN-resolved baseline).

| Scenario | Current | Approach 1 | Approach 2 |
|---|---|---|---|
| Full investigation | $2.28 | ~$1.55 | ~$2.00 |
| SCREEN-resolved | $0.63 | ~$0.35–0.55 | ~$0.50 |
| Savings (full) | — | ~30% | ~12% |
| Savings (SCREEN) | — | ~15–45% | ~20% |

**Approach 1 cost breakdown (full):** Sonnet main ~$0.50, 5 Opus consultations ~$0.60 (with prompt caching), subagents $0.42, judge $0.05.

**Approach 2 cost breakdown (full):** Opus main (lean, ~18 turns vs ~27) ~$1.30, hook preload $0.12, report drafter $0.12, subagents $0.42, judge $0.05.

**Speed:** Approach 1 adds ~2–3 min (consultation latency). Approach 2 saves ~1 min (hook preload). Net difference: Approach 2 is ~3–4 min faster on full investigations.

---

## Silent Sonnet Failure Modes

The dangerous case is correct-format, plausible-narrative, wrong-conclusion output.

| # | Failure | Severity | Caught by consultation? | Caught by existing hooks? | Commonality |
|---|---|---|---|---|---|
| 1 | **Premature adversarial dismissal** — refutes threat hypothesis on surface pattern, not discriminating evidence | Critical | Yes (ANALYZE consultation) | Partially (Tier 2 ADVERSARIAL_CHECK) | High (~20–40%) |
| 2 | **Suboptimal lead selection** — picks non-diagnostic lead | Costly, not dangerous | Yes (HYPOTHESIZE consultation) | No | Moderate (~15–25%) |
| 3 | **Forced archetype fit** — resolves to closest archetype despite unexplained features | High | Yes (CONCLUDE consultation) | Yes (Tier 2 COMPLETENESS) | Low–moderate |
| 4 | **Shallow evidence characterization** — misses subtle pattern in SIEM results | High | No — Opus reasons from same summary | No | **Already exists** (leads already run by Sonnet) |
| 5 | **Coherence decay over 20+ turns** — investigation.md becomes self-contradictory | Medium | Partially (consultation reads full log) | Partially (Tier 2 INTERNAL_CONSISTENCY) | Unknown |
| 6 | **Premature CONCLUDE** — concludes with undifferentiated hypotheses | High | Yes (ANALYZE consultation) | Yes (Tier 2 EVIDENCE_SUFFICIENCY) | Moderate |

**Key finding:** Failure #1 (premature adversarial dismissal) is the highest-risk and most frequent. It's caught by the mandatory ANALYZE consultation but not reliably by the post-hoc judge alone.

**Key finding:** Failure #4 (shallow characterization) is the one blind spot neither approach addresses — but it already exists in the current architecture since lead subagents already run on Sonnet.

---

## Assessment

**Approach 1 is the better cost lever.** Saves 2–3x more than Approach 2. The failure modes are mostly catchable by mandatory consultations + existing hooks. The one uncatchable failure (#4) is not a new risk.

**Approach 2 is more robust but the margin is thinner than it appears.** Most safety comes from hooks and the judge, not from Opus being the main agent. The cost savings are modest (~12%).

**The residual risk in Approach 1** is "coherent confabulation" — Sonnet writes a plausible narrative, the Opus consultation reasons from that narrative and agrees, the judge passes the well-formatted report. Mitigation: feed the consultation raw evidence observations from lead subagent returns, not just Sonnet's summary.

---

## Open Questions (resolve before committing)

1. **Run Sonnet-only on 3–5 scenarios without any consultant.** Read the investigation logs manually. How often does failure #1 actually fire? This determines whether the consultation architecture is necessary or over-engineering.

2. **Measure actual alert volume.** At low volume, $2.28/run may be tolerable and Approach 2's simplicity wins. The break-even depends on whether the ~$0.70/run savings × volume justifies the engineering complexity.

3. **Is an upgraded Tier 2 judge sufficient alone?** Promoting the judge from Haiku to Sonnet (or Opus) at CONCLUDE — without any mid-loop consultations — is dramatically simpler. The gap: the judge is post-hoc and can't fix bad lead selection earlier in the loop.

4. **Prompt caching for `claude --print` subprocesses.** Verify that the 3-layer caching structure (stable methodology prefix → per-run signature context → per-consultation question) actually achieves cache hits in practice. If caching doesn't work for CLI subprocesses, each consultation costs ~$0.20 instead of ~$0.12, which narrows the cost advantage.

---

## Recommended Next Steps

1. **Empirical validation first.** Run Sonnet-only (no consultant) on existing eval scenarios. Count failure #1 occurrences. This is 2 hours of work and determines the whole direction.
2. **Ship Stage 1 (hook-based CONTEXTUALIZE preload) regardless.** It's independently valuable, zero capability risk, and benefits both approaches.
3. **If Sonnet fails frequently → Approach 1.** Build the consultation prompt template, dispatch script, and enforcement hooks.
4. **If Sonnet is surprisingly competent → skip consultations**, upgrade the Tier 2 judge model, and pocket the savings from a straight model flip.
5. **If cost pressure is low → Approach 2.** Ship Stages 1–2 for modest savings with zero capability risk.
