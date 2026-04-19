# "Is it worth running the full experiment?" — Verdict

**Yes, with a narrower scope than the original design.**

Four trials on Case 1 (rule5710 monitoring-probe) across 2×2
depth×arm produced visibly differentiated outputs between Arm A
(invlang YAML prior) and Arm B (prose prior). Cost was parity, not
a blowup. Going to full 162 trials is premature — a 20-trial focused
round would already answer the "does prior format matter" question
cleanly.

## The signal, concretely

### Shallow cut (CONTEXTUALIZE only)

Both arms correctly routed to **GATHER, not HYPOTHESIZE** (contract:
"no HYPOTHESIZE without a fork"). They picked *different* first leads:

- **Arm A → `authentication-history`** (multi-axis lead — splits
  compromise-followup and cadence shape simultaneously)
- **Arm B → `source-classification`** (playbook lead #1 — partitions
  the archetype space before articulating any mechanism fork)

Both defensible. Arm B is more playbook-sequential; Arm A reaches
further. Interesting but not decisive on its own.

### Deep cut (ANALYZE_L1)

The arms diverged on **block shape**:

- **Arm A → HYPOTHESIZE with hierarchical refinement**. Shelved h-001,
  emitted child h-001-001 with a full `legitimacy_contract` bound to
  edge e-001 asking `authorization` against the
  `approved-monitoring-sources` authority. Predictions and refutation
  shape framed against the contract. Selected lead:
  `approved-monitoring-sources-anchor (new)` — explicitly requests a
  `trust_anchor_result` with `legitimacy_resolutions[]`.
- **Arm B → GATHER** (no HYPOTHESIZE). Selected lead:
  `monitoring-host-liveness (new, specialization of ad-hoc)`. Three
  lead-level predictions covering confirm / degraded-monitoring /
  anchor-unavailable, all routing to CONCLUDE.

**Both arms pick the right direction** — check monitoring-host
operational state to complete the anchor — but Arm A exercises the
formal invlang schema machinery (legitimacy contract + hierarchical
refinement) while Arm B uses simpler GATHER-with-lead-predictions
routing.

### Token cost

| Trial | Tokens | Tool Calls |
|-------|--------|------------|
| shallow × A | 46,349 | 6 |
| shallow × B | 46,446 | 7 |
| deep × A    | 54,260 | 15 |
| deep × B    | 52,118 | 8  |

Per-arm cost is within 5%. Arm A at deep uses ~2× the tool calls of
Arm B — likely because the subagent walks more reference files to
support the hierarchical refinement + legitimacy contract. That's a
real cost if scaled, but not prohibitive.

## What we learned that's actionable

1. **The format matters.** Outputs are not interchangeable. Arm A
   produces schema-richer hypothesis blocks when the fork is present;
   Arm B prefers simpler GATHER routing. Whether schema-richer is
   *better* is the experimental question worth answering.
2. **Shallow cuts are less differentiating.** Both arms route to
   GATHER; the difference is only which starter lead they pick. Narrow
   the focused round to deep cuts.
3. **The gold schema needs a dual shape** (HYPOTHESIZE | GATHER)
   because routing-to-GATHER is a legitimate output at either depth.
   Deferred from this sanity check — update before running the
   focused round.
4. **Case 2 remains blocked** on investigation.md enrichment; Case 7
   remains blocked on schema rework. Adding one of these would give
   a stress-cell variant (looks-malicious × benign or looks-benign ×
   malicious) to compare against Case 1's easy cell.

## Recommended focused round

Rather than 3 arms × 3 variants × 2 depths × 8 cases = 144 trials:

- **1 depth** (deep — ANALYZE_L1 or equivalent) — shallow didn't
  differentiate well
- **2 arms** (A, B) — drop C for this round; re-introduce if A/B
  delta is ambiguous
- **4 cases** — Case 1 (easy benign, ready) + Case 2 (noisy FP, once
  enriched) + Case 7 (stealth synth, once reworked) + one more (e.g.,
  a mixed × malicious from Case 8 candidate, synthesized fresh)
- **2 replicates per (case, arm)** — control for single-draw variance

= **16 trials**. With ~50k tokens each, ~800k tokens total, ≈ $10-15.
Plus judge-scoring by Opus on the 16 outputs for lead quality +
schema correctness + reasoning depth.

## Update: Case 7 deep × A vs B — arms converge

After adding Case 7 (rule550 SSH-persistence stealth synthetic) and
running its deep cut on both arms, a sharper picture emerged:

- **Case 1 deep**: Arm A → HYPOTHESIZE with legitimacy-contract
  refinement; Arm B → GATHER. Arms diverge.
- **Case 7 deep**: Arm A → GATHER; Arm B → GATHER. **Same selected
  lead** (`auditd-process-attribution`), different pitfall phrasing,
  same routing. Arms converge.

Why: at Case 1 deep, one hypothesis remains live and the
legitimacy-contract refinement is a *new* mechanism fork the invlang
schema specifically supports. Arm A had the structural prior to
exercise it; Arm B routed simpler. At Case 7 deep, two mechanism
hypotheses (h-002 admin, h-003 adversary-controlled) are already
enumerated with distinct parent-vertex classifications — no new fork
is available, so GATHER is the *only* contract-compliant shape,
regardless of prior format.

**Implication for the focused round.** The differentiating signal
concentrates on cases where the investigation state has **latent
schema capacity** — a live hypothesis with an unresolved
legitimacy question, or room for hierarchical refinement. Cases that
have exhausted their fork space (Case 7 deep) will converge on both
arms and provide no signal. The round needs to deliberately include
BOTH kinds:

- 2 cases where the deep cut has latent schema capacity (Case 1-like)
- 2 cases where the deep cut is fork-exhausted (Case 7-like)

If Arm A consistently outperforms Arm B on the first kind and ties
on the second kind, the experiment's verdict is "structured prior
helps when schema capacity exists, else no-op." That's a clean,
actionable finding.

## What we still don't know

- Whether Arm A's schema-richer output translates to **better
  investigation outcomes** end-to-end. Single-turn output quality is
  a proxy; running full loops to disposition is the truth. Defer
  full-loop until focused round confirms the single-turn signal is
  directionally correct.
- Whether the prior-format effect is **consistent across signature
  types**. Case 1 is rule5710 (SSH auth). Behavioral detections
  (rule100001, rule100110, rule550) may show different dynamics.
  The focused round should cover at least 2 signatures.
- Whether **Arm C (minimal / control) produces worse outputs** than
  B. If the gap is small, Arm B is effectively the control and we
  don't need C. If the gap is large, B itself is a meaningful prior
  and the experiment gains a third comparison point.

## Go / no-go

**Go — run the focused 16-trial round.** Block is authoring: Case 2
enrichment + Case 7 schema rework + one additional synthetic. The
sanity-check signal is strong enough that investing in the authoring
is justified. After the focused round, decide on full-loop scaling.
