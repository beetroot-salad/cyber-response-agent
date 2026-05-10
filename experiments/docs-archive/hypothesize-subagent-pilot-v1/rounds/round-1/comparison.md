# Round 1 (re-cut) — three yes/yes-candidate fixtures, Arm A minimal

**Scope:** three novel-alert fixtures, each written fresh under one-hop + lean discipline. One Arm A subagent per fixture (Sonnet, minimal bundle: fixture + SKILL.md + invlang spec + lead defs). Ground truths re-cut under the same discipline.

## Headline

**The new §HYPOTHESIZE + invlang spec produces consistent, well-shaped output with minimal context.** Across three structurally different fixtures (syscall-level Falco, host-level auditd, netflow-correlation), the subagent consistently produced: 3–4 lean one-hop hypotheses + single discriminating lead + both per-hypothesis and lead-level `predictions`, plus a valid invlang YAML companion block. No narrative padding; adversarial hypothesis preserved and un-split in all three.

## Per-fixture results

### F3 — db-outbound-lowrep (Falco syscall)

| Dimension | GT | Arm A |
|---|---|---|
| ASSESS verdict | yes/yes | yes/yes ✅ |
| Hypothesis count | 3 | 4 (extra split: extension vs. misconfigured-native-feature) |
| One-hop shape (attached_to_vertex, proposed_edge, parent_vertex.classification) | all 3 | all 4 ✅ |
| Predictions/hypothesis | ≤2 | ≤2 ✅ |
| Selected lead | `process-lineage` single | `process-lineage` single ✅ |
| Pre-registered lead predictions | 4 | 4 ✅ + data-gap fallback |
| Invlang YAML block | no | yes (bonus) |
| Schema detail | attached to edge (incorrect) | attached to vertex (correct) — GT was wrong |
| Adversarial preserved un-split | yes | yes ✅ |
| Pitfalls: alert-specific | yes | yes ✅ |

Net: Arm A ≥ GT on shape discipline and invlang conformance.

### F4 — cron-modification (auditd)

| Dimension | GT | Arm A |
|---|---|---|
| ASSESS verdict | yes/yes (my call) | **no/yes** (strict rubric) |
| Hypothesis count | 4 (incl. `?package-manager` weakly) | 3 (merged package-manager into the CM branch structurally) |
| One-hop shape | all 4 | all 3 ✅ |
| Predictions/hypothesis | ≤2 | exactly 2 ✅ |
| Selected lead | `auditd-syscall-audit` single | `auditd-syscall-audit` single ✅ |
| Pre-registered lead predictions | 6 | 4 (tighter) |
| Invlang YAML block | no | yes (bonus) |
| Adversarial preserved un-split | yes | yes ✅ |

**ASSESS call:** Arm A argued the next lead is `auditd` regardless of hypothesis — strict rubric says `no` on branching. My GT's yes/yes was wrong. Arm A flagged the tension explicitly: "Per the ASSESS rubric this is no/yes → skip HYPOTHESIZE, pre-register lead.predictions in GATHER. However, the task explicitly requests a HYPOTHESIZE block..." — then produced both layers and routed the interpretive work to lead-level predictions. Correct behavior under the strict reading.

### F5 — egress-spike (netflow + process correlation)

| Dimension | GT | Arm A |
|---|---|---|
| ASSESS verdict | yes/yes | yes/yes ✅ (different rationale) |
| Hypothesis count | 4 | 3 |
| Hypothesis coverage | backup, app-misbehavior, log-shipper-runaway, adversary | backup-overrun, misconfigured-backup, adversary |
| One-hop shape | all 4 | all 3 ✅ |
| Selected lead | `process-flow-attribution` single | `process-flow-attribution` single ✅ |
| Pre-registered lead predictions | 6 | 4 |
| Adversarial preserved un-split | yes | yes ✅ |

**Hypothesis delta:** Arm A's set is tighter and more closely matches the observed data (the spike was concentrated on `s3-prod-backups` → backup-agent centric). My GT carried `?app-misbehavior` and `?log-shipper-runaway` which are worse fits given the destination distribution (only s3-prod-backups spiked; other destinations were baseline). Arm A's pruning is actually better reasoning from the observables. Slight miss: Arm A did not include an explicit `?app-misbehavior` hypothesis which is still on-distribution for generic "app started writing to S3 unexpectedly" scenarios — but that's a judgment call.

**ASSESS rationale:** Arm A argued yes/yes from cost-weighted routing: benign story → backup-system-audit first (cheap, authoritative for intent); adversarial → process-flow-attribution first (reveals novel process). Defensible — the rubric reads "choice of the *very next* lead" and cost-conscious routing is a legitimate driver. Different rationale from GT (which argued yes/yes from interpretation-vulnerability of the process-attribution lead), converges on same verdict.

## Cross-cutting observations

1. **One-hop + lean discipline held consistently.** All 10 hypotheses across the three outputs conform to the invlang shape (attached_to_vertex = vertex not edge; proposed_edge with relation + parent_vertex.classification; ≤2 predictions; explicit refutation_shape). No narrative padding.

2. **Dual-layer predictions emerged as the default output shape.** Every output produced both per-hypothesis predictions (hypothesis-level) AND pre-registered lead-level predictions. Under strict rubric, no/yes cases say "skip HYPOTHESIZE, put predictions at lead level." But all three subagents produced both layers. Reading the outputs: per-hypothesis predictions describe *what a hypothesis claims* (audit trail for the invlang companion), while lead-level predictions describe *the routing decision tree* for the next GATHER. They serve different purposes and are not redundant — the subagents are effectively saying "here's the hypothesis state **and** here's how I'll read the outcome."

3. **Adversarial hypothesis reliably preserved un-split.** None of the three subagents pre-split the adversarial hypothesis into recon/c2/exfil or post-compromise/supply-chain/insider — all correctly deferred those refinements to hierarchical child IDs *after* the parent classification is confirmed. This is exactly the discipline the new SKILL.md asks for.

4. **Invlang YAML companion block produced spontaneously.** None of the prompts requested the YAML block explicitly — the subagents emitted it because §HYPOTHESIZE references the companion. Good signal that the spec is being read and applied.

5. **ASSESS verdict is slippery in single-lead-for-all cases.** F3 and F5 both have a single lead that serves all hypotheses. One subagent called it yes/yes (F3, F5), one called it no/yes (F4). The distinction is defensible either way depending on whether you read "branching" as "different step-1 lead" or "different cost-optimal first check." The **output shape was nearly identical regardless of the verdict** — this suggests the rubric's yes/yes vs. no/yes distinction matters less for extracted-subagent behavior than we thought.

## Implications for extraction

- **Viable.** The new SKILL.md §HYPOTHESIZE + invlang spec produces consistent, well-shaped output from a minimal context bundle. Three different fixtures, three clean outputs.
- **ASSESS column ambiguity needs tightening.** The rubric's branching axis reads differently depending on whether "same lead for all hypotheses" counts as no-branching. Tightening the rubric text or adding a worked example clarifying single-lead-for-all cases would collapse the current variance.
- **Dual-layer predictions as the canonical output shape.** When HYPOTHESIZE is called, produce per-hypothesis predictions (for the invlang record) + lead-level predictions (for the GATHER routing decision). Don't treat them as exclusive.
- **Round 2 candidates:** (a) Arm A reproducibility — rerun one fixture 2–3x, check output variance; (b) Arm B (enriched bundle) vs. Arm A — does enrichment still hurt under the new spec? (Round 1 found it hurt under the old spec; worth re-testing.); (c) Trust-check arm — feed Arm A output into a fresh main-agent and measure handoff acceptance.

## File map

```
rounds/round-1/
├── case-db-outbound-lowrep-arm-A.md
├── case-cron-modification-arm-A.md
├── case-egress-spike-arm-A.md
└── comparison.md  (this file)
```
