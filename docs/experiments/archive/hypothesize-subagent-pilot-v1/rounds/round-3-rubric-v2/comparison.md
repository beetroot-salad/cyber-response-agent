# Round 3 — F4 reproducibility under rewritten ASSESS rubric

**Method:** same fixture (F4 cron-modification), same minimal bundle, same Arm A prompt. Three independent runs. Sonnet. Rewritten ASSESS rubric in effect — branching is now a hypothesis-space property (multiple competing one-hop classifications), not a lead-identity property. Lead selection is framed as a distinct downstream step inside HYPOTHESIZE.

## Cross-run comparison

| Dimension | Run 1 | Run 2 | Run 3 |
|---|---|---|---|
| ASSESS: fork? | yes | yes | yes |
| ASSESS: interp.-vulnerable? | yes | yes | yes |
| Lead selection mode | primary-plus-deferred | primary-plus-deferred | single-with-deferred-secondaries |
| Primary lead | `auditd-syscall-audit` | `auditd-syscall-audit` | `auditd-syscall-audit` |
| Deferred secondary leads | cm-deploy-audit, session-audit | cm-deploy-audit (loop 2) | cm-deploy-audit, session-audit |
| Hypothesis count | 3 | 3 | 3 |
| Hypothesis set | cm-deploy / interactive-admin / adversary-persistence | cm-deploy / interactive-admin / adversary-persistence | cm-deploy / interactive-admin / adversary-persistence |
| Adversarial preserved un-split | yes | yes | yes |
| Per-hypothesis predictions | yes | yes | yes |
| Lead-level pre-registered predictions | 4 | 4 | 4 |
| Compromised-CM-agent pitfall flagged | yes | yes | yes |

**Meta-decision variance: zero.** All three runs converged on identical ASSESS verdict, lead choice, and hypothesis set. The "primary-plus-deferred" vs "single-with-deferred-secondaries" labels are synonyms — same dispatch shape.

## Comparison to Round 2 (rubric v1)

| Dimension | Round 2 | Round 3 |
|---|---|---|
| ASSESS verdicts across runs | no/yes ×2, yes/yes ×1 | yes/yes ×3 |
| Lead choices across runs | auditd ×2, cm-deploy-audit ×1 | auditd ×3 |
| Output shapes across runs | full block, skip-block, full block with different lead | uniform full-block |
| Hypothesis content | stable | stable |

The content layer (hypothesis set, lean discipline, adversarial preservation, pitfall enumeration) was already reproducible in Round 2 — what wasn't was the meta-decisions that depended on reading the ambiguous branching definition. Rewriting the rubric around hypothesis-space forking (rather than lead-identity change) collapsed the ambiguity.

## What the rewrite fixed

The old rubric asked "does the lead's identity change under different hypotheses?" — which conflated two orthogonal questions and admitted multiple defensible readings of F4:

- Run 2 (v1, no/yes): "auditd serves all hypotheses; same query regardless of story → no branching." Defensible.
- Run 3 (v1, yes/yes): "CM-story prefers cm-deploy-audit first, interactive prefers session-audit first → lead identity *would* change under different priors." Also defensible.

The new rubric separates these:
- **Branching** asks only about the hypothesis space: are there ≥2 competing one-hop classifications? For F4, unambiguously yes.
- **Lead selection** is a downstream optimization: given the fork, what edge measurement most efficiently discriminates? For F4, a single auditd query partitions all three — that's efficient lead selection, not absence of branching.

Under the new framing, all three subagents landed on the same answer to both questions.

## Implications

**The rewritten rubric is reproducible.** Three independent Sonnet runs produced identical meta-decisions on a fixture that produced 3-way variance under the previous rubric.

**Content reproducibility was never the problem.** Hypothesis set, lean discipline, adversarial preservation, lead-level prediction structure were stable across both rounds. The rubric fix targeted meta-decision variance, and that's what collapsed.

**Extraction viability strengthened.** Meta-decision variance was the main risk for the HYPOTHESIZE-as-subagent extraction — if each invocation could lottery between "produce a HYPOTHESIZE block" and "skip HYPOTHESIZE," downstream tooling (invlang validator, ANALYZE subagent) would be unreliable. With the rubric rewrite, that variance is gone under ambiguous fixtures.

## Next-round candidates

1. **Cross-fixture reproducibility check** — rerun F3 (db-outbound) 3× under new rubric to confirm the fix generalizes.
2. **Arm B — pre-extracted one-hop classification enumeration.** With meta-decision variance resolved, test whether bundle enrichment helps content-level consistency or biases the subagent toward the pre-listed classifications. Under old rubric this was the dominant worry; now it's isolated.
3. **Trust-check arm** — feed a Round-3 output into a fresh main-agent and measure whether it routes directly (extraction handoff works) or re-derives (subagent output is insufficient for main-agent continuation).

## File map

```
rounds/round-3-rubric-v2/
├── case-cron-modification-arm-A-run1.md
├── case-cron-modification-arm-A-run2.md
├── case-cron-modification-arm-A-run3.md
└── comparison.md  (this file)
```
