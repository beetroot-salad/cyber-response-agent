# Batch 2 post-mortem — V1 (frontier classifier)

**Variant edit:** +22 lines. New `## Frontier classification (Step 0)` section before §Decision procedure. Each open question on the confirmed graph is classified as either `attribute-of-confirmed-vertex` (resolves via `attribute_predictions[]`, `aN` IDs) or `upstream-edge-extension` (resolves via new hypothesis with `proposed_edge`, `hN` IDs). Includes the rule-100001-shaped worked example with the inferred containerd vertex.

**Matrix:** V1 × 5 cases × 3 reps = 15 cells. Wall: 514s @ parallelism 4. 15/15 ok.

**Aggregate score:** 0.621 (V0 baseline: 0.636 → **−0.015**).

## Per-case delta vs V0

| Case | V0 score | V1 score | Δ | V0 shape | V1 shape | Read |
|---|---|---|---|---|---|---|
| case-001 | 0.743 | 0.743 | 0.000 | E (3/3) | E (3/3) | No effect |
| case-002 | 0.733 | 0.725 | −0.008 | A (3/3) | A (3/3) | Right anchor lead 2/3 (vs V0 1/3) — masked by D5 noise |
| case-003 | 0.500 | 0.452 | −0.048 | E (3/3 wrong) | E (3/3 wrong) | M-recognition unchanged; D5 fired more |
| case-004 | 0.615 | 0.692 | **+0.077** | A (3/3 wrong) | E (1/3) + A (2/3) | **Variant succeeds 1/3** — see below |
| case-005 | 0.590 | 0.494 | −0.096 | M (2/3 wrong) | M (3/3 wrong) | V1 made the sideways pivot **more consistent** |

## case-004 rep-1 — the run-#44 reproduction, fixed

V1 emits a clean Shape E with 4 readings on `container-baseline`, including a `lp4: falco-coverage-gap` reading that explicitly handles the "Falco has no coverage record for this image" branch. The story replaces V0's invented `?operator-host-exec` hypothesis with: "the alert's `proc_pname` is null → refill the gap via a 7-day image-baseline query → branch on what the baseline returns."

This is **exactly what V1 was designed to produce** on the run-#44 case. The frontier classifier reframes "what process is the parent?" as an *attribute-of-confirmed-vertex* (parent identity is a property of the existing `bash` vertex), not as an unknown to be storied; the path-of-least-resistance is then "fill the attribute via lead," not "invent a hypothesis." **Discipline works when it activates.**

## case-004 reps 2-3 — variant did NOT activate consistently

Reps 2 and 3 regress to V0's pattern: Shape A with hypotheses `?host-side-exec-primitive` and `?host-side-runtime-exec`. **V1's frontier-classifier text was in the prompt all 3 reps, but the agent only consulted it once.** This is the central V1 finding — the discipline is correct when it fires; the worked example is not strong enough to make it fire reliably.

Two structural reasons this might be:
1. The classifier section sits *before* §Decision procedure, but §Decision procedure's existing wording ("default bias: E whenever uncertain") is also pro-E. The classifier doesn't change the decision rule, only adds an upstream step. Under prompt pressure, the agent can skip the upstream step and walk decision procedure as before.
2. The worked example is a *containerd*-shaped frontier (rule 100001 with the inferred containerd vertex). Case-004's alert does not have a pre-inferred containerd vertex (CONTEXTUALIZE doesn't run mechanism-inference yet — that's task #1 of the parent design). The example is structurally analogous but not pattern-matchable from the alert payload alone.

## case-005 — V1 regressed, didn't help

V0 scored 1/3 reps right (rep-1 emitted the correct Shape E upstream probe); reps 2-3 sideways-pivoted. **V1 pushes ALL three reps to the sideways-pivot Shape M with two peer hypotheses** (`?monitoring-system-is-the-actor` + `?credentials-used-outside-registered-actor`), attached to v-001 (the alert vertex). The peers share `proposed_edge` shape and predictions; this is the invoker-identity peer-fork anti-pattern in disguise.

**Hypothesis on the regression:** V1's classifier framing ("upstream-edge-extension → new hypothesis with proposed_edge") may be biasing the agent toward edge-extension framing *for every loop*, even when the right move (loop 3, after ++) is to attach to a *new* upstream vertex rather than a peer on the confirmed one. The variant's prose names "upstream-edge-extension" but doesn't distinguish "extension to *which* vertex." The existing `## Backward traversal on ++` discipline (left intact in V1) competes with the classifier's newly-loaded prose.

Worth noting: V1 made the pathology MORE consistent (V0: 2/3 wrong, V1: 3/3 wrong). When variants make existing failure modes more deterministic, that's a signal the prompt-pressure landscape changed in a measurable way — not necessarily for the better.

## case-003 — V1 did not help on M-recognition

All 3 reps still default to Shape E with NXDOMAIN-sampling leads (`source-reputation`, `network-analysis`, `correlated-endpoint-events`). V1's classifier categorizes the open question as "what mechanism explains the NXDOMAIN spike" → that should map to *upstream-edge-extension* with two competing parent classifications (misconfigured-resolver vs DGA-process), but V1 still picks E. The classifier doesn't override the "default bias: E" rule.

## case-001/002 — modest signal under D5/D2 noise

case-002: V1 picked `approved-monitoring-sources` (the rubric's expected anchor lead) on 2/3 reps vs V0's 1/3. Modest improvement masked by D5 false-positive rate.

case-001: identical to V0. V1's classifier doesn't change Shape E enrichment behavior on a clean loop-1 case.

## Failure-mode summary vs V0

| Failure | V0 | V1 | Net |
|---|---|---|---|
| Default to E on real M (case-003) | 3/3 wrong | 3/3 wrong | No change |
| Mechanism-spiral on null discriminator (case-004) | 3/3 wrong | 2/3 wrong | **+1 rep fixed** |
| Sideways pivot after ++ (case-005) | 2/3 wrong | 3/3 wrong | **−1 rep regressed** |
| Lead-choice noise (case-001) | persistent | persistent | No change |

## Verdict on V1

- **Discipline is correct when it activates.** The case-004 rep-1 envelope is the cleanest "right answer" produced in either batch so far.
- **Activation rate is the bottleneck.** 1/3 on the case the variant most directly targets means the worked example or wording isn't strong enough to outpull the existing E-default discipline.
- **Negative spillover on case-005.** The classifier's edge-extension framing may be biasing the agent toward peer hypotheses on the alert vertex even when backward traversal is the right move. The interaction with the existing backward-traversal discipline section is unclean.
- **Containerd-specific worked example may overfit.** Reps that don't see a containerd-shaped fingerprint may not generalize.

V1 is a partial signal: it can produce the correct discipline, but does so unreliably and with measurable spillover. Worth landing if the activation rate can be lifted (e.g., by replacing "default bias: E" with "default to whichever shape the classification pass identified") — but in its current form it nets a modest aggregate loss.

## Next: launch Batch 3 (V2 unknowns slot × 5 × 3)
