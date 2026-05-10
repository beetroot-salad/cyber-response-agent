# Long-investigation trajectory — billing svc-account mimicry (2 rounds, 3 configs)

Goal: a *harder* long-investigation fixture than mchen — one where surface signals strongly support benign and the discriminating tells require integration across multiple R1 evidence fields. Test whether the architecture's drift-correction mechanism produces outcome differences (not just trajectory differences) when defender drift has more room to compound.

## Fixture summary

Alert: serviceaccount `api-billing-prod`, 4720 queries on customer_pii in 4h Tuesday business hours (within 2σ of baseline). Query shape matches baseline. Pod image SHA matches helm 2.18.0. PR #6612 explains a recent customer-pii feature.

Hidden tells in R1 evidence packet:
- Pod created by `kubeconfig user dev:abansal@corp.com` (NOT deployment-controller). All other 90d billing-api pods are controller-created.
- Pod manifest mtime 2d ago; helm release was 7d ago.
- Pod env override `BILLING_DB_QUERY_LOG_LEVEL=ERROR` — log suppression, only pod in fleet with this.
- `/v2/exports/customer-pii` accounts for 0% of pod's traffic — the feature is *not* driving the volume.
- Inter-query timing tight 2.5–3s low-jitter — scripted, not request-driven.

Ground truth: malicious. abansal's kubeconfig leaked; attacker created an off-band pod from the legitimate image with logging suppressed, enumerating customer_pii.

## Trajectory by config

### Config A — Sonnet baseline

**R1**: leaning "legitimate volume spike driven by new endpoint." 5 hypotheses including H3 (origin pod exclusivity) and H5 (pod image digest at runtime). Did NOT propose pod-creator-principal check.

**R2**: **ESCALATE — high-confidence malicious activity.** Caught the kubeconfig-creator anomaly, log-suppression env var, timing signature. Listed concrete IR actions (evict pod, revoke kubeconfig, cluster-wide audit, treat as exfil).

Tokens 41.5K, wall-clock 29.8s, **cost ~$0.21**.

### Config B — Opus baseline

**R1**: leaning "likely benign." 6 hypotheses including `?slow-burn-enumeration-within-shape` with entropy/coverage lead — *exactly the truth-hypothesis*, named at R1. Plus pod image digest check.

**R2**: **escalate — high confidence.** Used `++/--` weighting; promoted a new hypothesis (`?adversary-controlled-pod-out-of-band-deploy`) from evidence; produced the most thorough writeup. Five-signal convergence cited (provenance break, authority mismatch, manifest mtime, log-suppression, behavioral fingerprint).

Tokens 58.5K, wall-clock 38.6s, **cost ~$2.63**.

### Config C — Sonnet defender + AGGRESSIVE critic

**R1 defender**: "BENIGN / authorized; **LOW** suspicion for exfil." Most benign-leaning R1 of all three configs. Load-bearing: "volume step-up tracks billing-export feature usage ramp."

**R1 aggressive critic**: sharp attack — "PR + helm paper trail provides provenance for the *deployment*, not the *traffic*." Demanded per-pod origin + inter-query timing histogram. Disposition demand: must show queries originate from billing-export pods *and* timing is request-driven.

**R2 defender**: "ESCALATE — HIGH suspicion." R1 assumption explicitly falsified. Recognized: "image digest match is a red herring: attacker reused legitimate image to blend in."

**R2 aggressive critic**: **CONCEDE**. "Manufacturing a critique would require inventing unobservable mechanisms — that is rationalization, not criticism."

Tokens 81.7K, wall-clock 39.0s, **cost ~$0.41**.

## Comparative summary

| Config | R1 leaning (baseline benign-ness) | R2 verdict | Cost | Notes |
|---|---|---|---|---|
| Sonnet baseline | "legitimate spike" | ESCALATE | $0.21 | caught it without naming truth-hypothesis at R1 |
| Opus baseline | "likely benign" | escalate | $2.63 | named truth-hypothesis (slow-burn enumeration) at R1 |
| Sonnet d+aggr-critic | "LOW suspicion" (most benign) | escalate (critic CONCEDE) | $0.41 | strongest drift; critic course-corrected before R2 |

All three reached the correct disposition. No false-benign closures even on a fixture designed to support them.

## Why the architecture didn't separate

The R2 evidence packet I wrote contained tells loud enough that all three configs caught them:
- "Created by kubeconfig user, NOT deployment-controller" is unambiguous
- "BILLING_DB_QUERY_LOG_LEVEL=ERROR — only pod in fleet" is unambiguous
- "0% traffic to the feature endpoint that supposedly explains the volume" is unambiguous

The intended discriminator was: a *drifted* defender at R1 would rationalize each tell at R2 ("kubectl exec is normal," "env var might be experimental"). In practice, three independent unambiguous signals at R2 were enough to overcome any R1 framing.

This is a fixture-design problem, not an architecture finding. **As experimenter writing the evidence packet, I cannot write tells subtle enough that baseline misses while the critic catches.** Every legible-to-me signal is legible-to-baseline. Every signal subtle enough to evade baseline is subtle enough to evade me when designing it.

## What this confirms

1. **Pattern across two fixtures**: Sonnet defender's R1 is the most benign-leaning of the three configs (mchen: "suspicious-leaning, not malicious" vs baselines "anomalous"; billing: "LOW suspicion" vs baselines "likely benign"). This is consistent enough to be the prompt's effect, not noise.

2. **The aggressive critic + gate continues to self-stop** — second clean CONCEDE under correct disposition. Validates that aggressive persona doesn't compound into paranoia.

3. **Architecture's mechanism is course-correction without outcome change** — second fixture in a row where the architecture changes the trajectory but not the verdict.

## What this experiment cannot show

The architecture's outcome value vs baseline is not measurable in any fixture I can write. The next discriminating test is **real tool usage** — when the defender's view of evidence is filtered by their own query selection (and a critic can attack what wasn't asked), the experimenter's authoring bias is broken.

See `tool_harness_design.md` for the proposed harness.
