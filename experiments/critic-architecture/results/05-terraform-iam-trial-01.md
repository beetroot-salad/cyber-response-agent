# Trial 05-01 — terraform-iam-mass-change

Fixture: `05-terraform-iam-mass-change` (label: true-benign, expected: CONCEDE)

## Defender
Claim: routine reviewed-IaC apply, benign.
Load-bearing assumption: CI artifacts (PR plan output, state diff, OIDC claims) are authoritative — independently fetched from GitHub/AWS, not echoed from runner-emitted logs.

## Critic
Verdict: **CRITIQUE**.
Mechanism: compromised runner image emits a forged plan artifact matching whatever IAM mutations it actually performs.
Lead: re-fetch plan via GitHub REST `actions/runs/.../artifacts` using SIEM-held PAT, hash; diff against CloudTrail IAM events 1:1.
Prediction: matching hashes + 1:1 mapping → benign; divergence → forged.

## Baseline (single-agent)
Hypotheses: `?legitimate-terraform-apply` (merge-SHA chain), `?adversary-controlled-pr` (privilege-escalation pattern in diff, reviewer chain), `?adversary-controlled-runner` (workflow-file at merged SHA matches protected version), `?adversary-controlled-oidc-trust` (CloudTrail UpdateAssumeRolePolicy 30d), `?plan-apply-divergence` (CloudTrail event count/hash vs plan).

## Comparison
**Critic novelty: marginal.** Baseline's `?plan-apply-divergence` covers the "1:1 CloudTrail to plan" check. Critic's "re-fetch artifact independently via GitHub REST and hash" is sharper than baseline's "verify workflow file matches at merged SHA" — the critic explicitly bypasses any runner-emitted log, baseline's check still relies on data the runner could touch. Slight critic edge in specificity; baseline broader in hypothesis enumeration.
