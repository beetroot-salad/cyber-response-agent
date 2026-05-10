# Trial 07-01 — cert-renew-handshake-failures

Fixture: `07-cert-renew-handshake-failures` (label: true-benign, expected: CONCEDE)

## Defender
Claim: documented cert-rotation transient matching runbook RB-44, benign.
Load-bearing assumption: cert-manager renewal at 11:08:11Z was authorized — secret v218 issued by expected ACME/internal CA against properly-scoped CertificateRequest, not attacker-triggered swap.

## Critic
Verdict: **CRITIQUE**.
Mechanism: cert-manager RBAC abuse or compromised Certificate CR forces early renewal pointing issuerRef at rogue ClusterIssuer.
Lead: SPKI/Issuer fingerprint v218 vs v217; CertificateRequest v218 issuerRef + creator (managedFields/audit) diff against prior 12 rotations.
Prediction: issuer fingerprint matches historical + creator is cert-manager controller SA → benign; mismatch → refutes.

## Baseline (single-agent)
Hypotheses: `?benign-cert-rotation-churn` (per-second EOF aligned to reload timestamps), `?legitimate-clients-old-session-cache` (sample 423 IPs against inventory), `?adversary-controlled-client-ip` (inventory diff), `?cert-misissue-or-chain-break` (secret SAN/chain/key inspection), `?adversary-controlled-cert-issuance` (cert-manager controller + audit logs, issuer/challenge/SA/CT-log entry vs prior 12), `?ingress-misconfig-or-overload`.

## Comparison
**Critic novelty: marginal.** Baseline's `?adversary-controlled-cert-issuance` lead covers issuer + requesting SA + CT-log comparison against prior 12 rotations. Critic's specific check is "SPKI fingerprint v218 vs v217" — a slightly sharper artifact than baseline's general "verify issuer." Baseline broader (6 hypotheses including client-IP inventory check critic missed).
