# Arm B training: 05-terraform-iam-mass-change

### Single agent (triage + self-review + directive)

- cost: $0.0906
- tokens: in=2 out=966 cache_read=11896 cache_create=18966

```
### TRIAGE

**Claim:** This is a legitimate Terraform-apply run by the platform team that executed a pre-approved IAM change set; the alert fired on volume, not anomaly.

**Hypotheses considered:**

- `?legitimate-tf-apply` — PR plan artifact matches CloudTrail change-for-change; lead: diff CloudTrail events against the plan JSON line-by-line.
- `?plan-injection` — CI artifact was tampered after plan but before apply; lead: compare plan artifact SHA against the artifact stored in GitHub Actions run 7799123 at plan time.
- `?adversary-controlled-runner` — i-09abc was compromised and used the OIDC token to issue additional calls beyond the plan; lead: pull all CloudTrail events for this role session and check for any calls not in the plan diff.
- `?stolen-oidc-token` — token exfiltrated and replayed from a different execution context; lead: verify OIDC claims (repo, ref, run_id, aud) match GitHub's token verification endpoint and confirm no duplicate session from a different source IP or instance.
- `?supply-chain-compromise` — malicious Terraform provider or module injected extra resources at apply time; lead: check for any resource changes in state diff that do not appear in the plan diff.
- `?privilege-escalation-via-iam` — attacker used the apply to embed a backdoor role/policy; lead: review the 5 created policies and 9 UpdateAssumeRolePolicy changes for trust relationships pointing to external principals.

**Disposition:** `benign`

**Load-bearing assumption:** The Terraform plan artifact in the CI run was not tampered with between plan and apply — i.e., what the reviewers approved is exactly what ran.

---

### SELF-REVIEW

**1. Flip evidence for the load-bearing assumption:** A CloudTrail event for any IAM action not present in the plan artifact (even one extra `iam:PutRolePolicy`) would flip the call from benign to malicious. Concretely: a line in CloudTrail for this session's `userAgent` that has no counterpart in the plan JSON.

**2. Lead classification:**

- `?legitimate-tf-apply` — diff CloudTrail vs. plan: `load-bearing` (directly validates the core claim)
- `?plan-injection` — artifact SHA check: `load-bearing` (integrity of the approved scope)
- `?adversary-controlled-runner` — full session call enumeration: `load-bearing` (out-of-plan calls)
- `?stolen-oidc-token` — OIDC claims verification: `corroborating` (token metadata is already internally consistent; an attacker with runner access wouldn't need to steal the token)
- `?supply-chain-compromise` — state vs. plan diff: `load-bearing` (detects injected resources at apply time)
- `?privilege-escalation-via-iam` — trust policy review: `load-bearing` (benign volume ≠ benign content)

Most leads are load-bearing — coverage is adequate.

**3. Counter-anchor check:** I did not consider `?review-bypass` — the two approvers are colluding with the author, and the PR itself contains the malicious change legitimately approved. In that scenario all provenance checks pass and the attack surface is the human review layer, not the technical controls. This is low-probability but structurally invisible to automated analysis.

---

### DIRECTIVE

For high-volume IAM alerts triggered by CI/CD pipelines with strong provenance, the critical discipline is **plan-to-reality binding, not principal legitimacy**. The OIDC chain, PR approvals, and run metadata are relatively easy to forge or satisfy legitimately — they establish *who ran*, not *what ran*. Attack the gap between what was approved and what executed: enumerate every CloudTrail event in the role session and diff against the approved artifact. Then audit *content* of the changes (trust relationships, wildcard permissions, cross-account principals) independent of count. Volume-based signatures on CI roles almost always fire on legitimate deployments; the real signal lives in the delta.
```
