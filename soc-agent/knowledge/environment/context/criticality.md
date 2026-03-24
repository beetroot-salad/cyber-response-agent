---
tags: [assets, criticality]
---

# System Criticality

## Criticality Tiers

| Tier | Definition | Escalation Threshold |
|------|------------|---------------------|
| Critical | Revenue-impacting, customer-facing, auth infrastructure | Any confirmed threat → immediate escalate |
| High | Internal production, CI/CD, data pipelines | Confirmed threat → escalate, suspicious → investigate thoroughly |
| Medium | Development, staging, internal tools | Normal investigation flow |
| Low | Test environments, sandboxes | Reduced investigation depth acceptable |

## Critical System Patterns

<!-- Example — replace with actual org critical systems
| Pattern | Tier | Reason |
|---------|------|--------|
| *-prod-* | High+ | Production systems |
| auth-*, sso-*, idp-* | Critical | Authentication infrastructure |
| db-prod-* | Critical | Production databases |
| ci-*, jenkins-*, gitlab-runner-* | High | CI/CD pipeline |
-->

## Investigation Impact

When alert involves a critical/high-tier system:
- Minimum 3 leads before resolution (regardless of signature severity)
- Adversarial hypotheses require stronger refutation (++ not sufficient alone)
- Consider scoping leads even for benign disposition
