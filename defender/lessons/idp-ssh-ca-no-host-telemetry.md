---
name: idp-ssh-ca-no-host-telemetry
description: Vault or IDP-issued SSH certificates leave no host-level artifact; name cloud control-plane audit sources as ceiling_test gaps instead of planning host leads.
telemetry_source: [ssh-ca, identity, sshd]
attack_phase: [initial-access, lateral-movement]
source_signature: [v2-cross-tier-ssh-pivot]
source_finding_ids:
  - live-xtier-pivot-3/2
created_at: 2026-06-03T00:00:00Z
---

When the suspected attack path involves IDP session token capture (e.g., Okta, Azure AD) followed by a short-lived SSH certificate request from a CA service (Vault, step-ca), the host-layer footprint is zero: certificate-based SSH auth writes no key to `authorized_keys`, no Falco alert fires for key injection, and the certificate issuance itself occurs entirely in the cloud control plane. Planning a host-query or SIEM lead to recover that evidence is a dead end — the lead returns nothing, and that absence does not distinguish "clean" from "attack occurred but no host telemetry."

**When IDP-fronted SSH CA access is a live hypothesis:**
1. The covering data sources are cloud control-plane audit logs: IDP audit logs (session token usage, short-lived cert requests correlated by session) and SSH CA audit logs (Vault: `ssh/sign` calls with requesting identity and cert TTL).
2. If those sources are not in the investigation toolset, record them by name in a `ceiling_test` gap — do not substitute a host-query lead that cannot reach them.
3. The only host-side signal is in sshd Accepted messages: an `RSA-CERT` token with an unrecognized CA fingerprint is the host-level indicator; the cloud control-plane logs explain what happened upstream.

Do not plan host or SIEM leads targeting key artifacts (authorized_keys, known_hosts) when the attack model uses certificate auth — there is no key artifact to find.
