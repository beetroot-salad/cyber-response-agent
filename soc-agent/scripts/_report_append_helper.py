#!/usr/bin/env python3
"""Temporary helper: append REPORT block to investigation.md and write report.md."""
import sys, pathlib

run_dir = sys.argv[1]

REPORT_APPEND = '''
## REPORT

**Verdict:** true_positive (medium confidence) — escalated; no precedent on file for post-exploit-interactive
**Confirmed hypothesis:** h-001 (?operator-runtime-exec — authorization contract ac1 refuted by change-management anchor; disposition flipped to true_positive)
**Trace:** container-baseline(+h-001) → correlated-endpoint-events(no-resolution) → change-management(unauthorized:h-001.ac1) → disposition:post-exploit-interactive

```yaml
conclude:
  termination:
    category: trust-root
    rationale: "Ticket server (authoritative change-management source) confirmed reachable\
      \ with zero tickets — no authorization record exists for exec access to container\
      \ 982cf96c79c5 at 2026-04-28T06:14:05Z, definitively failing h-001.ac1."
  disposition: true_positive
  impact_verdict: none
  impact_severity: null
  confidence: medium
  matched_archetype: post-exploit-interactive
  surviving_hypotheses:
  - h-001
  deferred_authorizations: []
  deferred_impact_predictions: []
  summary: "A bash shell (bash -c whoami) was exec\'d into container 982cf96c79c5\
    \ (image: cyber-response-agent_devcontainer-target-endpoint) at 2026-04-28T06:14:05Z\
    \ as root/loginuid=-1 with no change-management ticket on file. The change-management\
    \ anchor returned zero tickets, definitively failing the authorization contract.\
    \ No precedent exists for the post-exploit-interactive archetype; investigation\
    \ escalates."
```
'''

inv_path = pathlib.Path(run_dir) / "investigation.md"
inv_path.write_text(inv_path.read_text() + REPORT_APPEND)
print("investigation.md updated")

REPORT_MD = '''---
ticket_id: "1777356466.11733871"
signature_id: wazuh-rule-100001
status: escalated
disposition: true_positive
confidence: medium
matched_archetype: post-exploit-interactive
matched_ticket_id: null
trust_anchors_consulted:
  - anchor: ticket-server
    kind: org-authority
    result: refuted
    citation: "GET /tickets returned {total:0, tickets:[]} — no open or closed record\
      \\ authorizing exec access to container 982cf96c79c5 at 2026-04-28T06:14:05Z"
leads_pursued: 3
trace: "container-baseline(+h-001) → correlated-endpoint-events(no-resolution) →\
  \\ change-management(unauthorized:h-001.ac1) → disposition:post-exploit-interactive"
---

## Summary

A Falco rule-100001 alert fired when `bash -c whoami` was executed as root (loginuid=-1) inside container `982cf96c79c5` (image `cyber-response-agent_devcontainer-target-endpoint`) at 2026-04-28T06:14:05Z. The container-baseline lead confirmed this is a recurring pattern (48 identical events over 7 days), consistent with a host-side runtime exec rather than an in-container application shell-out. However, the change-management anchor — the ticket server — confirmed reachability and returned zero tickets, leaving the authorization contract for h-001 definitively unmet. With no precedent on file for the `post-exploit-interactive` archetype, the investigation escalates as true_positive/medium for analyst review.

## Investigation Trace

**Loop 1 — Baseline:**
- `container-baseline` (l-001): Queried Wazuh for rule-100001 events from image `cyber-response-agent_devcontainer-target-endpoint` over the prior 7 days. Returned 48 events with uniform `cmdline=bash -c whoami`, `loginuid=-1`, `tty=34816`, `exepath=/usr/bin/bash`. Parent geometry split: majority `pname=null/<NA>` (host-side namespace boundary), minority `containerd-shim`. No zero-count baseline (r1 failed); no positive loginuid (r2 failed). h-001 graded +.
- `correlated-endpoint-events` (l-001b): Queried Wazuh for co-firing rules in the ±15-min foreground window on container `982cf96c79c5`. Found 110 co-fires: rule-100002 (sshd dup2 to inbound TCP port 22, first at 06:07:02 with dense cluster 06:12–06:18) and rule-100006 (wazuh-syscheckd reading /etc/sudoers). Both artifact geometries confirmed present in the 7-day baseline — not novel. No l-001b resolutions against h-001 hypotheses.

**Loop 2 — Authorization:**
- `change-management` (l-002): Queried playground ticket server (`GET http://ticket-server:8080/tickets`). Server confirmed reachable (connected=true, ticket_count=0). Response: `{total:0, tickets:[]}`. No open or closed record authorizing exec access to container 982cf96c79c5 or its image class at 2026-04-28T06:14:05Z. Authorization contract h-001.ac1 definitively not satisfied.

**Routing:** ANALYZE loop 2 routed to REPORT — termination category `trust-root`, disposition `true_positive`, confidence `medium`.

## Hypothesis Outcomes

- **h-001 (?operator-runtime-exec):** `+` from l-001 (48-event recurring baseline, uniform loginuid=-1, pname null/containerd-shim geometry). Authorization contract ac1 **refuted** by l-002 (ticket server returned 0 tickets). Surviving hypothesis; mechanism plausible but authorization unconfirmed — investigation escalates.

## Key Evidence

- **48 rule-100001 events over 7 days** from image `cyber-response-agent_devcontainer-target-endpoint` with uniform `cmdline=bash -c whoami`, `loginuid=-1`, `tty=34816` — establishes this exec shape as recurring for the image.
- **Ticket server `{total:0, tickets:[]}`** (GET /tickets, 2026-04-28) — no authorization record for exec access to container 982cf96c79c5 at alert time; authorization contract h-001.ac1 definitively refuted.
- **Rule-100002 co-fires** in ±15-min window: sshd dup2 to inbound TCP 172.22.0.10:38356→172.22.0.13:22, first at 06:07:02 with dense cluster 06:12–06:18; sshd `exepath=\'\'` (empty string, not a standard binary path). Geometry confirmed in 7d baseline but SSH session attribution unverified.

## Observations

- The 100002 co-fires carry an inbound SSH connection tuple (lport=22, remote ephemeral 172.22.0.10:38356) with sshd as the actor and `exepath=\'\'` (empty). This is the dup2 syscall pattern of sshd redirecting stdio to an accepted SSH socket. The geometry is present in the 7d baseline but the identity behind the 06:12–06:18 dense cluster is unverified.
- The l-001b sample is truncated to 500 of ≥10,000 correlated events (~2-hour window); per-day volume normalization is unreliable, though geometry comparison is valid.
- One sampled l-001 event shows `pname=containerd-shim` rather than null/\\<NA\\>; this is internally consistent with h-001 (both patterns arise from host-side exec primitives) but diverges from the strict "namespace boundary crossing always produces null pname" framing.

## Verdict

**Disposition:** true_positive
**Confidence:** medium
**Status:** escalated
**Matched archetype:** post-exploit-interactive
**Termination:** trust-root — ticket server confirmed reachable with zero tickets; no authorization record covers exec access to container 982cf96c79c5 at 2026-04-28T06:14:05Z.

No precedent exists for the `post-exploit-interactive` archetype (`required_anchors: []`, no snapshot on file), so `status: resolved` is not achievable. The investigation escalates with true_positive/medium confidence for analyst review.

## For Analyst

**Why escalated:** The `post-exploit-interactive` archetype has no precedent snapshots on file. Even though the investigation reached a disposition (true_positive, medium confidence) via the trust-root path, `status: resolved` requires a matched precedent for archetypes with no required_anchors. A first confirmed instance should be recorded as a precedent under `knowledge/signatures/wazuh-rule-100001/archetypes/post-exploit-interactive/` to enable future resolved routing.

**What to verify:**

1. **Authorization:** Confirm whether any operator or automated system held explicit authorization to `docker exec` / `crictl exec` into container `982cf96c79c5` (image `cyber-response-agent_devcontainer-target-endpoint`) at 2026-04-28T06:14:05Z — the ticket server had zero records. If an out-of-band authorization exists (verbal approval, runbook exception), document it.

2. **SSH session at 06:12–06:18:** Rule-100002 co-fires show an inbound SSH connection (172.22.0.10:38356→172.22.0.13:22) with a dense cluster bracketing the alert event. Identify the source: is 172.22.0.10 a known jump host, CI agent, or operator workstation? `sshd exepath=\'\'` (empty string) is anomalous and warrants verification that sshd is unmodified.

3. **Host-side exec attribution:** The host-side audit trail (dockerd or containerd/runc exec log) for container 982cf96c79c5 at 06:14:05Z would identify the initiating principal and confirm or refute operator identity. This data was not available in the current investigation scope.

**Archetype note:** The `post-exploit-interactive` archetype matches when a shell is spawned without a valid authorization record. The baseline confirms the pattern is recurring (48 prior events), which is consistent with either routine authorized exec activity or a persistent attacker maintaining access — the authorization gap is the deciding factor, and it is currently unresolved.
'''

report_path = pathlib.Path(run_dir) / "report.md"
report_path.write_text(REPORT_MD)
print("report.md written")
