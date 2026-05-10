---
name: source-host-integrity-unverified
description: Classifying internal-source traffic as benign automation without a lead verifying the source host isn't compromised leaves supply-chain vectors untested.
source_finding_ids:
  - livetest-5710/1
created_at: 2026-05-10T00:00:00Z
---

You characterized traffic *from* an internal IP and concluded the pattern matched known-good automation, but you issued no lead to interrogate the source host itself.

The gap: an attacker who compromises the automation service (supply-chain, image-tampering, RCE inside the container) fully inherits its observed behavior — same source IP, same username set, same timing pattern. All SIEM leads that describe what the source *does* will return identical results under both the benign and compromised-automation hypotheses.

**Check to add before closing benign:** when the leading hypothesis is "legitimate automated process at host X," include a lead that directly tests X's legitimacy — process/image provenance, unexpected outbound sessions from X, or a CMDB query confirming X is a registered, managed node. If no such system is reachable, note the gap explicitly and escalate rather than resolve.

Traffic characterization proves what was sent; it does not prove who sent it is uncompromised.
