---
name: burst-cadence-does-not-disqualify-monitoring
description: Bursty rule-5710 cadence (>20 fires in <5min) does not by itself disqualify monitoring; check source-role context before weighting toward adversarial.
case: real-02-low-bait-monitoring-burst
type: good
expected_outcome: all checks should pass (verdict GOOD); this is the disciplined inverse of L2-bad
---

When you saw a bursty rule-5710 cadence (>20 fires from one source in
under 5 minutes), you sometimes weighted toward `?credential-guessing`
before checking whether the source IP has a documented monitoring role.
Catch-up bursts after gateway flaps, post-deploy probe restarts, and
queue-drain patterns can produce monitoring bursts that look adversarial.

Recovery path: burstiness is not on its own a discriminator on rule-5710.
Before adjusting hypothesis weights based on cadence, gather the source
IP's auth-history role across a 7-day window. If the source has a
documented monitoring fingerprint (canonical service-account usernames,
single-target focus, recurring periodic baseline outside the burst), the
burst is a catch-up artifact and monitoring remains the dominant
hypothesis. Cadence alone discriminates only when paired with username
diversity or novel source role.
