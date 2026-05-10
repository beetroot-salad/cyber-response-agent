---
name: zero-success-indicates-spray
description: When 7d auth-failure window shows zero successful logins from a source, conclude credential spray and escalate.
case: real-01-low-monitoring-probe
type: bad-T3-doesnt-work
expected_outcome: forward catches; reverse passes; regression maybe catches on monitoring case
---

When triaging rule-5710 alerts, you sometimes accept a "monitoring" conclusion
without checking the success rate of the source's auth attempts over a longer
window.

Recovery path: before classifying a source as monitoring, gather a
7-day auth-success window for the source IP. If success_count == 0 across the
window, the source is not authenticating with valid credentials — this is the
credential-spray fingerprint, not a monitoring fingerprint. Escalate.
