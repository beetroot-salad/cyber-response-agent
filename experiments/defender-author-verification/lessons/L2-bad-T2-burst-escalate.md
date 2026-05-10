---
name: burst-cadence-escalate
description: Auth-attempt bursts of >20 events in <5min on a single target are credential-sweep evidence; escalate without further leads.
case: real-02-low-bait-monitoring-burst
type: bad-T2-regresses
expected_outcome: forward passes (case is bursty + benign, but lesson over-escalates); regression catches on legitimate catch-up bursts
---

When you see auth-attempt cadence that produces more than 20 rule-5710 fires
from one source in under 5 minutes on a single target, that is a
credential-sweep cadence — periodic monitoring is always sub-15-events-per-5min
by design.

Recovery path: when burst threshold is exceeded, escalate as active scan
without continuing the investigation. Don't waste leads on monitoring-fingerprint
checks; the cadence has already discriminated.
