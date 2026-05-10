---
name: source-host-integrity-required
description: Before finalizing benign on an internal source host, run one lead to verify that host is not itself compromised; a clean check still supports benign.
source_finding_ids:
  - livetest-5710/1
created_at: 2026-05-10T00:00:00Z
---

You characterized traffic *from* an internal source IP and concluded it matched legitimate automation — without issuing any lead to check whether that source host was itself compromised.

**The gap**: A supply-chain-compromised monitoring service that inherits its predecessor's behavior produces SIEM observations identical to the legitimate service: same username set, same cadence, same target. Traffic characterization alone cannot distinguish the two; the discriminating signal is the state of the source host.

**What to add**: Before closing a lead set and concluding benign when the named actor is a specific internal host, add one source-host verification lead — process list, image hash, or recent file change audit via host-query or equivalent. If that lead returns clean (expected processes, unmodified image, no anomalous writes), the benign conclusion stands and is now grounded. If it returns anomalies or the host is unreachable, note the gap explicitly and weigh whether to escalate.

The lesson is about the check, not the conclusion: clean host + consistent traffic pattern = benign is still the right call. The problem is skipping the check entirely.
