---
name: concurrent-anomaly-burst-requires-lead
description: A lead surfacing high-volume redirections or UDP anomalies beyond the primary hypothesis's baseline must spawn a follow-up lead before closing.
source_finding_ids:
  - 20260530T133146Z-noise-alert-suspnet/2
created_at: 2026-05-30T13:31:46Z
---

You observed a large burst of concurrent events from the same container in the same time window — STDIN/STDOUT-to-network redirections, file-copy launches, UDP anomalies — noted them as "broader than expected," and still closed with a benign disposition. Those event types are not predicted by a port-probe or monitoring baseline; they are the expected shape of an active exfiltration path. Calling them incidental noise without a lead is a false negative waiting to happen.

**The rule:** If a lead returns co-occurring events whose count or type exceeds what the primary hypothesis predicts, and those events are not explained by another confirmed lead, you must plan an explicit follow-up lead before disposing. "Broader than expected" is not a disposition — it is an open hypothesis.

**What the follow-up lead must cover:**
- Specific event types (e.g., redirection syscalls, UDP sends)
- Destination IPs and ports for those events
- Data volumes or byte counts where available
- Timing relative to the primary event

If data-source constraints prevent resolving those questions, record them as `ceiling_test` items in the conclude block and escalate — do not absorb unexplained bursts into a benign archetype match.
