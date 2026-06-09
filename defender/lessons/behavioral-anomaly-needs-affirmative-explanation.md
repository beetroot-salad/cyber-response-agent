---
name: behavioral-anomaly-needs-affirmative-explanation
description: Authorization confirms access rights, not automation pattern; anomalous timing or sub-second session duration needs a process-audit or scheduler lead, not inferred attribution.
source_finding_ids:
  - live-sshd-success-1/0
created_at: 2026-06-03T00:00:00Z
---

When behavioral evidence (automated failure cadence, sub-second session duration) suggests scripted SSH rather than interactive use, a benign explanation typically invokes a specific automation artifact — "connectivity-check script," "scheduled health probe." IAM authorization and CMDB trust edges confirm that the principal *can* reach the host; they say nothing about whether a particular program runs on the source host or produces this behavioral fingerprint.

**Before naming a specific mechanism in the benign summary:**
1. Run a process-audit or host-state lead on the source host that confirms the binary or cron entry. That lead result is what lets you name the mechanism.
2. If the lead cannot be executed, record the open question in `ceiling_test`, naming the source host and the specific process-identity query needed.
3. In the conclude summary, describe the behavioral pattern neutrally — "automated SSH pattern from an authorized source" — rather than naming a script or job that was never confirmed. Authorization confirmed + no process-audit coverage supports a medium-confidence benign close, not a named-mechanism benign close.

The discipline is: close at the confidence level your evidence supports. If the automation is unconfirmed, the summary reflects that gap; it does not promote the inference to a confirmed finding.
