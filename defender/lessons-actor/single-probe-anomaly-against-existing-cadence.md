---
techniques: [T1040, T1046]
alert_rule_ids: [rule-v2-falco-suspicious-network-tool]
mutable: false
recorded_at: e8e5c01b9664
source_observation_ids: [20260530T133146Z-noise-alert-suspnet/1, live-falco-nettool-e2e-1/1]
relevance_criteria: bypass claims single-probe or low-count approach avoids volume-based anomaly detection for a network tool alert
---

A one-off probe is not quieter than an established baseline — it is louder. When the environment already has a recurring execution cadence for the same tool invocation pattern (e.g. a health-check running every few minutes, producing dozens of events per hour), a single novel instance stands out precisely because it breaks the pattern. Volume-based detectors measure deviation from baseline, not absolute count.

The hard-to-detect approach is to match the existing cadence closely enough that the new event is indistinguishable from the baseline run — same interval, same source, same destination, same argument shape. Understanding that the baseline already produces the cadence (and where it comes from) is a prerequisite for designing cover that blends into it rather than surfacing as an outlier.
