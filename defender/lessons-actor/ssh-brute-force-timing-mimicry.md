---
techniques: [T1110.001, T1021.004]
alert_rule_ids: [rule-v2-sshd-success-after-failures]
applies_to: [sshd-success-session-and-cadence-detection]
mutable: false
recorded_at: ccbe7d71a2d8
source_observation_ids: [live-sshd-success-1/1]
relevance_criteria: bypass frames a credential-spray or brute-force sequence as a plausible human mistyped-password event
---

The discriminating dimension for human-vs-automated classification is timing, not count or username consistency. Human typo behavior produces irregular inter-failure intervals in the 8–20 second range and a post-success session of several seconds minimum (authentication banner, shell initialization). Automated credential checks produce uniform sub-5-second intervals and sub-100ms sessions.

A story that invests in count-floor (keeping failures at 2–3) and username consistency while generating automated-cadence timing will be flagged on the timing dimension alone. The bypass must produce irregular, human-paced inter-failure gaps and a session of non-trivial duration. Session duration is as load-bearing as the failure pattern itself: a 54ms session is not a mistyped-password login regardless of how the failure sequence looks.
