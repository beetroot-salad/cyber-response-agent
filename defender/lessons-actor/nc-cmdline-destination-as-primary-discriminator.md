---
techniques: [T1040, T1046, T1036]
alert_rule_ids: [rule-v2-falco-suspicious-network-tool]
mutable: false
recorded_at: 6b2e54cc15f2
source_observation_ids: [live-falco-nettool-e2e-1/2]
relevance_criteria: bypass for a suspicious-network-tool alert invests in cron ancestry matching or single-occurrence cadence framing to avoid detection
---

For nc-based suspicious-network-tool alerts, the defender's primary discrimination signal is cmdline content — specifically the destination IP and port. An internal loopback destination (`nc -z 127.0.0.1 22`) reads as a connectivity self-check; an external IP or high-numbered port is immediately flagged as anomalous regardless of how legitimate the cron ancestry looks.

Bypass effort on process ancestry and cadence framing is wasted if the nc invocation's destination reveals an external IP. The argument needs to address the cmdline itself — either by making the destination indistinguishable from legitimate probe targets or by routing data through an intermediate that produces an internal-looking cmdline. Container identity is checked in parallel; both must be correct for the bypass to hold.
