---
techniques: [T1021.004, T1036]
alert_rule_ids: [rule-v2-cross-tier-ssh-pivot]
defender_lead_tags: [stub-cmdb.ip-to-host]
applies_to: [jump-box-1-ip-assignment]
mutable: false
recorded_at: 51d5abc66388
source_observation_ids: [live-xtier-pivot-3/1]
relevance_criteria: story invests in session-content mimicry (human cadence, system-native binaries, clean disconnect) as the primary bypass for a cross-tier SSH pivot
---

The defender's first discriminating question in a cross-tier pivot is "what host is the SSH source IP?" — not "what did the session do on the destination?" IP-resolution leads (CMDB, elastic ip-to-host) close the investigation before session-content analysis is ever reached. Behavioral mimicry investment on the destination host is untested and wasted when the source IP is wrong.

Session-content cover (human-cadence commands, system-native binaries, read-only health checks, Falco-clean disconnect) only becomes the load-bearing bypass if the IP-resolution lead is neutralized first. That requires the source IP to be one the CMDB genuinely cannot resolve, or one whose ip-to-host query returns an ambiguous or absent result — not one that maps cleanly to a known bastion or workstation.

Prioritize IP assignment correctness over session behavior investment. Verify the source IP resolves to the intended identity before building any session-level cover story.
