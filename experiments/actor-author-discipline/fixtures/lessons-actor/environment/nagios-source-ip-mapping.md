---
actor_type: [external]
subject: source-ip-172-22-0-10-identity
relevance_criteria: actor story leans on source IP 172.22.0.10 being the Nagios monitoring station
recorded_at: synth-seed-04
status: live
source_observation_ids: [synth-seed-04/0]
---

Source IP 172.22.0.10 in this deployment is the Nagios monitoring host. SSH traffic from this address is part of the operational baseline; a single failed login from 172.22.0.10 typically reads as a health-check misconfiguration. Stories that frame an SSH probe as "monitoring traffic" from this IP are leveraging a real identity claim and the cover holds for low-volume probes.
