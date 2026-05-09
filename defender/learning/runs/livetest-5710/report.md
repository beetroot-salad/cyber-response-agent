---
case_id: livetest-5710
disposition: benign
confidence: high
---

# Disposition: benign — misconfigured monitoring probe

Rule-5710 fires on `target-endpoint` trace to an automated monitoring probe at `172.22.0.10` that cycles through five standard monitoring service-account names — `nagios`, `zabbix`, `healthcheck`, `monitorprobe`, `sensu` — attempting SSH connections at a uniform ~22 events/hour cadence. The 7-day window shows 2,255 total fires with zero authentication successes, single-source/single-target scope, and no lateral spread to other hosts. The fixed set of monitoring-tool usernames, the regular cadence, and the complete absence of any success signal are inconsistent with adversarial credential-guessing; they are consistent with a misconfigured host reachability check (likely a monitoring agent such as Zabbix or Nagios) running SSH probes against a host that does not have the expected service accounts. No threat action is indicated; however, the monitoring configuration should be corrected — either create the requisite service accounts on `target-endpoint`, switch to key-based SSH health checks, or use a non-SSH reachability probe — to eliminate the noise and avoid masking genuine brute-force signals in the future.
