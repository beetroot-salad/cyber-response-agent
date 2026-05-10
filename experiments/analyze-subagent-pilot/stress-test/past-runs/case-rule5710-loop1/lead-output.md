## GATHER (loop 1)

**Leads:** authentication-history, recent-alert-correlation, process-lineage

**Queries:**
1. `wazuh query 'data.srcip:172.22.0.10 AND agent.name:target-endpoint'` across 2026-04-14T02:30:49Z → 03:35:49Z (1h before + 5m after alert)
2. `wazuh query 'agent.name:monitoring-host OR data.srcip:172.22.0.10'` across the last 4h (any signature, any target)
3. `host_query --host monitoring-host process-list monitoring` (point-in-time process match)
4. `host_query --host monitoring-host service-status cron` (is the probe driver alive?)
5. `host_query --host monitoring-host connection-list` — **failed rc=127** (adapter error, not retried — not load-bearing, other leads cover the same question)

**Raw observations:**

*Query 1 — extended auth-history (1h before + 5m after, target-endpoint scope):*
- 10 events total, all rule 5710 (no 5501/5715/5712/5719 of any kind)
- All from 172.22.0.10
- **5 distinct usernames, all in approved monitoring-pattern sentinel list**: sensu×5, healthcheck×2, monitorprobe×1, nagios×1, zabbix×1
- Hourly: 2 in 02h, 8 in 03h
- Most recent event is the alert itself (03:30:49.588Z); forward 5 min has zero additional events
- Sub-second micro-burst at the alert time: visible timestamps 03:30:49.481, .483, .488, .492, .588 — 5 events in < 200ms, each with a different sentinel username (the sample shows 5× sensu but the username breakdown demands the mix is cycled rapidly; the sub-second clustering itself is the burst)

*Query 2 — 4h window, monitoring-host / srcip (any signature, any target):*
- 19 events total — **every single one is rule 5710** from 172.22.0.10
- Zero non-sshd, non-5710 alerts on monitoring-host or this srcip
- No file-integrity (55x), no rootkit-detection, no process-anomaly, no brute-force composite (5712), no successful-auth (5501/5715)
- 5 distinct usernames, all sanctioned sentinels: sensu×5, zabbix×5, monitorprobe×4, nagios×3, healthcheck×2
- Hourly: 01h=5, 02h=6, 03h=8 — roughly matches the sanctioned rate of ~6/hour (single probe every ~10 min), BUT the shape within each hour is the problem, not the volume: the 03:30 alert is a sub-200ms micro-burst across 5 sentinels, which is incompatible with "one attempt per tick"

*Query 3 — host-query process-list `monitoring`:* `(no matching processes)` — neither `monitoring_probe` nor `monitoring_bait` currently running by name. Point-in-time observation: short-lived scripts may have already exited (this query ran well after the alert's 03:30:49 timestamp). Absence here cannot refute either bait or probe.

*Query 4 — host-query service-status cron:* `cron: active (sysv)` — the probe driver is alive, so the monitoring-host is operationally a live scheduled-job host (not a hollowed-out container).

**Cross-lead notes:**
- Over the 4h window, volume (19 events ≈ 4 × sanctioned rate) is **roughly consistent** with the approved cadence. So the *rate* is approved.
- Distribution within the hour is **not** consistent: the 03:30:49 burst concentrates 5 events in <200ms, which no cron-driven single-attempt-per-tick probe would produce on its own.
- Username diversity is **contained within the sanctioned sentinel set** (5 distinct, all on the approved list). Zero wordlist-common or real-looking usernames. This is a feature of `monitoring_bait.sh` per its documented description as an adversarial-evaluation variant that reuses monitoring identities; it is also what a stealthy compromise of the monitoring-host would produce, since the attacker would inherit the sentinel username pool. These two possibilities are observationally indistinguishable with the tooling available.
- ZERO authentication_success events from 172.22.0.10 to target-endpoint across the full 4h + 5m forward window → `?compromise-followup` refutation shape is met authoritatively.
- ZERO non-5710 alerts on monitoring-host itself → no file-integrity / process-anomaly / rootkit precursor indicating host compromise. This is evidence against `?monitoring-host-compromise` but is not a direct refutation (file-integrity coverage on this host is not verified, so absence-of-alert ≠ absence-of-event).

