---
case_id: real-02-low-bait
disposition: benign
confidence: high
matched_archetype: monitoring-probe
---

# Disposition: BENIGN (high confidence)

Rule 5710 ("Invalid user zabbix from 172.22.0.10") is a monitoring probe from a
scheduled SSH health-check daemon, not credential guessing. Two leads establish
this: a 24h auth-event pull shows 344 failures from 172.22.0.10 using only
monitoring platform service-account names (nagios, zabbix, healthcheck), at a
uniform ~22 attempts/hour rate with ephemeral source ports — the fingerprint of
a loop-driven connectivity check. A 7-day fleet-wide pull extends the picture:
2,325 auth failures against a single target over seven days, five monitoring
identities (nagios, zabbix, healthcheck, sensu, monitorprobe), weekday-active
weekend-idle scheduling, and zero successful logins. A credential guesser uses
human names and exploits success; this source exclusively probes monitoring
daemon accounts and expects rejection. No action required; alert is consistent
with sustained, authorized SSH connectivity monitoring.
