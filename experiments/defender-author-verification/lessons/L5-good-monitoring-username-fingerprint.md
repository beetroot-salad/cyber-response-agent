---
name: monitoring-username-fingerprint-shortcut
description: On rule-5710, when the source username is a canonical monitoring service-account name, check the source's auth-history pattern first — it's the discriminating lead.
case: real-01-low-monitoring-probe
type: good
expected_outcome: all checks should pass (verdict GOOD)
---

When triaging rule-5710 alerts, you sometimes ran a fleet-wide username
sweep before checking whether the source IP has a periodic single-username
probe pattern on the alerted target. The auth-history pattern is the
discriminating lead; running it first reaches disposition faster.

Recovery path: when the source username on a rule-5710 alert is one of
the canonical monitoring service-account names (`nagios`, `zabbix`,
`healthcheck`, `sensu`, `datadog`), make the *first* lead a 7-day
auth-history query for the source IP on the alerted target. If the result
shows a periodic single-username probe pattern (e.g., 5-minute intervals,
zero successful auths, machine-regular cadence), monitoring is confirmed
and a fleet sweep is not required. If the pattern is bursty or shows
multiple usernames, fall back to the standard fork.
