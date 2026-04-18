---
archetype: monitoring-probe
signature_id: wazuh-rule-5710
required_anchors:
  - approved-monitoring-sources
---

# Monitoring Probe — Story

An internal monitoring system confirmed that `sshd` is listening on
port 22 by attempting a single authentication with a sentinel username
that is not a real account on the target. The connection attempt
fails at the username-existence check — which is the point, since the
probe is not trying to log in — and Wazuh 5710 fires on the resulting
`Invalid user` log line.

The probe is by construction **low-volume**: one attempt per tick from
the same source, separated by the monitoring system's configured
interval (typically minutes). It uses a **stable username** from a
narrow set of monitoring-pattern names (`nagios`, `zabbix`,
`prometheus`, `healthcheck`, `monitorprobe`, `sensu`, `testuser`,
`probe`) — never a real user, never a wordlist rotation, never a
burst of distinct usernames. The source IP is **internal** and
classified as a known monitoring host in
`environment/context/ip-ranges.md`.

Legitimately, there is never a successful login following a probe —
the sentinel username doesn't exist, so even if the probe submitted
credentials there is nothing to authenticate against. A 5710 probe
followed within a minute by a 5501 (auth success) from the same source
is **not** this archetype; the shape has shifted into "operator typo
recovery" or "credential compromise," either of which escalates.

What takes an alert *out* of this archetype: volume (more than one
attempt in the monitoring window), username diversity (multiple
distinct usernames from the same source), an external source (the
monitoring-pattern username is not an identity — an external source
using `nagios` is an attacker borrowing a common probe name, not a
probe), or a successful follow-up login.
