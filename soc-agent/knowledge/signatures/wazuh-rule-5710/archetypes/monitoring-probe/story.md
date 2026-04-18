---
archetype: monitoring-probe
signature_id: wazuh-rule-5710
required_anchors:
  - approved-monitoring-sources
---

# Monitoring Probe — Story

An internal monitoring system confirms that `sshd` is listening on
port 22 by attempting authentication with a sentinel username that
is not a real account on the target. Each connection attempt fails
at the username-existence check — which is the point, since the
probe is not trying to log in — and Wazuh 5710 fires on the
resulting `Invalid user` log line.

The probe's defining shape is **periodic cadence**: distinct probe
attempts recur at a tool-configured interval (commonly 1m, 5m, 15m,
or hourly), not a one-off. A single probe attempt is typically one
connection event, but a natural SSH reconnect retry (network
hiccup, `ConnectTimeout`) can produce a 2-event cluster within a
few seconds — still one probe attempt. What is *not* this
archetype is a burst: many events within a second or two, or many
distinct probe attempts with no regular interval between them.

It uses a **stable username per probe source** from a narrow set
of monitoring-pattern names (`nagios`, `zabbix`, `prometheus`,
`healthcheck`, `monitorprobe`, `sensu`, `testuser`, `probe`) —
never a real user, never a wordlist rotation. Multiple monitoring
tools from the same source produce multiple *stable* `(srcip,
srcuser)` pairs, each with its own cadence; rotating usernames
from one source on a single schedule is adversary-shaped, not
tool-shaped. The source IP is **internal** and classified as a
known monitoring host in `environment/context/ip-ranges.md`.

Legitimately, there is never a successful login following a probe —
the sentinel username doesn't exist, so even if the probe submitted
credentials there is nothing to authenticate against. A 5710 probe
followed within a minute by a 5501 (auth success) from the same source
is **not** this archetype; the shape has shifted into "operator typo
recovery" or "credential compromise," either of which escalates.

What takes an alert *out* of this archetype: burst shape (a single
probe attempt with many events, or many attempts with no regular
interval), username rotation from a single source (the source is
cycling through sentinel names rather than a stable per-tool
identity), an external source (the monitoring-pattern username is
not an identity — an external source using `nagios` is an attacker
borrowing a common probe name, not a probe), or a successful
follow-up login.
