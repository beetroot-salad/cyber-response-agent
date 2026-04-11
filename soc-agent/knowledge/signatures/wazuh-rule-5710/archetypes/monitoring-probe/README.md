---
archetype: monitoring-probe
signature_id: wazuh-rule-5710
required_anchors:
  - approved-monitoring-sources
---

# Monitoring Probe

## Story

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

## Trust Anchors

### `approved-monitoring-sources`

**Question:** is the `(srcip, srcuser, target_host)` triple on the
sanctioned monitoring list — and is the observed cadence consistent
with what that entry declares?

**Confirmation:** the anchor returns an approved entry matching all
three keys, the cadence matches (single attempt per monitoring tick),
and the alert timestamp falls inside any time-bounded approval window
the entry declares. An entry that approves the source for a different
target, or a different username than observed, is not a confirmation.

A match here is load-bearing evidence that the alert is benign.
Absence of a match is a **refutation** — internal monitoring probes
must be on the sanctioned list, and an unlisted monitoring-shaped
probe is adversarial until proven otherwise.

## Precedents

Ticket snapshots that matched this archetype are stored next to this
README as `{TICKET-ID}.json`. Each snapshot is a pointer to the real
ticket in the source-of-truth ticketing system — the KB copy is a
cache for fast-path matching and few-shot grounding, and can be
replaced rather than refreshed in place.
