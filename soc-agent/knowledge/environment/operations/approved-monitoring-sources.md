---
tags: [trust-anchor, authorization, monitoring]
provides: [approved-monitoring-sources]
---

# Approved Monitoring Sources

Confirms whether a given source/identity pair is an authorized monitoring
probe against a given target — separating sanctioned health-check traffic
from look-alike adversary activity.

## Epistemic note

`environment/context/ip-ranges.md` and `environment/context/identity-patterns.md`
answer **what is it?** (classification). This anchor answers **is it
allowed?** (sanction). The two are orthogonal: an IP can be classified as
`internal monitoring host` yet not be approved to probe a specific target,
and a pattern-monitoring username used from an unexpected source is
adversary-shaped even when both halves look familiar in isolation.

A match in this anchor is load-bearing evidence that the alert is benign.
A miss is not a refutation on its own — it means "not on the approved
list", which is the premise this anchor is designed to make explicit.

## Question answered

For a given `(srcip, srcuser, target_host)` triple and alert timestamp,
is there a documented sanctioned monitoring relationship whose scope
covers all three?

## Available systems

<!-- Example — replace with actual org systems
| System | Coverage | Access | Priority |
|--------|----------|--------|----------|
| Monitoring inventory (Ansible/Salt) | All probe configs + schedules | Git / API | Primary |
| PagerDuty/Datadog synthetics registry | External uptime checks | API | Secondary |
| Internal wiki "approved health checks" page | Manual entries | Scrape | Last resort |
-->

## Query

<!-- Example
`MCP: monitoring_inventory.lookup(srcip, srcuser, target_host)`
Returns: { approved: bool, probe_name, cadence, scope, owner } or null
-->

## Playground Deployment

| Source | Target | Username | Cadence | Approved |
|--------|--------|----------|---------|----------|
| `172.22.0.10` (monitoring-host) | `target-endpoint` | `nagios` | single attempt every 5 min | yes |
| `172.22.0.10` (monitoring-host) | `target-endpoint` | `zabbix` | single attempt every 10 min | yes |
| `172.22.0.10` (monitoring-host) | `target-endpoint` | `healthcheck` | single attempt every 15 min | yes |
| `172.22.0.10` (monitoring-host) | `target-endpoint` | any other username | any | **no** |
| `172.22.0.10` | any other target | any | any | **no** |
| any other source | `target-endpoint` | any | any | **no** |

The monitoring-host runs `playground/monitoring-host/workloads/monitoring_probe.sh <username>`
on three independent cron entries — one per tool, each with its own stable
username and cadence. Real monitoring deployments pin one username per tool
(Nagios uses `nagios`, Zabbix uses `zabbix`, etc.); rotating usernames from
a single source would violate the archetype shape and break repeats-clustering.
Anything else from this source — in particular the manually-triggered
multi-attempt variants under `playground/monitoring-host/workloads/monitoring_bait.sh` —
is **not** sanctioned and must not match this anchor.

### Grounding the monitoring-host as a live, operational source

The playground deployment has no programmatic lookup API for "is this
monitoring source approved right now?" — but the monitoring-host container
is directly inspectable via the constrained host-query CLI (see
`environment/systems/host-query/SKILL.md`). A concrete citation for the
`approved-monitoring-sources` anchor, in this deployment, is a combination
of:

1. The `(srcip, srcuser, target)` triple appears in the table above.
2. The monitoring-host is operationally alive — verifiable via
   `python3 /workspace/soc-agent/scripts/tools/host_query.py --host monitoring-host service-status cron`
   and `package-installed openssh-client`.
3. The observed SIEM history pattern for this srcip matches the declared
   cadence (single attempt every ~10 min over the last hour), from an
   `authentication-history` query.

Any one of these alone is weak evidence; the combination is the
citation. The host-query CLI explicitly blocks `file-stat` on
`/opt/workloads/` and `/etc/cron.d/` (the playground answer-key paths)
so the agent cannot read the probe script or the cron entry directly
— the grounding must come from observable operational state plus the
SIEM history pattern, not from reading the simulation source.

## Confirmation shape

A confirmation requires all of:

- The `(srcip, srcuser, target)` triple is listed as approved
- The observed cadence is consistent with the approved cadence (single
  attempt, no retry burst)
- The alert timestamp falls within an active approval window (permanent,
  or a scheduled maintenance window if time-bounded)

A source that is approved for a *different* target is not a confirmation
for this alert. A username that is approved but used from a
non-approved source is not a confirmation.

## Failure modes

- **Anchor unavailable / monitoring inventory down:** escalate.
  Do not assume sanction.
- **Source approved but burst volume observed:** refutation — the
  approved shape is single-attempt. Escalate as "approved source,
  unexpected volume" and let the analyst judge whether the monitoring
  system itself is misbehaving or compromised.
- **Source approved but username mismatch:** refutation. The approved
  list is per-username.
- **Ambiguous pending-approval entries:** escalate with both the alert
  and the pending entry cited.
