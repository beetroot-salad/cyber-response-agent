---
ticket_id: "1776137449.1265639"
signature_id: wazuh-rule-5710
status: escalated
disposition: inconclusive
confidence: medium
matched_archetype: null
matched_ticket_id: null
trust_anchors_consulted:
  - anchor: approved-monitoring-sources
    kind: org-authority
    result: refuted
    citation: "(172.22.0.10, sensu, target-endpoint) triple is on the approved table, but the approved shape is 'single attempt every ~10 min'; observed shape is a sub-200ms burst of 5 sentinel-username attempts at 03:30:49 — per the anchor's failure-mode guidance, 'source approved but burst volume observed' is a refutation of the confirmation shape."
leads_pursued: 5
trace: "screen(monitoring-probe, source-classification+username-classification+auth-history+approved-monitoring-sources) -> no_match(burst) -> auth-history-1h+correlation-4h+host-query-monitoring(10 5710 events, 5 sentinels, 0 successes, 0 other alerts on monitoring-host, cron active, no live probe proc) -> auth-history-24h+host-query-target(93 5710 events across 16 active hours ≈5.8/hr, sanctioned cadence before and after a single sub-200ms burst, next tick clean at 03:40:02 healthcheck, target-endpoint only listens on sshd:22) -> analyze(?bait:+, ?compromise:-, ?compromise-followup:--, ?guessing:--, ?broken-loop:--) -> escalate:inconclusive"
---

# Investigation Report: 1776137449.1265639

## Summary

A Wazuh 5710 (SSH invalid user) alert fired for `sensu@target-endpoint` from the sanctioned playground monitoring source `172.22.0.10`. The `(srcip, srcuser, target)` triple is on the approved-monitoring-sources list, but the observed shape refutes the `monitoring-probe` archetype: at 03:30:49.481–.588Z, 5 attempts landed in under 200ms, and the 5-minute window preceding the alert contained 6 distinct 5710 events cycling through 5 different sanctioned sentinel usernames. No successful authentication from this source occurred anywhere in the 24h preceding or 5m following the alert, and sanctioned single-attempt cadence resumed cleanly one tick after the burst (healthcheck at 03:40:02Z). The best-supported explanation is the playground's documented `monitoring_bait.sh` adversarial-evaluation workload being manually triggered — which is explicitly NOT sanctioned by `approved-monitoring-sources` — but a stealthy compromise of monitoring-host that mimics the sentinel username pool cannot be refuted with `--` evidence using the available tooling. Per the playbook, "approved source but burst volume" escalates for analyst adjudication.

## Investigation Trace

screen(monitoring-probe, source-classification+username-classification+auth-history+approved-monitoring-sources) → no_match(burst) → auth-history-1h+correlation-4h+host-query-monitoring(10 5710 events, 5 sentinels, 0 successes, 0 other alerts on monitoring-host, cron active, no live probe proc) → auth-history-24h+host-query-target(93 5710 events across 16 active hours ≈5.8/hr, sanctioned cadence before and after a single sub-200ms burst, next tick clean at 03:40:02 healthcheck, target-endpoint only listens on sshd:22) → analyze(?bait:+, ?compromise:-, ?compromise-followup:--, ?guessing:--, ?broken-loop:--) → escalate:inconclusive

## Hypothesis Outcomes

- `?monitoring-bait-triggered`: active, best-supported at `+` — all observable features (sub-200ms burst, 5-sentinel rotation confined to the approved sentinel set, clean cadence before/after, no successful login, no parallel alerts on monitoring-host, cron still alive) match the shape the playground's `monitoring_bait.sh` workload is documented to produce. Circumstantial, not authoritative: the tooling deny-list blocks `file-stat` on `/opt/workloads/` and `/etc/cron.d/`, and the process-list query returned no live bait process (consistent with a short-lived script having already exited — cannot refute).
- `?monitoring-host-compromise`: active, weakly refuted at `-` — no positive compromise indicators (no non-5710 alerts on monitoring-host in the last 4h, no wordlist rotation, no successful follow-up login, cron daemon still alive, target-endpoint listens only on sshd:22). Not refuted with `--` because a patient adversary staying inside the sentinel username pool and emitting a single burst is shape-compatible with the observation; absence of further signals is not a direct contradiction.
- `?compromise-followup`: refuted at `--` — zero `authentication_success` (rule 5501/5715) events from `172.22.0.10` against `target-endpoint` anywhere in the full 24h preceding + 5m forward window. Direct contradiction of this hypothesis's core prediction.
- `?monitoring-loop-broken`: refuted at `--` — a broken retry loop on a single probe would cluster on one username, not round-robin through all 5 sentinels; moreover the sanctioned cadence resumed cleanly at 03:40:02Z, which a broken loop would not do.
- `?internal-credential-guessing`: refuted at `--` — all 93 observed 5710 events across 24h cycle through exactly the approved sentinel username set, with no real-looking usernames and no wordlist names. Incompatible with human typo recovery or manual credential guessing.

## Key Evidence

- **SCREEN authentication-history (5 min preceding):** 6 prior 5710 events from 172.22.0.10 against target-endpoint — 5× `sensu` + 1× `monitorprobe`; screen refuted `attempt_count_5min: 1` requirement.
- **SCREEN authentication-history (60s after):** 0 successful SSH logins from 172.22.0.10 → satisfies the compromise-followup negative-check for the narrow window.
- **Extended authentication-history (1h preceding + 5m after, target-endpoint scope):** 10 events total, 5 distinct sentinel usernames (sensu×5, healthcheck×2, monitorprobe×1, nagios×1, zabbix×1), zero successful logins, sub-second clustering visible at 03:30:49.481–.588Z (5 events in < 200ms).
- **Recent-alert correlation (4h, monitoring-host OR srcip 172.22.0.10, any signature):** 19 events — ALL rule 5710 from 172.22.0.10. Zero file-integrity, zero rootkit, zero process-anomaly, zero brute-force-composite (5712), zero successful-auth events.
- **host-query on monitoring-host:** `cron: active (sysv)`, `process-list monitoring` returned `(no matching processes)` at query time.
- **24h authentication-history baseline (same srcip → target-endpoint):** 93 events, all rule 5710, 5 usernames distributed evenly (sensu:22, healthcheck:20, monitorprobe:19, zabbix:18, nagios:14), 16 hours of activity averaging ~5.8 events/hour (within sanctioned rate of ~6/hour). Hourly distribution shows steady cadence on both sides of the alert burst; next event after the burst was a single `healthcheck` attempt at 03:40:02Z — ~9 minutes after the alert, matching sanctioned cadence exactly.
- **host-query on target-endpoint (`listening-sockets`):** Only sshd listening on `0.0.0.0:22` + `[::]:22`. No backdoor listeners, no alternate auth services, no unexpected ports.
- **Trust anchor `approved-monitoring-sources`:** triple `(172.22.0.10, sensu, target-endpoint)` is on the approved table (confirmation-on-identity), but the observed burst shape violates the "single attempt every ~10 min" cadence requirement. Per the anchor's own failure-mode guidance: "Source approved but burst volume observed: refutation — escalate as 'approved source, unexpected volume'."

## Observations

- The playground environment documentation (`ip-ranges.md`) explicitly mentions that `monitoring_bait.sh` on monitoring-host is a manually-triggered multi-attempt workload "for adversarial evaluation scenarios" that "should NOT match the monitoring-probe screen pattern." The observed shape fits this description closely; if that workload was triggered, this alert is the expected resulting signal.
- The host-query tooling explicitly blocks `file-stat` on `/opt/workloads/` and `/etc/cron.d/` on both hosts, preventing the agent from verifying whether `monitoring_bait.sh` was actually invoked or reading its schedule. Combined with `process-list` returning command names only (no argv, no parent, no start time), the tooling gap is precisely the evidence class needed to distinguish a benign test injection from a low-volume mimicry attack.
- A 9-hour gap in the 24h baseline (approximately 2026-04-13T17:00 through 2026-04-14T01:00) is unexplained by available data. Noted for completeness; not load-bearing for this verdict since the pre- and post-gap cadences match the sanctioned rate.
- Wazuh rule 5712 (SSH brute force composite) did NOT fire despite 6 attempts in 5 minutes, suggesting either the composite's threshold is higher than the observed burst or the composite is not enabled in this deployment.

## Verdict

**Escalate as "approved source, unexpected volume"** — the alert's `(srcip, srcuser, target)` triple is on the approved-monitoring-sources list, but the observed shape (sub-200ms burst of 5 distinct sentinel usernames at the alert timestamp) refutes the `monitoring-probe` archetype's confirmation shape, so no fast-path resolution is available. The best-supported explanation is the playground's documented `monitoring_bait.sh` adversarial-evaluation workload being manually triggered; the investigation can neither confirm that authoritatively (tool deny-list) nor refute the alternative that monitoring-host has been compromised (absence of compromise indicators is not a `--` refutation when a patient adversary could deliberately stay inside the sentinel username pool). Two mechanism hypotheses remain live after exhausting available leads; per the investigation philosophy, that state requires escalation.

## For Analyst

### What We Know

- Source is the sanctioned playground monitoring-host container at `172.22.0.10`; target is `target-endpoint` at `172.22.0.2`; both identities and the username are on the approved-monitoring-sources table.
- The alert is part of a sub-200ms burst: 5 consecutive `Invalid user sensu` events at 03:30:49.481/.483/.488/.492/.588Z; the preceding 5-minute window also contained 1 `monitorprobe` event (total 6 in 5 min).
- Zero successful SSH authentications from 172.22.0.10 against target-endpoint anywhere in the last 24 hours or the 5-minute forward window.
- Before the 03:30:49 burst, the monitoring-host was producing sanctioned-cadence single-attempt probes at ~5.8/hour, rotating evenly through the 5 approved sentinel usernames. After the burst, cadence resumed cleanly: the next event was a single `healthcheck` attempt at 03:40:02Z (≈9 minutes later, on schedule).
- No non-5710 alerts fired on monitoring-host in the last 4 hours (no FIM, no rootkit, no process anomaly, no brute-force composite).
- Target-endpoint listens only on sshd:22; no backdoor or alternate-auth listeners.

### What We Don't Know

- **What process produced the 03:30:49 burst on monitoring-host.** The host-query tooling blocks reading `/opt/workloads/` and `/etc/cron.d/`, and `process-list` returned no live `monitoring_probe` or `monitoring_bait` process at query time (consistent with a short-lived script having exited after the burst). The agent cannot discriminate a manual invocation of `monitoring_bait.sh` from a compromised-host variant using the sentinel username pool.
- **Whether `monitoring_bait.sh` was deliberately triggered today**, and by whom — this is the single disambiguator between the benign-origin and adversarial hypotheses. Answer lives in monitoring-host's shell history / audit log / deployment scheduler / bait-workload ownership, none of which the agent can reach.
- **Whether the 9-hour gap (2026-04-13T17:00–2026-04-14T01:00) in the 24h baseline represents a monitoring-host restart, a maintenance window, or an uninstrumented period**. This is not load-bearing for the verdict but is a loose end worth resolving.

### Suggested Next Steps

1. **Check monitoring-host shell history / audit log / deployment scheduler** for invocations of `monitoring_bait.sh` (or any script under `/opt/workloads/`) at or just before 2026-04-14T03:30:49Z. A matching entry authored by an authorized operator resolves this to benign; no entry or an unauthorized entry escalates further.
2. **Ask the bait-workload owner / adversarial-evaluation scheduler** whether a manual test was injected at that time. A confirmed test → benign test injection, close with a note to the monitoring alerting config (ideally the bait should be pre-announced via a change ticket or a sanction-table entry so the investigation loop can resolve it without escalation).
3. **If neither channel confirms a benign cause**: treat as potential compromise of the monitoring-host identity, rotate the sanctioned sentinel credentials (to the extent there are any effective credentials), audit monitoring-host's inbound access (who has shell / SSH to 172.22.0.10), and check for file-integrity indicators under `/opt/workloads/` and `/etc/cron.d/` via a channel that isn't subject to the investigation tooling deny-list.
4. **Consider a durable fix**: the `monitoring_bait.sh` workload exists specifically for adversarial evaluation. Either document its invocations in the `approved-monitoring-sources.md` operations file as a time-bounded approval window (so a future test doesn't re-escalate), or add a dedicated archetype under `knowledge/signatures/wazuh-rule-5710/archetypes/` capturing the bait shape with its own grounding anchor (e.g., a "scheduled-adversarial-evaluations" registry) so the loop can auto-resolve confirmed test events.
5. **Check rule 5712 threshold/enabled state** — six 5710 events in 5 minutes from the same source did not trigger the brute-force composite, which may indicate a tuning gap worth confirming with the detection engineering team.
