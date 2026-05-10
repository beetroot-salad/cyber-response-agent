## Synthetic GATHER for F1 — authentication-history (post-burst cadence)

**Lead:** authentication-history
**Status:** ok
**Query:** `rule.groups:sshd AND data.srcip:172.22.0.10 AND data.srcuser:nagios AND agent.name:target-endpoint`
**Window:** start=2026-05-05T05:23:53Z;end=2026-05-05T09:23:53Z (post-burst, T+5s through T+4h)

**Raw observation:**
- post_burst_event_count: 47 events
- post_burst_inter_event_gap_mean_s: 304.6
- post_burst_inter_event_gap_stdev_s: 12.1
- post_burst_max_cluster_size: 1 (no clusters in post-burst window — every event is single-attempt isolated)
- comparison_baseline (loop 1, 72h pre-burst): mean_gap_s ≈ 300, stdev ≈ 14, max_cluster_size = 1 except T0 burst
- successful_login_after_T: 0 events (no auth success)
- post_burst_pattern_match: post-burst cadence statistically indistinguishable from 72h baseline (within 1σ on mean and stdev; same single-attempt geometry)

**Interpretation hint for ANALYZE:** the 5-attempt 1-second burst at T0 is bracketed by stable single-attempt ~300s cadence in both directions; post-burst behavior is structurally identical to the 72h baseline. Reads as `lp1: foreground post-burst inter-event distribution matches the recurring baseline geometry → isolated-retry-burst, monitoring-probe-classification-retained → fork-at-authorization`.
