# ANALYZE — case-rule5710-loop1 / retest-p2

## Hypothesis Weights

- `?probe-retry-stuck`: `+` (was absent)
  - Sub-second micro-burst (5 events in <200ms) with 5 distinct sentinel usernames **refutes** core prediction of "repeated attempts on exactly ONE sentinel username". Timing and source remain consistent with monitoring patterns, but username diversity is incompatible with retry-stuck mechanism. Grade `+` for consistency-but-refuted-prediction.

- `?probe-enumeration-misconfigured`: `+` (was absent)
  - Rapid rotation through all 5 sentinel usernames on a single tick is **consistent** with config-drift causing full sentinel enumeration in one tick. Core prediction of "rotation through full sentinel set" is met. However, observationally indistinguishable from `?monitoring-bait-triggered` — process-list (neither `monitoring_probe` nor `monitoring_bait` running) provides no discriminator because both are short-lived. Grade `+` for consistent but unconfirmed.

- `?monitoring-bait-triggered`: `+` (was absent)
  - Single discrete burst event at 03:30 with sentinel-username-only reuse is **consistent** with bait design. Approved-cadence rate (~6/hour across 4h window) is consistent with one-off trigger. Process-list empty but cannot refute (short-lived exit). Grade `+` for consistent but unconfirmed.

- `?monitoring-host-compromise`: `-` (was absent)
  - Core predictions: (a) username rotation beyond sentinel set — REFUTED (observed all-sentinels-only), (b) sustained burst across 4h window — REFUTED (hourly 5→6→8 is roughly cadence-matched, not exponential), (c) successful login in forward window — REFUTED (zero 5501/5715 across 4h+5m). However, per refutation discipline: absence of wordlist-common usernames and absence of successful login are absence-of-evidence, not direct contradiction. Adversarial hypothesis remains live at `-` because an attacker deliberately mimicking approved sentinel username pool and implementing delay-and-silence would be observationally indistinguishable. Direct refutation would require positive evidence of compromise precursor (file-integrity, rootkit, process anomaly on monitoring-host) — none observed, but coverage unverified.

- `?internal-credential-guessing`: `--` (was absent)
  - Core predictions: (a) low volume — CONTRADICTED (6 events in 5 min, not low), (b) real-looking usernames — CONTRADICTED (all approved sentinel set, not real-looking). Grades `--` on direct positive evidence of both prediction failures.

- `?compromise-followup`: `--` (was absent)
  - Core prediction: successful SSH login from 172.22.0.10 following the burst. Observed: **zero authentication_success events** (rules 5501/5715) across full 4h+5m window. Grades `--` on direct positive evidence: comprehensive forward-window check refutes the hypothesis authoritatively.

## Routing Decision

**HYPOTHESIZE** — gate failures:

1. **Sibling disambiguation unresolved:** `?probe-enumeration-misconfigured` and `?monitoring-bait-triggered` both score `+` and are observationally indistinguishable. Process-lineage evidence (cron execution log vs. manual shell invocation) is the load-bearing discriminator.

2. **Discriminating lead within budget:** `process-lineage` on monitoring-host — retrieve cron execution log or syslog/audit trail for 03:25-03:35 window to identify spawning mechanism. If cron-driven at 03:30, supports enumeration-misconfig; if manual shell invocation, confirms bait; if neither, escalates compromise hypothesis.

## Selected Lead

**process-lineage** via `host_query --host monitoring-host log-search cron 03:25-03:35` or equivalent syslog audit trail. Alternative: direct execution audit on monitoring-host to confirm whether `monitoring_bait.sh` invocation appears in the 5 min preceding 03:30:49.

---

## Self-report

**Context wished for:**
- Cron execution log (monitoring-host, 03:25-03:35) — confirms whether the 03:30 burst was scheduled
- Syslog/audit trail (monitoring-host, 03:25-03:35) — confirms whether `monitoring_bait.sh` was manually invoked
- File-integrity coverage on monitoring-host — are critical paths monitored? (affects interpretation of "zero non-5710 alerts")

**Claims uncertain:**
- Whether `?probe-enumeration-misconfigured` or `?monitoring-bait-triggered` is the true cause. Both explain observed rapid sentinel-username cycling. Process-lineage is the only discriminator.
- Whether `?monitoring-host-compromise` can be truly refuted without positive evidence of compromise precursor. Absence of file-integrity / process-anomaly / rootkit alerts is suggestive but not direct refutation.

**Anomalies / inconsistencies in prior log:**
- **Approved-cadence violation:** Baseline states "one probe every ~10 min using one sentinel per tick". Observed 03:30:49 burst (5 sentinels in <200ms) is direct violation. Core anomaly forcing HYPOTHESIZE rather than CONCLUDE.
- **Hourly micro-structure:** Volume (5→6→8 across 4h) matches sanctioned rate, yet internal 03h structure is atypical. Sub-second clustering on one tick suggests either config-drift enumeration or test-mode bait — neither malicious but both need operator confirmation.
- **Query 5 (connection-list) failure (rc=127):** Noted non-load-bearing; authentication-history + alert-correlation cover successful-login check.
