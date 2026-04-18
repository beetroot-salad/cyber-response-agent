## ANALYZE (loop 1)

**Reviewing lead outputs against pre-committed predictions and named refutation checks.**

---

### Hypothesis assessments

#### `?monitoring-loop-broken` — `+`

**Reasoning:**

Predictions: sentinel usernames only ✓, burst window ✓, no successful login ✓, no parallel alerts on monitoring-host ✓. Cron is active ✓ (probe driver alive).

Against: the sub-200ms micro-burst clustering 5 events across 5 distinct sentinel usernames in <200ms is **not** consistent with a "retry loop" on a stuck cron probe. A broken cron loop would produce repeated attempts with the same invocation-level username (one probe attempt per tick, retrying the same username or the next in sequence), not a simultaneous scatter across 5 distinct sentinels in sub-second time. A looping probe that cycles through sentinels would produce them in sequence at probe-interval cadence — not compressed to <200ms.

The cron driver being alive is consistent with this hypothesis but is also consistent with every other benign hypothesis.

Pre-committed pitfall applied: "cron-driven loop could look periodic inside the burst; cadence violation alone may confuse bait vs loop." The sub-second multi-username scatter is the discriminator — a retry loop cannot produce it.

Grade rationale: predictions are partially met (sentinel usernames, no successful login, no parallel alerts), but the micro-burst shape is **inconsistent** with a cron retry loop mechanism. Circumstantial support only; the mechanism doesn't hold.

---

#### `?monitoring-bait-triggered` — `+`

**Reasoning:**

Predictions: sanctioned sentinel usernames only ✓ (5 distinct, all on approved list), burst = single discrete event not sustained ✓ (the sub-200ms micro-burst is a single clustered event, not a sustained stream), no successful login ✓, no other alerts on monitoring-host ✓.

Process-list shows no `monitoring_bait` process. However, the pre-committed pitfall explicitly says "if the bait process has already exited, name will not appear in process-list, and absence-of-name cannot refute." This query ran after the 03:30:49 alert; absence does not refute.

The sub-200ms multi-username scatter across 5 distinct sentinels in a single clustered event is **much more consistent** with `monitoring_bait.sh` (documented as an adversarial-evaluation variant that fires multiple probes programmatically in rapid succession, reusing monitoring identities) than with a broken cron loop.

Why not `++`? Per the pre-committed named refutation check: "For `?monitoring-bait-triggered` to go `++`: would require authoritative confirmation of the bait workload (process audit log, script ownership evidence). Circumstantial shape alone caps at `+`." Process-list came back empty; no authoritative confirmation is available. Circumstantial shape is consistent but is capped at `+`.

---

#### `?monitoring-host-compromise` — `-`

**Reasoning:**

Predictions for this hypothesis require at least one of: username rotation beyond sentinel set, sustained burst over the full hour, successful login in the forward window, other alerts on monitoring-host (file-integrity / process anomaly / rootkit), or unexpected processes.

Against each:
- Username rotation beyond sentinel set: **not observed**. All 5 distinct usernames are sanctioned sentinels across the full 4h window.
- Sustained burst over the full hour: **not observed**. Hourly volume (01h=5, 02h=6, 03h=8) is roughly consistent with the approved cadence of ~6/hour. Only the intra-hour shape at 03:30 is anomalous — a single clustered sub-200ms event, not a sustained elevated rate.
- Successful login in the forward window: **not observed** across the full 4h + 5min window. Zero 5501/5715 events.
- Other alerts on monitoring-host: **none** across the 4h window. Zero file-integrity, process-anomaly, rootkit, or brute-force composite events.
- Unexpected processes: process-list shows no unexpected processes (though short-lived processes may have exited).

Pre-committed adversarial safeguard applied: "adversary may stay within sentinel set deliberately to evade detection; absence of rotation is NOT proof of innocence." None of the individual refutation checks is individually authoritative.

Pre-committed refutation shape for `--`: requires (a) process ancestry on monitoring-host OR (b) authoritative evidence the bait workload was the cause. Neither is accessible. Per-commitment: "absence of any single check is not `--`."

The combined weight of five independent checks all returning negative pushes this toward `-` (weakly refuted) but the pre-commitment is correctly calibrated: the adversarial model specifically predicts that a stealthy compromise would deliberately mimic the monitoring shape. The evidence is consistent with that model. Grade is `-` not `--`.

---

#### `?internal-credential-guessing` — `--`

**Reasoning:**

Predictions for this hypothesis: low volume, real-looking usernames.

Both predictions are directly contradicted:
- Volume: 10 events in the primary window, 19 over 4h — not low-volume individual credential guessing.
- Usernames: all 5 observed usernames are approved monitoring-pattern sentinels (sensu, healthcheck, monitorprobe, nagios, zabbix) — none are real-looking human usernames.

This was already a preliminary refutation in HYPOTHESIZE; the GATHER output confirms it authoritatively. Direct contradiction of both core predictions → `--`.

---

#### `?compromise-followup` — `--`

**Reasoning:**

The refutation shape defined at pre-commitment: "no successful SSH login (rule 5501/5715) from the source IP in the forward window."

GATHER result: **zero** 5501/5715 events from 172.22.0.10 across the full 4h + 5min forward window. Query 1 explicitly covers 1h before + 5min after; Query 2 covers the full 4h window on monitoring-host / srcip across any signature. Both return clean.

The forward window in SCREEN (60s) was explicitly noted as narrower than needed. The full GATHER extended this to 5 minutes forward and the full 4h retrospective — still zero successful authentications.

Pre-committed adversarial note: "attacker may delay." However, the 4h retrospective also shows zero successful authentications in either direction, which removes the "delay" objection for this burst. A delayed attack would still require a successful SSH session to have value, and none is present across the full window.

This is a direct confirmation of the absence that the refutation shape specified. Grade: `--` (strongly refutes).

---

### Summary table

| Hypothesis | Grade | Key evidence |
|---|---|---|
| `?monitoring-loop-broken` | `+` | Sentinel-only usernames ✓; cron active ✓; but sub-200ms multi-username scatter inconsistent with retry-loop mechanism |
| `?monitoring-bait-triggered` | `+` | Sentinel-only ✓; single discrete burst ✓; no successful login ✓; process-list absent but absence cannot refute per pitfall; no authoritative confirmation → capped at `+` |
| `?monitoring-host-compromise` | `-` | All five refutation checks negative; adversarial model predicts mimicry of sentinel set; cannot issue `--` without process ancestry or bait confirmation |
| `?internal-credential-guessing` | `--` | Both core predictions (low volume, real usernames) directly contradicted |
| `?compromise-followup` | `--` | Zero 5501/5715 from srcip across full 4h + 5min forward; refutation shape met authoritatively |

---

### Adversarially live hypotheses after ANALYZE (loop 1)

Per pre-commitment, `?compromise-followup` required `--` before being cleared. That grade is now assigned based on the full forward + retrospective window. `?monitoring-host-compromise` required multiple converging checks, none individually authoritative. Neither check (a) nor (b) is accessible. This hypothesis remains adversarially live at `-` and cannot be dismissed.

**`?monitoring-host-compromise` remains adversarially live.**

---

### Next action: CONCLUDE

**Rationale:**

The two leading hypotheses (`?monitoring-loop-broken` and `?monitoring-bait-triggered`) are both at `+` and are observationally near-identical with available tooling. The sub-200ms multi-username clustering more strongly fits `?bait` mechanically, but authoritative confirmation is inaccessible (process exited; no process audit log; host_query connection-list failed rc=127).

`?compromise-followup` is `--` (refuted by full-window clean auth history). `?internal-credential-guessing` is `--`. `?monitoring-host-compromise` is `-` (adversarially live but weakened).

No additional leads would discriminate `?bait` vs `?broken-loop` without a process audit log or script ownership check that is not available in the current toolset. Continuing to loop would not change the grade distribution. The evidence is sufficient to conclude.

**Recommended disposition on CONCLUDE:**

Escalate (not auto-close). The leading shape fits a benign evaluation scenario (`?bait`) or a broken probe (`?broken-loop`), but `?monitoring-host-compromise` cannot be ruled out without authoritative process evidence. The analyst must:
1. Confirm whether the `monitoring_bait.sh` evaluation workload was intentionally triggered on monitoring-host at ~03:30 UTC.
2. If not, treat as potential compromise of monitoring-host and investigate process ancestry there.

Archetype: `monitoring-probe` is the closest match on username classification and source, but the burst shape (sub-200ms multi-username scatter) exceeds the approved cadence envelope. The right archetype annotation at CONCLUDE will require the analyst's confirmation; agent should not auto-resolve.

---

## Self-report

### Context I wished I had

1. **Process audit log or execve/audit trail for monitoring-host** — this was the single most discriminating missing piece. The process-list query returned empty (process already exited) and connection-list failed (rc=127). A process audit log (auditd, execve events) or script ownership evidence would have enabled the `?bait` `++` grade and possibly a clean `--` for `?compromise`.

2. **Clarification on `approved-monitoring-sources.md` cadence specification** — the investigation references "1 probe / ~10 min using one sentinel per tick" as the sanctioned baseline but doesn't surface the exact source document. Knowing whether this is a strict contract or an approximate estimate would affect how hard to weight the sub-200ms burst as an anomaly.

3. **File-integrity (FIM) coverage status on monitoring-host** — GATHER correctly notes "absence-of-alert ≠ absence-of-event" for the monitoring-host compromise check. Knowing whether FIM was even configured and indexing on that host would sharpen the `?monitoring-host-compromise` grade from `-` to something more precise.

4. **The specific mechanism of `monitoring_bait.sh`** — the investigation log references it as "fires multiple probes programmatically in rapid succession, reusing monitoring identities" but I inferred this from the description. Explicit documentation of its invocation pattern (single-shot, rapid-scatter across sentinel list) would convert the `?bait` `+` to a more defensible grade.

### Pre-commitments I actually used

**Used:**
- Adversarial status for `?compromise-followup` and `?monitoring-host-compromise` — directly drove the decision to assign `--` only after meeting the full refutation shape, and to keep `?compromise` adversarially live at `-`.
- Named refutation check for `?monitoring-bait-triggered`: "circumstantial shape alone caps at `+`" — applied precisely. Without this pre-commitment I might have awarded `++` on the basis of the burst shape fitting the bait mechanism.
- Named refutation check for `?monitoring-host-compromise`: "absence of any single check is not `--`" — prevented premature clearance despite all five checks returning negative.
- Pitfalls: "if the bait process has already exited, absence-of-name cannot refute" — directly applied to Query 3 (empty process-list); prevented incorrect downgrade of `?bait`.
- Pitfalls: "adversary may stay within sentinel set; absence of rotation is NOT proof of innocence" — directly applied to `?compromise` grading.

**Partially used / cross-checked:**
- "For `?monitoring-host-compromise` to go `--`: requires (a) process ancestry OR (b) authoritative bait confirmation" — used to set the threshold, then confirmed neither (a) nor (b) was accessible, resulting in `-` not `--`.

**Not used (irrelevant to this evidence set):**
- The cadence violation / confusion pitfall between loop and bait was noted but not the primary discriminator — the sub-200ms scatter was the actual discriminator.
- `?compromise-followup` predictions about sustained burst — not needed; refutation shape was the clean auth-history, which was directly confirmed.

### Claims I felt uncertain about

1. **The sub-200ms scatter as mechanism-discriminator between `?loop-broken` and `?bait`**: I inferred that a broken cron retry loop would not produce a simultaneous multi-username scatter in <200ms, whereas `monitoring_bait.sh` (a programmatic script) would. This inference is mechanically sound but rests on the undocumented assumption that the bait script fires all probes in a tight loop rather than serially with retries. If the bait also fires them serially with tight timing, the mechanism argument weakens. I noted this only implicitly.

2. **"Roughly consistent with approved cadence" for the 4h hourly totals**: GATHER says 01h=5, 02h=6, 03h=8 ≈ 6/hour sanctioned. But 03h=8 is 33% above the sanctioned rate, which I described as "roughly consistent." This is a judgment call — "roughly consistent" is defensible given uncertainty about the exact sanctioned rate specification, but an analyst expecting strict adherence would flag 03h=8 as an anomaly independent of the sub-200ms burst.

3. **CONCLUDE vs HYPOTHESIZE routing**: I concluded that additional loops would not discriminate further given available tooling (connection-list failed, process-list empty, no process audit). This is a judgment call. A third hypothesis that I could not rule out is that a different lead (e.g., `ad-hoc` query for SSH client key fingerprint or netstat-equivalent via a different adapter) might exist. I judged based on the leads listed in CONTEXTUALIZE and the adapter failure, but did not exhaustively enumerate all possible ad-hoc queries.
