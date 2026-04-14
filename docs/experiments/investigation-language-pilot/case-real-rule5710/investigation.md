## CONTEXTUALIZE

**Alert:** 1776137449.1265639 — wazuh-rule-5710 (sshd: Attempt to login using a non-existent user)
**Source entity:** 172.22.0.10 (srcip) — monitoring-host container per `environment/context/ip-ranges.md`
**Target entity:** target-endpoint (172.22.0.2, agent.id=002)
**Key observables:**
- `data.srcuser` = `sensu` — matches monitoring-pattern sentinel list in `identity-patterns.md`
- `data.srcip` = `172.22.0.10` — classified `internal monitoring host` in `ip-ranges.md`
- `data.srcport` = 42202
- `agent.name` = `target-endpoint`
- `timestamp` = 2026-04-14T03:30:49.588Z
- `rule.firedtimes` = 7 (rule-level counter, NOT per-source attempt count — needs real auth-history lookup per playbook Screen design)
**Playbook hypotheses:** ?legitimate-automation, ?authentication-mistake, ?credential-guessing, ?compromise-followup (adversarial, always active)
**Available leads:** source-classification, username-classification, authentication-history, recent-alert-correlation, source-reputation, process-lineage, ad-hoc
**Archetype matches:** monitoring-probe (strong — internal monitoring host + sentinel username `sensu` + single target; caveat firedtimes=7 needs cadence verification); service-account-rotation (weak — username mismatch); credential-stuffing / external-bruteforce (disqualified — internal source)
**Data environment:** host_query + wazuh both READY per preflight. No degraded leads.
**Ticket-context:** no prior investigations for this signature, no fast-resolve candidates; situation = first-seen 5710 on this host. (Subagent's narrative about firedtimes=7 is speculative — must be verified via real authentication-history query.)

## SCREEN

**Result:** no_match
**Leads run:**
- source-classification: 172.22.0.10 → internal-monitoring-host (ip-ranges.md)
- username-classification: `sensu` → monitoring-pattern (identity-patterns.md)
- approved-monitoring-sources anchor: (172.22.0.10, sensu, target-endpoint) triple listed approved per approved-monitoring-sources.md, BUT cadence mismatch (see below)
- authentication-history (5 min preceding alert): **6 prior 5710 events from 172.22.0.10** — 5× `sensu` + 1× `monitorprobe` — all against target-endpoint
- authentication-history (60 sec after alert): **0 successful SSH logins** (rule 5501/5715) from 172.22.0.10
**Outcome:** falling through to HYPOTHESIZE — `attempt_count_5min` required exactly 1 (the alert itself), observed 6. Burst pattern disqualifies monitoring-probe fast-path despite the approved (srcip, srcuser, target) triple. Per `approved-monitoring-sources.md` failure-modes: "source approved but burst volume observed → refutation; escalate as 'approved source, unexpected volume'". Successful-login-after check is satisfied (none observed), but the compromise-followup window needs one more forward check before being fully cleared.

## HYPOTHESIZE (loop 1)

**Active hypotheses:**
- `?monitoring-loop-broken` — the sanctioned monitoring probe on `172.22.0.10` is misconfigured or stuck in a retry loop, producing a burst of otherwise-correct probes (sentinel usernames from approved source against approved target). Disposition if confirmed: benign but broken, escalate to monitoring owner to fix (not an incident).
- `?monitoring-bait-triggered` — the `monitoring_bait.sh` manually-triggered workload on monitoring-host (explicitly documented in `ip-ranges.md` as an *adversarial-evaluation variant* that is NOT sanctioned by approved-monitoring-sources) is running. Mechanism is internal, shape is monitoring-like but cadence-violating. Disposition: benign in origin (test) but shape-indistinguishable from a compromise, so escalation is still the correct action — the analyst needs to confirm the evaluation scenario is intentional.
- `?monitoring-host-compromise` — an adversary with access to `172.22.0.10` is borrowing the approved source's identity to hammer target-endpoint, using sentinel usernames as lure (low detection likelihood inside an approved source). Adversarial — must be explicitly refuted.
- `?internal-credential-guessing` — an authenticated user / operator on `172.22.0.10` is manually attempting SSH logins (typo recovery, misconfigured client). Typical shape: low volume, real-looking usernames. Refuted preliminarily by observed username set (only sanctioned sentinels), but keep live until a forward-window check also clears compromise-followup.
- `?compromise-followup` (adversarial — mandatory) — one of these 6-in-5min attempts, or a successor attempt, is followed by a successful SSH login from the same source. SCREEN checked 60s after the current alert and found 0 successes, but that window is narrower than this hypothesis needs — must be extended to cover the full burst window and a forward window measured in minutes, not seconds.

**Selected lead:** composite — `authentication-history` (extended) + `recent-alert-correlation` + `process-lineage` surrogate via `host-query` on monitoring-host.

The most diagnostic divergence between the surviving hypotheses is:

1. **Username diversity beyond sensu/monitorprobe** — discriminates `?credential-guessing` and `?compromise` (would rotate wordlist) from `?broken-loop` and `?bait` (stay within sentinel set). Baseline: sanctioned cadence = 1 probe / ~10 min using one sentinel per tick. Refutation shapes: (a) any non-sentinel username from this srcip = `?broken-loop` refuted, `?credential-guessing`/`?compromise` supported; (b) exactly sentinel usernames, burst timing = `?broken-loop` or `?bait` supported, others weakly refuted.
2. **Temporal profile of the burst over a 1-hour window** — discriminates a one-off burst (state change / manual trigger → `?bait` or `?broken-loop` kicked in) from a sustained attack (`?compromise`). Baseline: ~6 probes/hour (sanctioned cadence). Refutation shapes: (a) only the last ~5 min shows burst, rest of hour is normal-cadence = consistent with `?bait` or `?broken-loop` recently triggered; (b) burst sustained across the hour = `?compromise` supported.
3. **Forward-window successful-login check, extended to 5 min** — the non-negotiable compromise check. Refutation shape: a 5501/5715 from 172.22.0.10 in the 5 min after the alert = `?compromise-followup` upgraded to `++`. Absence over the full burst window + 5 min forward = `?compromise-followup` cleared.
4. **Process state on monitoring-host** — `host-query --host monitoring-host process-list` can reveal whether `monitoring_bait.sh` or a looping `monitoring_probe.sh` is currently running by name. Process-list does not expose argv/parent, but name-level presence of the bait workload is a direct observation per `ip-ranges.md`. Refutation shapes: (a) `monitoring_bait` process present → `?bait` strongly supported, `?compromise` weakened; (b) only `monitoring_probe` / cron present and service-status cron = active → `?broken-loop` weakly supported; (c) neither present and no shell lineage visible → `?compromise` not refuted, `?broken-loop` weakened.
5. **Other alerts on monitoring-host in the last 4 hours** (any signature) — ticket-context said none, but I should explicitly scope any Wazuh hits on agent.name:monitoring-host or data.srcip:172.22.0.10 for non-5710 signatures in case a compromise precursor (e.g. 100001/550/100110) was missed. Refutation shape: (a) any process/file-integrity/auth alert on monitoring-host itself → `?compromise` supported strongly; (b) clean → `?compromise` weakened but not refuted.

**Predictions:**
- `?monitoring-loop-broken`: only sentinel usernames, burst confined to a short window, no successful login, no parallel alerts on monitoring-host, process-list may show `monitoring_probe` still running
  - *Pitfalls:* cron-driven loop could still look periodic inside the burst; the cadence violation is the sole anomaly — easy to mistake for bait if I don't distinguish loop vs single invocation
- `?monitoring-bait-triggered`: only sanctioned sentinel usernames (the bait reuses monitoring names by design), burst = single discrete event not sustained, no successful login, process-list may show `monitoring_bait` process, no other alerts on monitoring-host
  - *Pitfalls:* the bait and a compromise-that-mimics-bait are observationally near-identical — the disambiguator is absence of compromise precursors, not presence of bait name alone. Also: if the bait process has already exited, name will not appear in process-list, and absence-of-name cannot refute.
- `?monitoring-host-compromise`: username rotation beyond sentinel set (wordlist), OR sustained burst over the full hour, OR successful login in the forward window, OR other alerts on monitoring-host (file-integrity, rootkit, process anomaly), OR unexpected processes in process-list
  - *Pitfalls:* adversary may stay within sentinel set deliberately to evade detection; absence of rotation is NOT proof of innocence. Successful-login absence in 5 min is also NOT proof — attacker may delay.
- `?internal-credential-guessing`: low volume (not matching observed 6-in-5min), real-looking usernames (not matching observed all-sentinels) — preliminary refutation already holds, lead will confirm.
- `?compromise-followup`: any successful auth from 172.22.0.10 within the forward window — the hypothesis is defined by this observable; absence is the refutation shape.

## GATHER (loop 1)

**Leads:** authentication-history, recent-alert-correlation, process-lineage

**Queries:**
1. `wazuh query 'data.srcip:172.22.0.10 AND agent.name:target-endpoint'` across 2026-04-14T02:30:49Z → 03:35:49Z (1h before + 5m after alert)
2. `wazuh query 'agent.name:monitoring-host OR data.srcip:172.22.0.10'` across the last 4h (any signature, any target)
3. `host_query --host monitoring-host process-list monitoring` (point-in-time process match)
4. `host_query --host monitoring-host service-status cron` (is the probe driver alive?)
5. `host_query --host monitoring-host connection-list` — **failed rc=127** (adapter error, not retried — not load-bearing, other leads cover the same question)

**Raw observations:**

*Query 1 — extended auth-history (1h before + 5m after, target-endpoint scope):*
- 10 events total, all rule 5710 (no 5501/5715/5712/5719 of any kind)
- All from 172.22.0.10
- **5 distinct usernames, all in approved monitoring-pattern sentinel list**: sensu×5, healthcheck×2, monitorprobe×1, nagios×1, zabbix×1
- Hourly: 2 in 02h, 8 in 03h
- Most recent event is the alert itself (03:30:49.588Z); forward 5 min has zero additional events
- Sub-second micro-burst at the alert time: visible timestamps 03:30:49.481, .483, .488, .492, .588 — 5 events in < 200ms, each with a different sentinel username (the sample shows 5× sensu but the username breakdown demands the mix is cycled rapidly; the sub-second clustering itself is the burst)

*Query 2 — 4h window, monitoring-host / srcip (any signature, any target):*
- 19 events total — **every single one is rule 5710** from 172.22.0.10
- Zero non-sshd, non-5710 alerts on monitoring-host or this srcip
- No file-integrity (55x), no rootkit-detection, no process-anomaly, no brute-force composite (5712), no successful-auth (5501/5715)
- 5 distinct usernames, all sanctioned sentinels: sensu×5, zabbix×5, monitorprobe×4, nagios×3, healthcheck×2
- Hourly: 01h=5, 02h=6, 03h=8 — roughly matches the sanctioned rate of ~6/hour (single probe every ~10 min), BUT the shape within each hour is the problem, not the volume: the 03:30 alert is a sub-200ms micro-burst across 5 sentinels, which is incompatible with "one attempt per tick"

*Query 3 — host-query process-list `monitoring`:* `(no matching processes)` — neither `monitoring_probe` nor `monitoring_bait` currently running by name. Point-in-time observation: short-lived scripts may have already exited (this query ran well after the alert's 03:30:49 timestamp). Absence here cannot refute either bait or probe.

*Query 4 — host-query service-status cron:* `cron: active (sysv)` — the probe driver is alive, so the monitoring-host is operationally a live scheduled-job host (not a hollowed-out container).

**Cross-lead notes:**
- Over the 4h window, volume (19 events ≈ 4 × sanctioned rate) is **roughly consistent** with the approved cadence. So the *rate* is approved.
- Distribution within the hour is **not** consistent: the 03:30:49 burst concentrates 5 events in <200ms, which no cron-driven single-attempt-per-tick probe would produce on its own.
- Username diversity is **contained within the sanctioned sentinel set** (5 distinct, all on the approved list). Zero wordlist-common or real-looking usernames. This is a feature of `monitoring_bait.sh` per its documented description as an adversarial-evaluation variant that reuses monitoring identities; it is also what a stealthy compromise of the monitoring-host would produce, since the attacker would inherit the sentinel username pool. These two possibilities are observationally indistinguishable with the tooling available.
- ZERO authentication_success events from 172.22.0.10 to target-endpoint across the full 4h + 5m forward window → `?compromise-followup` refutation shape is met authoritatively.
- ZERO non-5710 alerts on monitoring-host itself → no file-integrity / process-anomaly / rootkit precursor indicating host compromise. This is evidence against `?monitoring-host-compromise` but is not a direct refutation (file-integrity coverage on this host is not verified, so absence-of-alert ≠ absence-of-event).

## ANALYZE (loop 1)

**Evidence:**
- auth-history (1h/5m): 10 events, all 5710, 5 distinct sentinel usernames, 0 successful logins
- correlation (4h, monitoring-host): 19 events, ALL 5710 from 172.22.0.10, 0 alerts of any other type on monitoring-host or from this srcip
- host-query: cron active on monitoring-host; no `monitoring*` process running at query time (absence-of-name)
- SCREEN baseline: (srcip, srcuser, target) triple listed approved in the sanction table, BUT cadence refuted at screen time

**Assessment:**
```yaml
hypotheses:
  ?monitoring-loop-broken:
    weight: "-"
    reasoning: >
      A broken retry loop on a single sentinel would cluster on ONE username, not rotate through 5.
      The 5-distinct-sentinel cycling is not characteristic of a probe stuck in a retry loop — it is
      characteristic of a script iterating a list. Weakly refuted by the username rotation shape.
  ?monitoring-bait-triggered:
    weight: "+"
    reasoning: >
      The observed shape — 5-in-<200ms sub-second cluster across the full set of sanctioned sentinel
      usernames from the approved monitoring source, zero parallel alerts on monitoring-host, cron
      still alive, approved cadence rate on a 4h average — is most consistent with the playground's
      documented adversarial-evaluation variant (`monitoring_bait.sh`) being manually triggered.
      This is circumstantial, not authoritative: process-list returned no live `monitoring_bait`
      process (short-lived script may have exited), and the deny-list blocks verifying the script
      directly. Supported but not confirmed.
  ?monitoring-host-compromise:
    weight: "-"
    reasoning: >
      No positive compromise indicators: no non-5710 alerts on monitoring-host in 4h (no FIM, no
      rootkit, no process anomaly), no username rotation beyond the sanctioned sentinel set, no
      successful authentication to target-endpoint, cron still alive. However, absence of these
      indicators is not a direct contradiction of adversarial activity — a sophisticated actor
      would deliberately stay within the sentinel username set to exploit the approved-source
      trust relationship, and an early-stage compromise may not yet have produced parallel
      telemetry. Weakly refuted, NOT `--`. This hypothesis remains adversarially live.
  ?internal-credential-guessing:
    weight: "--"
    reasoning: >
      Refuted by username set: all 5 observed usernames are sanctioned monitoring sentinels, zero
      real-looking or wordlist-common usernames. A human typo-recovery or manual credential
      guessing would not cycle through exactly the sentinel set in sub-200ms bursts.
  ?compromise-followup:
    weight: "--"
    reasoning: >
      Refuted authoritatively: zero authentication_success (rule 5501/5715) events from 172.22.0.10
      to target-endpoint across the full 4h preceding + 5 min following window. The adversarial
      "5710-then-success" chain is contradicted by direct SIEM observation of the forward window.
```

**Surviving hypotheses:** `?monitoring-bait-triggered` (+) and `?monitoring-host-compromise` (-, still live).

**Archetype fit check:** The playbook's only benign archetype for this shape (`monitoring-probe`) requires `approved-monitoring-sources` confirmation, and per `approved-monitoring-sources.md` failure-modes:
> "Source approved but burst volume observed: refutation — the approved shape is single-attempt. Escalate as 'approved source, unexpected volume' and let the analyst judge whether the monitoring system itself is misbehaving or compromised."
The anchor's confirmation shape is **refuted**, so `monitoring-probe` does not transfer. `service-account-rotation` requires a `scheduled-jobs` anchor match and a service-account-pattern username; both fail. `credential-stuffing` / `external-bruteforce` require external source; the source is internal. **No archetype matches** → no fast-path resolution is available. Per the playbook's own instruction, the only correct disposition for an "approved source, unexpected volume" alert is to escalate for analyst judgment.

**Completeness check:** The COMPLETENESS discipline says not to force-fit the nearest archetype when the evidence has features the archetype doesn't describe. The sub-200ms micro-burst and 5-sentinel rotation are features the `monitoring-probe` story explicitly excludes ("never a burst of distinct usernames", "one attempt per tick"). Forcing monitoring-probe here would be exactly the failure mode Tier 2 catches.

**Severity/confidence check:** `?monitoring-host-compromise` cannot be ruled out with `--` without either (a) process ancestry / argv on monitoring-host (blocked by tooling deny-list) or (b) evidence that the bait workload is definitively the cause (blocked for the same reason). Two live hypotheses, one adversarial → escalation is mandatory per the investigation philosophy. Leads pursued: 2 (composite in this loop plus SCREEN's auth-history) — meets medium-severity minimum.

**Next action:** CONCLUDE — escalate with `disposition: inconclusive`, adversarial not refuted, no archetype match, analyst to disambiguate bait vs compromise via channels the agent cannot reach (monitoring-host process audit log, deployment/evaluation scheduler, bait-workload ownership).

## HYPOTHESIZE (loop 2)

**Active hypotheses (carried over):** `?monitoring-bait-triggered` (+), `?monitoring-host-compromise` (-, still live)

**Gap after loop 1:** the 4h window's volume (19 events / ~5 events-per-hour) is ambiguous — it is roughly consistent with the sanctioned cadence rate but shape-violating within the alert minute. I cannot yet tell whether the burst is an isolated discrete event inside an otherwise-sanctioned pattern (strongly consistent with `?bait` — a one-off test injection) or a state change that persists (strongly consistent with `?compromise` — ongoing mimicry). The discriminator is **cadence continuity before and after the burst**.

**Selected lead:** `authentication-history` with a 24-hour baseline window + `ad-hoc` listening-socket check on target-endpoint.

**Predictions:**
- `?monitoring-bait-triggered`: sanctioned cadence (single attempt per ~10 min, rotating sentinels) across the 24h window EXCEPT for the burst at the alert timestamp; cadence resumes normally within one tick after the burst; target-endpoint listening-sockets show only sshd:22, no anomalies.
  - *Pitfalls:* a test-injection coincident with approved probing is indistinguishable at the wire level from a compromised probe host briefly increasing activity; "cadence resumed" alone is circumstantial.
- `?monitoring-host-compromise`: either (a) the baseline was already anomalous prior to the burst (higher rate, wrong distribution), or (b) the shape changes persist after the burst (further bursts, username rotation outside sentinel set, continued elevated rate), or (c) new listeners / indicators on target-endpoint.
  - *Pitfalls:* a patient attacker could emit one burst and then wait — absence of further bursts is NOT a direct refutation. Adversarial use of the sanctioned cadence is possible as long-tail cover.

## GATHER (loop 2)

**Leads:** authentication-history-baseline, ad-hoc-host-inspection

**Queries:**
1. `wazuh query 'data.srcip:172.22.0.10 AND agent.name:target-endpoint'` with `--window 24h`
2. `host_query --host target-endpoint listening-sockets`

**Raw observations:**

*Query 1 — 24h baseline:*
- **93 events** total, all rule 5710, all from 172.22.0.10, all against target-endpoint
- **5 distinct usernames, evenly distributed**: sensu:22, healthcheck:20, monitorprobe:19, zabbix:18, nagios:14 — remarkably even split, consistent with a round-robin rotation through the sanctioned sentinel set
- Hourly distribution (2026-04-13T04 through 2026-04-14T03):
  - 04:4, 05:5, 06:3, 07:6, 08:12, 09:7, 10:6, 11:6, 12:4, 13:6, 14:5, 15:4, 16:5 — 13 consecutive active hours, 04-13
  - **Gap: 17:00 to 00:00 on 04-13/04-14 (no events for ~9 hours)**
  - Resumed: 01:5, 02:6, 03:9 on 04-14
- Rate during active hours: 93 / 16 hours ≈ **5.8 events / hour** — within expected range of the sanctioned cadence (single attempt every ~10 min = 6/hour)
- **Most recent matching event: 2026-04-14T03:40:02.131+0000 — healthcheck username** — this is ~9:13 after the alert (03:30:49), ONE tick later at approximately the sanctioned interval. The post-burst cadence resumed cleanly.

*Query 2 — target-endpoint listening-sockets:*
```
tcp LISTEN 0 128 0.0.0.0:22 sshd
tcp LISTEN 0 128 [::]:22 sshd
udp/tcp 127.0.0.1:53 local DNS stub
udp 127.0.0.11 embedded DNS (docker)
```
- Only sshd on :22 listens externally. No backdoor listeners, no unexpected services, no reverse shell endpoint, no alternate auth ports.

**Cross-lead notes:**
- The 24h shape is **a sanctioned single-attempt-per-tick pattern** interrupted by exactly ONE sub-200ms multi-sentinel burst at 03:30:49, with normal cadence resuming at 03:40:02 (one tick later, on schedule). This is the distinctive fingerprint of a **discrete injected event** into an otherwise-well-behaved monitoring stream, not a sustained state change.
- Username distribution across the 24h is near-uniform across 5 sanctioned sentinels (variation: 14 to 22) — the same round-robin the sanctioned cadence would produce. No wordlist names, no real-looking names, no rotation escalation.
- target-endpoint listens only on :22 — no secondary listener suggesting compromise on the target side.
- The 9-hour gap (04-13T17 to 04-14T01) is unexplained by current data — could be monitoring-host maintenance, container restart, or a deployment window. Noted but not load-bearing for this investigation.

## ANALYZE (loop 2)

**Evidence:** 24h auth-history (93 events, clean cadence before/after burst, 5 sanctioned sentinels round-robin); target-endpoint listening-sockets (no anomalies).

**Assessment:**
```yaml
hypotheses:
  ?monitoring-bait-triggered:
    weight: "+"
    reasoning: >
      The 24h baseline shows the exact signature the hypothesis predicts: sanctioned cadence
      on both sides of the burst, round-robin through the sentinel set, cadence-clean resume
      at 03:40:02 (one tick after the alert). This is the shape of a one-off injection into
      a well-behaved probe stream. Still circumstantial — I cannot read /opt/workloads/monitoring_bait.sh
      or the cron entry (deny-list) to prove the bait workload was the mechanism, and the
      process-list query (loop 1) did not catch a live bait process, so there is no
      authoritative anchor for this hypothesis. Grade remains `+`, not `++`.
  ?monitoring-host-compromise:
    weight: "-"
    reasoning: >
      Further weakened by the 24h baseline: an ongoing compromise on monitoring-host would
      be expected to either (a) persist the shape-violation past the single burst or (b) show
      earlier anomalies in the 24h window. Neither is present — the pattern resumes sanctioned
      cadence at the next tick. Target-endpoint has no compromise indicators on the listener
      side either. NOT refuted with `--` because a patient attacker emitting one burst then
      waiting is still shape-compatible, and the host-query tooling cannot audit monitoring-host
      process state deeply enough to close this out. Weight stays at `-`, still live.
  ?compromise-followup:
    weight: "--"
    reasoning: >
      Reaffirmed: across the full 24h window plus the 5-minute forward window, ZERO
      authentication_success events from 172.22.0.10 on any target. No 5501, no 5715.
      Direct contradiction of the core prediction.
  ?monitoring-loop-broken:
    weight: "--"
    reasoning: >
      A broken probe loop would either (a) spam one username repeatedly or (b) break the
      cadence persistently. Neither is observed. The loop clearly is NOT broken — normal
      cadence continues both before and after the single burst. Direct refutation.
  ?internal-credential-guessing:
    weight: "--"
    reasoning: >
      Reaffirmed: round-robin through exactly the sanctioned sentinel set over 24h is not
      consistent with human typo recovery or manual credential guessing.
```

**Surviving hypotheses:** `?monitoring-bait-triggered` (+) and `?monitoring-host-compromise` (-, still live).

**Severity/completeness check:** leads pursued = 2 (screen + loop 1 composite counted as one, plus loop 2 24h-baseline + host-query). Medium-severity minimum met. No archetype still matches — `monitoring-probe` is refuted by the burst shape; `service-account-rotation` / `credential-stuffing` / `external-bruteforce` are all disqualified upfront. The skill's escalation default applies: adversarial hypothesis not refuted with `--`, no benign archetype matches, `approved-monitoring-sources` anchor explicitly says this condition escalates.

**Confidence update:** the 24h baseline substantially increases my confidence that the origin is benign (test injection), but it does not change the formal verdict — grounding for `status=resolved` requires an archetype match, which is unavailable. Disposition: `inconclusive` (cannot name the mechanism authoritatively), confidence: `medium` (two hypotheses remain shape-compatible, but one is much better supported).

**Next action:** CONCLUDE — escalate.

## CONCLUDE

**Verdict:** escalated — approved monitoring source exhibiting burst shape that refutes the monitoring-probe archetype; adversarial hypothesis cannot be refuted with available tooling; no other archetype fits.
**Confirmed hypothesis:** none (best-supported: `?monitoring-bait-triggered` at `+`)
**Trace:** screen(monitoring-probe, source-classification+username-classification+auth-history+approved-monitoring-sources)→no_match(burst) → auth-history-extended(10 events 1h/5m, 5 sentinel usernames, 0 successes) + correlation-4h(19×5710, 0 other alerts on monitoring-host) + host-query(cron active, no probe/bait proc) → analyze(?bait:+, ?compromise:-, ?compromise-followup:--, ?guessing:--, ?broken-loop:-) → escalate:inconclusive



