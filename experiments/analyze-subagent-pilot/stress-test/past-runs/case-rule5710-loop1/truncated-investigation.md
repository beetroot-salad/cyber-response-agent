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
- `?probe-retry-stuck` — the sanctioned monitoring probe on `172.22.0.10` is stuck in a retry loop against **a single sentinel identity**: one probe process attempts username A, fails, retries A, retries A. Mechanism: retry-with-backoff gone wrong on one tick. Predicts repeated attempts clustering on **one** username at retry cadence. Disposition if confirmed: benign but broken, escalate to monitoring owner.
- `?probe-enumeration-misconfigured` — the sanctioned monitoring probe on `172.22.0.10` has a config defect that causes it to fire the **full sentinel list** in a single tick rather than rotating one-per-tick. Mechanism: config drift enumerating all 5 sentinel names in rapid sequence. Predicts a burst cycling through all approved sentinel identities in sub-second cadence within one invocation. Disposition if confirmed: benign but broken, escalate to monitoring owner. Observationally near-identical to `?bait` — the only disambiguator is workload ownership on monitoring-host.
- `?monitoring-bait-triggered` — the `monitoring_bait.sh` manually-triggered workload on monitoring-host (explicitly documented in `ip-ranges.md` as an *adversarial-evaluation variant* that is NOT sanctioned by approved-monitoring-sources) is running. Mechanism is internal, shape is monitoring-like but cadence-violating. Disposition: benign in origin (test) but shape-indistinguishable from a compromise, so escalation is still the correct action — the analyst needs to confirm the evaluation scenario is intentional.
- `?monitoring-host-compromise` — an adversary with access to `172.22.0.10` is borrowing the approved source's identity to hammer target-endpoint, using sentinel usernames as lure (low detection likelihood inside an approved source). Adversarial — must be explicitly refuted.
- `?internal-credential-guessing` — an authenticated user / operator on `172.22.0.10` is manually attempting SSH logins (typo recovery, misconfigured client). Typical shape: low volume, real-looking usernames. Refuted preliminarily by observed username set (only sanctioned sentinels), but keep live until a forward-window check also clears compromise-followup.
- `?compromise-followup` (adversarial — mandatory) — one of these 6-in-5min attempts, or a successor attempt, is followed by a successful SSH login from the same source. SCREEN checked 60s after the current alert and found 0 successes, but that window is narrower than this hypothesis needs — must be extended to cover the full burst window and a forward window measured in minutes, not seconds.

**Selected lead:** composite — `authentication-history` (extended) + `recent-alert-correlation` + `process-lineage` surrogate via `host-query` on monitoring-host.

The most diagnostic divergence between the surviving hypotheses is:

1. **Username diversity beyond sensu/monitorprobe** — discriminates `?credential-guessing` and `?compromise` (would rotate wordlist) from probe/bait hypotheses (stay within sentinel set). Baseline: sanctioned cadence = 1 probe / ~10 min using one sentinel per tick. Refutation shapes: (a) any non-sentinel username from this srcip = all probe hypotheses refuted, `?credential-guessing`/`?compromise` supported; (b) exactly sentinel usernames, burst timing = probe/bait hypotheses supported, others weakly refuted. **Critical sub-discriminator:** within the sentinel set, *how* the usernames are distributed matters — all repeats of ONE sentinel supports `?probe-retry-stuck`; rotation through ALL sentinels refutes `?probe-retry-stuck` and supports `?probe-enumeration-misconfigured` or `?bait`.
2. **Temporal profile of the burst over a 1-hour window** — discriminates a one-off burst (state change / manual trigger → `?bait`, enumeration-misconfig, or retry-stuck kicked in) from a sustained attack (`?compromise`). Baseline: ~6 probes/hour (sanctioned cadence). Refutation shapes: (a) only the last ~5 min shows burst, rest of hour is normal-cadence = consistent with probe/bait recently triggered; (b) burst sustained across the hour = `?compromise` supported.
3. **Forward-window successful-login check, extended to 5 min** — the non-negotiable compromise check. Refutation shape: a 5501/5715 from 172.22.0.10 in the 5 min after the alert = `?compromise-followup` upgraded to `++`. Absence over the full burst window + 5 min forward = `?compromise-followup` cleared.
4. **Process state on monitoring-host** — `host-query --host monitoring-host process-list` can reveal whether `monitoring_bait.sh` or a looping `monitoring_probe.sh` is currently running by name. Process-list does not expose argv/parent, but name-level presence of the bait workload is a direct observation per `ip-ranges.md`. Refutation shapes: (a) `monitoring_bait` process present → `?bait` strongly supported, `?compromise` and probe-hypotheses weakened; (b) only `monitoring_probe` / cron present and service-status cron = active → `?probe-retry-stuck` or `?probe-enumeration-misconfigured` weakly supported; (c) neither present and no shell lineage visible → no probe hypothesis refuted (short-lived scripts exit).
5. **Other alerts on monitoring-host in the last 4 hours** (any signature) — ticket-context said none, but I should explicitly scope any Wazuh hits on agent.name:monitoring-host or data.srcip:172.22.0.10 for non-5710 signatures in case a compromise precursor (e.g. 100001/550/100110) was missed. Refutation shape: (a) any process/file-integrity/auth alert on monitoring-host itself → `?compromise` supported strongly; (b) clean → `?compromise` weakened but not refuted.

**Predictions:**
- `?probe-retry-stuck`: **repeated attempts on exactly ONE sentinel username**, burst at retry-cadence (tens of ms to seconds between attempts), no successful login, no parallel alerts, cron active, process-list may show `monitoring_probe`
  - *Pitfalls:* username-count is the key discriminator; a burst across multiple sentinel identities **refutes** this hypothesis outright — do not confuse with enumeration-misconfig
- `?probe-enumeration-misconfigured`: **rotation through the full sentinel set** (all 5 approved identities cycled) in a single sub-second tick, no successful login, no parallel alerts, cron active, process-list may show `monitoring_probe`
  - *Pitfalls:* observationally near-identical to `?bait` — cannot be distinguished from bait without workload-ownership evidence on monitoring-host. Grade accordingly
- `?monitoring-bait-triggered`: only sanctioned sentinel usernames (the bait reuses monitoring names by design), burst = single discrete event not sustained, no successful login, process-list may show `monitoring_bait` process, no other alerts on monitoring-host
  - *Pitfalls:* the bait and a compromise-that-mimics-bait are observationally near-identical — the disambiguator is absence of compromise precursors, not presence of bait name alone. Also: if the bait process has already exited, name will not appear in process-list, and absence-of-name cannot refute.
- `?monitoring-host-compromise`: username rotation beyond sentinel set (wordlist), OR sustained burst over the full hour, OR successful login in the forward window, OR other alerts on monitoring-host (file-integrity, rootkit, process anomaly), OR unexpected processes in process-list
  - *Pitfalls:* adversary may stay within sentinel set deliberately to evade detection; absence of rotation is NOT proof of innocence. Successful-login absence in 5 min is also NOT proof — attacker may delay.
- `?internal-credential-guessing`: low volume (not matching observed 6-in-5min), real-looking usernames (not matching observed all-sentinels) — preliminary refutation already holds, lead will confirm.
- `?compromise-followup`: any successful auth from 172.22.0.10 within the forward window — the hypothesis is defined by this observable; absence is the refutation shape.

