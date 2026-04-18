## HYPOTHESIZE (loop 1)

**Active hypotheses:**

- `?legitimate-automation` — attaches upstream of `v-src-ip-10.30.18.42` via `initiates`; proposed parent: `{type: process, classification: sanctioned-automated-system}`. Predicts: (1) `10.30.18.42` classifies as an internal monitoring host or known automation host in `environment/context/ip-ranges.md`; (2) the attempted username `root` OR its pattern matches a sentinel/service-account pattern in `environment/context/identity-patterns.md`. Refutation shape: IP classifies as internal-other (not monitoring/automation), or username classification is wordlist-common or unclassified rather than sentinel/service-account-pattern.

- `?authentication-mistake` — attaches upstream of `v-src-ip-10.30.18.42` via `initiates`; proposed parent: `{type: process, classification: human-or-automation-misfire}`. Predicts: (1) attempt count from `10.30.18.42` in the 5-minute window is exactly 1 (no retry burst); (2) a successful authentication from the same source follows within 60 seconds (the "typo-then-retry" correction). Refutation shape: no successful follow-up login within 60 seconds, or the volume is > 1 without a success, which shifts toward `?credential-guessing`; alternatively, a success exists but the username attempted here is not the one that succeeds.

- `?credential-guessing` — attaches upstream of `v-src-ip-10.30.18.42` via `initiates`; proposed parent: `{type: process, classification: adversarial-credential-attack}`. Predicts: (1) attempt count from `10.30.18.42` in the 5-minute window is > 1 OR the username `root` is the only attempt but classifies as wordlist-common; (2) no successful follow-up login (attack has not yet succeeded). Refutation shape: source classifies as internal-monitoring-host with an anchor-confirmed identity triple, reducing to `?legitimate-automation`; or a single attempt with a sentinel username.

- `?compromise-followup` (adversarial — keep active until explicitly refuted) — attaches upstream of `e-attempted-auth-01` via `precedes`; proposed parent: `{type: event, classification: successful-authentication-from-same-source}`. Predicts: (1) a 5501/5715 authentication-success event from `10.30.18.42` appears within 60 seconds after the alert timestamp; (2) no prior 5501/5715 from this source in the 4-hour window rules out a pre-existing session, making a new success significant. Refutation shape: `authentication-history` query over [alert_time, alert_time+60s] returns zero success events from `10.30.18.42`.

**Selected lead:** `source-classification` — measures the classification of vertex `v-src-ip-10.30.18.42` against `environment/context/ip-ranges.md`. Dispatch mode: **primary-deferred**.

- Primary: `source-classification`. This lead partitions all four hypotheses in one shot: if `10.30.18.42` is `internal-monitoring-host`, `?legitimate-automation` is elevated and `?credential-guessing` is substantially weakened; if it is `internal-other`, both external archetypes (`credential-stuffing`, `external-bruteforce`) are already disqualified and the investigation narrows to automation-mistake vs. internal-lateral; if it classifies as external (unexpected given the RFC1918 address but possible with SNAT/proxy), the two adversarial archetypes dominate. No other single measurement partitions the space as cleanly.
- Deferred (conditional on outcome): `authentication-history` (must run regardless, to service `?compromise-followup`; promoted to immediate second lead if source-classification is ambiguous or `internal-other`). `username-classification` deferred to lead 3, conditional on source result — it only discriminates within the benign half once source is resolved.

**Pitfalls:**

- `?legitimate-automation`: The attempted username `root` is not in the sentinel list (`nagios`, `zabbix`, `prometheus`, `healthcheck`, `monitorprobe`, `sensu`, `testuser`, `probe`) and is not a service-account-pattern name. Even if `10.30.18.42` classifies as a monitoring host, the username mismatch is a hard disqualifier for the `monitoring-probe` archetype and a near-disqualifier for `service-account-rotation`. Do not conflate "source is internal" with "automation is sanctioned" — the anchor lookup must confirm the `(srcip, srcuser, target)` triple, and `root` is almost certainly not in that registry.

- `?compromise-followup`: The CONTEXTUALIZE phase already reports no 5501/5715 success events from `app-web-07` in the last 4 hours, but this window precedes the alert and covers the past — not the 60 seconds after the alert timestamp. Do not use the CONTEXTUALIZE backward-look to refute `?compromise-followup`; only a forward-looking `authentication-history` query covering [2026-04-18T14:22:17Z, 2026-04-18T14:23:17Z] refutes this hypothesis. A missed post-alert success is the highest-severity failure mode.

- `?credential-guessing`: The internal source IP strongly weakens the two external archetypes as literally defined, but an internal compromised host performing lateral credential-guessing is a meaningful adversarial reading of the same shape. Do not discard `?credential-guessing` solely because the source is RFC1918 — reclassify it as a lateral-movement variant if the source turns out to be `internal-other` (not a known automation host) and the attempt count or username shape supports it.

- `?authentication-mistake`: The absence of a successful follow-up in the CONTEXTUALIZE 4-hour backward window does not refute this hypothesis, since a typo-recovery success would appear in the 60-second forward window. However, `root` as the attempted username makes the "accidental typo" story strained — operators rarely mistype their username as `root` when their real username is something else. Flag this implausibility but do not refute without the forward authentication check.

---

## Context used

Bundle file read only, no additional fetches.
