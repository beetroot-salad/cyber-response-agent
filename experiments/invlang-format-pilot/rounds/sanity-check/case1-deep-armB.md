# Alert

```json
{
  "predecoder": {
    "hostname": "target-endpoint",
    "program_name": "sshd",
    "timestamp": "Apr 17 10:30:06"
  },
  "agent": {
    "ip": "172.22.0.2",
    "name": "target-endpoint",
    "id": "002"
  },
  "manager": {
    "name": "wazuh.manager"
  },
  "data": {
    "srcuser": "healthcheck",
    "srcip": "172.22.0.10",
    "srcport": "41372"
  },
  "rule": {
    "mail": false,
    "level": 5,
    "hipaa": [
      "164.312.b"
    ],
    "pci_dss": [
      "10.2.4",
      "10.2.5",
      "10.6.1"
    ],
    "tsc": [
      "CC6.1",
      "CC6.8",
      "CC7.2",
      "CC7.3"
    ],
    "description": "sshd: Attempt to login using a non-existent user",
    "groups": [
      "syslog",
      "sshd",
      "authentication_failed",
      "invalid_login"
    ],
    "nist_800_53": [
      "AU.14",
      "AC.7",
      "AU.6"
    ],
    "gdpr": [
      "IV_35.7.d",
      "IV_32.2"
    ],
    "firedtimes": 3,
    "mitre": {
      "technique": [
        "Password Guessing",
        "SSH"
      ],
      "id": [
        "T1110.001",
        "T1021.004"
      ],
      "tactic": [
        "Credential Access",
        "Lateral Movement"
      ]
    },
    "id": "5710",
    "gpg13": [
      "7.1"
    ]
  },
  "decoder": {
    "parent": "sshd",
    "name": "sshd"
  },
  "input": {
    "type": "log"
  },
  "@timestamp": "2026-04-17T10:30:06.326Z",
  "location": "/var/log/auth.log",
  "id": "1776421806.3175703",
  "timestamp": "2026-04-17T10:30:06.326+0000"
}
```

## CONTEXTUALIZE

**Alert:** 1776421806.3175703 — wazuh-rule-5710
**Source entity:** 172.22.0.10 (srcip), username "healthcheck" (srcuser)
**Target entity:** target-endpoint (agent.name, IP 172.22.0.2)
**Key observables:** srcip=172.22.0.10, srcuser=healthcheck, srcport=41372, firedtimes=3, timestamp=2026-04-17T10:30:06.326Z
**Playbook hypotheses:** ?legitimate-automation, ?authentication-mistake, ?credential-guessing, ?compromise-followup
**Available leads:** source-classification, authentication-history, username-analysis, approved-monitoring-sources anchor
**Archetype matches:**
- monitoring-probe (strong) — sentinel username 'healthcheck' matches monitoring-pattern exactly; source 172.22.0.10 is internal monitoring host per ip-ranges.md; single-attempt shape consistent with probe; no successful follow-up indicated; required anchor: approved-monitoring-sources
- service-account-rotation (weak) — internal source matches but 'healthcheck' does not follow svc-*/backup-*/cron-* naming convention; no cron-cadence evidence in single alert; required anchor: scheduled-jobs
- credential-stuffing (no match) — requires external source; this is internal RFC1918
- external-bruteforce (no match) — requires external source + wordlist usernames; this is internal with sentinel username
**Adversarial archetype:** external-bruteforce — a real threat actor would most plausibly hide inside this signature using an external source iterating wordlists at high volume; current alert's internal source and sentinel-pattern username make this an implausible fit, but the ?compromise-followup hypothesis (5710 + subsequent 5501 from same source) must be explicitly refuted
**Data environment:** all systems reachable per preflight (host-query, playground-ticket, stub-ticket, wazuh); no degraded systems; no leads affected by outages



## SCREEN

**Result:** no_match
**Leads run:**
- source-classification: 172.22.0.10 classified as internal-monitoring-host (ip-ranges.md) — PASS
- username-classification: "healthcheck" classified as monitoring-pattern (identity-patterns.md) — PASS
- approved-monitoring-sources: triple (172.22.0.10, healthcheck, target-endpoint) listed as approved, cadence single attempt every ~10 min — PASS
- authentication-history (partial): alert field firedtimes=3 indicates multiple rule fires in burst window; screen requires exactly 1 attempt — FAIL
**Outcome:** Falling through to HYPOTHESIZE — attempt_count_5min indicator failed. firedtimes=3 is inconsistent with the single-attempt monitoring cadence. Source IP and username both match the approved monitoring-probe shape, but the burst volume disqualifies the fast-path screen. Full investigation required to determine whether this is an adversarial evaluation scenario (monitoring_bait.sh), normal probe cycled unusually, or something else.


## HYPOTHESIZE (loop 1)

**Active hypotheses:** ?legitimate-automation, ?credential-guessing, ?compromise-followup
**Selected lead:** authentication-history
**Predictions:**
- ?legitimate-automation (monitoring probe with burst / evaluation scenario): ≥3 5710 events from 172.22.0.10 in 5-minute window, single username "healthcheck", no 5501/5715 success from same srcip within 60 seconds. Cadence may be unusual (rapid retries or monitoring_bait.sh). No follow-up success is required for this hypothesis to survive.
  - *Pitfalls:* firedtimes=3 is a Wazuh rule-frequency counter and may not equal 3 independent SSH attempts — could reflect rule throttle/aggregation. Need raw event count from authentication-history SIEM query to be certain.
- ?credential-guessing (adversary using monitoring host as pivot): multiple distinct usernames from 172.22.0.10, or large volume inconsistent with monitoring cadence, suggesting the monitoring host was co-opted or a tool is running from it. Possibly mixed sentinel + wordlist usernames.
  - *Pitfalls:* an adversary using the known monitoring host and staying username-consistent could look exactly like a legitimate burst — username diversity is the discriminator, not volume alone.
- ?compromise-followup (monitoring host used in attack chain with subsequent success): any 5501/5715 from 172.22.0.10 within 60 seconds after the alert timestamp would take this out of the benign archetypes entirely.
  - *Pitfalls:* absence of 5501 in SIEM doesn't guarantee no auth success if logging pipeline has a gap — though for an auth.log-sourced alert this is unlikely.



## GATHER (loop 1)

**Lead:** authentication-history
**Query:** (A) sshd events from srcip=172.22.0.10, window 10:25:00Z–10:31:30Z; (B) authentication_success events from srcip=172.22.0.10, window 10:20:00Z–10:35:00Z; (C) rule.id:5710 AND srcip=172.22.0.10, 2h rolling window
**Raw observation:**
- **attempt_count_5min:** 1 — exactly one rule-5710 event from 172.22.0.10 in the 5-minute window preceding the alert (the alert event itself at 10:30:06.326Z; no earlier events in the window). `firedtimes:3` in the alert is Wazuh's rule-frequency counter, not a 5-minute attempt count.
- **successful_login_after_60s:** false — zero authentication_success (rule group authentication_success) events from srcip=172.22.0.10 in 10:20:00Z–10:35:00Z window.
- **Timing pattern:** periodic, ~600s interval, ±2s variance. Consecutive intervals in visible data: 600s, 601s, 598s, 600s.
- **Username diversity:** 3 distinct usernames over 2h — nagios (5 events), sensu (4 events), healthcheck (3 events). All three appear in the documented monitoring-pattern set for this host. Single username (healthcheck) in the 5-minute alert window.
- **Volume/rate:** 12 events in 2h = 6/hr; constant rate, no burst.
- **Source context:** 172.22.0.10 classified as internal monitoring host per ip-ranges.md (monitoring-host container, stable pinned IP, documented probe purpose).


## ANALYZE (loop 1)

**Evidence:** authentication-history — periodic 600s cadence, single attempt in 5-min window, 3 monitoring-pattern usernames over 2h, zero auth successes

**Assessment:**

**?legitimate-automation (h-001):** Both predictions confirmed. p1 satisfied — only username 'healthcheck' appears in the 5-minute window. p2 satisfied — no auth success within 60 seconds (or anywhere in 10:20–10:35 window). The 2-hour SIEM history shows an unbroken ~600s periodic cadence using exclusively monitoring-pattern usernames (nagios, sensu, healthcheck) — the shape exactly matches the documented single-attempt-every-~10min probe behavior for 172.22.0.10. Refutation r1 was not satisfied. Moving to `+`. Cannot yet commit `++` — the approved-monitoring-sources anchor requires a third confirmation component: the monitoring-host must be verified as operationally alive (cron running, openssh-client installed) via host-query. The static table match (#1) and SIEM cadence match (#3) are confirmed; host-query (#2) is still pending.

**?credential-guessing (h-002):** Refuted. The 5-minute window contains only username 'healthcheck'; the 2-hour window contains only monitoring-pattern usernames — no wordlist names, no unknown usernames, no username diversity consistent with guessing. Volume is exactly the expected monitoring cadence, not elevated. Refutation r1 fully satisfied. Moving to `--`.

**?compromise-followup (h-003):** Refuted. Zero authentication_success events from 172.22.0.10 in any queried window. No pre-alert username diversity suggesting probe-before-attack. Refutation r1 fully satisfied. Moving to `--`.

**Surviving hypotheses:** ?legitimate-automation (h-001) at `+`
**Next action:** HYPOTHESIZE loop 2 — need approved-monitoring-sources anchor host-query verification to confirm monitoring-host is operationally alive (cron + openssh-client). This is the remaining component to satisfy anchor confirmation and advance h-001 to `++`.



