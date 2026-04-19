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

```yaml
prologue:

  vertices:
    - id: v-001
      type: endpoint
      classification: internal-monitoring-host
      identifier: "172.22.0.10 (monitoring-host)"
      attributes:
        ip: "172.22.0.10"
        role: monitoring-host
        knowledge: full

    - id: v-002
      type: endpoint
      classification: internal-server
      identifier: "target-endpoint (172.22.0.2)"
      attributes:
        ip: "172.22.0.2"
        agent_id: "002"
        hostname: target-endpoint

    - id: v-003
      type: identity
      classification: monitoring-pattern
      identifier: "healthcheck"
      placeholder: true
      attributes:
        kind: service-account
        username: healthcheck
        note: "attempted username; does not exist on target-endpoint"

  edges:
    - id: e-001
      relation: attempted_auth
      source_vertex: v-001
      target_vertex: v-002
      when:
        timestamp: "2026-04-17T10:30:06.326Z"
      attributes:
        srcuser: healthcheck
        srcport: "41372"
        result: failed
        rule_id: "5710"
        firedtimes: 3
      authority:
        kind: siem-event
        source: wazuh-rule-5710 / /var/log/auth.log
```

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

```yaml
hypothesize:
  hypotheses:
    - id: h-001

      name: "?legitimate-automation"
      attached_to_vertex: v-001
      proposed_edge:
        relation: initiated_by
        parent_vertex:
          type: process
          classification: monitoring-probe-process
          attributes:
            kind: service-account
            note: "sanctioned monitoring script running on monitoring-host, expected to probe target-endpoint at regular cadence"
      predictions:
        - id: p1
          claim: "all 5710 events from 172.22.0.10 in 5-minute window use the same username 'healthcheck' with no other usernames observed"
        - id: p2
          claim: "no successful authentication (rule group authentication_success) from 172.22.0.10 to target-endpoint within 60 seconds after alert timestamp"
      refutation_shape:
        - id: r1
          claim: "a 5501 or 5715 event from srcip=172.22.0.10 appears within 60 seconds after 2026-04-17T10:30:06Z"
      weight: null
      status: active

    - id: h-002
      name: "?credential-guessing"
      attached_to_vertex: v-001
      proposed_edge:
        relation: initiated_by
        parent_vertex:
          type: process
          classification: attack-tool
          attributes:
            kind: service-account
            note: "attacker or misconfigured tool running from monitoring-host, iterating usernames against target-endpoint"
      predictions:
        - id: p1
          claim: "multiple distinct usernames attempted from 172.22.0.10 in the 5-minute window, or attempt volume significantly exceeds expected ~10 min cadence"
      refutation_shape:
        - id: r1
          claim: "only username 'healthcheck' appears in 5710 events from 172.22.0.10 in the 5-minute window with no other usernames observed"
      weight: null
      status: active

    - id: h-003
      name: "?compromise-followup"
      attached_to_vertex: v-001
      proposed_edge:
        relation: initiated_by
        parent_vertex:
          type: session
          classification: unauthorized-session
          attributes:
            kind: user
            note: "adversarial session on monitoring-host using 5710 attempts as precursor to a successful auth"
      predictions:
        - id: p1
          claim: "a successful SSH authentication event (rule group authentication_success) from 172.22.0.10 to target-endpoint appears within 60 seconds after alert timestamp"
      refutation_shape:
        - id: r1
          claim: "no authentication_success events from srcip=172.22.0.10 within 60 seconds after alert; and no 5710 events from this source within 5 minutes before alert from other usernames"
      weight: null
      status: active
```

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

```yaml
gather:
  - id: l-001
    loop: 1
    name: authentication-history
    target: v-001
    tests: [h-001, h-002, h-003]
    observes:
      - { hypothesis: h-001, predictions: [p1, p2], refutations: [] }
      - { hypothesis: h-002, predictions: [], refutations: [r1] }
      - { hypothesis: h-003, predictions: [], refutations: [r1] }
    query_details:
      system: wazuh-indexer
      template: authentication-history
      query: "rule.groups:sshd AND data.srcip:172.22.0.10 | rule.groups:authentication_success AND data.srcip:172.22.0.10 | rule.id:5710 AND data.srcip:172.22.0.10"
      time_window: "5min before + 60s after alert (narrow); 2h rolling (cadence)"
      substitutions:
        srcip: "172.22.0.10"
        alert_timestamp: "2026-04-17T10:30:06.326Z"
    outcome:
      attribute_updates:
        - vertex: v-001
          updates:
            cadence_observed: "~600s periodic, ±2s variance"
            username_set_observed: "nagios, sensu, healthcheck (all monitoring-pattern)"
            rate_per_hour: 6
      observations:
        vertices: []
        edges:
          - id: e-002
            relation: attempted_auth
            source_vertex: v-001
            target_vertex: v-002
            attributes:
              count: 12
              window_start: "2026-04-17T08:43:00Z"
              window_end: "2026-04-17T10:42:59Z"
              distinct_usernames: 3
              username_set: "nagios, sensu, healthcheck"
              cadence: "~600s periodic"
              follow_up_success: false
            authority:
              kind: siem-event
              source: wazuh-indexer rule.id:5710 2h window
    resolutions:
      - hypothesis: h-001
        before: null
        after: "+"
        severity_of_test: moderate
        matched_prediction_ids: [p1, p2]
        matched_refutation_ids: []
        reasoning: "Both predictions confirmed: single username 'healthcheck' in 5-min window (p1); zero auth success within 60s or broader 15-min window (p2). The 2-hour cadence pattern — ~600s intervals, monitoring-pattern usernames only, constant 6/hr rate — is exactly the shape documented for this monitoring host. However, the approved-monitoring-sources anchor requires all three confirmation components; host-query verification of operational state is still pending, so ++ is not yet warranted."
        supporting_edges: [e-002]
      - hypothesis: h-002
        before: null
        after: "--"
        severity_of_test: severe
        matched_prediction_ids: []
        matched_refutation_ids: [r1]
        reasoning: "Refutation r1 satisfied: only 'healthcheck' in the 5-minute window; all 12 events over 2h use exclusively monitoring-pattern usernames (nagios, sensu, healthcheck). No wordlist names, no unknown usernames, no volume inconsistent with documented ~10-min monitoring cadence. If credential-guessing were occurring we would see username diversity or elevated volume — neither is present."
        supporting_edges: [e-002]
      - hypothesis: h-003
        before: null
        after: "--"
        severity_of_test: severe
        matched_prediction_ids: []
        matched_refutation_ids: [r1]
        reasoning: "Refutation r1 satisfied: zero authentication_success events from srcip=172.22.0.10 in the 15-minute window surrounding the alert. No pre-alert username diversity. If this were a compromise-followup scenario, a successful auth would be observable in the SIEM; it is not."
        supporting_edges: [e-002]
```

## HYPOTHESIZE (loop 2)

**Active hypotheses:** ?legitimate-automation (h-001 at +)
**Selected lead:** approved-monitoring-sources anchor — host-query verification
**Predictions:**
- ?legitimate-automation: monitoring-host container is operationally alive — cron service running, openssh-client package installed. This, combined with the static table match and SIEM cadence already confirmed, satisfies the full approved-monitoring-sources anchor citation for the monitoring-probe archetype.
  - *Pitfalls:* host-query CLI explicitly blocks `file-stat` on `/opt/workloads/` and `/etc/cron.d/` — cannot read the probe script or cron entry directly. The operational check is observable state only (service status + package), not direct script inspection.

## GATHER (loop 2)

**Lead:** approved-monitoring-sources anchor — host-query verification
**Query:** `host_query --host monitoring-host service-status cron` and `host_query --host monitoring-host package-installed openssh-client`
**Raw observation:**
- `cron: active (sysv)` — cron daemon is running on monitoring-host
- `openssh-client: installed` — openssh-client package is present on monitoring-host

## ANALYZE (loop 2)

**Evidence:** approved-monitoring-sources anchor — cron active, openssh-client installed

**Assessment:**

**?legitimate-automation (h-001):** Anchor fully confirmed. The three required components of the `approved-monitoring-sources` citation are all satisfied:
1. (172.22.0.10, healthcheck, target-endpoint) triple appears in the approved-monitoring-sources table as approved with declared cadence single attempt every ~10 min.
2. monitoring-host is operationally alive: `cron: active (sysv)` and `openssh-client: installed` confirmed via host-query.
3. SIEM history (l-001) shows ~600s periodic cadence, single attempt in 5-min window, exclusively monitoring-pattern usernames — consistent with declared cadence.

All three `approved-monitoring-sources` anchor components confirmed. The `++` refutation attempt was already run in l-001: the check was "any 5501/5715 from srcip=172.22.0.10 within 60 seconds"; the result was false (no success observed). That attempt to falsify did not succeed, backing the `++` grade with a failed falsification. Advancing h-001 to `++`.

**Surviving hypotheses:** ?legitimate-automation (h-001 at `++`)
**Next action:** CONCLUDE — mechanism confirmed with authoritative anchor, adversarial hypotheses explicitly refuted, full evidence coverage, monitoring-probe archetype matched.

```yaml
gather:
  - id: l-002

    loop: 2
    name: approved-monitoring-sources-anchor
    target: v-001
    selection_rationale: "Complete the three-component approved-monitoring-sources anchor citation. Components #1 (static table) and #3 (SIEM cadence) already confirmed by l-001; this lead verifies #2 (operational state of monitoring-host)."
    tests: [h-001]
    query_details:
      system: host-query
      template: monitoring-probe-anchor-verification
      query: "service-status cron; package-installed openssh-client"
      time_window: "current state at investigation time"
      substitutions:
        host: monitoring-host
    outcome:
      attribute_updates:
        - vertex: v-001
          updates:
            cron_status: "active (sysv)"
            openssh_client: installed
            anchor_verified: true
      observations:
        vertices: []
        edges: []
      trust_anchor_result:
        anchor_id: approved-monitoring-sources
        kind: org-authority
        result: confirmed
        as_of: "2026-04-17T10:30:06.326Z"
        authority_for_question: full
    resolutions:
      - hypothesis: h-001
        before: "+"
        after: "++"
        severity_of_test: severe
        matched_prediction_ids: [p1, p2]
        matched_refutation_ids: []
        reasoning: "Approved-monitoring-sources anchor confirmed with all three components: (1) static table approves (172.22.0.10, healthcheck, target-endpoint) triple; (2) host-query confirms cron active and openssh-client installed — monitoring-host is operationally live; (3) SIEM cadence from l-001 is ~600s periodic single-attempt, matching the approved cadence. The ++ is backed by the failed refutation attempt in l-001 (no auth success within 60s). All three components together constitute the authoritative citation."
        supporting_edges: [e-002]
```

## CONCLUDE

**Verdict:** resolved — monitoring-probe archetype confirmed with approved-monitoring-sources anchor; all adversarial hypotheses explicitly refuted with -- evidence
**Confirmed hypothesis:** ?legitimate-automation
**Trace:** screen(monitoring-probe-fast-path, source+username+anchor) → no_match(firedtimes=3) → auth-history(attempt_count_5min=1, cadence=600s±2s, usernames=monitoring-pattern, success=false) → anchor-verification(cron=active, openssh-client=installed) → disposition:benign

```yaml
conclude:
  termination:
    category: adversarial-refuted
    rationale: "Both adversarial hypotheses refuted with -- evidence from authentication-history lead: h-002 (?credential-guessing) refuted by absence of username diversity and normal monitoring volume; h-003 (?compromise-followup) refuted by zero authentication_success events from srcip=172.22.0.10. The benign hypothesis h-001 (?legitimate-automation) confirmed to ++ via approved-monitoring-sources anchor (all three components satisfied)."
  disposition: benign
  confidence: high
  matched_archetype: monitoring-probe
  summary: "SSH invalid-user alert from 172.22.0.10 (srcuser=healthcheck) against target-endpoint is the sanctioned monitoring-host probe running its expected periodic SSH health-check. Authentication-history confirmed single attempt in the 5-minute window, ~600s cadence, monitoring-pattern usernames only, and zero follow-up auth successes. The approved-monitoring-sources anchor was fully confirmed via static table match, SIEM cadence pattern, and live host-query verification of cron and openssh-client on the monitoring-host."
```

