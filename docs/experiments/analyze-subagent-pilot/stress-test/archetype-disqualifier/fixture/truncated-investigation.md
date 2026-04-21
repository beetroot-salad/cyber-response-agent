# Investigation — wazuh-rule-5710 / alert 1713715201.123456

## PHASE: CONTEXTUALIZE

Alert: rule-5710, invalid SSH user `nagios` from `10.0.1.42` targeting
`target-endpoint` (10.0.2.15) at 2026-04-21T14:20:01Z. Source IP is in
the RFC1918 range declared internal in
`environment/context/ip-ranges.md` (10.0.1.0/24 = internal-ops subnet,
known to host monitoring tooling). Username `nagios` is a
monitoring-pattern sentinel name per the playbook's known-probe list.

```yaml
prologue:
  vertices:
    - {id: v-alert-001, class: event, kind: rule-5710, ts: "2026-04-21T14:20:01Z"}
    - {id: v-srcip-001, class: host, address: "10.0.1.42", zone: internal-ops}
    - {id: v-srcuser-001, class: identity, name: nagios, kind: sentinel-monitoring-name}
    - {id: v-target-001, class: host, address: "10.0.2.15", name: target-endpoint}
  edges:
    - {id: e-001, from: v-srcip-001, to: v-alert-001, kind: emitted, authority: siem-event}
    - {id: e-002, from: v-srcuser-001, to: v-alert-001, kind: claimed-as, authority: siem-event}
```

## PHASE: HYPOTHESIZE (loop 1)

```yaml
hypothesize:
  hypotheses:
    - id: h-001
      label: "?monitoring-probe"
      parent_edge: e-001
      classification: "sanctioned-internal-monitor"
      predictions:
        - {id: p1, shape: "source appears on approved-monitoring-sources registry for (srcip, srcuser=nagios, target=target-endpoint)"}
        - {id: p2, shape: "cadence is regular at a documented tool interval (1m/5m/15m/hourly), not burst"}
        - {id: p3, shape: "no successful SSH session from 10.0.1.42 in a ±5min window around the probe"}
      refutation_shape:
        - {id: r1, shape: "source absent from approved-monitoring-sources registry"}
        - {id: r2, shape: "burst shape (≥3 attempts within 5s from same srcip) or irregular inter-arrival"}
        - {id: r3, shape: "successful 5501 login from same srcip within ±5min window — out-of-archetype per monitoring-probe story.md"}
      legitimacy_contract:
        id: lc1
        on_edge: e-001
        asks: "is 10.0.1.42 a sanctioned monitoring host authorized to probe target-endpoint as nagios?"
    - id: h-002
      label: "?adversary-borrowing-probe-name"
      parent_edge: e-001
      classification: "adversary-controlled-source"
      predictions:
        - {id: p1, shape: "source absent from approved-monitoring-sources registry, OR registry match for a different target/user"}
        - {id: p2, shape: "session outcome suggests reconnaissance followup — successful login, lateral scan, or username rotation"}
      refutation_shape:
        - {id: r1, shape: "source is on approved list AND no successful follow-on session AND cadence is tool-regular"}
    - id: h-003
      label: "?operator-typo"
      parent_edge: e-002
      classification: "misconfigured-legitimate-user"
      predictions:
        - {id: p1, shape: "a correlated 5501 success from same srcip within 1-2 min using a different, real username"}
      refutation_shape:
        - {id: r1, shape: "no 5501 success from srcip in ±10min, OR success was with `nagios` itself"}
```

## PHASE: GATHER (loop 1)

```yaml
gather:
  - lead:
      id: l-001
      name: source-classification
      hypothesis_refs: [h-001, h-002]
      asks: authorization
      query: "approved-monitoring-sources.lookup(srcip=10.0.1.42, srcuser=nagios, target=target-endpoint)"
      outcome:
        observations:
          - "Registry match: entry `mon-042` — srcip=10.0.1.42 (host `ops-nagios-01`), srcuser=nagios, target=target-endpoint, declared_cadence=60s, approval_window=unbounded."
          - "trust_anchor_result: approved-monitoring-sources returned {authorized: true, entry_id: mon-042}"
        trust_anchor_result:
          anchor: approved-monitoring-sources
          asks: authorization
          verdict: authorized
          entry_id: mon-042
        legitimacy_resolutions:
          - {edge: e-001, contract: lc1, verdict: authorized, via: approved-monitoring-sources:mon-042}
        attribute_updates:
          - {vertex: v-srcip-001, attribute: role, value: "sanctioned-monitoring-host"}
```

## PHASE: ANALYZE (loop 1)

**Evidence:** source-classification — registry match `mon-042` (ops-nagios-01) authorizes 10.0.1.42 to probe target-endpoint as `nagios`; declared cadence 60s.

**Assessment:**
- ?monitoring-probe: + (was new) — matched p1 (on approved registry). Legitimacy_contract lc1 resolved `authorized`. p2 (cadence) and p3 (no follow-up success) not yet tested.
- ?adversary-borrowing-probe-name: - (was new) — r1 partially satisfied (source on approved list); still live pending cadence + session-outcome checks.
- ?operator-typo: - (was new) — no evidence; still possible a human operator on ops-nagios-01 mistyped; awaiting 5501-correlation check.

**Surviving hypotheses:** ?monitoring-probe, ?adversary-borrowing-probe-name, ?operator-typo
**Next action:** HYPOTHESIZE — need to discriminate via (a) cadence shape of prior 5710s from this source (tests p2/r2) and (b) correlated 5501 successes from 10.0.1.42 in ±10min (tests p3/r3 and disqualifier clause).

## PHASE: HYPOTHESIZE (loop 2)

No new hypotheses; loop-1 forks persist pending discriminating evidence.

## PHASE: GATHER (loop 2)

```yaml
gather:
  - lead:
      id: l-002
      name: cadence-check
      hypothesis_refs: [h-001, h-002]
      query: "wazuh_cli.search(rule.id=5710 AND data.srcip=10.0.1.42 AND data.srcuser=nagios, window=T-3600..T)"
      outcome:
        observations:
          - "6 prior rule-5710 alerts from 10.0.1.42 user=nagios at T-60, T-120, T-180, T-240, T-300, T-360 (±1.5s drift)"
          - "Inter-arrival intervals: 60.8s, 59.3s, 60.1s, 60.2s, 59.9s, 60.4s — regular 60s cadence matching mon-042 declared_cadence"
          - "No burst clusters (no ≥3 events within 5s)."
  - lead:
      id: l-003
      name: session-outcome-correlation
      hypothesis_refs: [h-001, h-002, h-003]
      query: "wazuh_cli.search((rule.id=5501 OR rule.id=5715) AND data.srcip=10.0.1.42, window=T-300..T+300)"
      outcome:
        observations:
          - "1 rule-5501 hit: 2026-04-21T14:20:19Z — `Accepted publickey for ubuntu from 10.0.1.42 port 41288 ssh2` on target-endpoint (18s after the 5710 probe)."
          - "Session remained open for 14 minutes; 3 sudo invocations logged under user `ubuntu` during the session (rule-5402)."
          - "No other 5501/5715 hits from 10.0.1.42 in the window."
