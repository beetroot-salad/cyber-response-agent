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

## HYPOTHESIZE (loop 1)

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

## ANALYZE (loop 1)

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

