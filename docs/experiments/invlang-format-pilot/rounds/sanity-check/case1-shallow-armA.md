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

