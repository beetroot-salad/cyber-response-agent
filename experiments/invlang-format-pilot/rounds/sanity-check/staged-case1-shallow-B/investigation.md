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



