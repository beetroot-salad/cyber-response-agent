# Alert

```json
{
  "timestamp": "2026-04-21T03:47:22.143+0000",
  "@timestamp": "2026-04-21T03:47:22.143Z",
  "id": "1776937642.1234567",
  "location": "syscheck",
  "decoder": { "name": "syscheck_integrity_changed" },
  "syscheck": {
    "path": "/etc/ssh/sshd_config.d/99-crypto.conf",
    "event": "modified",
    "changed_attributes": ["size", "mtime", "md5", "sha1", "sha256"],
    "size_before": "612",
    "size_after": "654",
    "md5_before": "a3f19b6c9e2d104781fb58c91aa4e203",
    "md5_after": "b47e2c1ad88937f421905eec63b7c9f1",
    "sha1_before": "4a7c1b9e0f82d5a3719bcd04e7fa2198cb4e5d11",
    "sha1_after": "7d9e82ba1f3c40a895e2b7d018fc4e32d91b0ac7",
    "sha256_before": "2e9dbfa041c85b8c24fd29e17c9e4f82ab1bcd6e9ea34527b19f6d4e802a16c5",
    "sha256_after": "9a1b4ec2dd58f6a40e9c118b6fd7d9e8bc3e0a9a45b87a2c1e5d3b8f904a26d1",
    "mtime_before": "2026-04-19T14:22:08",
    "mtime_after": "2026-04-21T03:47:21",
    "uid_after": "0",
    "gid_after": "0",
    "uname_after": "root",
    "perm_after": "rw-r--r--",
    "mode": "scheduled"
  },
  "agent": { "name": "target-endpoint", "id": "002" },
  "manager": { "name": "wazuh.manager" },
  "rule": {
    "id": "550",
    "level": 7,
    "description": "Integrity checksum changed.",
    "groups": ["ossec", "syscheck", "syscheck_entry_modified", "syscheck_file"],
    "mitre": {
      "technique": ["Stored Data Manipulation"],
      "id": ["T1565.001"],
      "tactic": ["Impact"]
    },
    "firedtimes": 1
  },
  "input": { "type": "log" }
}
```

## CONTEXTUALIZE

```yaml
prologue:
  vertices:
    - id: v-001
      type: endpoint
      classification: internal-server
      identifier: "target-endpoint (172.22.0.2)"
      attributes:
        ip: "172.22.0.2"
        agent_id: "002"
        hostname: target-endpoint
    - id: v-002
      type: file
      classification: sshd-dropin-config
      identifier: "/etc/ssh/sshd_config.d/99-crypto.conf"
      attributes:
        owner: "root:root"
        perm: "0644"
        effective_on: "sshd reload or restart"
    - id: v-003
      type: process
      classification: unclassified-process
      identifier: "unknown writer (attribution pending)"
      placeholder: true
      attributes:
        note: "process responsible for the 2026-04-21T03:47:21Z write — not yet resolved"

  edges:
    - id: e-001
      relation: wrote_to
      source_vertex: v-003
      target_vertex: v-002
      when:
        timestamp: "2026-04-21T03:47:21Z"
      attributes:
        size_delta: 42
        hash_changed: true
        perm_unchanged: true
        owner_unchanged: true
      authority:
        kind: siem-event
        source: wazuh-rule-550 / syscheck
```

## HYPOTHESIZE (loop 1)

```yaml
hypothesize:
  hypotheses:
    - id: h-001
      name: "?automated-config-writer"
      attached_to_vertex: v-002
      proposed_edge:
        relation: wrote_to
        parent_vertex:
          type: process
          classification: automated-config-management-process
          attributes:
            kind: system
            note: "package manager (apt/dpkg) or config-management agent (Ansible/Chef/Puppet) that reapplies templates on schedule"
      predictions:
        - id: p1
          claim: "package-transaction history (apt/dpkg) OR config-management run log shows a transaction/run on target-endpoint within 120 seconds of mtime_after (2026-04-21T03:47:21Z)"
      refutation_shape:
        - id: r1
          claim: "no package transaction AND no config-management run in the 2026-04-21T03:45:00–03:49:00 window"
      weight: null
      status: active

    - id: h-002
      name: "?admin-interactive-writer"
      attached_to_vertex: v-002
      proposed_edge:
        relation: wrote_to
        parent_vertex:
          type: process
          classification: admin-interactive-session
          attributes:
            kind: user
            note: "shell session of a user holding admin-group / sudoers membership; write produced via editor (vi/nano/sed) invocation"
      predictions:
        - id: p1
          claim: "auditd write-syscall attribution for /etc/ssh/sshd_config.d/99-crypto.conf at 2026-04-21T03:47:21Z resolves to a process whose session leader was opened by a user in admin-group / sudoers"
      refutation_shape:
        - id: r1
          claim: "auditd attribution resolves to a user not in admin-group / sudoers (and not a documented automation identity — that branch belongs to h-001)"
      legitimacy_contract:
        - id: lc1
          target_edge: e-001
          authority: approved-change-window
          asks: authorization
          question: "Does an approved change-window cover a sshd-config edit on target-endpoint at 2026-04-21T03:47:21Z?"
          resolves_to: [authorized, unauthorized, indeterminate]
      weight: null
      status: active

    - id: h-003
      name: "?adversary-controlled-writer"
      attached_to_vertex: v-002
      proposed_edge:
        relation: wrote_to
        parent_vertex:
          type: process
          classification: adversary-controlled-session
          attributes:
            kind: user
            note: "session on target-endpoint whose initiating identity is unauthorized OR whose origin (source IP / session provenance) is inconsistent with the identified user's documented access pattern"
      predictions:
        - id: p1
          claim: "auditd attribution resolves to (a) a non-admin account that is also not a documented automation identity, OR (b) an admin-group account whose originating ssh session came from a source IP outside the admin jump-host CIDR range"
      refutation_shape:
        - id: r1
          claim: "auditd attribution resolves to an admin-group user with session origin inside the admin jump-host CIDR range, AND no integrity-anomaly signals (impossible-travel, concurrent session from unexpected source) are present"
      weight: null
      status: active
```

## GATHER (loop 1)

## ANALYZE (loop 1)

```yaml
gather:
  - id: l-001
    loop: 1
    name: package-transaction-and-config-mgmt-history
    target: v-001
    tests: [h-001]
    observes:
      - { hypothesis: h-001, predictions: [], refutations: [r1] }
    query_details:
      systems: [host-query, ansible-tower]
      template: automated-writer-sweep
      queries:
        - "apt-history target-endpoint --window 2026-04-21T03:45:00Z..03:49:00Z"
        - "dpkg-log target-endpoint --window 2026-04-21T03:45:00Z..03:49:00Z"
        - "ansible-tower runs --host target-endpoint --window 2026-04-20T00:00:00Z..2026-04-21T04:00:00Z"
      time_window: "24h before mtime_after"
      substitutions:
        host: target-endpoint
        mtime_after: "2026-04-21T03:47:21Z"
    outcome:
      attribute_updates:
        - vertex: v-001
          updates:
            automated_writer_activity_in_window: none
      observations:
        vertices: []
        edges: []
    resolutions:
      - hypothesis: h-001
        before: null
        after: "--"
        severity_of_test: severe
        matched_prediction_ids: []
        matched_refutation_ids: [r1]
        reasoning: "Refutation r1 fully satisfied: zero package transactions (apt/dpkg) and zero config-management runs touched target-endpoint in the 4-minute window around mtime_after, and no such activity in the broader 24h window. Automated-writer hypothesis is structurally incompatible with the observed timeline."
        supporting_edges: [e-001]
      - hypothesis: h-003
        before: null
        after: "+"
        severity_of_test: moderate
        matched_prediction_ids: []
        matched_refutation_ids: []
        reasoning: "Not directly tested by this lead, but refutation of the automated-writer branch narrows the mechanism space to human-driven sessions. Early-morning timing weakly favors non-routine human activity. Weight moves to + pending the auditd discriminator."
        supporting_edges: []

```

