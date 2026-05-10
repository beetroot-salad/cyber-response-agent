## CONTEXTUALIZE

**Alert:** 1776937642.1234567 — wazuh-rule-550
**Source entity:** unknown writer process on target-endpoint (attribution pending)
**Target entity:** /etc/ssh/sshd_config.d/99-crypto.conf on target-endpoint (agent ID 002)
**Key observables:**
- `syscheck.changed_attributes`: ["size", "mtime", "md5", "sha1", "sha256"] — real content change
- Size delta: 612 → 654 (+42 bytes), consistent with one added line
- mtime_before: 2026-04-19T14:22:08; mtime_after: 2026-04-21T03:47:21 — 37h gap
- uid/gid/perm unchanged (0/0, rw-r--r--)
- Path is an sshd drop-in config: changes only take effect after sshd reload
- No `syscheck.diff` field at alert time — content diff requires separate probe
- alert timestamp: 2026-04-21T03:47:22Z (early-morning, outside typical admin hours)

**Playbook hypotheses:** ?automated-config-writer, ?admin-interactive-writer, ?adversary-controlled-writer
**Available leads:** package-transaction-history, config-mgmt-run-history, auditd-process-attribution, approved-change-window-lookup, file-diff, baseline-history, sshd-reload-check
**Archetype matches:**
- admin-interactive-change (moderate) — consistent with a drop-in sshd config edit; requires change-window anchor and auditd attribution to ground
- config-mgmt-template-drift (moderate) — drop-in path is commonly templated; requires a config-mgmt run log entry near mtime_after
- package-replacement (weak) — 99-crypto.conf is a site override, unlikely package-owned; unlikely
- adversary-persistence-preposition (weak but active) — edit-without-reload is the signature failure mode we must refute explicitly

**Adversarial archetype:** adversary-persistence-preposition — a threat actor with a foothold would edit SSH drop-in config to prepare an activation (crypto downgrade, forced-command lock, or authorized-key addition via `Include` directive) and avoid immediate `systemctl reload sshd` to stay silent. The alert's shape (content change + no automated-writer signals correlated in time) is compatible with this mode.

**Data environment:** wazuh (connected), host-query (connected), auditd access via host-query (connected). approved-change-window anchor operational via playground-ticket. package-transaction queries via host-query apt/dpkg.

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

**Active hypotheses:** ?automated-config-writer, ?admin-interactive-writer, ?adversary-controlled-writer
**Selected lead:** package-transaction-and-config-mgmt-history
**Predictions:**

- **?automated-config-writer (h-001)**: The write was produced by an automated system — package manager applying an openssh-* update, or a config-management agent (Ansible/Chef/Puppet) reapplying a template. Predictions: apt/dpkg history shows a transaction at mtime_after ±120s OR Ansible/Chef/Puppet run log records a play/run executed on target-endpoint in the same window. Single predicted attribute: transaction-log-entry-near-mtime-after.
  - *Pitfalls:* unattended-upgrades can install early-morning packages silently — an apt transaction near 03:47Z IS plausible and would confirm, not refute, this hypothesis. Config-management backoff/retry can produce entries slightly outside a ±60s window.

- **?admin-interactive-writer (h-002)**: The write was produced by a human admin in an interactive session. Predictions: auditd process ancestry resolves to a user in admin-group / sudoers AND a sshd process session chain AND (legitimacy_contract lc1) an approved-change-window covers the mtime_after timestamp. Single predicted attribute: auditd-user-is-admin-group-member.
  - *Pitfalls:* an admin may make a genuine change outside an approved window (emergency or habit). Treat an unmatched change-window as weakening but not refuting — the mechanism is still admin-interactive; the legitimacy question routes through `legitimacy_contract` resolution rather than a mechanism refutation.

- **?adversary-controlled-writer (h-003)**: The write was produced by a session whose initiating identity is not an authorized administrator — either a non-admin account with no business editing sshd config, or an admin-group account whose session is being driven by an adversary (credential theft / session hijack). This is a *mechanism-level* discrimination from h-002, not a legitimacy variant — the parent-vertex classification is `adversary-controlled-session`, distinct from `admin-interactive-session`. Predictions: auditd process ancestry resolves to a non-admin account OR session originated from a source IP outside the documented admin jump-host range. Single predicted attribute: writer-provenance-anomaly (either non-admin uid OR unexpected source).
  - *Pitfalls:* service accounts that legitimately manage specific config paths (e.g., a certbot renewal hook rewriting TLS config) look non-admin in auditd but are authorized — h-003 should not refute on "non-admin" alone without checking whether the account is a documented automation identity. That check lives in the h-001 hypothesis.

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

**Lead:** package-transaction-and-config-mgmt-history
**Queries:**
- (A) `host-query apt-history target-endpoint --window 2026-04-21T03:45:00Z..03:49:00Z`
- (B) `host-query dpkg-log target-endpoint --window 2026-04-21T03:45:00Z..03:49:00Z`
- (C) Ansible Tower / AWX run history for target-endpoint in the 24h preceding mtime_after
- (D) Puppet / Chef report history for target-endpoint in the same window

**Raw observations:**
- (A) apt history: no transactions between 2026-04-21T00:00:00Z and 2026-04-21T06:00:00Z. Last apt activity 2026-04-20T06:30:14Z (chrony 4.3-2, unrelated).
- (B) dpkg log: no package state changes in the window. Last change matches apt history (chrony, 2026-04-20T06:30:14Z).
- (C) Ansible Tower: no plays executed against target-endpoint on 2026-04-21. Last play 2026-04-16T10:14:02Z (baseline hardening, no sshd_config.d template).
- (D) No Puppet/Chef infrastructure deployed to target-endpoint.

**Cross-lead notes:** All four queries returned empty results for the mtime_after window. The target-endpoint host is confirmed operational and reachable via host-query throughout the window (no degraded-source signals). The automated-writer prediction (p1 under h-001) fully fails; the refutation-shape (r1) is fully satisfied.

## ANALYZE (loop 1)

**Evidence:** package-transaction-and-config-mgmt-history — zero automated-writer activity on target-endpoint in the window surrounding 2026-04-21T03:47:21Z.

**Assessment:**

**?automated-config-writer (h-001):** Refuted. All four discriminating queries returned empty. Refutation r1 fully satisfied. There is no automated system-level process that could have produced the write at this timestamp. Moving to `--`.

**?admin-interactive-writer (h-002):** Unaffected by this lead. Prediction p1 and the legitimacy contract lc1 both require auditd attribution + change-management consultation — neither ran in this lead. Weight remains `null`, status active.

**?adversary-controlled-writer (h-003):** Weakly supported. The refutation of automated-writer narrows the mechanism space to human-driven sessions (admin or adversary). Early-morning timing (03:47Z) slightly favors non-routine human activity, but timing alone is not decisive. Weight moves to `+` pending the auditd discriminator.

**Surviving hypotheses:** ?admin-interactive-writer (h-002, active/null), ?adversary-controlled-writer (h-003, `+`)
**Next action:** the remaining fork is h-002 vs h-003 — both attach to the same vertex, differ only on parent-vertex classification (admin-interactive-session vs. adversary-controlled-session), and share a single discriminating observable: auditd process attribution + session provenance. No new mechanism hypotheses are available to emit. The next turn should GATHER on auditd-process-attribution rather than emit a speculative HYPOTHESIZE refinement.

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
