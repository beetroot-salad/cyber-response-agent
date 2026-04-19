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


