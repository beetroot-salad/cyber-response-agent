## Meta

### Files actually read

- `/workspace/docs/experiments/hypothesize-subagent-pilot/fixtures/case-cron-modification/truncated-investigation.md`
- `/workspace/soc-agent/skills/investigate/SKILL.md` (full — §ASSESS around line 138, §HYPOTHESIZE)
- `/workspace/docs/investigation-language.md` (§Hypothesis, lines 225–345)
- `/workspace/soc-agent/knowledge/common-investigation/leads/process-lineage/definition.md`
- `/workspace/soc-agent/knowledge/common-investigation/leads/authentication-history/definition.md`
- `/workspace/soc-agent/knowledge/common-investigation/leads/ad-hoc/definition.md`
- `/workspace/soc-agent/knowledge/environment/operations/deploy-runs.md`
- `/workspace/soc-agent/knowledge/environment/operations/scheduled-jobs.md`
- `/workspace/soc-agent/knowledge/environment/operations/approved-monitoring-sources.md`
- `/workspace/soc-agent/knowledge/environment/operations/change-windows.md`
- `/workspace/soc-agent/knowledge/environment/operations/workload-manifest.md`
- `/workspace/soc-agent/knowledge/environment/context/identity-patterns.md`

### ASSESS verdict

**Fork: YES. Interpretation-vulnerable: YES.**

At the anchor (the `file_modification` event on `/etc/cron.d/backup-tasks`), three competing one-hop parent classifications for the modifying process are plausible and observationally distinguishable: `cm-deploy-agent` (Ansible/Salt/Puppet), `interactive-admin-shell` (human operator via SSH), and `adversary-persistence-agent` (attacker-controlled process planting a cron backdoor). They predict different process ancestry, session contexts, and CM control-plane corroboration — a real fork exists. The chosen lead is `auditd-syscall-audit`, which recovers the modifying process's pid/ppid/sid and full command-line. The process binary path and parent chain fields are interpretation-vulnerable: reading "ansible-playbook" vs. "bash" vs. an unknown binary requires classifying the result, not just parsing a number — a reviewer could reasonably disagree on whether an unfamiliar binary name indicates a dropped tool or a legitimately installed CM agent.

### Lead selection mode

**Single lead** (`auditd-syscall-audit`), **with pre-registered predictions on the process ancestry and binary path fields.**

Rationale: auditd syscall records at the modification timestamp directly expose the modifying process's pid, ppid, session id, binary path, and full command-line — all in one query, requiring no cross-source join. This single measurement partitions all three hypotheses: a CM agent produces a recognizable ancestry chain (ansible/salt/puppet binary under a known service account, ppid from the CM agent daemon); an admin shell produces sshd → bash (or similar) ancestry with a corresponding interactive session; an adversary-controlled process produces an anomalous binary path, novel parent chain, or unknown session context. Secondary leads (`cm-deploy-audit`, `session-audit`) are deferred — their results are genuinely conditional on the auditd outcome and running them first would be wasteful if the ancestry is immediately decisive. Primary-plus-deferred is the right structure, but the first lead runs alone because it is expected to partition the fork cleanly.

---

## HYPOTHESIZE (loop 1)

**Active hypotheses:**

- `?cm-deploy` — attaches upstream of `v-file-modification` (the `openat O_WRONLY|O_TRUNC` event on `/etc/cron.d/backup-tasks`) via `initiated_by`; proposed parent: `{type: process, classification: cm-deploy-agent}`. Predicts: (1) the modifying process binary path matches a known CM agent executable (e.g., `/usr/bin/ansible-playbook`, `/usr/bin/salt-minion`, `/opt/puppetlabs/puppet/bin/puppet`) and its parent chain terminates in a CM daemon or init; (2) the process runs under a service account identity consistent with a CM agent (uid/euid maps to a declared automation account, not a human operator or root-interactive session). Refutation shape: binary path is a shell interpreter (`/bin/bash`, `/bin/sh`, `/usr/bin/python3`) with no CM ancestor in the parent chain; or uid=0 with interactive session ID (not a CM daemon session).

- `?interactive-admin` — attaches upstream of `v-file-modification` via `initiated_by`; proposed parent: `{type: process, classification: interactive-admin-shell}`. Predicts: (1) the modifying process binary path is a shell interpreter (`/bin/bash`, `/bin/sh`) or text editor, and the parent chain includes `sshd` with a session ID that maps to an SSH login; (2) the modification timestamp falls within an active SSH session on `prod-api-02` for a human admin identity. Refutation shape: no SSH session in the T−30min window on `prod-api-02`; or the parent chain does not include `sshd`.

- `?adversary-persistence` — attaches upstream of `v-file-modification` via `initiated_by`; proposed parent: `{type: process, classification: adversary-controlled-process}`. Predicts: (1) the modifying process binary path is unrecognized (not a known CM tool, not a standard shell under expected ancestry) — e.g., a dropped binary under `/tmp/`, `/dev/shm/`, or `/usr/local/sbin/` with no corresponding package install event; or a shell spawned from an unexpected parent (web process, container runtime, service binary). Refutation shape: the modifying process is a well-known CM agent binary with a clean parent chain from a CM daemon, or a shell with an SSH parent session matching a human admin login.

**Selected lead:** `auditd-syscall-audit` — queries auditd records at T=2026-04-18T03:47:22Z on `prod-api-02` for the syscall sequence associated with the `openat(O_WRONLY|O_TRUNC)` event on `/etc/cron.d/backup-tasks`. Recovers: modifying process pid, binary path, full command-line, ppid, parent binary, session id, uid/euid/suid. Outcome discriminates `?cm-deploy` (CM binary + daemon ancestry), `?interactive-admin` (shell + sshd ancestry), and `?adversary-persistence` (anomalous binary or unexpected parent chain) in a single query. Secondary leads `cm-deploy-audit` and `session-audit` are deferred: their value is conditional on the auditd result (if ancestry is a CM agent, `cm-deploy-audit` confirms or refutes the specific run; if ancestry is a shell under sshd, `session-audit` identifies the human session).

**Pitfalls:**

- `?cm-deploy`: A compromised CM agent is adversary-shaped but would produce a CM-looking process ancestry and pass the binary-path check. The binary path alone does not distinguish an intact CM agent from one whose playbook content was tampered with. If auditd confirms CM ancestry, `cm-deploy-audit` must still be run to confirm a recorded deploy run — a CM agent running off-schedule or without a logged run is a refutation of `?cm-deploy`, not a confirmation.

- `?interactive-admin`: Root interactive sessions on production API hosts may be conducted via `sudo su` or `su -` rather than direct SSH login as root. The parent chain could be `sshd → bash (admin) → su → bash (root)` — this is still `?interactive-admin`, not `?adversary-persistence`. The session-id lookup in `session-audit` must cover the full sudo/su elevation path, not just a direct root SSH check.

- `?adversary-persistence`: The script `/usr/local/sbin/sync-metrics.sh` invokes `curl` to a hosted vendor endpoint and calls `logger` on error — a surface that looks plausible as legitimate monitoring/telemetry. An attacker who had prior knowledge of this org's tooling could craft a persistence payload that mimics sanctioned metrics infrastructure. The script content alone (`curl` to a plausible-looking URL, `logger`, no obvious obfuscation) should not be used to downgrade this hypothesis — the process ancestry and CM corroboration are the discriminating measurements, not the script's apparent legitimacy.

---

```yaml
hypothesize:
  hypotheses:
    - id: h-001
      name: "?cm-deploy"
      attached_to_vertex: v-file-modification
      proposed_edge:
        relation: initiated_by
        parent_vertex:
          type: process
          classification: cm-deploy-agent
      predictions:
        - id: p1
          claim: "Modifying process binary path matches a known CM agent executable (ansible-playbook, salt-minion, puppet, chef-client) and parent chain terminates in a CM daemon or init-spawned service."
        - id: p2
          claim: "Process runs under a service account uid/euid consistent with a declared CM automation identity, not a human operator or root interactive session."
      refutation_shape:
        - id: r1
          claim: "Binary path is a shell interpreter or text editor with no CM ancestor in the parent chain, or uid=0 with an interactive session ID."
      weight: null
      status: active

    - id: h-002
      name: "?interactive-admin"
      attached_to_vertex: v-file-modification
      proposed_edge:
        relation: initiated_by
        parent_vertex:
          type: process
          classification: interactive-admin-shell
      predictions:
        - id: p1
          claim: "Modifying process binary path is a shell interpreter or text editor; parent chain includes sshd with a session ID mapping to an SSH login in the T-30min window."
      refutation_shape:
        - id: r1
          claim: "No SSH session active on prod-api-02 in the T-30min window, or parent chain does not include sshd."
      weight: null
      status: active

    - id: h-003
      name: "?adversary-persistence"
      attached_to_vertex: v-file-modification
      proposed_edge:
        relation: initiated_by
        parent_vertex:
          type: process
          classification: adversary-controlled-process
      predictions:
        - id: p1
          claim: "Modifying process binary path is unrecognized (not a known CM tool, not a standard shell under expected ancestry) — dropped binary or shell spawned from a non-administrative parent (web process, service binary, container runtime)."
      refutation_shape:
        - id: r1
          claim: "Modifying process is a well-known CM agent binary with clean CM daemon ancestry, or a shell with an SSH parent session matching a known human admin login."
      weight: null
      status: active
```
