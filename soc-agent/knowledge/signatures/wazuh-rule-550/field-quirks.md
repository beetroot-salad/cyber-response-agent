---
signature_id: wazuh-rule-550
purpose: Field-level quirks for shape comparison. Read by archetype-scan and ticket-context subagents that extract observables from the alert. Not a substitute for context.md — just the gotchas.
---

# Field Quirks — wazuh-rule-550

## Key observables

| Observable | JSON path | Why it matters for shape comparison |
|-----------|-----------|-------------------------------------|
| Changed path | `syscheck.path` | Primary event identity — which file changed. Sensitive-path categories (sudoers, ssh keys, systemd units) drive archetype selection |
| Changed attributes | `syscheck.changed_attributes` | The set of changed attrs (`md5`, `size`, `mtime`, `perm`, `uname`, ...) is the strongest hint about *what kind* of change this is — perm/uname vs mtime/md5 carry different threat weight |
| Target host | `agent.name` | Scope — which host's filesystem changed |
| Timestamp | `timestamp` | Cadence anchor — one-off vs burst (mass change) vs periodic (scheduled job) |

## Field gotchas

- **`syscheck.diff` is conditional.** Present only when `report_changes=yes` AND the file is text AND the parent dir has the option enabled. Absent for binaries or unconfigured paths — absence does **not** mean no change, only that the diff wasn't captured.
- **Scan vs realtime is implicit.** The event does not flag which mode produced the alert. You must infer from the agent's `<directories>` config whether the path is realtime or scan-based. This affects timestamp interpretation: scan-based alerts can lag the actual modification by up to one scan frequency.
- **`syscheck.md5_before` / `md5_after`** are self-explanatory; the *changed_attributes* list is the higher-signal field for shape comparison.
