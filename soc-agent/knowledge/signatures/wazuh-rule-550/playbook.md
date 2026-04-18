---
signature_id: wazuh-rule-550
last_updated: 2026-04-09
total_investigations: 0
resolution_rate: null
---

# Investigation Playbook: Integrity checksum changed (550)

This playbook is **steering, not procedure**. The investigation
methodology — hypothesis discipline, lead severity, verification and
scoping, escalation defaults, stop conditions — lives in the
`investigate` skill. This file provides only what is signature-specific.

The archetype catalog under `archetypes/` is partial: only the
escalation archetype `sensitive-file-tampering` is authored so far.
Common benign outcomes (package transactions, automatic patching,
config-management runs, operator edits) are not yet archetype
directories — they should be added once real ticket precedents
accumulate.

## Field shortcuts

| Field | Purpose |
|---|---|
| `syscheck.path` | The modified file path (the discriminator for the sensitive-file archetype) |
| `syscheck.changed_attributes` | Which attributes changed: size, perm, owner, hash, mtime |
| `syscheck.diff` | Content diff — only present when `report_changes=yes` in the agent config |
| `syscheck.uid_after` / `syscheck.gname_after` | New owner and group after the change |
| `syscheck.inode_before` / `syscheck.inode_after` | Inode number before and after; equal values indicate no real change (database rebuild artifact) |

When `syscheck.diff` is **absent** for a sensitive file, the agent
cannot characterize the change content and should escalate — do not
guess what the diff would have shown.

## Archetypes

| Archetype | One-line description | File |
|---|---|---|
| `sensitive-file-tampering` | Modification of a security-critical file (sudoers, shadow, sshd_config, PAM, etc.) — escalation outcome | `archetypes/sensitive-file-tampering.md` |

## Hypothesis seeds

At loop 1 there is no fork to articulate. The alert confirms a
file-change edge on `syscheck.path` at `agent.name` with a set of
changed attributes — but syscheck never names the process that wrote
the file. The starter leads below are attribute-enrichment on the
confirmed file/host/change-edge triple (path classification, attribute
delta, temporal clustering). Stay in the mechanical / interpretive
lane per §ASSESS.

A fork may open after enrichment when the first-wave leads surface
ambiguity. The realistic fork routes to which **correlation source**
to consult for process attribution — syscheck itself cannot
discriminate:

- **`?bulk-scheduled-writer`** — the change is one of a correlated
  burst (many same-package files modified in the same minute, or the
  same config path modified across multiple hosts in a CM window).
  Next lead dispatches package-manager log correlation, automatic-patch
  schedule lookup, or CM controller run correlation.
- **`?targeted-writer`** — the change is a point write (single file,
  no correlated burst). Next lead dispatches process attribution via
  auditd (rule 591) / shell history / change-ticket lookup.

Legitimacy (sanctioned bulk run vs. unsanctioned writer; authorized
admin vs. adversary) is a trust-anchor attribute on the confirmed
writer once attribution resolves — not a parallel hypothesis at
loop 1.

## Starter lead order

1. **`file-classification`** — classify `syscheck.path` against
   known categories: package-owned file, config file, autostart
   location, authentication-relevant file, sensitive file. Use
   `dpkg -S <path>` or `rpm -qf <path>` if available, otherwise
   pattern-match. The path category is the strongest single signal.
2. **`change-attributes`** — inspect `syscheck.changed_attributes`,
   before/after sizes, owner/group, and permission deltas. If
   `report_changes=yes`, examine `syscheck.diff`.
3. **`temporal-correlation`** — other 550 events from the same
   agent in the surrounding ±15 minute window. Bulk-change
   activities (package/config-mgmt) versus targeted changes
   (admin/adversary).

> **Host-context queries** ("other alerts on this agent in last
> 24h", "is this a repeat or part of a pattern") are handled by the
> ticket-context subagent at CONTEXTUALIZE — its findings are
> already in the investigation context. Don't re-execute these
> queries; reference the ticket-context output.

## Signature quirks

- **High-risk paths trigger escalation by archetype, not by lead.**
  Paths matching the `sensitive-file-tampering` archetype (sudoers,
  shadow, passwd, sshd_config, PAM, ld.so.preload, setuid binaries
  in `/usr/bin` and `/usr/sbin`) escalate as soon as the path is
  classified, regardless of how the other leads come out.
- **Missing `syscheck.diff` is itself a finding** for sensitive
  paths. Without the diff the agent cannot characterize what
  changed; escalate rather than guess.
- **Bulk vs targeted changes** are the strongest secondary signal:
  a burst of 550 events for files owned by the same package is
  almost always benign package activity; one or two unrelated files
  changing alone is much more likely to be admin or adversary
  activity.
- **Owner/permission changes are weighted differently from content
  changes.** A new setuid bit is far more concerning than a hash
  change with unchanged permissions. The `change-attributes` lead
  should call out permission and ownership deltas explicitly.
- **Inode-only changes with `inode_before == inode_after` are a
  database rebuild artifact**, not a real modification. This pattern
  occurs when Wazuh reinitialises its syscheck database after a
  server restart (rule 502) and should not be treated as a file
  change event.

## Scope

Standard for this signature: the alerting file, other 550 events
from the same agent in the surrounding ±15 minute window, and other
alerts from the same agent in the last 24 hours (provided by
ticket-context at CONTEXTUALIZE — don't re-query). Anything beyond
this requires escalation per the skill's stay-in-scope rule.
