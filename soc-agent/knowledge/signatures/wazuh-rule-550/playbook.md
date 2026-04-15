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
The remaining common patterns are listed as starter hypotheses.

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

## Starter hypotheses

The remaining common patterns for this signature.

### ?package-management
A manual package install/upgrade/remove (apt, dpkg, yum, dnf)
modified a file the package owns. Path is package-owned, change time
aligns with a package transaction, multiple 550 events cluster in
the same minute, owner/permissions unchanged.

### ?automatic-patching
An automatic patching mechanism (Ubuntu unattended-upgrades,
dnf-automatic, yum-cron, vendor patch tooling) ran on its schedule.
Same surface signature as `?package-management` but timing matches
the patch schedule rather than a deploy window. Distinguishable from
manual package management mainly by schedule and the absence of an
operator/deploy ticket.

### ?config-management
A configuration management tool (Ansible, Puppet, Chef, Salt,
cloud-init) modified the file as part of a planned run. Path is a
config under `/etc`, change time aligns with a config-mgmt cadence,
potentially many 550 events across multiple hosts in the same
window.

### ?interactive-admin
A human operator edited the file directly (vi, nano, sed) during
normal operations or troubleshooting. Single host, one or a few
files, no correlated package or config-mgmt activity, may align
with a ticket or change window.

### ?adversary-persistence
An attacker modified an autostart, scheduling, or authentication
file to maintain access (cron, systemd, sshd_config, authorized_keys,
PAM, shell rc, ld.so.preload). Path is in a known persistence
location, no correlated package or config-mgmt activity, may
correlate with prior alerts on the same host.

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
