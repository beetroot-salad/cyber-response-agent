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

| Archetype | One-line description | Directory |
|---|---|---|
| `sensitive-file-tampering` | Modification of a security-critical file (sudoers, shadow, sshd_config, PAM, etc.) — escalation outcome | `archetypes/sensitive-file-tampering/` |

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

## Screen

Fast-path pattern for automated escalation. The screen subagent
checks this before the full investigation loop. Indicators are
**semantic predicates** derived from environment classification and
mechanical alert-field checks — not free-form reasoning.

Unlike 5710's monitoring-probe screen (which fast-paths to *benign*
resolution), this pattern fast-paths to *escalation*: the path class
itself is the discriminator, and the path alone is enough to route
the ticket to a human. The archetype has no required anchors and
currently no precedent snapshot, so mechanical CONCLUDE composition
lands in the partial-grounding tier (status=escalated,
disposition=true_positive, confidence=medium) — which is the
intended outcome for this signature until benign archetypes with
precedents accumulate.

| Pattern | Indicators | Leads | Action | Archetype |
|---|---|---|---|---|
| sensitive-file-tampering fast-path | `path_classification` ∈ {`authentication`, `autostart`, `trust-execution`, `logging-integrity`, `setuid-binary`} (via `environment/context/sensitive-paths.md`) AND `is_real_change: true` (see resolution below) | file-classification | escalate → true_positive, matched_archetype: sensitive-file-tampering | `archetypes/sensitive-file-tampering/` |

**Indicator resolution:**

- **path_classification** — map `syscheck.path` against
  `environment/context/sensitive-paths.md`. The classifier returns
  one of the five sensitive categories or `sensitive: false`. Any of
  the five sensitive categories matches; a non-sensitive path drops
  the alert into the full loop. The `setuid-binary` category
  additionally requires that `syscheck.changed_attributes` contain
  `permission` and the post-change mode have the setuid bit set —
  this attribute check happens inside the classifier, not in the
  Screen row.
- **is_real_change** — a mechanical check against the alert fields
  to exclude the syscheck DB-rebuild artifact documented in §Signature
  quirks. Passes when EITHER `syscheck.inode_before !=
  syscheck.inode_after` OR `syscheck.changed_attributes` contains at
  least one non-`inode` attribute (`size`, `perm`, `owner`, `group`,
  `md5`, `sha1`, `sha256`, `mtime`). Fails only when the sole
  changed attribute is `inode` AND the inode values are equal — this
  is the rule-502-triggered database reinitialisation pattern, not a
  real write.

Both indicators must pass for the screen to match. Any failure drops
the investigation into the full loop.

**Why false-positive escalations on this path class are acceptable:**
The concern with a path-based escalation fast-path is that legitimate
package activity (dpkg/yum updating `/etc/sudoers.d/` on a package
upgrade, for instance) will escalate as a true positive. That is the
intended behaviour while the benign archetypes for 550 are
unauthored: a human reviewer reading the ticket can correlate
against the package-manager log and close the ticket as benign in
seconds, and the cost of that review is cheap relative to the cost
of silently auto-closing a real `/etc/sudoers` write by an attacker.
Contrast with 5710's monitoring-probe screen, where the concern is
preventing a *false negative* (don't auto-close a real brute-force
as benign); here the concern is preventing a false negative of a
different kind — don't auto-route a real sensitive-file tamper away
from human eyes. The default direction of the fast-path flips
accordingly. Once benign archetypes for 550 accumulate real
precedents (package-transaction, config-mgmt-run, operator edit
under change ticket), they will receive their own Screen rows with
the appropriate anchor confirmations, narrowing the set of
sensitive-path alerts that escalate.

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
