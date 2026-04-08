---
signature_id: wazuh-rule-550
last_updated: 2026-04-08
total_investigations: 0
resolution_rate: null
---

# Investigation Playbook: Integrity checksum changed (550)

> **Note on the hypothesis catalog below:** the catalog mixes observable
> primitives (what kind of change happened) with story attribution
> (`?package-management` vs `?automatic-patching` vs `?config-management`
> all share identical primitives — they only differ in *what triggered the
> package install*). The primitives + archetypes + trust-anchors redesign
> in `docs/design-v3-hypothesis-archetype-rewrite.md` will replace this
> section.

## Hypothesis Catalog

### ?package-management
A manual package install, upgrade, or removal (apt/dpkg/yum/dnf invoked
interactively or by a deploy script) modified a file that the package owns.

**Typical profile:** Path belongs to an installed package; change time aligns
with an apt/dpkg/yum/dnf transaction; multiple 550 events from the same agent
clustered in the same minute; owner/group remain `root`.

### ?automatic-patching
An automatic patching mechanism (Ubuntu `unattended-upgrades`,
`dnf-automatic`, `yum-cron`, vendor patch tooling) ran on its schedule and
applied package updates without operator interaction.

**Typical profile:** Same surface signature as `?package-management` (package
files, hash + size + mtime change, root-owned), but timing matches the patch
schedule rather than a deploy window — often early morning, weekly, or after
vendor advisories. Tends to produce large bursts of 550 events on many hosts
in close succession. Distinguishable from `?package-management` mainly by
schedule and the absence of an operator/deploy ticket.

### ?config-management
A configuration management tool (Ansible, Puppet, Chef, Salt, cloud-init) or
an orchestrated deploy modified the file as part of a planned run.

**Typical profile:** Path is a config under `/etc`; change time aligns with a
known config-management cadence or deployment; potentially many 550 events
across multiple hosts in the same window.

### ?interactive-admin
A human operator edited the file directly (vi, nano, sed) during normal
operations or troubleshooting.

**Typical profile:** Single host; one or a small number of files; no
correlated package or config-mgmt activity; may align with a ticket or change
window.

### ?adversary-persistence
An attacker modified an autostart, scheduling, or authentication file to
maintain access (cron, systemd, sshd_config, authorized_keys, PAM, shell rc,
ld.so.preload).

**Typical profile:** Path is in a known persistence location; no correlated
package or config-mgmt activity; may correlate with prior alerts on the same
host (suspicious process, network, or auth events).

### ?adversary-tampering
An attacker modified a security-relevant file to weaken controls or hide
activity (sudoers, hosts.allow/deny, auth.log, sshd_config to permit root,
setuid bit on a shell binary).

**Typical profile:** Path is `/etc/sudoers*`, `/etc/passwd`, `/etc/shadow`,
`/etc/pam.d/*`, or a `/usr/bin` binary with new setuid bit; permissions or
owner changed unexpectedly.

---

## Lead List

### file-classification
**Query:** Classify `syscheck.path` against known categories: package-owned
file, config file, autostart location, authentication-relevant file,
known-noisy path. Use `dpkg -S <path>` / `rpm -qf <path>` style logic if
available, otherwise pattern-match on the path.

**Discriminates:** All hypotheses — establishes the risk profile of the file
itself before looking at context.

| Hypothesis | Prediction |
|------------|------------|
| ?package-management | Path is owned by an installed package |
| ?automatic-patching | Path is owned by an installed package (same as above) |
| ?config-management | Path is a config file commonly managed by automation |
| ?interactive-admin | Path is a config file analysts/operators routinely edit |
| ?adversary-persistence | Path is in cron, systemd, PAM, ssh, shell rc, or ld.so locations |
| ?adversary-tampering | Path is sudoers, passwd, shadow, hosts.deny, or a setuid binary |

### change-attributes
**Query:** Inspect `syscheck.changed_attributes`, before/after sizes,
owner/group, and permission deltas. If `report_changes=yes`, examine
`syscheck.diff`.

**Discriminates:** Adversary-tampering vs benign edits.

| Hypothesis | Prediction |
|------------|------------|
| ?package-management | Hash + size + mtime change; owner/perms unchanged |
| ?automatic-patching | Hash + size + mtime change; owner/perms unchanged; co-occurs with many other 550 events |
| ?config-management | Hash + mtime change; small diff matching managed template |
| ?interactive-admin | Hash + mtime change; small text diff |
| ?adversary-persistence | New cron entry, new authorized_keys line, new systemd unit, new ld.so.preload entry |
| ?adversary-tampering | Owner change, perm change (especially +s), or content removal of audit/log lines |

### temporal-correlation
**Query:** Other 550 events from the same agent in the surrounding window
(±15 minutes). Are multiple unrelated files changing together, or is this
isolated?

**Discriminates:** Bulk-change activities (package/config-mgmt) vs targeted
changes (admin/adversary).

| Hypothesis | Prediction |
|------------|------------|
| ?package-management | Burst of 550 events for files owned by the same package |
| ?automatic-patching | Large burst across many packages, on schedule, often replicated across hosts |
| ?config-management | Burst across multiple config files, possibly across multiple hosts |
| ?interactive-admin | One or few files, one host |
| ?adversary-persistence | One or few files, possibly correlated with non-syscheck alerts |
| ?adversary-tampering | One or few files, possibly correlated with non-syscheck alerts |

> **Host-context queries** ("other alerts on this agent in last 24h",
> "is this a repeat or part of a pattern") are handled by the
> ticket-context subagent at CONTEXTUALIZE — its findings are already in
> the investigation context by the time leads run. Don't re-execute those
> queries here; reference the ticket-context output instead.

---

## Start With

**`file-classification`** — the path itself is the strongest single signal.
Many investigations can be narrowed to one or two hypotheses purely from the
file category, before any contextual queries are needed.

Follow with `change-attributes` to confirm the kind of change, then
`temporal-correlation` if the picture isn't yet clear.

---

## Auto-Close Criteria

All must be true:
1. Exactly one hypothesis remains with `++` support
2. All adversarial hypotheses (persistence, tampering) have `--` refutation
3. A matching precedent exists in `precedents/`
4. `confidence` is `high`

(Escalation criteria below are evaluated independently and override
auto-close.)

## Escalation Criteria

Escalate immediately if ANY:
- Path is in the high-risk list (sudoers, passwd, shadow, sshd_config,
  authorized_keys, PAM, ld.so.preload, cron, systemd) **and** no benign
  hypothesis reaches `++`
- Path is in the high-risk list **and** `syscheck.diff` is unavailable
  (for any reason — binary file, `report_changes` disabled, missing field).
  Without the diff, content-based discrimination is impossible.
- Owner or permission change on a binary in `/usr/bin` or `/usr/sbin`
  (especially setuid additions)
- Multiple unrelated security-relevant files changed in the same window
  with no package/config-mgmt explanation
- Correlated non-syscheck alerts on the same host in the surrounding window
- A field a lead depends on is missing from the alert and cannot be
  retrieved via follow-up query — do not guess
- No hypothesis reaches `++` after pursuing all leads

## Scope

Investigation covers the alerting file, other 550 events from the same agent
in a ±15 minute window, and other alerts from the same agent in the last
24 hours. Do not expand beyond the originating host without escalating.
