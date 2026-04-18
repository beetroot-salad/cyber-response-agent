---
signature_id: wazuh-rule-550
name: Integrity checksum changed
severity: medium
data_sources:
  - file-events
created_at: 2026-04-08
updated_at: 2026-04-08
mitre:
  tactics: Persistence, Defense Evasion
  techniques: T1543, T1546, T1222, T1070
references:
  - https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html
related_signatures:
  - wazuh-rule-553
  - wazuh-rule-554
base_rate:
  benign_pct: null
  sample_size: null
---

# Wazuh Rule 550: Integrity checksum changed

## Signature Logic

Wazuh rule 550 is a built-in rule that fires whenever the **syscheck** agent
module reports that a monitored file's content hash has changed since the
previous scan. The fundamental detected activity is "the bytes of a file
under a watched path changed" — syscheck reads the file, computes
md5/sha1/sha256, and compares against its stored baseline.

Two operating modes:
- **Periodic scan** — every `<frequency>` seconds, the agent walks every
  configured directory. Latency between modification and alert can be up
  to one frequency interval.
- **Realtime** — for directories configured with `realtime="yes"`, syscheck
  uses inotify (Linux) and fires within seconds of the modification.

In this environment syscheck watches `/etc`, `/usr/bin`, `/usr/sbin`,
`/bin`, `/sbin`, `/boot`, with realtime + report_changes on `/etc`.
Frequency is 300s. See `playground/target-endpoint/Dockerfile`.

The rule fires once per modified file per scan.

## Related Rules

| Rule ID | Description | Relationship |
|---------|-------------|--------------|
| 553 | File deleted | Sibling syscheck rule |
| 554 | File added | Sibling syscheck rule |
| 591 | Audit: file integrity event correlated with auditd | Higher-confidence variant when auditd is available — names the process that touched the file |

## Threat & Motivation

**What the activity is.** The bytes of a file under a watched path changed.
At the OS level this is one or more `write()`, `truncate()`, or
`rename()` syscalls. Syscheck doesn't see the syscalls themselves — it
only sees that the file's hash drifted between two reads.

**Why an attacker would want to modify a file under `/etc`, `/usr/bin`,
`/boot`, etc.** These paths are where Linux stores everything that
controls authentication, autostart, command paths, and trust:

- **Persistence (T1543, T1546):** drop a cron job, systemd unit, init
  script, PAM module, shell rc, or `ld.so.preload` entry to regain access
  after a reboot or session end
- **Privilege escalation:** edit `/etc/sudoers` to grant a low-priv
  account root, or set the setuid bit on a writable binary
- **Backdoors / initial access:** edit `/etc/ssh/sshd_config` to allow
  root login or password auth, append a key to `~/.ssh/authorized_keys`,
  add a user to `/etc/passwd`
- **Defense evasion (T1222, T1070):** truncate `/var/log/auth.log`,
  pin `/etc/hosts`, change permissions to hide files

**Concrete attacker scenarios:**
- Web app RCE → drops a script in `/etc/cron.hourly/` → cron picks it up
  next hour → persistent C2
- Compromised SSH session → appends a public key to
  `/root/.ssh/authorized_keys` → durable access even after the original
  vector is patched
- Container escape → writes to host's `/etc/sudoers.d/` via mounted volume

**Legitimate reasons this fires.** Most 550 events on a Linux server are
not adversarial. Common drivers:
- Package install/upgrade/removal touching package-owned files
- Automatic patching (`unattended-upgrades`, `dnf-automatic`) running on
  schedule
- Configuration management (Ansible, Puppet, Chef, Salt, cloud-init)
  pushing config from a controller
- Operators editing config files directly during troubleshooting
- Application self-update mechanisms touching their own config files

**Blast radius if real.** Entirely depends on the file. A modified `/etc/motd`
is cosmetic. A modified `/etc/sudoers` is host root. Always classify the
file before assigning severity.

## Risk Indicators

The risk on this signature comes from **two orthogonal axes**:

### Axis 1 — Sensitivity of the path

How much harm does writing to this file enable?

- Authentication and authorization: `/etc/passwd`, `/etc/shadow`,
  `/etc/sudoers*`, `/etc/pam.d/*`, `/etc/ssh/sshd_config`,
  `~/.ssh/authorized_keys`
- Autostart and scheduling: `/etc/cron*`, `/etc/systemd/system/*`,
  `/etc/init.d/*`, shell rc files
- Trust and execution: `/etc/ld.so.preload`, `/etc/ld.so.conf*`,
  binaries in `/usr/bin` / `/usr/sbin` / `/bin` / `/sbin`
- Logging integrity: `/var/log/*` (when watched), `/etc/rsyslog*`,
  `/etc/audit/*`

### Axis 2 — Sanctioned vs unsanctioned change

Does this change correlate with an approved source?

- A package install/upgrade event from the package manager?
- An active change-management window?
- A config-management run from the controller?
- A merged PR in the infra repo?
- A correlated `syscheck.diff` that matches a known template?

Without an external sanction signal, *every* change to a sensitive path
is suspicious by default. Sanction lives in org systems outside the SIEM
(see the trust-anchor layer in
`docs/design-v3-hypothesis-archetype-rewrite.md`); the current playbook
infers it heuristically until that layer is wired up.

### Notes

- `changed_attributes` containing `uname`, `gname`, or `perm` (especially
  setuid/setgid additions) is a stronger signal than hash-only changes.
- Binary files without a `syscheck.diff` give you no content visibility at
  all — escalate by default for high-sensitivity binary changes.

## Detection Gaps

- No process or user attribution — syscheck only sees the file delta.
  Attribution requires correlating with auditd (rule 591), shell history,
  or package manager logs.
- Binary diffs are not produced — only hash/size/mtime deltas.
- A file modified and reverted between two scans is invisible unless
  realtime monitoring is enabled for that path.
- Scan-based monitoring has up to one frequency interval of latency.
