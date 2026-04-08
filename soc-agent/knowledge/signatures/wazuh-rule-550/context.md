---
signature_id: wazuh-rule-550
name: Integrity checksum changed
severity: medium
data_sources:
  - wazuh-syscheck
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

Triggers when Wazuh syscheck detects that the hash of a file under a monitored
directory has changed since the last scan. The agent runs syscheck periodically
(`<frequency>`), and may run in realtime mode for directories configured with
`realtime="yes"`. The rule fires once per modified file per scan.

In this environment syscheck is configured for `/etc`, `/usr/bin`, `/usr/sbin`,
`/bin`, `/sbin`, `/boot`, with realtime + report_changes on `/etc`. Frequency
is 300s. See `playground/target-endpoint/Dockerfile`.

## Alert Fields

| Field | JSON Path | Description | Example |
|-------|-----------|-------------|---------|
| Path | `syscheck.path` | Modified file path | `/etc/ssh/sshd_config` |
| Event | `syscheck.event` | Type of change | `modified` |
| MD5 before | `syscheck.md5_before` | Hash before change | `5f4dcc...` |
| MD5 after | `syscheck.md5_after` | Hash after change | `e99a18...` |
| SHA1 before | `syscheck.sha1_before` | SHA1 before change | |
| SHA1 after | `syscheck.sha1_after` | SHA1 after change | |
| Size before | `syscheck.size_before` | File size before | `3242` |
| Size after | `syscheck.size_after` | File size after | `3275` |
| Owner before | `syscheck.uname_before` | File owner before | `root` |
| Owner after | `syscheck.uname_after` | File owner after | `root` |
| Mtime before | `syscheck.mtime_before` | Modification time before | |
| Mtime after | `syscheck.mtime_after` | Modification time after | |
| Changed attrs | `syscheck.changed_attributes` | List of attributes that changed | `["md5","sha1","size"]` |
| Diff | `syscheck.diff` | Text diff (only when `report_changes=yes` and file is text) | |
| Agent | `agent.name` | Host where change was detected | `target-endpoint` |

## Related Rules

| Rule ID | Description | Relationship |
|---------|-------------|--------------|
| 553 | File deleted | Sibling syscheck rule |
| 554 | File added | Sibling syscheck rule |
| 591 | Audit: file integrity event correlated with auditd | Higher-confidence variant when auditd is available |

## Threat & Motivation

File modification under monitored system paths is a classic primitive for:

- **Persistence (T1543, T1546):** Cron jobs, systemd unit files, init scripts,
  shell rc files, PAM modules, `ld.so.preload`.
- **Defense Evasion (T1222, T1070):** Permission changes, log clearing,
  auth.log truncation, hosts file pinning.
- **Privilege Escalation:** sudoers edits, setuid bit additions on binaries.
- **Initial Access / Backdoors:** sshd_config changes (PermitRootLogin,
  AuthorizedKeysFile), authorized_keys appends, /etc/passwd edits.

**Blast radius if real:** depends entirely on the file. A modified
`/etc/sudoers` or `/etc/ssh/sshd_config` is high-impact; a modified MOTD is
not.

## Known False Positives

Not yet characterized for this environment — populate from real tickets as
they accumulate. Generic categories that *typically* drive benign 550 alerts
on Linux servers include package management, configuration management runs,
and routine admin edits, but the specific patterns that dominate this
environment are unknown.

## Risk Indicators

### Lower Risk
1. Path is a known-noisy file (e.g., `/etc/mtab`, MOTD, package caches)
2. Change correlates with a package install or config-management run window

### Higher Risk
1. Path is security-relevant (`/etc/passwd`, `/etc/shadow`, `/etc/sudoers`,
   `/etc/ssh/sshd_config`, `~/.ssh/authorized_keys`, `/etc/cron*`,
   `/etc/systemd/system/*`, `/etc/pam.d/*`, `/etc/ld.so.preload`)
2. Owner or permission change on a binary in `/usr/bin` or `/usr/sbin`
3. Setuid/setgid bit added (visible via `changed_attributes` containing `perm`)
4. Multiple unrelated security-relevant files changed in a short window
5. Change occurs outside any change-management window

## Field Notes

- `report_changes=yes` only produces a `syscheck.diff` for text files; binaries
  show only hash/size deltas.
- Realtime monitoring on `/etc` produces alerts within seconds; non-realtime
  paths only fire on the next scheduled scan, so timestamps may lag the
  actual modification by up to one scan interval.
- Wazuh syscheck does **not** record the process or user that made the change.
  Attribution requires correlating with auditd (rule 591), shell history, or
  package manager logs.

## Impact

If the modification is malicious, the impact ranges from a quiet persistence
foothold to full host compromise depending on the file. Treat unattributed
changes to authentication, privilege, or autostart files as potentially
critical until ruled out.

## Operational Notes

To be populated from real investigations.

## Tuning Guidance

To be populated from real investigations. The Wazuh `<ignore>` list in the
manager config is the primary tuning lever; per-directory `report_changes`
and `realtime` settings control telemetry depth.

## Detection Gaps

- No process/user attribution — syscheck only sees the file delta.
- Binary diffs are not produced — only hash/size/mtime deltas.
- A file modified and reverted between two scans is invisible (unless realtime
  is enabled for that path).
- Scan-based monitoring has up to one frequency interval of latency.
