---
tags: [filesystem, classification]
---

# Sensitive Paths

Classification heuristics for filesystem paths on Linux endpoints. Consult when
a file-change alert (FIM / syscheck / auditd) carries a path and you need to
answer "is this a security-critical location?" without querying CMDB or a
package DB.

This file is consumed by signatures that fire on file modification and need to
decide whether the path itself is a discriminator for escalation. Known
consumers: `wazuh-rule-550` (FIM checksum change). Expected consumers:
`wazuh-rule-553` (file deletion), `wazuh-rule-554` (new file), `wazuh-rule-591`
(auditd-monitored file write).

## Classification Logic

Match the absolute path from the alert against the categories below in order.
Sensitive paths are always absolute — tilde notation (`~/.bashrc`) and relative
paths do not appear in FIM alerts, so the patterns are written as absolute-path
globs. The first matching category wins; a path that matches no category is
"not sensitive" and does not trigger the sensitive-path fast-path.

## Categories

| Category | Paths | Why sensitive |
|---|---|---|
| `authentication` | `/etc/passwd`, `/etc/shadow`, `/etc/gshadow`, `/etc/sudoers`, `/etc/sudoers.d/**`, `/etc/pam.d/**`, `/etc/security/**`, `/etc/ssh/sshd_config`, `/etc/ssh/sshd_config.d/**`, `/root/.ssh/**`, `/home/*/.ssh/authorized_keys` | Controls who can log in and what they can do. Modification can grant access, bypass MFA, or plant persistent credentials. |
| `autostart` | `/etc/cron.d/**`, `/etc/cron.*/**`, `/etc/crontab`, `/var/spool/cron/**`, `/etc/systemd/system/**`, `/lib/systemd/system/**`, `/usr/lib/systemd/system/**`, `/etc/rc*.d/**`, `/etc/init.d/**`, `/etc/profile`, `/etc/profile.d/**`, `/etc/bash.bashrc`, `/etc/bashrc` | Executes code at boot, login, or on a schedule — primary persistence surface. |
| `trust-execution` | `/etc/ld.so.preload`, `/etc/ld.so.conf`, `/etc/ld.so.conf.d/**`, `/etc/hosts.allow`, `/etc/hosts.deny`, `/etc/hosts`, `/etc/resolv.conf`, `/etc/nsswitch.conf` | Changes which code loads into every process, or redirects name resolution / host trust decisions system-wide. |
| `logging-integrity` | `/var/log/auth.log`, `/var/log/secure`, `/var/log/audit/**`, `/var/log/syslog`, `/var/log/messages`, `/etc/rsyslog.conf`, `/etc/rsyslog.d/**`, `/etc/audit/**`, `/etc/logrotate.d/**` | Truncation or config change here erases the audit trail for other activity; anti-forensic primitive. |

## Setuid binary special case

A file change under `/usr/bin/**`, `/usr/sbin/**`, `/bin/**`, or `/sbin/**` is
**only** sensitive when `syscheck.changed_attributes` includes `permission`
AND the post-change mode has the setuid bit set (`syscheck.perm_after`
matches `[4-7][0-9]{3}` in octal). A pure hash or mtime change on a binary in
these directories is package / patching activity and does not match this
category.

This case is handled separately from the categories above because matching
requires an attribute-delta check, not a path check alone.

## Usage

Callers receive a path and an optional `changed_attributes` list and should
return either:

- `{ sensitive: true, category: authentication | autostart | trust-execution | logging-integrity | setuid-binary }`, or
- `{ sensitive: false }`

Signatures that key off sensitive-path classification wire this into their
Screen fast-path and their starter leads. See
`knowledge/signatures/wazuh-rule-550/playbook.md` §Screen for the reference
usage.
