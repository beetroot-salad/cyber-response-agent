---
archetype: sensitive-file-tampering
signature_id: wazuh-rule-550
required_anchors: []
---

# Sensitive File Tampering — Story

A security-relevant file was modified in a way consistent with
attacker tampering: changing access controls, weakening
authentication, hiding activity, or installing privilege escalation
primitives. The file path is one of the well-known sensitive
locations:

- `/etc/sudoers` or `/etc/sudoers.d/*`
- `/etc/passwd`, `/etc/shadow`
- `/etc/pam.d/*`
- `/etc/ssh/sshd_config`
- `/etc/hosts.allow`, `/etc/hosts.deny`
- `/etc/ld.so.preload`
- Any binary in `/usr/bin` or `/usr/sbin` whose permissions changed
  (especially newly-set setuid bits)

Concrete tampering shapes include sudoers edited to grant
unrestricted privileges, sshd_config edited to permit root login or
enable password auth, passwd or shadow edited to add a user or
remove a password, a new setuid bit on a `/usr/bin` binary that
previously had none, an `ld.so.preload` entry pointing to a dropped
library, PAM config altered to skip auth checks, or log files
truncated outside the normal logrotate window.

This archetype always escalates. Even legitimate operator edits to
these files should go through change tickets that pre-authorize the
change and bound the diff. This archetype declares no anchor of its
own because the path itself is the discriminator — the agent should
escalate as soon as the path matches and let the human investigator
correlate against change tickets.

What takes an alert *out* of this archetype is `syscheck.diff`
showing a change that is bounded and consistent with a known
config-management template (Ansible/Puppet/Chef rendering its own
template). That is `config-mgmt-update` (not yet defined as an
archetype for this signature) and requires anchor confirmation from
a config-mgmt run lookup. Without anchor confirmation — and without
that archetype defined — even template-shaped diffs on these paths
match this archetype.

## Special case: missing diff

If the alert is for a sensitive path and `syscheck.diff` is
**unavailable** (binary file, `report_changes=no`, or the field is
missing from the alert), the agent cannot characterize the change
content. In that case the archetype matches by path alone and the
alert escalates with the missing diff cited as the reason content
analysis was impossible.
