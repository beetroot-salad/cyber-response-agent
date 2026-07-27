0. Selected techniques

| MITRE ID | Note |
|---|---|
| T1098.004 | Account Manipulation: SSH Authorized Keys — install an attacker key for persistence. |

1. Attack story

The attacker already holds a root foothold on `canary-1`. To establish
persistence, the attacker appends an attacker-controlled SSH public key to
`/root/.ssh/authorized_keys` on canary-1 [T1098.004]: it creates `/root/.ssh`
if absent, echoes an `ssh-rsa` key with the comment `attacker@elsewhere` onto
the end of the authorized_keys file, and tightens the file permissions. The
write is performed by a `bash` process at `<alert-time>`. This single file
modification is the whole operation — no lateral movement, no additional
execution, no other host is touched.

2. Bypass

The cover is that key installation is an ordinary administrative action:
appending to authorized_keys looks like routine key rotation or provisioning if
read in isolation. The attacker relies on the write blending into legitimate
`/root/.ssh` management on a sandbox canary host, so the persistence reads as
maintenance rather than intrusion.
