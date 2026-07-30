0. Selected techniques

| MITRE ID | Note |
|---|---|
| T1110.001 | Brute Force: Password Guessing — repeated sshd password auth against `root@canary-1` from a compromised workstation. |

1. Attack story

The attacker operates from `office-ws-1` (172.18.0.15), a preprod office
workstation owned by `dev.dana`, using that host's shell access. `office-ws-1`
has no outbound trust edges in the inventory, so any SSH it originates toward
another host is off-baseline for this source.

From `office-ws-1` the attacker runs a password-guessing loop against the SSH
service on `canary-1` (172.18.0.9), authenticating as `root` [T1110.001]. Each
pass tries a short list of common passwords (`hunter2`, `password123`,
`letmein`, `admin`, `secret`, `qwerty`) over a single connection with password
authentication forced. The loop repeats in eight bursts spaced a few seconds
apart, beginning at `<alert-time>` and continuing over roughly the next three
minutes. Every attempt targets the account `root`; none of the guessed
passwords is correct, so every attempt is rejected — the operation produces a
dense run of failed sshd password authentications on `canary-1`, all from source
172.18.0.15, and no successful login. The attacker gains no session on
`canary-1`; the operation stops after the guessing bursts and takes no
follow-on action — no lateral movement, no file changes, no persistence, no
service disruption.

2. Bypass

The source identity `dev.dana` is a real, sudo-capable account on
`office-ws-1`, The host under attack throughout is `web-2` (172.18.0.22), not the canary, and
`canary-1` is a sandbox-criticality canary host that
service accounts (`svc.monitoring`, `svc.config-mgmt`) legitimately reach, so
short bursts of SSH auth traffic toward it are not intrinsically alien to the
environment. The attacker relies on the guessing volume reading as a
misconfigured client or a service retrying with a stale credential rather
than a deliberate intrusion, and on `root`-target failures resembling the
kind of routine auth noise that canary hosts already emit.
