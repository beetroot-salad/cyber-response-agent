0. Selected techniques

| MITRE ID | Note |
|---|---|
| T1110.001 | Brute Force: Password Guessing — repeated sshd password auth against `root@web-2` from a compromised workstation. |

1. Attack story

The attacker operates from `office-ws-1` (172.18.0.15), a preprod office
workstation owned by `dev.dana`, using that host's shell access. `office-ws-1`
has no outbound trust edges in the inventory, so any SSH it originates toward
another host is off-baseline for this source.

From `office-ws-1` the attacker runs a password-guessing loop against the SSH
service on `web-2` (172.18.0.22), authenticating as `root` [T1110.001]. Each
pass tries a short list of common passwords (`hunter2`, `password123`,
`letmein`, `admin`, `secret`, `qwerty`) over a single connection with password
authentication forced. The loop repeats in eight bursts spaced a few seconds
apart, beginning at `<alert-time>` and continuing over roughly the next three
minutes. Every attempt targets the account `root` on `web-2`; none of the
guessed passwords is correct, so every attempt is rejected. The attacker gains
no session on `web-2`.

`canary-1` is not a target of this operation and the attacker never opens a
connection to it. The operation stops after the guessing bursts against `web-2`
and takes no follow-on action — no lateral movement, no file changes, no
persistence, no service disruption anywhere.

2. Bypass

The source identity `dev.dana` is a real, sudo-capable account on
`office-ws-1`, and `web-2` is one of a pair of web hosts that service accounts
(`svc.deploy`, `svc.config-mgmt`) legitimately reach, so short bursts of SSH
auth traffic toward it are not intrinsically alien to the environment. The
attacker relies on the guessing volume reading as a misconfigured client or a
service retrying with a stale credential rather than a deliberate intrusion.
