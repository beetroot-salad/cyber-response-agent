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