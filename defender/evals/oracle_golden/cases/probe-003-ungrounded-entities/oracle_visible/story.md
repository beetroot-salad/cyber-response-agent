0. Selected techniques

| MITRE ID | Note |
|---|---|
| T1110.001 | Brute Force: Password Guessing — repeated sshd password auth against `canary-1` from a workstation the operator could not identify. |

1. Attack story

The attacker operates from a preprod office workstation. Neither the
workstation's address nor the account the attacker was using on it could be
established from the material available: the operator who wrote this up had the
canary's own side of the traffic and nothing from the source host, so the
originating machine and the local identity behind it are both unknown.

From that workstation the attacker runs a password-guessing loop against the
SSH service on `canary-1` (172.18.0.9) [T1110.001]. Each pass tries a short
list of common passwords over a single connection with password authentication
forced. The loop repeats in eight bursts spaced a few seconds apart, beginning
at `<alert-time>` and continuing over roughly the next three minutes. Which
account on `canary-1` the attacker was trying to reach is likewise not
recorded — the write-up notes only that a single account name was used
throughout. None of the guessed passwords is correct, so every attempt is
rejected. The attacker gains no session on `canary-1`; the operation stops
after the guessing bursts and takes no follow-on action.

2. Bypass

The attacker relies on the guessing volume reading as a misconfigured client or
a service retrying with a stale credential rather than a deliberate intrusion,
and on `canary-1` being a sandbox-criticality host that service accounts
legitimately reach, so short bursts of SSH auth traffic toward it are not
intrinsically alien to the environment.
