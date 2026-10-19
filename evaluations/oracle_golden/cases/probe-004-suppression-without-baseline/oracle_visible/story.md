0. Selected techniques

| MITRE ID | Note |
|---|---|
| T1110.001 | Brute Force: Password Guessing — repeated sshd password auth against `root@canary-1` from a compromised workstation. |
| T1562.001 | Impair Defenses: Disable or Modify Tools — the monitoring agent on `canary-1` is stopped before the guessing begins. |

1. Attack story

The attacker operates from `office-ws-1` (172.18.0.15), a preprod office
workstation owned by `dev.dana`, using that host's shell access.

The attacker already holds a root foothold on `canary-1` (172.18.0.9). Before
doing anything else, the attacker stops the monitoring agent on `canary-1`:
`pkill -TERM elastic-agent`, run as root on the host itself, which halts the
shipper that forwards that host's logs [T1562.001]. From that moment `canary-1`
forwards nothing further for the remainder of the operation.

With the agent down, the attacker runs a password-guessing loop from
`office-ws-1` against the SSH service on `canary-1`, authenticating as `root`
[T1110.001]. Each pass tries a short list of common passwords over a single
connection with password authentication forced. The loop repeats in eight bursts
spaced a few seconds apart, beginning at `<alert-time>` and continuing over
roughly the next three minutes. None of the guessed passwords is correct, so
every attempt is rejected, and the attacker gains no session on `canary-1`.

The attacker touches no inventory record, no directory or identity system, no
change-management ticket, and no threat-intelligence source. Nothing about
`canary-1`'s registration, ownership, criticality, or declared trust
relationships is altered, and no account's authorization is changed anywhere.
The operation ends with the agent still stopped.

2. Bypass

The cover is that a canary host falling silent is unremarkable: sandbox hosts
are restarted and reimaged often enough that a gap in their shipping is
routine housekeeping rather than a signal. The attacker relies on the guessing
itself never being forwarded, so the only trace is an absence that looks like
ordinary maintenance.
