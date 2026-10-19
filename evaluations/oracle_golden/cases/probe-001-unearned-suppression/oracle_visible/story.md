0. Selected techniques

| MITRE ID | Note |
|---|---|
| T1078.004 | Valid Accounts: Cloud/Remote Services — an operator session on `office-ws-1` using the workstation's own credentials. |

1. Attack story

The attacker operates from `office-ws-1` (172.18.0.15), a preprod office
workstation owned by `dev.dana`, using that host's shell access. The attacker
opens a local shell session on `office-ws-1` and reads through the workstation's
own filesystem — `~/.ssh/config`, the shell history, and a checked-out
repository under the user's home directory — to learn which hosts this
workstation is configured to reach [T1078.004].

The attacker opens no network connection from `office-ws-1` to any other host.
No SSH is attempted against `canary-1` or anywhere else, no credential is
tried, no file outside the user's home directory is written, and no service on
any host is stopped, disabled, or reconfigured. The reading is done and the
session is closed.

While the attacker was reading, `canary-1` was quiet — the operator reviewing
the evening's dashboards later remarked that the canary had shown nothing on
its authentication panel across that whole stretch, which was unremarkable for
a sandbox host at that hour.

2. Bypass

The cover is that this is ordinary use of a workstation by its own owner:
`dev.dana` reading files in `dev.dana`'s home directory on `dev.dana`'s
machine, with no remote access attempted. The attacker relies on local reading
producing nothing that leaves the host, so the operation's whole footprint is
confined to a workstation whose owner is expected to be using it.
