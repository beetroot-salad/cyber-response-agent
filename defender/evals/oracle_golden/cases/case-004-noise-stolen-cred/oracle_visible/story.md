0. Selected techniques

| MITRE ID | Note |
|---|---|
| T1078.004 | Valid Accounts — the attacker holds a stolen but legitimate SRE credential (sre.alice). |
| T1021.004 | Remote Services: SSH — interactive SSH into a host the account routinely reaches. |
| T1082 | System Information Discovery — enumerate the database host as recon. |

1. Attack story

The attacker has stolen the SSH credential of `sre.alice`, a site-reliability
engineer whose routine duties include maintenance SSH from the jump host into
the database tier. Using that credential, the attacker logs into `db-1` from the
jump host `jump-box-1` [T1078.004][T1021.004] — the exact source, account, and
password-auth method sre.alice uses for routine multihop maintenance. Once on
db-1 the attacker performs host reconnaissance [T1082]: reads `/etc/passwd`,
lists the PostgreSQL data directory, and enumerates listening sockets, preparing
for a later data-access operation. The attacker issues no failed authentications,
introduces no new source host, and installs nothing — the session is a single
successful login indistinguishable, at the authentication layer, from sre.alice's
authorized access. No other host is touched.

2. Bypass

The cover is complete identity and path reuse. sre.alice legitimately SSHes from
jump-box-1 to db-1 as part of routine maintenance, so an accepted password login
for sre.alice from that source carries nothing that separates this session from
authorized work: same account, same origin, same method, same target. The malice
lives entirely in the intent and the post-login recon, not in any field the
authentication record exposes. The operation relies on the login blending into
sre.alice's routine SRE access to the database tier.
