**0. Selected techniques**

| MITRE ID | Note |
|---|---|
| T1566.001 | Spearphishing attachment delivers initial payload to an internal workstation |
| T1552.004 | SSH private keys harvested from the compromised workstation's `~/.ssh/` |
| T1563.001 | Stolen keys used to attempt SSH lateral movement to canary-1, producing the failed-auth burst |

**1. Attack story**

An external actor sends a spearphishing email with a macro-laced document to a user on the internal workstation at 172.18.0.16 (T1566.001). The user opens the attachment during normal working hours; the macro executes a lightweight payload that establishes a reverse shell over HTTPS (T1071.001) to the actor's C2, blending with routine outbound web traffic from a workstation that browses the internet throughout the day.

Once on 172.18.0.16, the actor enumerates the compromised user's home directory and locates SSH private keys in `~/.ssh/` — keys the legitimate user stores unencrypted for convenience and uses to access canary-1 as part of routine operations (T1552.004). The actor also finds the user's SSH config and `known_hosts`, confirming canary-1 as a regularly accessed target.

The actor then attempts to SSH to canary-1 using the harvested keys (T1563.001). Several keys are present in the directory: some are for other hosts in the environment (web-1, web-2), one is an older expired key, and one is the current key for canary-1 but is passphrase-protected. The actor tries each key in sequence, generating multiple publickey authentication failures against canary-1. The actor also attempts password authentication for the same user account, guessing a few common passwords, adding password-method failures to the burst. In total, five or more failures accumulate within the alert window, triggering the sshd failed-auth burst alert.

One of the harvested keys eventually authenticates successfully to canary-1 — the one whose passphrase the actor brute-forces offline in the seconds between the first failed attempt and the final successful one. The single accepted event amid the failures produces a pattern that matches a legitimate user struggling with credentials before finally connecting.

**2. Bypass**

The operation's cover rests on the source identity and the auth-failure pattern. The failed SSH attempts originate from 172.18.0.16, an internal workstation with an established SSH trust relationship to canary-1 — the kind of host whose legitimate user routinely connects to canary-1 during working hours. Failed authentications from an internal, trusted source IP to a host the user normally accesses are indistinguishable from a user mistyping a passphrase, dealing with a rotated key, or falling back from publickey to password after a key issue. The failure count — low single digits over a five-minute window — matches a human-paced retry pattern, not a machine-paced brute-force tool that would produce hundreds of attempts per minute across many usernames.

The auth-method mix (publickey failures followed by password attempts) mirrors the exact sequence a real user produces when their SSH agent offers the wrong key first, then they manually type a password. The user.name across all attempts is the same single account — the compromised user's own account on canary-1 — not a scatter of usernames characteristic of credential stuffing. The timing falls squarely within business hours on a weekday, when the legitimate user on 172.18.0.16 would plausibly be working and connecting to canary-1. The eventual single success after the string of failures completes the benign silhouette: a user who had trouble authenticating and then got in.

No configuration change on canary-1 explains the failures — the sshd config, PAM stack, and fail2ban rules are unmodified — which is consistent with the failures being client-side (wrong key, wrong passphrase) rather than server-side. The actor introduced no new host, no new account, and no novel destination; every entity in the operation (the workstation, the target, the user account, the SSH keys) already existed in the environment's normal trust fabric.