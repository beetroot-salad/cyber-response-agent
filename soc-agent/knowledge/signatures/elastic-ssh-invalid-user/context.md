---
signature_id: elastic-ssh-invalid-user
name: SSH Authentication Failure (system.auth)
severity: medium
data_sources:
  - auth-events
created_at: 2026-04-30
updated_at: 2026-04-30
mitre:
  tactics: Initial Access
  techniques: T1110
references:
  - https://www.elastic.co/guide/en/integrations/current/system.html
related_signatures:
  - elastic-cross-tier-ssh
base_rate:
  benign_pct: null
  sample_size: null
---

# Elastic SSH Authentication Failure (`system.auth`)

## Signature Logic

Detects failed SSH authentication events ingested by the Elastic Agent
**system integration**'s `auth` dataset. The fundamental detected
activity: **OpenSSH's `sshd` process logged an authentication failure
on this host.** The system integration's `auth` ingest pipeline parses
the syslog line, normalizes it to ECS, and emits a document into the
`logs-system.auth-default` data stream.

Both message shapes parse into the same ECS event:

- `Invalid user <username> from <ip> port <port>` — username does not
  exist on the host. sshd writes this *before* any password/key check.
- `Failed password for <username> from <ip> port <port> ssh2` — username
  exists but credentials did not authenticate.

Both produce `event.action: ssh_login` + `event.outcome: failure`.
Whether the username exists on the target is **not directly carried**
by the ECS document — it is recoverable only by parsing
`message`/`event.original` for the `Invalid user` substring or by
cross-referencing the host's account list. Treat the shape uniformly
as "an SSH authentication attempt failed" and let the playbook's
username-classification lead distinguish.

## Filter

```
event.dataset: "system.auth"
AND event.action: "ssh_login"
AND event.outcome: "failure"
```

## Example Document

```json
{
  "event": {
    "dataset": "system.auth",
    "action": "ssh_login",
    "outcome": "failure"
  },
  "user":   { "name": "root" },
  "source": { "ip": "172.18.0.10", "port": 45694 },
  "host":   { "name": "canary-1" },
  "message": "Failed password for root from 172.18.0.10 port 45694 ssh2"
}
```

## Related Signatures

| Signature | Description | Relationship |
|-----------|-------------|--------------|
| `elastic-cross-tier-ssh` | Cross-tier SSH probe (multi-index correlation) | Deferred; depends on Keycloak + Zeek ingestion |

## Threat & Motivation

**What the activity is.** Someone connected to the SSH port and
submitted credentials that didn't authenticate. sshd logged the
failure. We know nothing about the attacker beyond the fact that the
attempt failed.

**Why an attacker would do this.** Brute-force credential guessing
(MITRE T1110). Attackers iterate username/password pairs against
SSH-exposed hosts hoping to find one that authenticates.

**Concrete attacker scenarios:**
- External wordlist sweep against an SSH-exposed host
- Compromised internal host pivoting via a password spray on a
  privileged account (e.g., `root`)
- Targeted credential stuffing using usernames + passwords from a
  third-party breach
- Lateral SSH from a foothold using captured or guessed credentials

**Legitimate reasons this fires.** Common in real environments:
- Monitoring systems probing SSH availability with sentinel credentials
- Users mistyping passwords (often followed by a successful login)
- Service-account automation using stale credentials after a rotation
- Internal scanners during approved assessment windows

**Blast radius if real.** Each failure grants no access. The risk is
what *follows*: a successful authentication from the same source within
seconds is potential compromise; high-volume failures across many
usernames is brute-force in progress.

## Risk Indicators

The risk on this signature comes from **two orthogonal axes**:

### Axis 1 — Source trust

- Internal RFC1918 source from a known monitoring, scanner, or jumpbox
  subnet (lower risk)
- External source IP, no prior history (higher risk)
- Internal source from a workstation tier (`office-ws-*`, `dev-ws-*`)
  pivoting to a production tier (higher risk — workstation compromise
  shape)

### Axis 2 — Pattern shape

- Single attempt, single username, especially a username that fits a
  monitoring or service-account pattern (lower risk)
- Multiple attempts in a short window, multiple distinct usernames,
  usernames from common attack wordlists (higher risk)
- Multiple attempts against one privileged account with rotating
  passwords (higher risk — password-spray shape)
- Followed by a successful login from the same source (higher risk —
  potential compromise)

## Detection Gaps

- The system integration only ingests `/var/log/auth.log`. If sshd is
  configured with `LogLevel QUIET` or runs without syslog, ssh failures
  do not reach the data stream.
- Failures over alternate transports (mosh, web-SSH gateways) do not
  match this signature.
- A successful login on the *first* attempt produces no failure event
  — credential stuffing with valid creds is invisible to this rule.
