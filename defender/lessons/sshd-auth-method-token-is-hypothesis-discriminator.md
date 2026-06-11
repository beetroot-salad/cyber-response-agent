---
name: sshd-auth-method-token-is-hypothesis-discriminator
description: Parse sshd Accepted auth-method token on every session; when the observed credential type contradicts the oracle-projected type for a service account, treat the mismatch as a first-order hypothesis discriminator requiring explicit resolution, not a partial-grade note.
telemetry_source: [sshd]
attack_phase: [initial-access, credential-access]
source_signature: [v2-cross-tier-ssh-pivot, v2-sshd-success-after-failures]
source_finding_ids:
  - live-xtier-pivot-3/1
  - live-cross-tier-pivot-3/1
created_at: 2026-06-03T00:00:00Z
---

sshd Accepted messages carry a message field whose format differs by authentication method. A password-auth event contains `Accepted password for <user> from <ip> port <n> ssh2`. A certificate-auth event contains `Accepted publickey for <user> from <ip> port <n> ssh2: RSA-CERT ID <user> (serial N) CA <ca-fingerprint>` — the certificate variant carries the issuing CA's fingerprint.

**Extract from every sshd Accepted message:**
1. Auth method: `password`, `publickey`, `gssapi-with-mic`, or other.
2. Key type (publickey events only): `RSA-CERT`, `Ed25519`, `ecdsa-sk`, etc.
3. CA fingerprint (certificate events only): the token after `CA` — match against a known-CAs list.

**Contradiction with the oracle-projected type is a first-order signal.** If the oracle projects a service account as using certificate-based SSH and sshd logs return `password`, that is a mechanism contradiction — not a secondary confidence note. The certificate/agent-forwarding attack path requires cert material; a password event eliminates that mechanism and opens the credential-stuffing path instead. Do not record this as "partial grade on p3" and move past it — reassign hypothesis weights explicitly and name which mechanism the auth-method evidence rules out or rules in.

A mismatch between the observed method and the provisioned type means either the provisioning oracle is stale or the session did not authenticate the expected way. Both warrant a hypothesis weight update before closing, not a marginal notation.

Missing this field means a Vault-issued certificate auth is indistinguishable from a password login in the analyze output, suppressing a discriminator between a compromised IDP entry and a routine bastion connection.
