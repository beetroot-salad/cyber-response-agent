---
name: sshd-auth-method-token-is-hypothesis-discriminator
description: Parse auth-method token from every sshd Accepted message; password vs. publickey RSA-CERT with CA fingerprint discriminates credential-stuffed logins from Vault-CA-issued certificate sessions.
source_finding_ids:
  - live-xtier-pivot-3/1
created_at: 2026-06-03T00:00:00Z
---

sshd Accepted messages carry a message field whose format differs by authentication method. A password-auth event contains only `Accepted password for <user> from <ip> port <n> ssh2`. A certificate-auth event contains `Accepted publickey for <user> from <ip> port <n> ssh2: RSA-CERT ID <user> (serial N) CA <ca-fingerprint>`. These strings are structurally distinct — the certificate variant carries the issuing CA's fingerprint.

This field is a first-order discriminator between credential-stuffed logins and IDP-fronted SSH CA attacks. If the attack path involves an IDP session compromise followed by a Vault SSH certificate request, the sshd message will include `RSA-CERT` and a CA fingerprint that identifies the issuing CA. A plain password event cannot be that attack; a certificate event with an unrecognized or unexpected CA fingerprint is the host-level indicator that the CA layer may be involved.

**Extract from every sshd Accepted message:**
1. Auth method: `password`, `publickey`, `gssapi-with-mic`, or other.
2. Key type (publickey events only): `RSA-CERT`, `Ed25519`, `ecdsa-sk`, etc.
3. CA fingerprint (certificate events only): the token after `CA` — match against a known-CAs list.

Missing this field means a Vault-issued certificate auth is indistinguishable from a password login in the analyze output, suppressing a discriminator between a compromised IDP entry and a routine bastion connection.
