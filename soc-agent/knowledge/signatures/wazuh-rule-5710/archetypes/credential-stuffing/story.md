---
archetype: credential-stuffing
signature_id: wazuh-rule-5710
required_anchors: []
---

# Credential Stuffing — Story

An external actor attempted to log in as a small set of **real-looking
usernames** with credentials likely sourced from a third-party breach.
The attempt volume is low — one to three tries per source — and the
usernames are not drawn from an attack wordlist but from a leaked
credential dump: plausible first-name / last-name combinations,
service account names from specific products (`jenkins`, `gitlab`,
`jira`), or usernames that correspond to real accounts elsewhere in
the org but not on this host.

The shape differs from `external-bruteforce` in **volume** and
**username style**. Brute-force iterates wordlists at high volume to
find *any* account that accepts a guess; credential stuffing targets
*specific* identities with presumed-valid credentials. Brute-force
fires 5712 (the composite rule) routinely; credential stuffing
usually does not — the volume is below 5712's threshold.

The shape differs from `monitoring-probe` in **source classification
and username realism**. Monitoring probes come from internal
monitoring hosts with sentinel usernames; credential stuffing comes
from external sources using realistic usernames.

This archetype always escalates. The disposition is always escalate
to a human — the analyst needs to verify whether the attempted
usernames correspond to real accounts on *any* host in the
environment, and whether any of them appear in a known breach dump.

What takes an alert *out* of this archetype: internal source (a
different archetype entirely), high-volume wordlist pattern
(`external-bruteforce`), or a single-attempt sentinel username
(`monitoring-probe`).
