---
archetype: external-bruteforce
signature_id: wazuh-rule-5710
required_anchors: []
precedents: []
---

# External Brute-Force

## Story

An external actor systematically attempted SSH authentication against
this host using a wordlist of common usernames. The source IP is
external (not in any RFC1918 range or org-internal subnet). Multiple
distinct usernames are tried in close succession — typically more
than five attempts in five minutes — drawn from common attack
wordlists like `admin`, `root`, `user`, `test`, `oracle`, `postgres`,
or service-account names the attacker doesn't actually have.

The attacker's goal is to find any account that accepts a guess. They
are not targeting a specific identity. The high volume and username
diversity is the signature.

This archetype always escalates. There is no trust anchor that
confirms "this brute-force attempt was authorized" — penetration
tests that would mimic this pattern should be coordinated through
change windows in advance, in which case the matched archetype would
be a `scheduled-pentest` variant (not yet defined for this signature).
Without that pre-coordination, brute-force activity from external
sources is adversarial by definition.

What takes an alert *out* of this archetype is the volume profile or
the source classification. A single attempt is `credential-stuffing`
(if the username is real-looking) or noise. Attempts from an internal
source are an entirely different archetype (operator typo, automation
misconfiguration, monitoring probe). The combination of external
source + multiple distinct usernames + high volume is what defines
this archetype.

## Precedents

The legacy precedent `precedents/brute-force-001.json` covers this
pattern under the older hypothesis-shape catalog. It can be migrated
to reference this archetype when the precedent schema is updated.
