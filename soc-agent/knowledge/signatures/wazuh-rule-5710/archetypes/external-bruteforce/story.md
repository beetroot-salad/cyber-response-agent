---
archetype: external-bruteforce
signature_id: wazuh-rule-5710
required_anchors: []
---

# External Brute-Force — Story

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

This archetype always escalates. External sources running wordlist
attacks are adversarial by definition; coordinated pentests would
match a different archetype anchored by a change ticket.

What takes an alert *out* of this archetype is the volume profile or
the source classification. A single attempt is `credential-stuffing`
(if the username is real-looking) or noise. Attempts from an internal
source are an entirely different archetype (operator typo, automation
misconfiguration, monitoring probe). The combination of external
source + multiple distinct usernames + high volume is what defines
this archetype.
