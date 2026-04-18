---
archetype: external-bruteforce
signature_id: wazuh-rule-5710
required_anchors: []
---

# External Brute-Force

Story: `story.md` (read that file for the observable shape).

## Trust Anchors

None — this archetype always escalates. Penetration tests that would
mimic this pattern should be coordinated through change windows in
advance, in which case the matched archetype would be a
`scheduled-pentest` variant (not yet defined for this signature).
Without that pre-coordination, brute-force activity from external
sources is adversarial by definition.

## Precedents

Ticket snapshots that matched this archetype live as sibling
`{TICKET-ID}.json` files next to this README.
