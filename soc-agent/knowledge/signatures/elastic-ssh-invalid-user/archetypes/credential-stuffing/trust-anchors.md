---
archetype: credential-stuffing
signature_id: elastic-ssh-invalid-user
required_anchors: []
---

# Credential Stuffing

Story: `story.md` (read that file for the observable shape).

## Trust Anchors

None — this archetype always escalates. There is no anchor that
confirms "this external credential-stuffing attempt was authorized."
A coordinated red-team exercise would fall under a different
archetype anchored by the exercise's change ticket.

## Precedents

Ticket snapshots live as sibling `{TICKET-ID}.json` files next to
this README.
