---
archetype: sensitive-file-tampering
signature_id: wazuh-rule-550
required_anchors: []
---

# Sensitive File Tampering

Story: `story.md` (read that file for the observable shape).

## Trust Anchors

None — this archetype always escalates. The path itself is the
discriminator, and there is no organizational source of truth that
pre-authorizes arbitrary edits to these sensitive locations;
legitimate operator edits would be covered by a `config-mgmt-update`
or change-ticket-anchored archetype (not yet defined for this
signature).

## Precedents

None yet.
