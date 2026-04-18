---
archetype: container-init-script
signature_id: wazuh-rule-100001
required_anchors:
  - image-baseline
---

# Container Init Script

Story: `story.md` (read that file for the observable shape).

## Trust Anchors

### `image-baseline`

**Question:** for this `container.image`, does the historical record
show 100001 events firing within seconds of container start, from
the same `proc.pname`, with the same `proc.cmdline` shape, on every
(or nearly every) prior container start observed in the environment?

**Confirmation:** the anchor returns a baseline showing this image
fires this exact pattern at startup, with sample size large enough
to be representative (≥10 prior starts is a reasonable floor) and
recent enough to reflect the current image version (no major version
change since the baseline was established).

## Precedents

None yet.
