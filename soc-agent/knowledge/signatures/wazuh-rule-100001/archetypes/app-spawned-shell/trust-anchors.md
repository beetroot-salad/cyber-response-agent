---
archetype: app-spawned-shell
signature_id: wazuh-rule-100001
required_anchors:
  - image-baseline
---

# Application-Spawned Shell

Story: `story.md` (read that file for the observable shape).

## Trust Anchors

### `image-baseline`

**Question:** for this `container.image`, does the historical record
show 100001 events firing from the same `proc.pname` with a similar
`proc.cmdline` shape, with sufficient frequency and over a long
enough window to be considered routine?

**Confirmation:** the anchor returns a baseline showing this
parent/cmdline shape recurring across many prior events for this
image, with sample size large enough to be representative and a
recency window that includes the current image version. A baseline
that shows only a few recent occurrences without a longer-term
pattern is *not* sufficient confirmation — it could be the early
stages of a compromise that the agent is now treating as the new
normal.

## Precedents

None yet.
