---
archetype: _template
signature_id: _template
required_anchors: []
---

# {Archetype Name}

Story: `story.md` (read that file for the observable shape).

## Trust Anchors

Delete this section entirely if `required_anchors: []` in frontmatter.

For each entry in `required_anchors`, add a subsection:

### `anchor-name`

**Question:** what does this anchor answer for this archetype? One
sentence.

**Confirmation:** what shape of response counts as a confirmation? Be
specific about what *doesn't* confirm (e.g., "a ticket matching a
different target is not a confirmation").

## Precedents

Ticket snapshots that matched this archetype live as sibling
`{TICKET-ID}.json` files next to this README. Each snapshot is a
pointer to the real ticket in the source-of-truth ticketing system —
the KB copy is a cache for fast-path matching and few-shot grounding.

A precedent with a `temporal: true` entry in `anchors_at_time`
represents a confirmation that depended on time-bounded state at the
time of ticket close (on-call window, change-management ticket,
deploy run). Temporal confirmations do not transfer forward in time
— they must be re-confirmed today.
