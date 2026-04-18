# New Signature Template

## How to create a new signature

### 1. Setup

1. Copy this directory: `cp -r _template/ {signature-id}/`
2. Remove this README.md from the copy (it's only for onboarding)
3. Create permissions: `cp -r ../../config/signatures/_template/ ../../config/signatures/{signature-id}/`

### 2. Research past tickets

Before writing any knowledge, study real data for this signature:

1. **Pull the signature definition** from the SIEM — detection logic, fields, severity, related rules
2. **Query past alerts** for this signature (aim for 20-50+ if available). Note:
   - Volume and base rate — how often does this fire?
   - Common dispositions — what % were benign vs escalated?
   - Recurring patterns — same source IPs, usernames, time-of-day clusters?
3. **Review closed tickets** — read analyst notes, resolution reasoning, and any false positive annotations
4. **Identify distinct outcome clusters** — group tickets by what actually happened (monitoring probe, brute force, misconfiguration, etc.). Each cluster becomes an archetype.
5. **Extract useful investigation tricks** — what queries or checks did analysts use to resolve quickly? What dead ends wasted time?
6. **Select representative tickets per archetype** — 1-2 per cluster that best illustrate the pattern. These become precedent snapshots under the matching archetype directory.

This research phase is the foundation. The context, playbook, and archetypes should reflect what actually happens with this signature, not what might theoretically happen.

### 3. Fill in knowledge files

**context.md:**
- Update all frontmatter fields (signature_id, name, severity, etc.)
- Signature logic — from the SIEM definition + your understanding of what it actually detects
- Threat model — grounded in what you saw in real tickets
- Known false positives — from the recurring benign patterns you identified
- Risk indicators — the fields and values that actually discriminated outcomes in past tickets

**playbook.md:**
- Update frontmatter (signature_id, last_updated)
- Archetype catalog — list one archetype per outcome cluster you identified in research (must include at least one adversarial archetype)
- Starter lead order — the leads that discriminate between the archetypes cheaply
- Screen table (optional, recommended) — fast-path patterns for the most common benign archetype. Only include a pattern if every indicator is unambiguous and every indicator is queryable via a real lead, not just alert-field matching
- Scope — how far the investigation may range before escalating

**field-quirks.md (new):**
- Extract the subset of `context.md` that matters for shape comparison: the Key Observables table (observable → JSON path → why it matters) plus any field-level gotchas (e.g., counterintuitive field semantics, NAT-egress caveats). Read by the archetype-scan subagent instead of the full `context.md` — keep it tight.

**archetypes/{archetype-name}/:**
- Create one directory per archetype you identified in research
- Inside each, write:
  - `story.md` — frontmatter (archetype, signature_id, required_anchors) + observable-shape narrative. Read by the archetype-scan subagent.
  - `README.md` — same frontmatter + trust-anchor definitions + precedent pointer. Read by the main agent at grounding time.
  - Copy the shape of `archetypes/_template/story.md` and `archetypes/_template/trust-anchors.md`.
- Drop one JSON snapshot per representative ticket next to the README, named `{TICKET-ID}.json`. See `archetypes/_template/TEMPLATE.json` for the schema

**Trust anchors (optional but recommended):**
- Benign archetypes should declare `required_anchors` in frontmatter — these point at files under `../../environment/operations/{anchor-name}.md` that describe the org source of truth confirming the archetype in a specific instance
- If an anchor you need doesn't exist yet, scaffold it under `environment/operations/` with the same shape as existing anchors
- If no anchor is available for a benign archetype, the archetype cannot resolve to benign without `matched_ticket_id` — Tier 1 enforces this

## Directory structure after setup

```
{signature-id}/
├── context.md               # Signature reference (detection logic, threat model, FPs)
├── field-quirks.md          # Key observables + field-level gotchas (scanner-scoped subset of context.md)
├── playbook.md              # Archetype catalog, leads, screen table, escalation criteria
└── archetypes/              # One subdirectory per recognized archetype
    └── {archetype-name}/
        ├── story.md         # Frontmatter + observable-shape narrative (scanner target)
        ├── trust-anchors.md # Frontmatter + required-anchor grounding contract + precedent pointer
        └── {TICKET-ID}.json # One or more precedent snapshots (ticket cache)
```

## The two-leg resolution model

Closing an alert without human escalation requires **both**:

1. **Shape** — the investigation's observed evidence fits an archetype story (documented in `story.md` under the archetype directory).
2. **Grounding** — at least one of:
   - (a) the archetype's `required_anchors` all confirmed at investigation time, OR
   - (b) a `matched_ticket_id` pointing at a valid precedent snapshot under the same archetype.

If the archetype declares no `required_anchors`, (b) is mandatory. If the archetype declares required anchors, (a) is the primary path and (b) is supplementary confidence. An anchor confirmation that depended on time-bounded state (on-call window, change ticket, deploy run) is marked `temporal: true` in the precedent's `anchors_at_time` — temporal confirmations do not transfer forward in time and must be re-confirmed at the current investigation.

## References

- v3 architecture: `docs/design-v3-architecture.md`
- Archetype rewrite design: `docs/design-v3-hypothesis-archetype-rewrite.md`
- Example signature: `wazuh-rule-5710/` (4 archetypes + 2 precedent snapshots)
- Precedent schema: `schemas/precedent.py`
- Report frontmatter schema: `schemas/report_frontmatter.py`
- Trust anchor examples: `knowledge/environment/operations/`
