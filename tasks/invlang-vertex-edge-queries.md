---
title: Expand corpus query capabilities to vertex and edge attributes
status: backlog
groups: invlang, knowledge
depends_on: invlang-live-yaml-investigation
---

## Goal

New query classes that operate on the vertex/edge graph in companions, enabling questions
like:

- "Which hypothesis patterns appear when the alert's source vertex has `knowledge: partial`
  (i.e. IP-only, no hostname attribution)?"
- "Which leads produced `supporting_edges` of type `attempted_auth`, and how effective were
  they at discriminating adversarial hypotheses?"
- "For investigations where `attached_to_vertex` is an `endpoint` with `trust_root: true`,
  what is the typical termination category?"
- "Which hypothesis types arise from `proposed_edge.relation: spawned` vs `attempted_auth`?"

## Why this matters

The investigation language models the alert as a graph. Vertex attributes (type, classification,
`knowledge: partial`, `trust_root`) and edge relations carry structural information about
*what kind of alert* is being investigated, independently of the signature ID. Cross-signature
queries on vertex/edge shape could reveal patterns not visible when grouping only by
`signature_id`.

## Depends on

`invlang-live-yaml-investigation` — the live-writing migration. Once investigation.md carries
full v2.5 YAML blocks, Tier-1 (agent-written) companions have vertex/edge graphs. Until then
only Tier-2 hand-curated companions support these queries and the corpus is too small to be
useful (N≈6).

## Proposed query classes

**Class 13 — Vertex-attribute hypothesis patterns.**
Given a vertex attribute filter (e.g. `type=endpoint AND knowledge=partial`), return the
distribution of hypothesis names that appear in investigations where any vertex matching the
filter is present. Identifies which hypothesis classes are structurally associated with
attribution-opaque sources.

**Class 14 — Edge-relation lead effectiveness.**
For each `edge.relation` type present in `outcome.observations`, compute mean weight delta
and discrimination score across all resolutions whose `supporting_edges` include an edge of
that relation type. Answers: "which observed edge relations are most evidentially useful?"

**Class 15 — Trust-root shape analysis.**
For investigations that reached `trust_root_reached`, characterize the trust root vertex
(type, classification, authority kind of the terminal edge). Groups by disposition. Answers:
"what does the investigation graph look like when it terminates cleanly vs when it escalates?"

**Class 16 — Proposed-edge hypothesis clustering.**
Group hypotheses by `proposed_edge.relation`. For each relation type, return distribution of
final weights and dispositions. Answers: "hypotheses proposing a `spawned` upstream cause —
how often do they confirm vs refute?"

## Notes

- Polars can handle nested YAML fields loaded into DataFrames; the existing corpus loader
  will need extension to flatten vertex/edge arrays into queryable rows.
- Natural language fallback (Class 0) should be extended to handle vertex/edge questions
  once these classes exist — the subagent should know to try Classes 13–16 for graph-shaped
  questions.
