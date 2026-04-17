# Investigation Language — Agent Reference

Schema v2.6. Validator: `hooks/scripts/invlang_validate.py` (PreToolUse hook on investigation.md writes).

---

## Principles

**Graph discovery.** An investigation constructs a directed graph by working backward from the alert. Confirmed vertices and edges grow monotonically. The investigation halts when it reaches a trust root (no accessible upstream) or has explicitly refuted every adversarial hypothesis.

**Entities as vertices.** Every observed entity (endpoint, process, identity, session, file…) becomes a typed vertex with a classification and identifier. Model at the granularity the investigation reasons at — don't decompose a process into threads unless a lead reveals heterogeneous structure that changes hypothesis trajectory.

**Relations as edges.** Observed connections and events between entities become edges. Each edge carries authority (how reliably the source recorded it) and optional temporal data.

**Hypotheses as proposed edges.** A hypothesis proposes that one specific upstream vertex exists, connected to a confirmed vertex by exactly one edge (`proposed_edge`). Predictions describe what observable evidence would confirm or contradict it; keep to 1–2 predictions — the minimum that distinguishes this hypothesis from competing ones.

**Attributes.** Facts about a vertex that don't add topology (IP classification, process owner, port) stay as `attributes` on the vertex or as `attribute_updates` in a lead outcome. Don't materialize a vertex just to carry an attribute.

**Leads.** A lead is a graph operation: topology-extending (new vertices/edges enter the confirmed graph via `outcome.observations`) or attribute-refining (existing vertices enriched via `attribute_updates`), or both. `tests` declares which hypotheses it discriminates; `resolutions` records weight effects with reasoning.

**Granularity.** Model at the resolution the investigation reasons at, not finer. When a lead forces inward decomposition, append sub-vertices via `component_of` with hierarchical IDs (`v-{parent}-{nonce}`); the parent vertex and its edges remain valid. Coarser observations are still true.

**Corpus.** Past investigations are indexed and queryable by hypothesis name, lead outcome, archetype, and disposition. Query before HYPOTHESIZE to calibrate hypothesis names and initial weights against known patterns. Use `matched_archetype` at CONCLUDE to connect this run to the indexed corpus.

---

## Phase-to-block map

| Phase | Block written | When |
|---|---|---|
| CONTEXTUALIZE | `prologue:` | end of CONTEXTUALIZE |
| SCREEN | first `gather:` lead with `mode: screen` | after screen subagent returns |
| HYPOTHESIZE | `hypothesize:` | end of HYPOTHESIZE |
| GATHER | narrative only — no YAML block | during GATHER |
| ANALYZE | complete `gather:` lead block (outcome + resolutions together) | end of ANALYZE |
| CONCLUDE | `conclude:` | after conclusion_checks.json, before report.md |

Call `invlang --enum` before writing any block that introduces new IDs or references existing ones.

---

## Top-level structure

```yaml
prologue:       # vertices + edges from alert entities
  vertices: [...]
  edges: [...]

hypothesize:    # initial proposed frontier; omit for screen-matched cases
  hypotheses: [...]

gather:         # one entry per lead; written at ANALYZE, not during GATHER
  - lead: {...}

conclude:
  ...
```

---

> **Embedding rule.** The section headers below (`Vertex`, `Edge`, `Hypothesis`) show the
> schema as standalone YAML fragments with an outer key (`vertex:`, `edge:`, `hypothesis:`).
> When you embed these inside a list (`prologue.vertices`, `prologue.edges`,
> `hypothesize.hypotheses`, `gather[].lead.outcome.observations.vertices`, etc.) **drop the
> outer key** — the list item is the object directly:
>
> ```yaml
> # CORRECT — flat list items
> prologue:
>   vertices:
>     - id: v-001
>       type: endpoint
>   edges:
>     - id: e-001
>       relation: attempted_auth
> hypothesize:
>   hypotheses:
>     - id: h-001
>       name: "?opportunistic-scanner"
>
> # WRONG — do not add a wrapping key
> prologue:
>   vertices:
>     - vertex:           # ← this extra key breaks ID collection
>         id: v-001
> ```

---

## Vertex

```yaml
vertex:
  id: v-{nonce}              # stable, append-only; sub-vertices: v-{parent}-{nonce}
  type: <string>             # from type vocabulary
  classification: <string>   # from seed list or {type}:{slug} provisional
  identifier: <string>       # human-readable primary key
  attributes: {}             # type-specific key-value pairs; omit if empty
  trust_root: true           # omit when false
  placeholder: true          # omit when false
  concerns: []               # omit if empty
  citations: []              # omit if single or implicit
```

---

## Edge

```yaml
edge:
  id: e-{nonce}
  relation: <string>         # from relation catalog
  source_vertex: v-{id}
  target_vertex: v-{id}
  when: { timestamp: <iso> } # omit if not meaningful
  attributes: {}             # omit if empty
  status: observed           # omit; emit hypothesized | refuted when non-default
  authority:
    kind: siem-event | runtime-audit | authoritative-source
        | client-asserted | inferred-structural
    source: <string>
    trust_chain: []          # omit if empty
  concerns: []               # omit if empty
```

---

## Hypothesis

```yaml
hypothesis:
  id: h-{nonce}              # child refinements: h-{parent}-{nonce}
  name: "?descriptive-slug"
  attached_to_vertex: v-{id}
  proposed_edge:
    relation: <string>
    parent_vertex:
      type: <string>
      classification: <string>
      attributes: {}         # omit if empty
  predictions:
    - id: p1
      claim: "<source-agnostic claim about world state>"
  refutation_shape:          # omit if no clean refutation shape exists
    - id: r1
      claim: "<observation that would contradict a core prediction>"
  concerns: []               # omit if empty
  weight: null               # null | "++" | "+" | "-" | "--"
  weight_history: []         # omit until transitions exist; each lead resolution that changes
                             # weight appends { from: <before>, to: <after>, lead: l-{id} }
  status: active             # omit; emit confirmed | refuted | shelved when non-default
```

`proposed_edge.parent_vertex` is the *causal upstream* — the vertex that, if it existed, would explain the current confirmed anchor via the proposed relation. "Parent" means upstream in the causal chain, not schema hierarchy. Relation direction is irrelevant: `executed_in: command → session` means `proposed_edge.parent_vertex` for a hypothesis about what session a command ran in is still the session vertex.

---

## Lead

```yaml
lead:
  id: l-{nonce}
  loop: <int>
  name: <string>
  target: v-{id}
  selection_rationale: <string>   # optional; 1–3 sentences on why this lead now
  mode: screen                    # omit unless SCREEN-dispatched
  tests: [h-{id}, ...]            # optional; hypotheses this lead discriminates
  observes:                       # optional; explicit prediction/refutation mapping
    - { hypothesis: h-{id}, predictions: [p1], refutations: [r1] }
  query_details:
    system: <string>
    template: <string>
    query: <string>
    time_window: <string>
    substitutions: {}
  concerns: []                    # omit if empty
  outcome:
    attribute_updates:            # enriches existing confirmed vertices
      - vertex: v-{id}
        updates: {}
    observations:
      vertices: []
      edges: []
    trust_anchor_result:          # include when the lead queried a named trust anchor
                                  # (an authoritative-source that can give a definitive verdict).
                                  # Omit for SIEM queries that are not anchors.
      anchor_id: <string>
      kind: <string>
      result: confirmed | refuted | partial | no-data
      as_of: <iso>                # timestamp the answer is authoritative ABOUT
      authority_for_question: full | partial
    trust_root_reached: v-{id}    # omit when null
    failure_reason: <string>      # adapter-error | attribution-opaque | partial-coverage
                                  # | permission-denied | timeout | other
    screen_result: match | no_match  # only when mode: screen; only on final screen lead
  new_hypotheses: []              # full hypothesis records
  shelved: []                     # hypothesis IDs shelved by this lead
  resolutions:
    - hypothesis: h-{id}
      before: null | "++" | "+" | "-" | "--"
      after: "++" | "+" | "-" | "--"
      severity_of_test: severe | moderate | weak
      matched_prediction_ids: []
      matched_refutation_ids: []
      reasoning: "<string>"       # explain why this evidence moves weight — not a field restatement
      supporting_edges: []
```

---

## Conclude

```yaml
conclude:
  termination:
    category: trust-root | adversarial-refuted | severity-ceiling | exhaustion-escalation
    rationale: <string>
  disposition: benign | true_positive | unclear
  confidence: high | medium | low
  matched_archetype: <name> | null   # use the archetype directory name from
                                     # knowledge/signatures/{sig}/archetypes/{name}/
  ceiling_test:                   # required when category = severity-ceiling
    kind: out-of-band-human-contact | tool-unavailable | legal-authorization | other
    subject: <string>
  ceiling_rationale: <string>     # required when category = severity-ceiling
  summary: <string>
```

---

## Observation conventions

**Lifecycle vs action.** Is the observation's natural noun an invocation? → `command` vertex with `executed_in → session` and `targeted → <thing>`. Is it an entity whose later state the investigation reasons about? → lifecycle (typed vertex + edge verb). CRUD operations (`CreateUser`, `DeleteObject`, `GetObject`) are uniformly action-shaped.

**Aggregate observations.** N occurrences of the same thing → single edge with `count` and `window_*` attributes. Do not materialize one vertex per occurrence.

---

## Type vocabulary

| Type | Notes |
|---|---|
| `endpoint` | Compute unit with OS. IP-only: `attributes.knowledge: partial` |
| `process` | Running execution unit |
| `thread` | Sub-entity of process; `component_of` + hierarchical ID |
| `memory-region` | Sub-entity of process; `component_of` + hierarchical ID |
| `module` | Loaded library/DLL; `component_of` |
| `container` | Runtime container |
| `session` | Authenticated interactive or API session |
| `identity` | `attributes.kind ∈ {user, group, role, service-account, application}` |
| `storage` | `attributes.kind ∈ {object-store, block, file, secrets, nfs}` |
| `database` | Structured data system with query interface |
| `network-device` | Firewall, switch, router, load balancer, WAF |
| `file` | Specific file artifact |
| `command` | Audited invocation (action-shaped observation) |
| `socket` | Network socket (transport-layer) |

Use `unclassified-{type}` when unknown; `ambiguous-{a}-or-{b}` when genuinely indistinguishable.

---

## Relation catalog

| Relation | Source → Target | Notes |
|---|---|---|
| `spawned` | process → process | |
| `executed` | process → file | |
| `loaded_by` | process → file | Modules/libraries |
| `opened` | process → socket | |
| `connected_to` | socket → endpoint | Transport-layer only |
| `read` / `wrote` | process → file | |
| `runs_in` | process → container | |
| `runs_on` | process \| container \| database \| session → endpoint | Compute-substrate containment |
| `authenticated_as` | session → identity | |
| `initiated_by` | session → identity \| endpoint | |
| `triggered_by` | process \| session → process \| session | |
| `escalated_privilege` | session → session | Self-edge |
| `executed_in` | command → session | |
| `targeted` | command → endpoint \| storage \| database \| identity \| file \| container \| network-device | Action-target for command vertices |
| `member_of` | identity → identity | User→group, role→bundle |
| `identified_as` | placeholder → real-vertex | Post-hoc attribution; never mutate the placeholder |
| `component_of` | vertex → vertex | Part-of for inward decomposition; sub-entity → container |
| `listed` | session \| process → storage \| database | Enumeration (provisional) |
| `modified` | session \| process → storage \| database \| identity \| file | State change (provisional) |
| `attempted_auth` | endpoint \| process \| session → endpoint | Auth attempt, may be failed (provisional) |
| `classified_as` | vertex → classification-value | |

---

## Examples

### Hypothesis — lean one-hop predictions

```yaml
hypothesis:
  id: h-001
  name: "?opportunistic-scanner"
  attached_to_vertex: v-001          # confirmed source endpoint (203.0.113.47)
  proposed_edge:
    relation: initiated_by           # source behavior was initiated by automated tooling
    parent_vertex:
      type: identity
      classification: automated-scanner
      attributes: { kind: service-account }
  predictions:
    - id: p1
      claim: "source IP appears in at least one passive-DNS or threat-intel scanner list"
  refutation_shape:
    - id: r1
      claim: "source IP has prior authenticated sessions against this host — not a blind scanner"
  weight: null
  status: active
```

**One-hop discipline:** `proposed_edge.parent_vertex` is the immediate upstream cause — exactly one new vertex, one new edge. Predictions test the *proposed vertex's* existence or nature, not the alert data already in hand. `p1` here is falsifiable against threat-intel; it would not appear for a legitimate admin IP. Do not write predictions that re-describe what the alert already tells you — those are observations, not predictions.

### Lead — attribute update + resolution with reasoning

```yaml
lead:
  id: l-001
  loop: 1
  name: source-classification
  target: v-001                      # source endpoint
  selection_rationale: "IP attribution determines which hypotheses are live before
    committing to discriminating queries — cheaper to classify the source first."
  tests: [h-001, h-002]
  query_details:
    system: wazuh-indexer
    template: source-ip-lookup
    query: "agent.ip:10.0.0.50 AND src_ip:203.0.113.47"
    time_window: "30d"
    substitutions: { src_ip: "203.0.113.47" }
  outcome:
    attribute_updates:
      - vertex: v-001
        updates:
          classification: external-unknown
          asn: "AS64496 TEST-NET"
    observations:
      vertices: []
      edges: []
  resolutions:
    - hypothesis: h-001
      before: null
      after: "+"
      severity_of_test: weak
      matched_prediction_ids: [p2]
      reasoning: "No prior authenticated sessions from this IP in 30-day window.
        Consistent with opportunistic scanner but not discriminating alone — many
        legitimate first-time sources would also show no session history."
      supporting_edges: [e-002]
```

`reasoning` explains *why* this evidence moves weight — not a restatement of the field values. Cite what was found, what it rules in or out, and what residual uncertainty remains.

---

## Key rules

1. **Edge authority.** `++`/`--` resolutions must cite at least one `siem-event`, `runtime-audit`, or `authoritative-source` edge in `supporting_edges`.
2. **Refutation IDs.** Every `--` resolution requires non-empty `matched_refutation_ids` referencing IDs that exist in the target hypothesis.
3. **Prediction completeness.** `++` requires `matched_prediction_ids` to cover the full prediction set; partial coverage caps at `+`.
4. **Append-only.** Never mutate an existing record. Decompose by appending sub-vertices; attribute by appending `attribute_updates`.
5. **`trust_anchor_result` completeness.** When present, all five fields (`anchor_id`, `kind`, `result`, `as_of`, `authority_for_question`) are required.
6. **Partial authority cap.** A resolution grounded solely by `authority_for_question: partial` cannot push a hypothesis past `+` or `-`.
7. **`screen_result` scope.** Only valid on `mode: screen` leads; only on the final lead in a SCREEN sequence. SCREEN-matched companions omit the top-level `hypothesize` block.
