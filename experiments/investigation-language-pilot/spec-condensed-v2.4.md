# Investigation Language — Condensed Spec v2.4 (pilot, retrieval-aware)

Revised from v2.3 after the hypothesis-as-graph-extension design session.
**Four material changes** from v2.3, all additive — no fields removed, no
types removed. The schema gets a cleaner first-principles foundation
without growing in size.

---

## §A — Changes from v2.3 (read first if you know v2.3)

1. **`explains` field on hypothesis (additive).** A hypothesis now
   carries an explicit semantic pointer to what it is accounting for.
   `attached_to_vertex` stays as the **structural anchor** — the graft
   point in the confirmed graph where the proposed extension connects.
   `explains` is the **semantic label** — which confirmed edges and/or
   vertices this hypothesis is trying to explain.

   ```yaml
   explains:
     edges: [e-001]        # confirmed edges whose existence is being explained
     vertices: [v-002]     # confirmed/placeholder vertices being identified
   ```

   Both lists are independently optional; omit `explains` entirely when
   both are empty. Three patterns emerge naturally:

   - **Explains edge only** — both endpoints of the edge are confirmed;
     the question is what upstream actor produced the action. All
     rule-5710 hypotheses (h-001..h-004) are this shape: `explains.edges:
     [e-001]`.
   - **Explains edge + vertex (coupled)** — one endpoint is a
     placeholder; the hypothesis simultaneously identifies what the
     placeholder is AND explains why it produced the edge. These are
     inseparable: `explains.edges: [e-x], explains.vertices: [v-ph]`.
   - **Explains vertex only** — rare; typically a Q2 hypothesis
     explaining why a just-materialized vertex exists. In practice this
     always comes with a new proposed edge, so the "vertex only" shape
     collapses into the coupled case at the next lead.

   Why this matters: `attached_to_vertex` is a structural proxy for
   what the hypothesis explains, not the explanation itself. Two
   hypotheses with the same anchor but explaining different edges (e.g.,
   an explanatory hypothesis for e-001 and a Q2 hypothesis for
   e-materialized) are structurally distinguishable. The `explains`
   field also makes the Q1 → Q2 explanation chain queryable: following
   `explains.edges` across a refinement chain traces the full backward
   traversal path.

2. **`attribute_updates` in lead outcome (additive).** Scope and trust
   leads that refine vertex attributes without materializing new topology
   can now record those refinements explicitly instead of using an empty
   `observations` block.

   ```yaml
   outcome:
     attribute_updates:
       - vertex: v-001
         updates:
           classification: monitoring-host
           attributes:
             role_hint: "playground monitoring container"
   ```

   `attribute_updates` and `observations` coexist — a trust lead can
   both refine an existing vertex's attributes and materialize new
   vertices in the same outcome. Either may be omitted when empty.

   Scope leads that previously returned `observations: { vertices: [],
   edges: [] }` and effectively refined vertex attributes via
   classification lookups should use `attribute_updates` instead. This
   makes attribute refinements queryable (find all leads that updated
   vertex V's classification) without parsing empty observation blocks.

3. **`component_of` relation (additive, §10).** A part-of relation for
   inward vertex decomposition. Covers thread-in-process, memory-region-
   in-process, module-in-process, and any case where an investigation
   reveals that a confirmed vertex has heterogeneous internal structure.
   Source is the sub-entity; target is the containing entity. Vertex
   type discriminates the semantics — `component_of` is intentionally
   neutral, and the distinction between "execution unit" vs "structural
   part" is carried by vertex type (`thread`, `memory-region`, `module`),
   not by the relation name. See the new §3 subsection for the full
   decomposition convention.

4. **Vertex decomposition subsection (§3, additive).** Documents the
   inward decomposition pattern: when a confirmed vertex is revealed
   mid-investigation to have heterogeneous internal structure, append
   sub-vertices with hierarchical IDs and link via `component_of`.
   Coarse edges on the parent remain valid. The pattern is the inward
   analogue of the investigation's backward traversal.

**Net delta:** +1 hypothesis field (`explains`), +1 lead outcome field
(`attribute_updates`), +1 relation (`component_of`), +1 §3 subsection.
No removed fields. No removed types.

---

## §B — Eight v2.3 changes (recap)

1. **Drop `canonical` from hypothesis schema.**
2. **Hierarchical hypothesis IDs for refinement chains.**
3. **Lean hypothesis methodology.**
4. **Type vocabulary cleanup** (`endpoint`, `identity`, `storage`,
   `database`, `network-device`; `anchor-source` deprecated).
5. **Action-as-vertex via `command` + new `targeted` relation.**
6. **`outcome.trust_anchor_result`** on trust-mode leads.
7. **`conclude.ceiling_test`** for severity-ceiling termination.
8. **Distiller projects, not schema fields.**

---

## §C — Five v2 changes (recap)

1. Journal form. 2. Implicit defaults. 3. Discrimination-level
hypothesis rule. 4. Host context as attributes. 5. Mechanical leads
stay within their data source.

## §D — Five v2.1 changes (recap)

1. `intended_hypothesis_set` required on materialize/trust.
2. No `execution` block. 3. No `outcome.status`. 4. No `source_lead`.
5. Unified `concerns`.

## §E — Six v2.2 changes (recap)

1. Prediction IDs + ID-based rule 6. 2. `abstract_type` → `type`.
3. `outcome.produced` → `outcome.observations`. 4. `anchor-backed` →
`authoritative-source`. 5. Optional `lead.observes`. 6.
`proposed_edge.parent_vertex` is exactly one backward hop.

---

## 1. Top-level structure

```yaml
prologue:                 # CONTEXTUALIZE
  vertices: [...]
  edges: [...]

hypothesize:              # HYPOTHESIZE — often empty if mechanical leads run first
  hypotheses: [...]

gather:                   # GATHER — ordered list of self-contained lead blocks
  - lead: {...}

conclude:                 # ANALYZE + CONCLUDE
  ...
```

Append-only. No record is mutated after it is written.

---

## 2. Common record conventions

**IDs.**

- `v-{nonce}`, `e-{nonce}`, `l-{nonce}` for vertices, edges, and leads.
  Stable and local to the run.
- **Hypothesis IDs follow a hierarchical naming convention** to encode
  refinement chains:
  - **Top-level:** `h-{nonce}` — e.g., `h-001`, `h-002`.
  - **Refinement:** `h-{parent-id-suffix}-{nonce}` — e.g., `h-001-001`
    is the first refinement of `h-001`; `h-001-002` is the second
    refinement; `h-001-001-001` is the first refinement of `h-001-001`.
  - Each segment is a sequential ordinal at that level, allocated when
    the refinement is created.
  - **Append-only:** once an ID is allocated, it is never reused.
  - **Parent is recoverable** by stripping the last `-{nonce}` segment.
  - Investigations cap at 7 loops; worst-case ID length is ~27
    characters. No structural limit is enforced.
- **Decomposed sub-vertex IDs** follow the same hierarchical convention:
  `v-{parent}-{nonce}` — e.g., `v-001-01` and `v-001-02` are
  sub-entities of `v-001`. The prefix query `v-001-*` retrieves all
  sub-entities without edge traversal. See §3 vertex decomposition.
- **Predictions and refutation shapes** carry `p1`, `p2`, … and
  `r1`, `r2`, …, scoped to the containing hypothesis.

**Implicit defaults — omit when at default.**

| Field                              | Default   | Emit when                                          |
|------------------------------------|-----------|----------------------------------------------------|
| `vertex.trust_root`                | `false`   | a successful trust lead sets it `true`             |
| `vertex.attributes`                | `{}`      | there are type-specific attributes to record       |
| `vertex.concerns`                  | `[]`      | there's a limitation or trap worth flagging        |
| `edge.attributes`                  | `{}`      | there are relation-specific attributes             |
| `edge.when`                        | omitted   | the relation is instantaneous or extended          |
| `edge.status`                      | `observed`| `hypothesized` or `refuted`                        |
| `edge.concerns`                    | `[]`      | as for vertex.concerns                             |
| `edge.authority.trust_chain`       | `[]`      | a client-asserted edge sits on a promotion chain   |
| `hypothesis.explains`              | omitted   | there are edges or vertices to reference           |
| `hypothesis.concerns`              | `[]`      | an alert-specific trap or residual                 |
| `hypothesis.weight_history`        | `[]`      | there are recorded transitions                     |
| `hypothesis.status`                | `active`  | `confirmed`, `refuted`, or `shelved`               |
| `lead.concerns`                    | `[]`      | lead has a reliability, cost, or data concern      |
| `lead.observes`                    | omitted   | declaring testable prediction IDs                  |
| `lead.outcome.attribute_updates`   | omitted   | lead refined existing vertex attributes            |
| `lead.outcome.failure_reason`      | omitted   | lead errored or returned degraded data             |
| `lead.outcome.trust_root_reached`  | omitted   | a trust lead succeeded                             |
| `lead.outcome.trust_anchor_result` | omitted   | a trust lead consulted an anchor (required then)   |

---

## 3. Prologue block

Records derived directly from the alert, before any lead runs.

```yaml
prologue:
  vertices:
    - id: v-001
      type: command
      classification: rds-query-call
      identifier: "SELECT FROM customer_pii by data-pipeline-svc @02:17:04Z"
      attributes:
        api_name: "rds-data:ExecuteStatement"
        sql_summary: "SELECT * FROM customer_pii LIMIT 1000"
        status: succeeded
        rows_returned: 943

    - id: v-002
      type: identity
      classification: shared-service-role
      identifier: "data-pipeline-svc"
      attributes:
        kind: role
        provider: aws-iam
        arn: "arn:aws:iam::123456789012:role/data-pipeline-svc"

    - id: v-003
      type: database
      classification: customer-pii-database
      identifier: "rds-prod-customers"
      attributes:
        kind: postgres
        database: "customers"
        table_accessed: "customer_pii"

  edges:
    - id: e-001
      relation: targeted
      source_vertex: v-001
      target_vertex: v-003
      when: { timestamp: "2026-04-14T02:17:04Z" }
      authority:
        kind: authoritative-source
        source: "cloudtrail:event=evt-abc123"
```

### Scale of reasoning — pick the granularity the investigation works at

Vertices in the companion are not "the smallest observable unit" — they
are the unit at which the investigation **reasons**. `process`, `session`,
`endpoint`, `container`, `database` are all valid granularities; the
right choice depends on what the investigation is trying to answer.

- If the question is "which binary ran this?" → `process`.
- If the question is "who had a shell on this box?" → `session`.
- If the question is "which host is compromised?" → `endpoint`.
- If the question is "which query touched this table?" → the query is
  an observation on the `database` (an edge or attribute), not a new
  entity.

Fine-grained observations that *support* the reasoning but aren't the
unit of reasoning belong as attributes or as finer-grained vertices
that **compose with** the primary one via containment relations
(`runs_on`, `runs_in`, `executed_in`, `triggered_by`, `component_of`).
They don't *replace* it.

**Scale can change across loops.** A scope lead may materialize a
process tree (finer) inside a previously-materialized session (coarser);
both levels coexist in the graph, linked by containment relations.
Decompose to a finer scale only when evidence forces the distinction.

**Aggregation is an attribute, not a vertex decomposition.** When an
observation describes N occurrences of something, the aggregate belongs
on a single vertex or edge with `count` + `window_*` attributes.

**Cartography analogy.** A world map renders an island as opaque; a
city map shows streets; a building floor plan shows rooms. All three
are valid representations of the same land — the right one depends on
what question is being asked.

### Inward decomposition — when a vertex is revealed to be composite

Most investigations never decompose a vertex inward — `process`,
`session`, and `endpoint` are opaque and that is fine. Inward
decomposition occurs when a lead reveals mid-investigation that a
confirmed vertex has **heterogeneous internal structure** that the
investigation must reason about distinctly.

**Example:** an investigation into svchost.exe making anomalous network
connections starts at process level. A thread-enumeration lead reveals
an injected thread alongside normal service threads. The disposition
changes: svchost.exe as a whole is legitimate; the injected thread is
the adversarial actor. The investigation must model both.

**Mechanism — append sub-vertices with hierarchical IDs:**

```yaml
# v-001 was confirmed at loop 1 (process level).
# Loop 3 lead forces decomposition:

- id: v-001-01
  type: thread
  classification: service-host-main
  identifier: "svchost.exe main service thread"
  attributes:
    permissions: "RX (expected)"

- id: v-001-02
  type: thread
  classification: unclassified-process   # adversarial
  identifier: "svchost.exe injected thread (CreateRemoteThread origin)"
  attributes:
    permissions: "RX (unexpected — not backed by any loaded module)"
    origin: external-injection

edges:
  - id: e-010
    relation: component_of
    source_vertex: v-001-01
    target_vertex: v-001
    authority: { kind: runtime-audit, source: "thread-enum:pid=1234" }

  - id: e-011
    relation: component_of
    source_vertex: v-001-02
    target_vertex: v-001
    authority: { kind: runtime-audit, source: "thread-enum:pid=1234" }
```

**Append-only preservation:** v-001 and its existing edges are NOT
mutated. The coarse edge "v-001 connected to C2" (e.g., from the
prologue) remains a valid observation at the process level. New
fine-grained edges from v-001-02 *specialize* it — they are more
precise, not replacements. Both coexist in the graph. Distillers can
retrieve "finest-grained attribution" by preferring sub-vertex edges
over parent edges when both exist for the same (source, target) pair.

**Vertex type, not relation, discriminates semantics.** `component_of`
is intentionally neutral — `thread`, `memory-region`, and `module`
all use the same relation. Queries discriminate by vertex type:
`v-001-*` with `type: thread` finds execution sub-entities; with
`type: memory-region` finds address-space sub-entities. This matches
the broader pattern: vertex type is the primary semantic discriminator;
relation name is a structural label.

**Do not pre-decompose.** A vertex is atomic until a lead forces the
distinction. Pre-decomposing adds sub-entities the investigation hasn't
needed to reason about — graph clutter with no discrimination value.

### When to use `command` + `targeted` vs entity + edge verb

SIEM observations come in two shapes. The choice depends on what
happened in the world, not on which lead or hypothesis the observation
is being offered against.

**Lifecycle observations** materialize a persistent entity: a process
that now exists on a host, a file that now has new content, a container
that was started, a socket that was opened, a login session that was
established. The entity outlives the event that created it and the
investigation will refer to it as a noun. Model the entity as a vertex
of its own type; model the event with an edge verb (`spawned`, `wrote`,
`runs_in`, `opened`, `triggered_by`, `authenticated_as`, …).

**Action observations** are audit-log records of an operation. What
the log captures is the invocation itself — who called what with which
arguments — recorded by a control plane. Model as a `command` vertex
carrying the action's attributes, with `targeted → <thing acted on>`
and (when applicable) `executed_in → session`. This covers cloud API
calls, failed auth attempts, list/query/describe operations, and
configuration changes.

**Control-plane CRUD is uniformly action-shaped.** `iam:CreateUser`,
`s3:DeleteObject`, and `s3:GetObject` all model as `command` vertices,
even when the operation creates, deletes, or mutates an entity. Promote
the target to its own vertex only if subsequent reasoning actually
references it as a noun. Until then, the command alone is sufficient.

**Discriminator:** is the observation's natural noun an invocation
(who, what, when, against what target)? → action. Is it an entity
whose later state the investigation will reason about? → lifecycle.

**Examples:**

| Observation                                                 | Perspective | Modeling                                                                |
|-------------------------------------------------------------|-------------|-------------------------------------------------------------------------|
| Falco: bash spawned in container                            | lifecycle   | `process(bash)` + `spawned` from parent process                         |
| Wazuh FIM: write to `/etc/passwd` (writer known)            | lifecycle   | `process(tee)` + `wrote` to `file(/etc/passwd)`                         |
| Windows 4624: interactive logon as `CORP\alice`             | lifecycle   | `session` + `authenticated_as` to `identity(alice)`                     |
| CloudTrail: `s3:ListObjectsV2` from a service role          | action      | `command(s3-list-call)` + `targeted` to `storage` bucket                |
| CloudTrail: `iam:CreateUser` by admin principal             | action      | `command(iam-create-user-call)` + `targeted` to `identity(new-user)`    |
| sshd-audit: failed login as `sensu`                         | action      | `command(ssh-auth-attempt)` + `targeted` to `endpoint`                  |
| kube-audit: pods/exec on container                          | action      | `command(kube-exec-call)` + `targeted` to `container`                   |

### Unknown endpoints in lifecycle observations (placeholder vertices)

Lifecycle observations require two endpoints but telemetry sometimes
reports only one. Write a placeholder vertex with `placeholder: true`
and `classification: unknown`. The placeholder carries whatever
observed properties are available in `attributes`. Model the lifecycle
edge normally from/to the placeholder.

If a later lead identifies the real entity, append a new real vertex
and link with an `identified_as` edge from the placeholder. Never
mutate the placeholder.

```yaml
vertex:
  id: v-{nonce}
  type: process | socket | file | ip | identity | container | session
      | endpoint | storage | database | network-device | command | thread
      | memory-region | module
  classification: <string>
  identifier: <string>
  attributes: <object>           # omit if empty
  trust_root: true               # omit when false
  placeholder: true              # omit when false
  concerns: [<string>, ...]      # omit if empty
  citations: [<string>]          # emit when evidence traces to multiple sources
```

`thread`, `memory-region`, and `module` are sub-entity types produced
by inward decomposition. They follow the `v-{parent}-{nonce}` ID
convention and connect to their parent via `component_of`.

---

## 4. Vertex schema (summary)

See §3 for the full vertex record inline. Vendor specifics live in
`attributes.kind`. Trust posture lives in `classification`.
`trust_root: true` marks a vertex where backward traversal halts.
The `anchor-source` type from v2.2 is **removed**.

---

## 5. Edge schema

```yaml
edge:
  id: e-{nonce}
  relation: <string>             # from §10
  source_vertex: v-{id}
  target_vertex: v-{id}
  when: { timestamp: <iso> }     # optional
  attributes: <object>           # omit if empty
  status: observed | hypothesized | refuted   # omit when observed
  authority:
    kind: siem-event | runtime-audit | authoritative-source
        | client-asserted | inferred-structural
    source: <string>
    trust_chain: [<anchor-id>, ...]   # omit if empty
  concerns: [<string>, ...]      # omit if empty
```

---

## 6. Hypothesis schema, the discrimination-level rule, and the leanness rule

### The investigation graph and hypothesis extensions

At any point in the investigation, the graph has two layers:

- **Confirmed layer** — vertices and edges with authority-backed
  observations (prologue + lead materializations).
- **Proposed layer** — the competing frontier of candidate extensions,
  one proposed subgraph per active hypothesis.

A hypothesis is a proposed extension of the confirmed graph anchored
to at least one confirmed vertex. It answers: "if this hypothesis
holds, the following upstream cause exists and connects to the confirmed
graph via this relation." Leads test whether proposed elements
actually exist, moving them from proposed to confirmed (or refuting
them).

Two kinds of extension occur in practice:

- **Upstream extension** (the normal case): proposes what *caused*
  the anchor vertex to exhibit the observed behavior. The proposed
  vertex is external and upstream — a process that ran on an endpoint,
  a session that initiated an action. Direction: cause → effect.
- **Inward extension** (rare): proposes that the anchor vertex has
  heterogeneous internal structure. The proposed vertices are sub-
  entities inside the anchor. See §3 vertex decomposition.

Both anchor to a confirmed vertex. Both use one-hop proposed edges.
The difference is direction: outward-upstream vs inward-decomposing.

### The discrimination-level rule (recap from v2)

A hypothesis lives at the **deepest materialized vertex where
explanations genuinely fork**. Run mechanical scope leads first if
the immediate parent is opaque.

### `proposed_edge.parent_vertex` is exactly one backward hop (recap from v2.2)

The `parent_vertex` inside `proposed_edge` describes the **immediate
upstream vertex**, not a distant ancestor. Count edges from
`attached_to_vertex` to `parent_vertex.type`: it must be exactly one.

### The leanness rule (recap from v2.3)

A hypothesis describes the **immediate next discrimination question**,
not a deep causal narrative. Lean hypotheses have 1-2 predictions.
Refine via hierarchical IDs only when evidence forces the distinction.

### Schema

```yaml
hypothesis:
  id: h-{nonce} | h-{parent-id-suffix}-{nonce}
  name: "?descriptive-mechanism-name"
  attached_to_vertex: v-{id}        # anchor: structural graft point in confirmed graph

  explains:                          # optional — omit when both lists are empty
    edges: [e-{id}, ...]             # confirmed edges whose existence this hypothesis accounts for
    vertices: [v-{id}, ...]          # confirmed/placeholder vertices being identified

  proposed_edge:
    relation: <string>              # exactly one backward (or inward) hop
    parent_vertex:
      type: <string>
      classification: <string>
      attributes: <object>          # optional

  predictions:
    - id: p1
      claim: "<source-agnostic claim about world state>"

  refutation_shape:
    - id: r1
      claim: "<observation contradicting a core prediction>"

  concerns: []                      # omit if empty
  weight: "++" | "+" | "-" | "--" | null
  weight_history: []                # omit until there are transitions
  status: active                    # omit; emit when non-default
```

**`explains` field (new in v2.4).** The semantic pointer to what
the hypothesis accounts for in the confirmed graph.

- `explains.edges` — the confirmed edge(s) whose existence this
  hypothesis is trying to explain. For Q1 hypotheses (explaining the
  original alert edge) this is typically `[e-001]`. For Q2 hypotheses
  (explaining why a materialized vertex exists/acted), this is the
  edge that connected that vertex to the graph. Following `explains.edges`
  across a refinement chain traces the full backward explanation path.
- `explains.vertices` — confirmed or placeholder vertices being
  identified. Use when a hypothesis simultaneously identifies an
  unknown/placeholder vertex AND explains the edge it participated in
  (the coupled case — the two questions are inseparable when the edge's
  endpoint is a placeholder).
- Both are optional lists. Omit `explains` entirely when neither applies
  (rare — most hypotheses explain at least one edge).

**No `canonical` field.** The distiller recognizes seed-matching
hypotheses post-hoc.

**Lean hypotheses typically have 1-2 predictions.** Refined hypotheses
may have 3+ predictions, but each should be independently testable.

---

## 7. Lead block

### Leads as graph operations

Leads are operations on the investigation graph in one of two modes:

- **Topology-extending leads** materialize new vertices and edges
  (confirmed layer grows). They discriminate between competing
  hypothesis proposals. `intended_hypothesis_set` declares which
  proposals are being tested.
- **Attribute-refining leads** enrich existing confirmed vertices
  without adding new topology. They answer "what more do we know
  about this entity?" Output goes in `attribute_updates`, not
  `observations`. Scope leads are always attribute-refining. Trust
  leads may be either, or both.

The `mode` field (scope / materialize / trust) describes the query
source. `intended_hypothesis_set` is present when the lead
discriminates between hypotheses, absent when it only refines
attributes.

```yaml
gather:
  - lead:
      id: l-{nonce}
      loop: <int>
      name: <string>
      mode: materialize | scope | trust
      target: v-{id}
      intended_hypothesis_set: [h-{id}, ...]   # required for materialize; present for
                                                # trust leads that discriminate; omit for
                                                # scope and attribute-only trust leads

      observes:                                # optional
        - { hypothesis: h-{id}, predictions: [p1, p2], refutations: [r1] }

      query_details:
        system: <string>
        template: <string>
        query: <string>
        time_window: <string>
        substitutions: <object>

      concerns: [<string>, ...]                # omit if empty

      outcome:
        attribute_updates:                     # optional — scope/trust leads refining
          - vertex: v-{id}                     # existing vertex attributes
            updates: <object>

        observations:
          vertices: [<full vertex records>]
          edges: [<full edge records>]

        trust_anchor_result:                   # required for mode=trust when an anchor was queried
          anchor_id: <string>
          kind: <anchor-name>
          result: confirmed | refuted | partial | no-data
          as_of: <iso-timestamp>
          authority_for_question: full | partial

        trust_root_reached: v-{id}             # omit when null
        failure_reason: <string>               # omit unless error/degraded

      new_hypotheses: [<full hypothesis records>]
      shelved: [h-{id}, ...]

      resolutions:
        - hypothesis: h-{id}
          before: "+" | "-" | "++" | "--" | null
          after: "+" | "-" | "++" | "--"
          severity_of_test: severe | moderate | weak
          matched_prediction_ids: [p1, p2, ...]
          matched_refutation_ids: [r1, ...]
          reasoning: "<...>"
          supporting_edges: [e-{id}, ...]
```

### `attribute_updates` (new in v2.4)

Records attribute refinements produced by scope or trust leads that
enrich existing vertices without adding new topology. Examples:

- A classification lookup returns that v-001 (source IP) is a known
  monitoring host → `attribute_updates: [{vertex: v-001, updates:
  {classification: monitoring-host}}]`
- A trust anchor confirms an identity's employment status → update
  v-005's `attributes.employment_status`

`attribute_updates` and `observations` are independent — a trust lead
can both refine an existing vertex (in `attribute_updates`) and
materialize new vertices (in `observations`). Scope leads that
previously used `observations: { vertices: [], edges: [] }` to record
conceptual-only results should use `attribute_updates` instead, or
omit the outcome block entirely if there is nothing to record.

The substantive anchor return goes in `observations` when it describes
graph entities; `attribute_updates` is for enriching already-confirmed
entities that cannot be re-materialized (they already exist in the
confirmed layer from an earlier step).

### `outcome.trust_anchor_result` (recap from v2.3)

Required for `mode: trust` leads that consulted an anchor. Five
fields: `{anchor_id, kind, result, as_of, authority_for_question}`.

- **`result`** — `confirmed | refuted | partial | no-data`
- **`as_of`** — ISO-8601 timestamp the answer is **authoritative
  about**: event-time for event anchors, query-time for current-state
  anchors, last-sync-time for slowly-changing references.
- **`authority_for_question`** — `full` or `partial`. Partial caps
  weight per rule 16 (see §12).

### `failure_reason` convention

`adapter-error` | `attribution-opaque` | `partial-coverage` |
`permission-denied` | `timeout` | `other`

### Severity of test

| Severity   | Meaning                                                                       | Max weight effect       |
|------------|-------------------------------------------------------------------------------|-------------------------|
| `severe`   | Outcome directly contradicts or directly confirms a core prediction           | up to `++` / `--`       |
| `moderate` | Outcome constrains plausibility without directly contradicting                | one step                |
| `weak`     | Circumstantial consistency                                                     | caps at `+` or `-`      |

---

## 8. Conclude block

```yaml
conclude:
  termination:
    category: trust-root | adversarial-refuted | severity-ceiling | exhaustion-escalation
    rationale: <string>
  disposition: benign | true_positive | unclear
  confidence: high | medium | low
  matched_archetype: <name> | null
  ceiling_test:                # required when termination.category = severity-ceiling
    kind: out-of-band-human-contact | tool-unavailable | legal-authorization | other
    subject: <string>
  ceiling_rationale: <string>  # human-readable rationale (still required for severity-ceiling)
  summary: <string>
```

### Termination categories

- **`trust-root`** — backward traversal reached a vertex where further
  traversal would require evidence not accessible to this agent. The
  proposed layer collapses.
- **`adversarial-refuted`** — every adversarial hypothesis proposal has
  been explicitly refuted by confirmed evidence.
- **`severity-ceiling`** — the proposed layer contains live hypotheses
  whose critical edges cannot be queried with available tools. A
  structured `ceiling_test` records the out-of-band test that would
  resolve it.
- **`exhaustion-escalation`** — loop budget exhausted with unresolved
  hypotheses.

---

## 9. Classifications (seed vocabulary)

**Process / Thread / Memory-region / Module:**
- Process: `service-entrypoint-process`, `service-child-process`,
  `interactive-shell-in-workload`, `host-runtime-shim`,
  `operator-tool-invocation`, `automation-pipeline-process`,
  `unclassified-process`
- Thread: `service-thread`, `injected-thread`, `unclassified-thread`
- Memory-region: `code-region`, `injected-region`, `stack-region`,
  `heap-region`, `unclassified-memory-region`
- Module: `system-module`, `application-module`, `unknown-module`,
  `unclassified-module`

**Container:**
- `runtime-workload`, `sidecar-workload`, `build-container`,
  `debug-container`, `unclassified-container`

**Endpoint** *(replaces host, device, remote-endpoint)*:
- `kubernetes-worker-node`, `kubernetes-control-plane`, `bastion-host`,
  `corporate-laptop`, `developer-workstation`, `production-server`,
  `ci-runner-host`, `internal-endpoint`, `external-endpoint`,
  `unknown-endpoint`, `unclassified-endpoint`
- `attributes.kind ∈ {linux-vm, windows-laptop, ec2-instance, gcp-vm,
  azure-vm, baremetal, container-host, …}`

**Identity** *(replaces user)*:
- `employee-with-exec-rbac`, `employee-without-exec-rbac`,
  `automation-identity`, `shared-service-role`, `dedicated-service-role`,
  `unknown-attacker`, `unclassified-identity`
- `attributes.kind ∈ {user, group, role, service-account, application}`
- `attributes.provider ∈ {aws-iam, azure-ad, okta, gcp-iam, linux-pam,
  k8s-rbac, corp-sso, …}`

**Storage:**
- `customer-pii-store`, `internal-restricted-store`, `public-shared-store`,
  `secrets-vault`, `application-state-store`, `audit-log-store`,
  `unclassified-storage`
- `attributes.kind ∈ {object-store, block, file, secrets, nfs}`

**Database:**
- `customer-pii-database`, `internal-restricted-database`,
  `application-state-database`, `audit-log-database`, `analytics-database`,
  `unclassified-database`
- `attributes.kind ∈ {postgres, mysql, mariadb, mongodb, dynamodb,
  mssql, oracle, snowflake, redshift, elasticsearch, …}`

**Network-device:**
- `perimeter-firewall`, `internal-firewall`, `vpn-concentrator`,
  `core-switch`, `edge-router`, `application-load-balancer`,
  `web-application-firewall`, `unclassified-network-device`
- `attributes.kind ∈ {firewall, switch, router, load-balancer, vpn, waf}`

**Session:**
- `kubectl-exec-session`, `ssh-session`, `iam-role-session`,
  `iam-user-session`, `service-session`, `mfa-session`,
  `unclassified-session`

**IP:**
- `corp-vpn-egress`, `internal-cluster-node`, `internal-corp-network`,
  `external-sanctioned-automation`, `unclassified-ip`

**Command:**
- `ssh-auth-attempt`, `kubectl-exec-call`, `s3-list-call`, `s3-get-call`,
  `rds-query-call`, `sudo-invocation`, `file-write`, `process-spawn`,
  `cloud-api-call`, `unclassified-command`

Use `unclassified-{type}` or `ambiguous-{a}-or-{b}` when applicable.
Vendor specifics live in `attributes.kind`, never in the type itself.

---

## 10. Relation catalog

| Relation               | Source → Target                                                                            |
|------------------------|--------------------------------------------------------------------------------------------|
| `spawned`              | process → process                                                                          |
| `executed`             | process → file                                                                             |
| `loaded_by`            | process → library-file                                                                     |
| `opened`               | process → socket                                                                           |
| `connected_to`         | socket → endpoint                                                                          |
| `read` / `wrote`       | process → file                                                                             |
| `runs_in`              | process → container                                                                        |
| `runs_on`              | container → endpoint, process → endpoint, database → endpoint                             |
| `authenticated_as`     | session → identity                                                                         |
| `initiated_by`         | session → identity \| endpoint                                                             |
| `triggered_by`         | process \| session → process \| session                                                    |
| `escalated_privilege`  | session → session (self-edge)                                                              |
| `executed_in`          | command → session                                                                          |
| **`targeted`**         | **command → endpoint \| storage \| database \| identity \| file \| container \| network-device** |
| `member_of`            | identity → identity                                                                        |
| `classified_as`        | vertex → classification-value                                                              |
| `identified_as`        | placeholder-vertex → real-vertex (post-hoc attribution, §3)                               |
| **`component_of`**     | **vertex → vertex** (sub-entity → containing entity; inward decomposition, §3)            |
| `listed`               | session \| process → storage \| database                                                   |
| `modified`             | session \| process → storage \| database \| identity \| file                              |
| `attempted_auth`       | endpoint \| process \| session → endpoint                                                  |

**Notes:**

- **`targeted`** is the generic action-target relation for command
  vertices. Use for SIEM-observed actions per §3. **Do NOT use for
  lifecycle events.**
- **`component_of`** (new in v2.4) is the part-of relation for inward
  vertex decomposition. Source is the sub-entity; target is the
  containing entity. Vertex type discriminates semantics — `thread`,
  `memory-region`, and `module` all use this relation; the query layer
  filters by type. Use hierarchical IDs (`v-{parent}-{nonce}`) for
  decomposed sub-vertices to enable prefix-based retrieval. See §3
  vertex decomposition for the full convention.
- **`connected_to`** — transport-layer socket → endpoint. Do not abuse
  for actions.
- **`runs_on`** captures compute-substrate relationships.
- **`listed`**, **`modified`**, **`attempted_auth`** are per-walk
  proposal entries pending broader case exercise before landing as
  permanent catalog entries.
- **`identified_as`** — append-only escape hatch for placeholder
  vertices. Never mutate a placeholder; append a real vertex and link.
- **`attested_by`** (v2.2) removed — its job is done by
  `outcome.trust_anchor_result`.

---

## 11. Authority table — OBSERVATIONAL ONLY, NOT LEGITIMACY

| Authority kind           | Meaning                                                                    | Max weight supportable |
|--------------------------|----------------------------------------------------------------------------|------------------------|
| `siem-event`             | Backed by a SIEM / audit log event                                         | `++` / `--`            |
| `runtime-audit`          | Backed by a runtime or OS audit stream                                     | `++` / `--`            |
| `authoritative-source`   | From a source authoritative for this observation question                  | `++` / `--`            |
| `client-asserted`        | From a self-reported field                                                 | `+` / `-`              |
| `inferred-structural`    | Inferred from co-occurrence                                                | `+` / `-`              |

Authority describes how reliably the source **recorded the observation**.
It does NOT claim the observed action was authorized, benign, or
correctly interpreted.

### Per-question authority is at the lead level

**Per-question authority** — whether the source has full or partial
coverage for the semantic question being asked — lives at the lead
level in `outcome.trust_anchor_result.authority_for_question`.

### Trust chain promotion

A `client-asserted` edge on a verified trust chain gets effective
`authoritative-source` authority. Record the chain in
`edge.authority.trust_chain`.

---

## 12. Write-time validator rules

1. **Schema validity.** Required fields present, enum values valid,
   IDs well-formed (including hierarchical ID formats for hypotheses
   and decomposed sub-vertices).
2. **Classification vocabulary.** Every `classification` in §9 or a
   `{type}:{slug}` provisional.
3. **Relation catalog.** Every `edge.relation` in §10.
4. **Edge authority rule.** Strong-weight (`++`/`--`) resolutions cite
   at least one strong-authority supporting edge (§11).
5. **Refutation ID match.** Every `--` resolution's
   `matched_refutation_ids` is non-empty and references real IDs.
6. **Prediction ID match + completeness for `++`.** Every `++`
   resolution's `matched_prediction_ids` is non-empty; the union
   across resolutions must equal the full prediction set; partial
   coverage caps at `+`.
7. **ID references resolve.** All `v-*`, `e-*`, `h-*`, `l-*`
   references point to records that exist — including IDs in
   `explains.edges` and `explains.vertices` (new in v2.4).
8. **Append-only.** No record is mutated.
9. **Self-containment of lead blocks.** Every vertex/edge/hypothesis
   produced by a lead lives inside that lead's `outcome.observations`,
   `new_hypotheses`, or `shelved`.
10. **Scope leads omit `intended_hypothesis_set`.**
11. **Mechanical leads stay within their data source.**
12. **`observes` subset (when present).**
13. **Trust lead requires `trust_anchor_result`** when the lead
    consulted an anchor. Exception: trust leads where the anchor
    query failed — `failure_reason` is set instead.
14. **Hierarchical hypothesis ID consistency:** a hypothesis with ID
    `h-001-002` requires that `h-001` exists in the same companion.
15. **`ceiling_test` requires severity-ceiling termination** and is
    forbidden otherwise.
16. **`partial` authority caps weight:** a resolution citing ONLY a
    `trust_anchor_result` with `authority_for_question: partial`
    cannot push a hypothesis to `++` or `--`. Cap is `+` / `-`.
17. **`explains` IDs resolve (new in v2.4):** all IDs in
    `explains.edges` and `explains.vertices` must reference records
    that exist in the companion. IDs in `explains.vertices` should
    reference vertices that are confirmed in the graph at the point
    the hypothesis is written (typically prologue vertices or
    vertices materialized by an immediately prior lead).
18. **`component_of` sub-vertex ID convention (new in v2.4):**
    vertices using `component_of` should follow the `v-{parent}-{nonce}`
    ID convention. Not mechanically enforced; enforced by review.

---

## 13. Worked example — RDS query on customer-PII outside service-role pattern

A CloudTrail alert fires on role `data-pipeline-svc` issuing an unusual
`SELECT FROM customer_pii` query against `rds-prod-customers` at 02:17
UTC. The role has RDS query permission; ~30 batch jobs share the role;
the query is outside the role's documented access pattern.

This example exercises: the action-as-vertex pattern, the new types
(`endpoint`, `identity`, `database`), `trust_anchor_result` at lead
level, **a lean hypothesis refined into hierarchical children**,
partial-authority capping, severity-ceiling termination, and the new
v2.4 **`explains` field** on hypotheses.

```yaml
prologue:
  vertices:
    - id: v-001
      type: command
      classification: rds-query-call
      identifier: "SELECT FROM customer_pii by data-pipeline-svc @02:17:04Z"
      attributes:
        api_name: "rds-data:ExecuteStatement"
        sql_summary: "SELECT * FROM customer_pii LIMIT 1000"
        status: succeeded
        rows_returned: 943
      citations: ["cloudtrail:event=evt-abc123"]

    - id: v-002
      type: identity
      classification: shared-service-role
      identifier: "data-pipeline-svc"
      attributes:
        kind: role
        provider: aws-iam
        arn: "arn:aws:iam::123456789012:role/data-pipeline-svc"
      concerns:
        - "shared role: ~30 nightly batch jobs assume this role; identity at this layer cannot attribute to a specific job or human"

    - id: v-003
      type: database
      classification: customer-pii-database
      identifier: "rds-prod-customers"
      attributes:
        kind: postgres
        instance: "rds-prod-customers"
        database: "customers"
        table_accessed: "customer_pii"
        sensitivity: "customer-pii"
      concerns:
        - "data-pipeline-svc has read permission on this database, but customer_pii is outside its documented access pattern"

    - id: v-004
      type: session
      classification: iam-role-session
      identifier: "iam-role-session: data-pipeline-svc @02:17:04Z"
      attributes:
        role_arn: "arn:aws:iam::123456789012:role/data-pipeline-svc"
        session_name: "i-0a1b2c3d-1750000000"
        source_ip: "10.0.4.55"

    - id: v-005
      type: endpoint
      classification: production-server
      identifier: "i-0a1b2c3d (ec2)"
      attributes:
        kind: ec2-instance
        instance_id: "i-0a1b2c3d"
        region: "us-east-1"
        ip: "10.0.4.55"

  edges:
    - id: e-001
      relation: executed_in
      source_vertex: v-001
      target_vertex: v-004
      authority:
        kind: authoritative-source
        source: "cloudtrail:event=evt-abc123"

    - id: e-002
      relation: targeted
      source_vertex: v-001
      target_vertex: v-003
      when: { timestamp: "2026-04-14T02:17:04Z" }
      authority:
        kind: authoritative-source
        source: "cloudtrail:event=evt-abc123"

    - id: e-003
      relation: authenticated_as
      source_vertex: v-004
      target_vertex: v-002
      authority:
        kind: authoritative-source
        source: "cloudtrail:event=evt-abc123"

    - id: e-004
      relation: initiated_by
      source_vertex: v-004
      target_vertex: v-005
      authority:
        kind: inferred-structural
        source: "cloudtrail:event=evt-abc123:source_ip=10.0.4.55"

# Discrimination level is at v-004 (the role-session).
# All three hypotheses explain e-001 (the command's executed_in edge)
# and e-002 (the targeted edge) — they are answering "why did this
# role-session execute this query?" The explains field makes this explicit.
hypothesize:
  hypotheses:
    - id: h-001
      name: "?scheduled-batch-run"
      attached_to_vertex: v-004
      explains:
        edges: [e-001, e-002]
      proposed_edge:
        relation: triggered_by
        parent_vertex:
          type: command
          classification: scheduled-job-invocation
      predictions:
        - id: p1
          claim: "a job-scheduler entry exists assigning role data-pipeline-svc to a job that runs at ~02:17 UTC and queries customer_pii"
      refutation_shape:
        - id: r1
          claim: "no registered job assigns this role + table + time-window combination"
      weight: null

    # Lean hypothesis. Captures "human-attributable session" without
    # pre-committing to operator-vs-attacker. Refines at loop 2 if a
    # human session is materialized. explains points to the same edges
    # as h-001 — all three hypotheses are competing over the same
    # observation.
    - id: h-002
      name: "?interactive-human-action"
      attached_to_vertex: v-004
      explains:
        edges: [e-001, e-002]
      proposed_edge:
        relation: triggered_by
        parent_vertex:
          type: session
          classification: ssh-session
      predictions:
        - id: p1
          claim: "an interactive session (SSH or equivalent) on v-005 (i-0a1b2c3d) overlaps temporally with the role assumption at 02:17"
      refutation_shape:
        - id: r1
          claim: "no interactive session on v-005 in the ±5m window around the role assumption"
      weight: null

    - id: h-003
      name: "?compromised-role-credential"
      attached_to_vertex: v-004
      explains:
        edges: [e-001, e-002]
      proposed_edge:
        relation: authenticated_as
        parent_vertex:
          type: identity
          classification: unknown-attacker
      predictions:
        - id: p1
          claim: "the role session originates from an IP, network path, or signing identity that does not match the documented data-pipeline-svc usage pattern"
      refutation_shape:
        - id: r1
          claim: "the role session originates from a corp-internal compute endpoint matching the documented data-pipeline-svc usage pattern"
      concerns:
        - "stolen role credentials are unfalsifiable without out-of-band MDM/SSO trust-chain evidence"
      weight: null

gather:
  - lead:
      id: l-001
      loop: 1
      name: "anchor-lookup(job-scheduler)"
      mode: trust
      target: v-004
      intended_hypothesis_set: [h-001]
      observes:
        - hypothesis: h-001
          predictions: [p1]
          refutations: [r1]
      query_details:
        system: job-scheduler
        template: "leads/anchor-lookup/templates/job-scheduler.md"
        query: "registered jobs for role=data-pipeline-svc table=customer_pii window=02:00-03:00 UTC"
        time_window: "02:00-03:00 UTC 2026-04-14"
      outcome:
        observations: { vertices: [], edges: [] }
        trust_anchor_result:
          anchor_id: job-scheduler
          kind: job-scheduler
          result: refuted
          as_of: "2026-04-14T02:17:30Z"
          authority_for_question: full
      resolutions:
        - hypothesis: h-001
          before: null
          after: "-"
          severity_of_test: severe
          matched_refutation_ids: [r1]
          reasoning: "job-scheduler returned no registered job for (data-pipeline-svc, customer_pii, 02:17 window). r1 directly satisfied. Not -- because the refutation is local to the canonical scheduler; does not exclude misregistered or out-of-band scheduled work."
          supporting_edges: []

  - lead:
      id: l-002
      loop: 1
      name: "scope(endpoint, interactive-sessions)"
      mode: scope
      target: v-005
      query_details:
        system: host-audit
        template: "leads/concurrent-sessions/templates/host-audit.md"
        query: "interactive sessions on i-0a1b2c3d ±5m around 02:17:04Z"
        time_window: "02:12:04Z - 02:22:04Z"
      outcome:
        observations:
          vertices:
            - id: v-006
              type: session
              classification: ssh-session
              identifier: "ssh-session: marcus@i-0a1b2c3d @02:14:20Z"
              attributes:
                tty: "pts/0"
                started_at: "2026-04-14T02:14:20Z"
                still_active: true
            - id: v-007
              type: identity
              classification: employee-with-exec-rbac
              identifier: "marcus@company.com"
              attributes:
                kind: user
                provider: corp-sso
                email: "marcus@company.com"
          edges:
            - id: e-005
              relation: authenticated_as
              source_vertex: v-006
              target_vertex: v-007
              authority:
                kind: runtime-audit
                source: "host-audit:i-0a1b2c3d:sshd"
            - id: e-006
              relation: triggered_by
              source_vertex: v-001
              target_vertex: v-006
              when: { timestamp: "2026-04-14T02:17:04Z" }
              authority:
                kind: inferred-structural
                source: "process-tree correlation: marcus's bash → aws cli → rds-data:ExecuteStatement"

      # h-002 (?interactive-human-action) was lean. The scope lead
      # materialized the human session. Refine into discriminable
      # sub-hypotheses, shelve the parent. The children explain the
      # newly materialized edge e-006 (triggered_by session → command),
      # which is the Q2 question: why did this session trigger this action?
      shelved: [h-002]
      new_hypotheses:
        - id: h-002-001
          name: "?ad-hoc-operator-direct"
          attached_to_vertex: v-006
          explains:
            edges: [e-006]    # Q2: explains why the materialized session triggered the command
          proposed_edge:
            relation: authenticated_as
            parent_vertex:
              type: identity
              classification: employee-with-exec-rbac
          predictions:
            - id: p1
              claim: "marcus authenticated to the SSH session via MFA from a compliant device"
            - id: p2
              claim: "the SQL query is justified by a known operational task (change ticket, on-call response)"
          refutation_shape:
            - id: r1
              claim: "marcus did not MFA at session start"
            - id: r2
              claim: "no operational justification exists for the SQL query"
          weight: null

        - id: h-002-002
          name: "?stolen-credential-via-session"
          attached_to_vertex: v-006
          explains:
            edges: [e-006]    # same Q2 edge; competing with h-002-001
          proposed_edge:
            relation: authenticated_as
            parent_vertex:
              type: identity
              classification: unknown-attacker
          predictions:
            - id: p1
              claim: "the SSH session origin or auth context shows an anomaly inconsistent with marcus's normal pattern"
          refutation_shape:
            - id: r1
              claim: "the SSH session originated from marcus's MFA-verified, MDM-compliant device on his usual network path"
          concerns:
            - "stolen credentials are unfalsifiable without MDM trust-chain evidence"
          weight: null

      resolutions:
        - hypothesis: h-001
          before: "-"
          after: "--"
          severity_of_test: moderate
          matched_refutation_ids: [r1]
          reasoning: "interactive SSH session active on v-005 — strong evidence query was human-initiated, not scheduled. Combined with l-001 no-registered-job, h-001 is now --."
          supporting_edges: [e-005, e-006]

  - lead:
      id: l-003
      loop: 2
      name: "anchor-lookup(vpn-mfa)"
      mode: trust
      target: v-007
      intended_hypothesis_set: [h-002-001, h-002-002]
      observes:
        - hypothesis: h-002-001
          predictions: [p1]
          refutations: [r1]
        - hypothesis: h-002-002
          predictions: [p1]
          refutations: [r1]
      query_details:
        system: vpn-mfa
        template: "leads/anchor-lookup/templates/vpn-mfa.md"
        query: "MFA authentications for marcus@company.com between 02:00-02:20 UTC 2026-04-14"
      outcome:
        observations:
          vertices:
            - id: v-008
              type: session
              classification: mfa-session
              identifier: "marcus mfa session @02:13:50Z"
              attributes:
                started_at: "2026-04-14T02:13:50Z"
                method: "yubikey-touch"
                device_id: "macbook-marcus-2025"
                device_compliant: true
                device_attested_by: "mdm-jamf"
          edges:
            - id: e-007
              relation: authenticated_as
              source_vertex: v-008
              target_vertex: v-007
              when: { timestamp: "2026-04-14T02:13:50Z" }
              authority:
                kind: authoritative-source
                source: "vpn-mfa:marcus@company.com:2026-04-14T02:13:50Z"
        trust_anchor_result:
          anchor_id: vpn-mfa
          kind: vpn-mfa
          result: confirmed
          as_of: "2026-04-14T02:13:50Z"
          authority_for_question: full
      resolutions:
        - hypothesis: h-002-001
          before: null
          after: "+"
          severity_of_test: severe
          matched_prediction_ids: [p1]
          reasoning: "vpn-mfa confirmed marcus MFA'd at 02:13:50Z from MDM-compliant device. p1 confirmed via e-007 (authoritative-source). p2 (operational justification) not tested by this lead. Caps at + per rule 6 completeness."
          supporting_edges: [e-007]
        - hypothesis: h-002-002
          before: null
          after: "-"
          severity_of_test: severe
          matched_refutation_ids: [r1]
          reasoning: "vpn-mfa confirmed marcus MFA'd from his MDM-compliant device (v-008, e-007). r1 satisfied. Not -- because residual stolen-credential scenarios remain unfalsifiable."
          supporting_edges: [e-007]

  - lead:
      id: l-004
      loop: 2
      name: "anchor-lookup(change-management)"
      mode: trust
      target: v-007
      intended_hypothesis_set: [h-002-001]
      observes:
        - hypothesis: h-002-001
          predictions: [p2]
          refutations: [r2]
      query_details:
        system: change-management
        template: "leads/anchor-lookup/templates/change-management.md"
        query: "open or recent tickets assigned to marcus@company.com touching customer_pii or rds-prod-customers 02:00-03:00 UTC"
      outcome:
        observations: { vertices: [], edges: [] }
        trust_anchor_result:
          anchor_id: change-management
          kind: change-management
          result: no-data
          as_of: "2026-04-14T02:18:10Z"
          authority_for_question: full
      resolutions:
        - hypothesis: h-002-001
          before: "+"
          after: "+"
          severity_of_test: moderate
          matched_refutation_ids: [r2]
          reasoning: "change-management returned no ticket for marcus touching customer_pii. r2 (no operational justification) satisfied. h-002-001 stays at + — human presence confirmed, justification absent. Disposition is to escalate with the operational-justification gap as the open question."
          supporting_edges: []

  - lead:
      id: l-005
      loop: 2
      name: "anchor-lookup(ec2-instance-integrity)"
      mode: trust
      target: v-005
      intended_hypothesis_set: [h-003]
      observes:
        - hypothesis: h-003
          predictions: [p1]
          refutations: [r1]
      query_details:
        system: ec2-instance-integrity
        template: "leads/anchor-lookup/templates/ec2-integrity.md"
        query: "integrity scan for i-0a1b2c3d at ±10m around 02:17:04Z"
      outcome:
        observations: { vertices: [], edges: [] }
        trust_anchor_result:
          anchor_id: ec2-instance-integrity
          kind: ec2-instance-integrity
          result: confirmed
          as_of: "2026-04-14T02:15:00Z"
          authority_for_question: partial    # covers disk + IMDSv2; not in-memory implants
      resolutions:
        - hypothesis: h-003
          before: null
          after: "-"
          severity_of_test: moderate
          matched_refutation_ids: [r1]
          reasoning: "ec2-instance-integrity returned clean for disk integrity and IMDSv2. r1 satisfied at the disk/IMDS layer. Validator rule 16 cap: authority_for_question is partial — does not cover in-memory implants. Weight cannot advance past -."
          supporting_edges: []

conclude:
  termination:
    category: severity-ceiling
    rationale: "h-002-001 at + with confirmed MFA but unmet operational justification. h-002-002 at -, unfalsifiable without out-of-band MDM trust-chain. h-003 capped at - by partial-authority on ec2-instance-integrity. No adversarial reaches --, no benign reaches ++."
  disposition: unclear
  confidence: medium
  matched_archetype: null
  ceiling_test:
    kind: out-of-band-human-contact
    subject: "marcus@company.com"
  ceiling_rationale: "the test that would close this case is direct confirmation from marcus that the SQL query was intentional and operationally justified (or denial, in which case h-002-002 advances). No anchor accessible to this agent can substitute."
  summary: "data-pipeline-svc role issued unusual SELECT FROM customer_pii at 02:17 UTC. h-001 (?scheduled-batch-run) refuted -- (no registered job, human session active). h-002 (?interactive-human-action) refined into h-002-001 (?ad-hoc-operator-direct, +: MFA confirmed, change ticket missing) and h-002-002 (?stolen-credential-via-session, -). h-003 (?compromised-role-credential) capped at -. Severity-ceiling: contact marcus@company.com. All hypothesis explains fields point to [e-001, e-002] for the Q1 pair and to [e-006] for the Q2 pair, tracing the explanation chain."
```

**Things to notice about v2.4 in this example:**

1. **`explains` traces the explanation chain.** h-001..h-003 all have
   `explains.edges: [e-001, e-002]` — they are competing explanations
   of the same Q1 observation. h-002-001 and h-002-002 have
   `explains.edges: [e-006]` — they are competing explanations of the
   Q2 observation (why did the materialized session trigger the command).
   Following `explains.edges` from the refined children back to the
   parent's edges traces the full Q1→Q2 backward path.

2. **`attribute_updates` is absent** in this example because all scope
   lead results materialize new vertices rather than purely refining
   existing ones. An example where `attribute_updates` applies: a
   scope lead that looks up v-001's source IP in an IP classification
   table and adds `classification: corp-vpn-egress` to the endpoint
   vertex without creating new entities.

3. **`component_of` is absent** — this investigation never needs inward
   decomposition. The vertex level (session, identity, endpoint) is the
   right granularity throughout.

---

## 14. What you write

1. **Read** the alert and retrieval-sim.
2. **Fill `prologue`** with vertices and edges. Use the action-vertex
   pattern (`command` + `targeted`) for SIEM-observed actions.
3. **Decide** whether to hypothesize now or run a mechanical scope
   lead first. If the alert's immediate parent is opaque, leave
   `hypothesize.hypotheses: []`.
4. **Write hypotheses lean.** State the immediate next discrimination
   claim. Add `explains.edges` pointing to the confirmed edge(s) being
   explained. Add `explains.vertices` when a hypothesis identifies a
   placeholder endpoint of the edge.
5. **Write each GATHER lead as a self-contained block.** Mechanical
   leads stay within their data source. Use `attribute_updates` when
   the lead only refines existing vertex attributes.
6. **Use `outcome.trust_anchor_result`** on every trust-mode lead that
   consulted an anchor.
7. **Refine lean hypotheses** when a lead materializes evidence that
   splits them. Children's `explains.edges` should point to the
   newly-materialized edge that made the Q2 question answerable.
8. **Cite prediction/refutation IDs** in resolutions.
9. **Write `conclude`** with termination, disposition, and (for
   severity-ceiling) the structured `ceiling_test`.

---

## 15. What v2.4 explicitly does NOT change

All distiller-side projections from v2.3 §15 remain as-is. The `explains`
field is a writer-side semantic pointer; distiller-side hypothesis
lineage recovery from hierarchical IDs is unchanged. The three-layer
model (confirmed graph / proposed extensions / leads-as-operations) is
the conceptual foundation of the schema; it is not surfaced as new
schema fields beyond the four changes in §A.
