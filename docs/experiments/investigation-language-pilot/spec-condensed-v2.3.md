# Investigation Language — Condensed Spec v2.3 (pilot, retrieval-aware)

Revised from v2.2 after the case-real-rule5710 fidelity exercise and the
case-a4 retrieval-needs walk. **Eight material changes** from v2.2, most
of which **simplify rather than expand** the schema. The retrieval-load
v2.2 attempted to carry in fields is moved to the distiller; the schema
gets smaller, more general, and more action-centric.

---

## §A — Changes from v2.2 (read first if you know v2.2)

1. **Drop `canonical` from hypothesis schema.** It was a post-ingestion
   concern (does this hypothesis match a seed in `hypothesis_index.yaml`?)
   imposed at write time. The distiller can recompute it post-hoc by
   matching hypothesis name + vertex shape against the seed library. No
   validator rule depended on it; no on-ingest payoff.

2. **Hierarchical hypothesis IDs for refinement chains.** Top-level
   hypotheses use `h-{nonce}` (e.g., `h-001`). Refinements use
   `h-{parent-id}-{nonce}` (e.g., `h-001-001` is a refinement of `h-001`;
   `h-001-001-001` is a refinement of that). Lineage is encoded in the
   ID itself; parent is recoverable by stripping the last segment.
   Walks cap at 7 loops, so worst-case length is ~27 characters. **No
   `derived_from` field is needed.**

3. **Lean hypothesis methodology.** Hypotheses describe the **immediate
   next discrimination question**, not a deep causal narrative. Lean
   hypotheses have **fewer predictions** and refine into more specific
   children only when evidence forces them. The refinement chain is
   expressed via hierarchical IDs (#2). Pre-committing to a deep
   narrative fragments the hypothesis space across cases that would
   otherwise be retrievable as the same pattern.

4. **Type vocabulary cleanup.** Five generalizations and one deprecation:
   - **`endpoint`** replaces `host`, `device`, and `remote-endpoint`. A
     compute unit with a rich OS — server, laptop, k8s node, EC2 instance,
     bastion. Vendor specifics in `attributes.kind`; trust posture in
     classification.
   - **`identity`** replaces `user`. Any authenticatable entity.
     `attributes.kind ∈ {user, group, role, service-account, application}`
     covers AWS principals, Azure AD objects, Okta users/groups, Linux
     PAM, k8s service accounts.
   - **`storage`** (new) for object/file/blob/secret stores.
     `attributes.kind ∈ {object-store, block, file, secrets, nfs}`.
   - **`database`** (new) for structured data systems with query
     interfaces, distinct from underlying compute.
     `attributes.kind ∈ {postgres, mysql, mongodb, dynamodb, mssql,
     oracle, snowflake, redshift, …}`.
   - **`network-device`** (new) for firewalls, switches, routers,
     load balancers, VPN concentrators, WAFs.
   - **`anchor-source` deprecated.** The information it carried (anchor
     identity + answer) moves to the new `trust_anchor_result`
     lead-level field (#6).

5. **Action-as-vertex via `command` + new `targeted` relation.** v2.2's
   `command` type was underused. v2.3 elevates it as the canonical
   pattern for SIEM-observed actions: a `command` vertex carries the
   action shape (verb, status, attributes), `executed_in` places it in
   its session context, and a new **`targeted: command → endpoint |
   storage | database | identity | file | container | network-device`**
   edge links the action to its target. This generalizes uniformly
   across CloudTrail, kube-audit, pam-audit, sshd-audit — all "actor
   performed action on target" shaped. **Control-plane CRUD is uniform**:
   reads, writes, creates, deletes, and updates (including
   `iam:CreateUser`-style ops that materialize entities) all start as
   `command` vertices; the target entity is promoted to its own vertex
   only when later reasoning references it. `connected_to` returns to
   its actual job (transport-layer socket → endpoint observations).
   See §3 for the full rule and worked examples.

6. **`outcome.trust_anchor_result`** on trust-mode leads. A small
   structured field at the lead level carrying the anchor's verdict.
   Five writer fields only: `{anchor_id, kind, result, as_of,
   authority_for_question}`. **No `structured_fields` dict** — the
   normalized per-anchor projection that distillers want is derived
   from `observations` + a per-anchor schema in `anchor_manifest.yaml`,
   not typed by the writer. (The case-a1 translation showed every
   field a writer would put in `structured_fields` was already in
   observation vertex attributes — pure duplication.) The agent
   materializes the substantive anchor return as graph entities in
   `observations.vertices/edges`; `trust_anchor_result` carries only
   what's not already in the graph: anchor identity, the verdict
   enum, the timestamp the verdict is authoritative about, and the
   per-question authority cap. **`authority_for_question: partial`**
   expresses scope-partial anchor returns (e.g., `ec2-instance-integrity`
   covers disk + IMDSv2 but not in-memory implants); **`as_of`**
   expresses temporal validity independently (an hr-directory lookup
   against a 14-hour-stale sync is full-scope but temporally-stale).
   Closes the rule-5710 fidelity gap and A.4 R-3/R-6.

7. **`conclude.ceiling_test`** for severity-ceiling termination.
   `{kind: out-of-band-human-contact | tool-unavailable |
   legal-authorization | other, subject: <string>}`. Required when
   `termination.category: severity-ceiling`. Closes A.4 R-8.

8. **Distiller projects, not schema fields.** Retrieval needs derivable
   from existing schema (R-1, R-2, R-4, R-5, R-7, R-9, R-10 from the
   case-a4 walk) are explicitly punted to a **distillation/query
   script**. The schema does NOT carry: `trace`,
   `prediction_status_at_termination`, `escalation_handoff`,
   `correlated_with`, `final_weight`, `mandatory_adversarial`. These
   are distiller projections, computed once at case close, stored in
   the §5 retrieval indices.

**Net delta:** −1 hypothesis field (`canonical`), −4 vertex types
(`host`, `user`, `remote-endpoint`, `device`), −1 vertex type
(`anchor-source`), +5 vertex types (`endpoint`, `identity`, `storage`,
`database`, `network-device`), +2 relations (`targeted`, `identified_as`),
+1 vertex field (`placeholder`), +2 lead/conclude fields
(`trust_anchor_result` (5 writer fields: anchor_id, kind, result, as_of,
authority_for_question), `ceiling_test`). The schema is roughly the
same size but generalizes farther, is more action-centric, handles
unknown lifecycle endpoints honestly via placeholder vertices, and
pushes retrieval load to the distiller where it belongs.

---

## §B — Five v2 changes (recap)

1. **Journal form.** Four top-level keys: `prologue`, `hypothesize`,
   `gather`, `conclude`.
2. **Implicit defaults.** Fields at default are omitted.
3. **Discrimination-level hypothesis rule.** Run mechanical scope leads
   first if the immediate parent is opaque.
4. **Host context as attributes** on the container (when the container
   is the focus). v2.3 also allows a first-class `endpoint` vertex when
   the host itself is the focus.
5. **Mechanical leads stay within their data source.**

## §C — Five v2.1 changes (recap)

1. `intended_hypothesis_set` required on materialize/trust, omitted on
   scope.
2. No `execution` block on leads.
3. No `outcome.status` field.
4. No `source_lead` field.
5. Unified `concerns` field.

## §D — Six v2.2 changes (recap)

1. Prediction IDs + ID-based rule 6.
2. `abstract_type` → `type`.
3. `outcome.produced` → `outcome.observations`.
4. `anchor-backed` → `authoritative-source` + §11 clarification.
5. Optional `lead.observes` field.
6. `proposed_edge.parent_vertex` is exactly one backward hop.

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
    characters. No structural limit is enforced — the cap is methodology.
- **Predictions and refutation shapes within a hypothesis** carry their
  own IDs: `p1`, `p2`, … and `r1`, `r2`, …, scoped to the containing
  hypothesis.

**Implicit defaults — omit when at default.**

| Field                            | Default        | Emit when                                        |
|----------------------------------|----------------|--------------------------------------------------|
| `vertex.trust_root`              | `false`        | a successful trust lead sets it `true`           |
| `vertex.attributes`              | `{}`           | there are type-specific attributes to record     |
| `vertex.concerns`                | `[]`           | there's a limitation or trap worth flagging      |
| `edge.attributes`                | `{}`           | there are relation-specific attributes           |
| `edge.when`                      | omitted        | the relation is instantaneous or extended        |
| `edge.status`                    | `observed`     | `hypothesized` or `refuted`                      |
| `edge.concerns`                  | `[]`           | as for vertex.concerns                           |
| `edge.authority.trust_chain`     | `[]`           | a client-asserted edge sits on a promotion chain |
| `hypothesis.concerns`            | `[]`           | an alert-specific trap or residual               |
| `hypothesis.weight_history`      | `[]`           | there are recorded transitions                   |
| `hypothesis.status`              | `active`       | `confirmed`, `refuted`, or `shelved`             |
| `lead.concerns`                  | `[]`           | lead has a reliability, cost, or data concern    |
| `lead.observes`                  | omitted        | declaring testable prediction IDs                |
| `lead.outcome.failure_reason`    | omitted        | lead errored or returned degraded data           |
| `lead.outcome.trust_root_reached`| omitted        | a trust lead succeeded                           |
| `lead.outcome.trust_anchor_result`| omitted       | a trust lead consulted an anchor (required then) |

There is no `execution` block, no `outcome.status` field, no
`source_lead` field, and **no `canonical` field** on any record.
Structural position is authoritative.

---

## 3. Prologue block

Records derived directly from the alert, before any lead runs. The
example below uses v2.3 type vocabulary and the action-as-vertex pattern.

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
      classification: customer-pii-store
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

**The action-as-vertex pattern.** The SIEM-observed action is `v-001`
(a `command` vertex). It carries the action shape in attributes
(`api_name`, `sql_summary`, `status`). The `targeted` edge links the
action to what it acted on (the database). The session it executed in
is added by mechanical scope leads, not in the prologue.

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
(`runs_on`, `runs_in`, `executed_in`, `triggered_by`). They don't
*replace* it.

**Scale can change across loops.** A scope lead may materialize a
process tree (finer) inside a previously-materialized session
(coarser); both levels coexist in the graph, linked by containment
relations. Decompose to a finer scale only when evidence forces the
distinction — pre-decomposing fragments the graph without
discrimination value, and retroactive refinement via hierarchical
hypothesis IDs is the canonical v2.3 pattern for this.

**Aggregation is an attribute, not a vertex decomposition.** When an
observation describes N occurrences of something (17 ListObjectsV2
calls over a 172-second window; 93 auth events over 24 hours), the
aggregate belongs on a single vertex or edge with `count` + `window_*`
attributes. Do NOT materialize one vertex per occurrence. The SIEM's
native unit is the alert (a single detection event, even when the
alert describes aggregate activity); model at that unit, not finer.

**Cartography analogy.** A world map renders an island as opaque; a
city map shows streets; a building floor plan shows rooms. All three
are valid representations of the same land — the right one depends on
what question is being asked. The companion follows the same rule:
pick the scale that matches the investigation's reasoning, decompose
when evidence forces it, and accept that coarse-grained entities are
not "lies of omission" — they're just the right level of resolution.

### When to use `command` + `targeted` vs entity + edge verb

SIEM observations come in two shapes. The choice depends on what
happened in the world, not on which lead or hypothesis the observation
is being offered against.

**Lifecycle observations** materialize a persistent entity at the
abstraction level the investigation reasons at: a process that now
exists on a host, a file that now has new content, a container that
was started, a socket that was opened, a login session that was
established. The entity outlives the event that created it and the
investigation will refer to it as a noun. Model the entity as a
vertex of its own type; model the event with an edge verb (`spawned`,
`wrote`, `runs_in`, `opened`, `triggered_by`, `authenticated_as`, …).

**Action observations** are audit-log records of an operation. What
the log captures is the invocation itself — who called what with which
arguments — recorded by a control plane. Model as a `command` vertex
carrying the action's attributes, with `targeted → <thing acted on>`
and (when applicable) `executed_in → session`. This covers cloud API
calls, failed auth attempts, list/query/describe operations, and
configuration changes.

**Control-plane CRUD is uniformly action-shaped.** `iam:CreateUser`,
`s3:DeleteObject`, `iam:UpdateUser`, and `s3:GetObject` all model as
`command` vertices, even when the operation creates, deletes, or
mutates an entity. The control plane is reasoning about *invocations*;
the entity's existence is a side effect of the invocation the
investigation may or may not care about. Promote the target to its
own vertex (linked by `targeted`) **only if subsequent reasoning
actually references it as a noun** — e.g., a later lead asks "what
does this user do now?" or "what other objects did this principal
touch?". Until that happens, the command alone is sufficient and the
graph stays lean. This rule gives CRUD a uniform family: reads,
writes, creates, deletes, and updates all start as `command`.

Rationale: when you read a file on your host, a syscall is made under
the hood, but the investigation doesn't model it at that level unless
the case turns on OS semantics. The same principle applies to cloud
control-plane operations: model at the abstraction level the
investigation reasons at, not at the lowest level where an entity
technically materializes.

**Discriminator:** is the observation's natural noun an invocation
(who, what, when, against what target)? → action. Is it an entity
whose later state the investigation will reason about? → lifecycle.

**Dual-shape events and keeping data you already have.** A single
real-world event sometimes produces log records of both shapes —
`kubectl exec`, for instance, emits a kube-audit API-call record
(action shape) and a Falco execve event (lifecycle shape). **Do not
actively query a second source for corroboration** — authoritative
sources are authoritative on their own, and multi-witness retrieval
is spend without payoff. **But do not throw away data you already
have.** If the alert envelope contains both records and each carries
distinct attributes your investigation might reference (one has the
API principal and request parameters, the other has the spawned PID
and command line), model both — they're different projections of the
same event, not duplicates, and suppressing either loses whichever
projection a later hypothesis turns out to need. For the pure
same-shape case (two EDRs both recording the same execve), use a
single vertex with multiple entries in `citations`. No `correlates_with`
edge, no trust-boost machinery — the temporal proximity and matching
identifiers speak for themselves.

**Examples:**

| Observation                                                 | Perspective | Modeling                                                                |
|-------------------------------------------------------------|-------------|--------------------------------------------------------------------------|
| Falco: bash spawned in container                            | lifecycle   | `process(bash)` + `spawned` from parent process                          |
| Wazuh FIM: write to `/etc/passwd` (writer known)            | lifecycle   | `process(tee)` + `wrote` to `file(/etc/passwd)`                          |
| Wazuh FIM: write to `/etc/cron.d/backup` (writer unknown)   | lifecycle   | `process(unknown)` placeholder + `wrote` to `file(...)` — see below      |
| Windows 4624: interactive logon as `CORP\alice`             | lifecycle   | `session` + `authenticated_as` to `identity(alice)`                      |
| CloudTrail: `s3:ListObjectsV2` from a service role          | action      | `command(s3-list-call)` + `targeted` to `storage` bucket                 |
| CloudTrail: `s3:GetObject` on a backup bucket               | action      | `command(s3-get-call)` + `targeted` to `storage` bucket                  |
| CloudTrail: `iam:CreateUser` by admin principal             | action      | `command(iam-create-user-call)` + `targeted` to `identity(new-user)`     |
| CloudTrail: `iam:DeleteUser` on a contractor account        | action      | `command(iam-delete-user-call)` + `targeted` to `identity(contractor)`   |
| sshd-audit: failed login as `sensu`                         | action      | `command(ssh-auth-attempt)` + `targeted` to `endpoint`                   |
| RDS audit: SELECT from customer_pii                         | action      | `command(rds-query-call)` + `targeted` to `database`                     |
| kube-audit: pods/exec on container                          | action      | `command(kube-exec-call)` + `targeted` to `container`                    |
| Falco execve: same kube-exec as observed at the host        | lifecycle   | `process(runc)` + `spawned` to `process(bash)`                           |

The `iam:CreateUser`, `iam:DeleteUser`, and `s3:GetObject` rows show
the uniform CRUD treatment: all three are `command` vertices regardless
of whether they create, delete, or read. The `targeted` edge points at
the entity the action acted on; that target entity becomes a full
vertex only if later reasoning needs it.

The kube-exec rows show the dual-shape case. If the alert envelope
carried both records, and both carry distinct useful attributes, model
both. If only one landed in the envelope, model only that one — don't
go fetch the other.

### Unknown endpoints in lifecycle observations (placeholder vertices)

Lifecycle observations require two endpoints (agent → edge → patient),
but telemetry sometimes reports only one. FIM monitors watch inodes
and report state changes without always knowing which process wrote
the file. Network flow logs report connections without always knowing
the originating process. The investigation's actual state is "we saw
the event, one endpoint is unknown" — neither suppression nor
fabrication captures that faithfully.

**Convention:** write a placeholder vertex for the missing endpoint
with `placeholder: true` and `classification: unknown`. The
placeholder carries whatever observed properties are available (a
timestamp, a host, a user-space attribution hint) in `attributes`.
Model the lifecycle edge normally from/to the placeholder.

```yaml
- id: v-017
  type: process
  classification: unknown
  identifier: "unknown-writer-at-2026-04-14T02:17:04Z"
  placeholder: true
  attributes:
    observed_on: "host-prod-db-01"
    observed_at: "2026-04-14T02:17:04Z"
```

**Append-only-preserving late attribution.** If a later lead identifies
the real writer, do **not** mutate the placeholder. Append a new real
vertex (e.g., `process(tee)`) and link with an `identified_as` edge
from the placeholder to the real vertex. The placeholder stays in the
graph as a record of what the investigation knew at the moment the
observation was made; the `identified_as` edge records when and how
attribution was recovered. Distillers can retrieve "investigations
with unattributed lifecycle events" and "investigations that recovered
attribution post-hoc" as separate classes.

Placeholders apply only to lifecycle observations with genuinely
missing endpoints. Do not use them to defer work ("I'll fill in the
real vertex later") and do not use them for action observations
(`command` vertices already carry what's known about an invocation;
unknown principals or targets belong in the command's attributes).

```yaml
vertex:
  id: v-{nonce}
  type: process | socket | file | ip | identity | container | session
      | endpoint | storage | database | network-device | command
  classification: <string>
  identifier: <string>
  attributes: <object>           # omit if empty
  trust_root: true               # omit when false
  placeholder: true              # omit when false — see §3 unknown-endpoints convention
  concerns: [<string>, ...]      # omit if empty
  citations: [<string>]          # emit when evidence traces to multiple sources
```

Vendor specifics live in `attributes.kind` for `endpoint`, `identity`,
`storage`, `database`, `network-device`, and `command` types. Trust
posture lives in `classification`.

`trust_root: true` marks a vertex where backward traversal halts
because further traversal would require evidence we don't have access
to. **It is not a legitimacy certification** — see §11.

The `anchor-source` type from v2.2 is **removed**. Anchor query results
live in `lead.outcome.trust_anchor_result` (§7).

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

(Schema unchanged from v2.2; the relation catalog in §10 is updated.)

---

## 6. Hypothesis schema, the discrimination-level rule, and the leanness rule

### The discrimination-level rule (recap from v2)

A hypothesis lives at the **deepest materialized vertex where
explanations genuinely fork**. Run mechanical scope leads first if
the immediate parent is opaque.

### `proposed_edge.parent_vertex` is exactly one backward hop (recap from v2.2)

The `parent_vertex` inside `proposed_edge` describes the **immediate
upstream vertex**, not a distant ancestor. Count edges from
`attached_to_vertex` to `parent_vertex.type`: it must be exactly one.

### The leanness rule (new in v2.3)

A hypothesis describes the **immediate next discrimination question**,
not a deep causal narrative.

**Anti-pattern:** writing
`?ad-hoc-operator-marcus-direct-from-mfa-device-with-no-change-ticket`
at loop 1, before the SSH session has even been materialized. This
pre-commits to a deep story that:

- **Fragments the hypothesis space** — every variation in the deep
  story creates a new hypothesis, defeating retrieval pattern matches
  across cases.
- **Creates spurious work** — the agent must enumerate prediction IDs
  for facts it doesn't yet have evidence about.
- **Fights rule 6** — the more predictions a hypothesis has, the
  harder it is to reach `++` cleanly.

**Pattern:** write `?interactive-human-action` at loop 1 (the lean
discrimination claim). Refine to `?ad-hoc-operator-direct` and
`?stolen-credential-via-session` at loop 2 once the SSH session and
operator identity are materialized.

Lean hypotheses have **fewer predictions** because they make fewer
claims. The single core prediction of `?interactive-human-action` is
"a human-attributable session correlates temporally with the action."
That's it. Refinements add specificity (and predictions) only as
evidence forces them.

### Refinement chains via hierarchical IDs

When evidence forces the agent to refine a lean hypothesis into more
specific children:

1. **Allocate child IDs** as `h-{parent}-{ordinal}` — e.g., `h-001`
   becomes parent of `h-001-001` and `h-001-002`.
2. **Write the children as full hypothesis records** inside the lead
   block that triggered the refinement (they live in `new_hypotheses`).
3. **Shelve the parent** in the same lead block: `shelved: [h-001]`.
4. **Children inherit no weight from the parent.** Their weight
   histories are independent.
5. **The chain is reconstructable by string-parsing the IDs.** No
   `derived_from` field is needed.

A lean → refined chain is the canonical pattern when a lead materializes
evidence that splits a hypothesis into discriminable sub-cases. The
hierarchical ID is the schema's expression of investigation refinement.

### Schema

```yaml
hypothesis:
  id: h-{nonce} | h-{parent-id-suffix}-{nonce}
  name: "?descriptive-mechanism-name"
  attached_to_vertex: v-{id}

  proposed_edge:
    relation: <string>            # exactly one backward hop
    parent_vertex:
      type: <string>
      classification: <string>
      attributes: <object>        # optional

  predictions:
    - id: p1
      claim: "<source-agnostic claim about world state>"
    - id: p2
      claim: "<another claim>"

  refutation_shape:
    - id: r1
      claim: "<observation contradicting a core prediction>"

  concerns: []                    # omit if empty
  weight: "++" | "+" | "-" | "--" | null
  weight_history: []              # omit until there are transitions
  status: active                  # omit; emit when non-default
```

**No `canonical` field.** The distiller recognizes seed-matching
hypotheses post-hoc.

**Lean hypotheses typically have 1-2 predictions.** Refined hypotheses
may have 3+ predictions, but each prediction should still be
independently testable by some lead.

---

## 7. Lead block

```yaml
gather:
  - lead:
      id: l-{nonce}
      loop: <int>
      name: <string>
      mode: materialize | scope | trust
      target: v-{id}
      intended_hypothesis_set: [h-{id}, ...]   # required for materialize/trust; omit for scope

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

### `outcome.trust_anchor_result` (new in v2.3)

A small structured anchor-verdict record at the lead level. **Required
for `mode: trust` leads that consulted an anchor**, with one exception:
trust leads where the anchor query failed (in which case
`failure_reason` is set instead). Five fields:

- **`anchor_id`** — stable identifier matching `anchor_manifest.yaml`
  entries.
- **`kind`** — anchor name (e.g., `kube-audit`, `pam-audit`,
  `vpn-mfa`, `change-management`, `approved-monitoring-sources`).
- **`result`** — one of:
  - `confirmed` — the anchor's answer satisfies the hypothesis's
    prediction or supports its weight.
  - `refuted` — the anchor's answer contradicts the hypothesis (e.g.,
    approved triple but cadence violation; or no-registered-job for
    `?scheduled-batch-run`).
  - `partial` — the anchor's answer is non-empty but covers only some
    of the question.
  - `no-data` — the anchor returned no record (silent on the question).
- **`as_of`** — ISO-8601 timestamp the anchor's answer is
  **authoritative about** (not the query time, unless those happen
  to coincide). Three cases cover every anchor class:
  - **Event anchor** (answers "did X happen at time T?") — `as_of`
    is the event timestamp. Example: `vpn-mfa` returning marcus's
    MFA → `as_of: "2026-04-14T02:13:50Z"` (the MFA event time).
  - **Current-state anchor** (answers "is property X true now?") —
    `as_of` is the query time, or the snapshot timestamp if the
    anchor returns one. Example: `mdm-intune` listing enrolled
    devices → `as_of: "2026-04-14T14:32:30Z"` (query time).
  - **Slowly-changing reference** (answers "was policy/status X as
    of its last sync?") — `as_of` is the reference's last-modified
    or last-sync time, NOT the query time. Example: `hr-directory`
    employment status → `as_of: "2026-04-14T00:00:00Z"` (last HRIS
    sync, even if queried at 14:30). A stale reference is a real
    reasoning concern; encoding query time here would hide it.

  Writers record staleness explicitly: if `as_of` is materially
  older than the event being investigated, add a `concerns[]` entry
  on the lead (or on the resolution) naming the gap. No validator
  rule caps weight on staleness in v2.3 — it's a reasoning signal
  that the writer makes visible.

- **`authority_for_question`** — `full` or `partial`.
  - **`partial` means the anchor is authoritative for the data it
    returned but does not cover all aspects of the question being
    asked.** Example: `ec2-instance-integrity` covers disk integrity
    and IMDSv2 but not in-memory implants or kernel rootkits, so for
    the question "is this instance compromised at any layer?" it is
    partial-authority. **Capping rule (validator rule 16):** a `partial`
    authority anchor cannot push a hypothesis past `-` (or past `+`)
    on its own, even with a clean return.
  - **`authority_for_question` and `as_of` are orthogonal.** Scope
    (spatial) and freshness (temporal) are independent: a full-scope
    anchor can be temporally stale, and a partial-scope anchor can
    be temporally fresh. Encode them separately; don't collapse.

**The substantive anchor return goes in `observations`, not here.**
If the anchor answers "who initiated this kube-api call?" with
"alice@company.com from 10.200.14.77", the writer materializes
`v-005: identity(alice)` and `v-006: ip(10.200.14.77)` in
`outcome.observations.vertices`, with edges connecting them. The
`trust_anchor_result` carries only the verdict, not a duplicate of
the data. If the anchor returns metadata that doesn't fit any
existing vertex (e.g., vpn-mfa returns MFA method + device + time),
materialize a new vertex of an appropriate type — typically a
`session` (e.g., `mfa-session`) or a `command` if the anchor's return
is action-shaped — and put the metadata in that vertex's attributes.

**Why no `structured_fields` dict.** The case-a1 v2.3 translation
exercise showed that every field a writer would naturally put in
`structured_fields` was already in observation vertex attributes.
The dict was pure duplication. The distiller projects per-anchor
normalized retrieval indices from `observations` + a per-anchor
projection schema declared in `anchor_manifest.yaml`. This is
consistent with v2.3's central design choice (§15): retrieval load
that the distiller can compute does not belong in the writer's
schema.

The `trust_anchor_result` field replaces the `anchor-source` vertex
pattern from v2.2. Anchor verdicts are properties of the lead; the
data the anchor returned is in the graph.

### `failure_reason` convention (tightened in v2.3)

The `failure_reason` string should follow a small enum where applicable:

- `adapter-error` — the query system failed to respond
- `attribution-opaque` — the query returned successfully but the data
  is not informative for this vertex shape (e.g., `process-lineage`
  on in-container processes)
- `partial-coverage` — the query succeeded but only covered part of
  the question
- `permission-denied` — the query system rejected the query for
  authorization reasons
- `timeout` — the query did not complete in budget
- `other` — fallback with a free-form rationale

The distiller projects `attribution-opaque` failures into
`dead_leads_index.yaml` automatically.

### Severity of test (unchanged from v2.2)

| Severity   | Meaning                                                                       | Max weight effect                    |
|------------|-------------------------------------------------------------------------------|--------------------------------------|
| `severe`   | Outcome could directly contradict (or directly confirm) a core prediction    | up to `++` / `--`                    |
| `moderate` | Outcome constrains plausibility without directly contradicting                | one step                             |
| `weak`     | Circumstantial consistency                                                     | caps at `+` or `-`                   |

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

### `ceiling_test` (new in v2.3)

A structured slot for the out-of-band test that would close a
severity-ceiling case. The `kind` enum allows distillation queries
like "find all severity-ceiling cases that needed human contact"
without parsing prose. The `subject` string names the specific person,
tool, or authorization required:

- `kind: out-of-band-human-contact, subject: "marcus@company.com"`
- `kind: tool-unavailable, subject: "/opt/workloads/ deny-listed for file-stat"`
- `kind: legal-authorization, subject: "GDPR data-access approval for EU customer table"`
- `kind: other, subject: "<free-form>"`

`ceiling_rationale` remains as a free-form human-readable explanation.
The structured `ceiling_test` is for retrieval; the prose is for
analyst readers.

---

## 9. Classifications (seed vocabulary)

**Process:**
- `service-entrypoint-process`, `service-child-process`,
  `interactive-shell-in-workload`, `host-runtime-shim`,
  `operator-tool-invocation`, `automation-pipeline-process`,
  `unclassified-process`

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
  `iam-user-session`, `service-session`, `unclassified-session`

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

| Relation               | Source → Target                                                          |
|------------------------|--------------------------------------------------------------------------|
| `spawned`              | process → process                                                        |
| `executed`             | process → file                                                           |
| `loaded_by`            | process → library-file                                                   |
| `opened`               | process → socket                                                         |
| `connected_to`         | socket → endpoint                                                        |
| `read` / `wrote`       | process → file                                                           |
| `runs_in`              | process → container                                                      |
| `runs_on`              | container → endpoint, process → endpoint, database → endpoint            |
| `authenticated_as`     | session → identity                                                       |
| `initiated_by`         | session → identity \| endpoint                                           |
| `triggered_by`         | process → process \| session                                             |
| `escalated_privilege`  | session → session (self-edge)                                            |
| `executed_in`          | command → session                                                        |
| **`targeted`**         | **command → endpoint \| storage \| database \| identity \| file \| container \| network-device** |
| `member_of`            | identity → identity (e.g., user → group, role → role-bundle)             |
| `classified_as`        | vertex → classification-value                                            |
| `identified_as`        | placeholder-vertex → real-vertex (post-hoc attribution, §3)              |

**Notes:**

- **`targeted`** is the new generic action-target relation for command
  vertices. It is the v2.3 expression of "this action acted on this
  thing." Use it for SIEM-observed actions whose subject is a `command`
  vertex per §3 — cloud API calls, failed auth attempts, list
  operations, queries, configuration changes. **Do NOT use it for
  lifecycle events** (process spawn, file write observed at runtime,
  socket open, container start). Lifecycle events use entity vertices
  + edge verbs (`spawned`, `wrote`, `opened`, `runs_in`). See §3 for
  the full lifecycle-vs-action rule.
- **`connected_to`** retargets from `remote-endpoint` (deprecated) to
  `endpoint`. It returns to its actual job: transport-layer socket →
  endpoint observations. Do not abuse it for actions.
- **`runs_on`** is added to capture compute-substrate relationships
  (database on host, container on host) without conflating identity.
- **`member_of`** is added for identity hierarchies.
- **`attested_by`** (v2.2) is removed — its job is now done by
  `outcome.trust_anchor_result`.
- **`identified_as`** is the append-only-preserving escape hatch for
  lifecycle observations whose agent was unknown at write time. See
  §3 unknown-endpoints subsection. Never mutate a placeholder vertex;
  append a new real vertex and link it.

---

## 11. Authority table — OBSERVATIONAL ONLY, NOT LEGITIMACY

(Edge-level authority unchanged from v2.2.)

| Authority kind           | Meaning                                                                    | Max weight supportable |
|--------------------------|----------------------------------------------------------------------------|------------------------|
| `siem-event`             | Backed by a SIEM / audit log event                                         | `++` / `--`            |
| `runtime-audit`          | Backed by a runtime or OS audit stream                                     | `++` / `--`            |
| `authoritative-source`   | From a source authoritative for this observation question                  | `++` / `--`            |
| `client-asserted`        | From a self-reported field                                                  | `+` / `-`              |
| `inferred-structural`    | Inferred from co-occurrence                                                 | `+` / `-`              |

Authority describes how reliably the source **recorded the observation**.
It does NOT claim the observed action was authorized, benign, or
correctly interpreted. Legitimacy is always agent-level derivation.

### Per-question authority is at the lead level (new in v2.3)

The flat edge-level authority enum describes how reliably a single edge
was recorded. **Per-question authority** — whether the source has full
or partial coverage for the **semantic question** being asked — is a
property of the (anchor, question) pair and lives at the lead level
in `outcome.trust_anchor_result.authority_for_question`.

This is distinct from edge `authority.kind`. Example:
`ec2-instance-integrity` produces edges with `authority.kind:
authoritative-source` (the data it returned is authoritative for
disk + IMDSv2 observations), but its `authority_for_question` for
"is this instance compromised at any layer?" is `partial` (it does
not cover in-memory implants).

### Trust chain promotion (unchanged from v2)

A `client-asserted` edge sitting on a verified trust chain gets
effective `authoritative-source` authority. The chain is recorded in
`edge.authority.trust_chain`.

---

## 12. Write-time validator rules

1. **Schema validity.** Required fields present, enum values valid,
   IDs well-formed (including hierarchical hypothesis ID format).
2. **Classification vocabulary.** Every `classification` in §9 or a
   `{type}:{slug}` provisional.
3. **Relation catalog.** Every `edge.relation` in §10.
4. **Edge authority rule.** Strong-weight (`++`/`--`) resolutions cite
   at least one strong-authority supporting edge (§11).
5. **Refutation ID match.** Every `--` resolution's
   `matched_refutation_ids` is non-empty and references real IDs in
   the target hypothesis.
6. **Prediction ID match + completeness for `++`.** Every `++`
   resolution's `matched_prediction_ids` is non-empty and references
   real IDs; the union across resolutions on the hypothesis must
   equal the full prediction set; partial coverage caps at `+`.
7. **ID references resolve.** All `v-*`, `e-*`, `h-*`, `l-*` references
   point to records that exist.
8. **Append-only.** No record is mutated.
9. **Self-containment of lead blocks.** Every vertex/edge/hypothesis
   produced by a lead lives inside that lead's `outcome.observations`,
   `new_hypotheses`, or `shelved`.
10. **Scope leads omit `intended_hypothesis_set`.**
11. **Mechanical leads stay within their data source.** A scope lead's
    `outcome.observations.vertices` contains only vertices the data
    source directly observes. **Test:** would the data source's raw
    event stream contain a record naming this vertex by its native
    identity? If no, do not materialize. Cmdline text fragments and
    causal implication do not count as native naming.
12. **`observes` subset (when present).**
13. **Trust lead requires `trust_anchor_result`** (new in v2.3) when
    the lead consulted an anchor. Exception: trust leads where the
    anchor query failed — `failure_reason` is set in that case
    instead.
14. **Hierarchical hypothesis ID consistency** (new in v2.3): a
    hypothesis with ID `h-001-002` requires that `h-001` exists in
    the same companion. Refinement IDs cannot be allocated without
    their parent.
15. **`ceiling_test` requires severity-ceiling termination** (new in
    v2.3): the `ceiling_test` field is required when
    `termination.category: severity-ceiling` and forbidden otherwise.
16. **`partial` authority caps weight** (new in v2.3): a resolution
    that cites supporting edges grounded ONLY by a `trust_anchor_result`
    with `authority_for_question: partial` cannot push a hypothesis
    to `++` or `--`. The cap is `+` for confirmation-shaped resolutions
    and `-` for refutation-shaped resolutions.

### Why rule 6 stays mechanical

ID matching is set membership; paraphrase is impossible. Lean
hypotheses (§6) make the completeness clause more tractable in
practice because they have fewer predictions per hypothesis. If a
prediction doesn't fit cleanly into a single conjunctive hypothesis,
that's a signal to refine into hierarchical sub-hypotheses, not to
delete the prediction or stuff it into prose.

---

## 13. Worked example — RDS query on customer-PII outside service-role pattern

A CloudTrail alert fires on role `data-pipeline-svc` issuing an unusual
`SELECT FROM customer_pii` query against `rds-prod-customers` at 02:17
UTC during the nightly batch window. The role has RDS query permission
on this database; ~30 batch jobs share the role; the query is outside
the role's documented access pattern.

This example exercises: the action-as-vertex pattern, the new types
(`endpoint`, `identity`, `database`), `trust_anchor_result` at lead
level, **a lean hypothesis refined into hierarchical children**,
partial-authority capping, and severity-ceiling termination with
structured `ceiling_test`.

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

# Discrimination level is at v-004 (the role-session): "what initiated this
# role-session at 02:17, and was the SQL its intended workload?"
hypothesize:
  hypotheses:
    - id: h-001
      name: "?scheduled-batch-run"
      attached_to_vertex: v-004
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

    # h-002 is intentionally LEAN. It captures the immediate discrimination
    # ("a human-attributable session correlates temporally with this role
    # assumption") without pre-committing to operator-vs-attacker. Refinement
    # happens in loop 2 if l-002 materializes a human session.
    - id: h-002
      name: "?interactive-human-action"
      attached_to_vertex: v-004
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
        - "stolen role credentials are unfalsifiable without out-of-band MDM/SSO trust-chain evidence; refutation here is 'no current network-path anomaly', not 'credential theft ruled out'"
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
          as_of: "2026-04-14T02:17:30Z"   # query time (current-state anchor — "is there a job registered now?")
          authority_for_question: full
      resolutions:
        - hypothesis: h-001
          before: null
          after: "-"
          severity_of_test: severe
          matched_refutation_ids: [r1]
          reasoning: "job-scheduler returned no registered job for (data-pipeline-svc, customer_pii, 02:17 window). r1 directly satisfied. Anchor is full-authority for 'is this a registered scheduled job?' Weight transitions to -. Not -- because the refutation is local to the canonical scheduler — it does not exclude misregistered or out-of-band scheduled work, only the canonical case."
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
          # Mechanical lead materializes only what host-audit directly observes:
          # the SSH session and the user it authenticated.
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

      # h-002 (?interactive-human-action) was lean. The scope lead just
      # materialized the human session. Now refine into discriminable
      # sub-hypotheses, allocate child IDs, and shelve the parent.
      shelved: [h-002]
      new_hypotheses:
        - id: h-002-001
          name: "?ad-hoc-operator-direct"
          attached_to_vertex: v-006
          proposed_edge:
            relation: authenticated_as
            parent_vertex:
              type: identity
              classification: employee-with-exec-rbac
          predictions:
            - id: p1
              claim: "marcus authenticated to the SSH session via MFA from a compliant device"
            - id: p2
              claim: "the SQL query is justified by a known operational task (change ticket, on-call response, or routine maintenance)"
          refutation_shape:
            - id: r1
              claim: "marcus did not MFA at session start"
            - id: r2
              claim: "no operational justification exists for the SQL query"
          weight: null

        - id: h-002-002
          name: "?stolen-credential-via-session"
          attached_to_vertex: v-006
          proposed_edge:
            relation: authenticated_as
            parent_vertex:
              type: identity
              classification: unknown-attacker
          predictions:
            - id: p1
              claim: "the SSH session origin or auth context shows a network-path or device-posture anomaly inconsistent with marcus's normal pattern"
          refutation_shape:
            - id: r1
              claim: "the SSH session originated from marcus's MFA-verified, MDM-compliant device on his usual network path"
          concerns:
            - "stolen credentials are unfalsifiable without MDM trust-chain evidence; refutation here is 'no current anomaly', not 'theft ruled out'"
          weight: null

      resolutions:
        # h-002 is shelved, not refuted — the lean parent has been replaced
        # by its refinements. Status moves to shelved; weight stays null.
        - hypothesis: h-001
          before: "-"
          after: "--"
          severity_of_test: moderate
          matched_refutation_ids: [r1]
          reasoning: "an interactive SSH session was active on v-005 at the time of the query — strong evidence the query was human-initiated, not scheduled. Combined with l-001's no-registered-job, h-001 is now -- (no scheduled-batch story remains)."
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
        # The MFA event is materialized as a session vertex (lifecycle
        # perspective, per §3): it represents marcus's authentication state
        # at a specific time, which the resolution will reference. The
        # authenticated_as edge links the MFA session to marcus.
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
          as_of: "2026-04-14T02:13:50Z"   # MFA event time (event anchor — when marcus actually touched his YubiKey)
          authority_for_question: full
      resolutions:
        - hypothesis: h-002-001
          before: null
          after: "+"
          severity_of_test: severe
          matched_prediction_ids: [p1]
          reasoning: "vpn-mfa confirmed marcus MFA'd at 02:13:50Z (≈3m before the SSH session at 02:14:20Z) from MDM-compliant device macbook-marcus-2025, materialized as session v-008 with the MFA attributes. p1 (MFA from compliant device) confirmed via the authenticated_as edge e-007 (authoritative-source). p2 (operational justification) is NOT tested by this lead — it requires change-management. Caps at + per rule 6 completeness; will be re-evaluated after l-004."
          supporting_edges: [e-007]
        - hypothesis: h-002-002
          before: null
          after: "-"
          severity_of_test: severe
          matched_refutation_ids: [r1]
          reasoning: "vpn-mfa confirmed marcus MFA'd from his MDM-compliant device (v-008, e-007). r1 directly satisfied. Weight transitions to -. Not -- because residual stolen-credential and coerced-actor scenarios remain unfalsifiable without out-of-band confirmation — see h-002-002.concerns."
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
        query: "open or recent tickets assigned to marcus@company.com touching customer_pii or rds-prod-customers between 02:00-03:00 UTC"
      outcome:
        # change-management returned empty for this query. No graph
        # entities to materialize — the verdict enum + the lead's
        # query_details carry everything the distiller needs.
        observations: { vertices: [], edges: [] }
        trust_anchor_result:
          anchor_id: change-management
          kind: change-management
          result: no-data
          as_of: "2026-04-14T02:18:10Z"   # query time (current-state anchor over an open-ticket index)
          authority_for_question: full
      resolutions:
        - hypothesis: h-002-001
          before: "+"
          after: "+"
          severity_of_test: moderate
          matched_refutation_ids: [r2]
          reasoning: "change-management returned no ticket for marcus touching customer_pii in the window. r2 (no operational justification) satisfied. h-002-001 stays at + (does not advance to ++ because p2 is now refuted not confirmed; the +' cap is the right encoding of 'human-presence yes, justification no'). The hypothesis cannot be both confirmed and refuted; the right disposition is to escalate to analyst with the operational justification gap as the open question."
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
        # Scan results are the anchor's detailed output, but they're not
        # graph entities — they're a verdict about v-005's integrity at
        # scan time. The high-level verdict is carried by
        # result: confirmed + authority_for_question: partial; the
        # scoped cleanness (disk+IMDSv2 yes, in-memory no) lives in the
        # resolution reasoning.
        observations: { vertices: [], edges: [] }
        trust_anchor_result:
          anchor_id: ec2-instance-integrity
          kind: ec2-instance-integrity
          result: confirmed
          as_of: "2026-04-14T02:15:00Z"      # scan snapshot timestamp (event anchor — the integrity scan result is about this moment)
          authority_for_question: partial    # covers disk + IMDSv2; not in-memory implants
      resolutions:
        - hypothesis: h-003
          before: null
          after: "-"
          severity_of_test: moderate
          matched_refutation_ids: [r1]
          reasoning: "ec2-instance-integrity returned clean for its in-scope coverage (disk integrity clean, IMDSv2 enforced, SSM agent healthy; in-memory scan not performed). r1 (corp-internal compute, normal usage pattern) satisfied at the disk/IMDS layer. **Validator rule 16 cap:** authority_for_question is partial — the anchor does not cover in-memory implants or kernel rootkits. Weight cannot advance past -. h-003 caps at -."
          supporting_edges: []

conclude:
  termination:
    category: severity-ceiling
    rationale: "h-002-001 (?ad-hoc-operator-direct) at + with confirmed MFA but unmet operational justification. h-002-002 (?stolen-credential-via-session) at -, unfalsifiable without out-of-band MDM trust-chain evidence. h-003 (?compromised-role-credential) capped at - by partial-authority on ec2-instance-integrity. No adversarial reaches --, no benign reaches ++, and the test that would resolve it is direct out-of-band contact with marcus."
  disposition: unclear
  confidence: medium
  matched_archetype: null
  ceiling_test:
    kind: out-of-band-human-contact
    subject: "marcus@company.com"
  ceiling_rationale: "the test that would close this case is direct confirmation from marcus that the SQL query was intentional and operationally justified (or denial, in which case h-002-002 advances). No anchor accessible to this agent can substitute for direct operator confirmation. Secondary in-scope test that could narrow further: in-memory integrity scan of i-0a1b2c3d (would advance h-003 to -- if clean), but that requires SSM document execution which is out-of-scope for the agent."
  summary: "data-pipeline-svc role issued an unusual SELECT FROM customer_pii on rds-prod-customers at 02:17 UTC. h-001 (?scheduled-batch-run) refuted -- (no registered job, human session active). h-002 (?interactive-human-action) was lean and refined into h-002-001 (?ad-hoc-operator-direct) and h-002-002 (?stolen-credential-via-session); h-002-001 capped at + (MFA confirmed, change ticket missing); h-002-002 capped at -. h-003 (?compromised-role-credential) capped at - by partial-authority anchor. Severity-ceiling escalation: contact marcus@company.com directly to confirm or deny intent."
```

**Things to notice:**

1. **No `canonical` field anywhere.**
2. **Hierarchical hypothesis IDs.** `h-002-001` and `h-002-002` are
   refinements of the lean `h-002`. The lineage is in the IDs themselves.
   The parent is shelved when the children are created (in the same
   lead block).
3. **Lean hypothesis at loop 1.** `h-002: ?interactive-human-action`
   makes a single discrimination claim with one prediction. It does
   NOT pre-commit to operator-vs-attacker; that question is deferred
   until the SSH session has been materialized.
4. **Action-as-vertex.** `v-001` is a `command` vertex carrying the SQL
   action shape. `executed_in` places it in the role-session;
   `targeted` links it to the database. No abuse of `connected_to`.
5. **`endpoint`, `identity`, `database` types** generalize across
   vendor specifics. EC2 → `endpoint` with `kind: ec2-instance`;
   postgres RDS → `database` with `kind: postgres`; the IAM role →
   `identity` with `kind: role`.
6. **`trust_anchor_result` is a 5-field verdict block** on all four
   trust leads: `{anchor_id, kind, result, as_of, authority_for_question}`.
   `job-scheduler` returned `refuted/full` as-of query time; `vpn-mfa`
   returned `confirmed/full` as-of the MFA event time (02:13:50Z, three
   minutes before the RDS query — fresh); `change-management` returned
   `no-data/full` as-of query time; `ec2-instance-integrity` returned
   `confirmed/partial` as-of the scan snapshot time. `as_of` is
   **orthogonal** to `authority_for_question` — scope and freshness are
   independent, and both land in this worked example. **No
   `structured_fields` dict** — substantive anchor returns live in
   `observations` when they describe graph entities (e.g., l-003
   materializes `v-008: session(mfa-session)` + e-007 to carry
   marcus's MFA context as a lifecycle entity) or in
   `resolutions[].reasoning` when they're verdicts about existing
   vertices that can't be re-materialized under append-only (l-005's
   scoped-clean integrity result). The distiller projects per-anchor
   retrieval indices from observations + `anchor_manifest.yaml`
   schemas — retrieval load is not carried in the writer's schema.
7. **Partial-authority cap fires** on l-005: even though the anchor
   returned clean, `authority_for_question: partial` caps h-003 at -
   (validator rule 16). The cap is mechanical and structurally visible
   from the 5-field `trust_anchor_result` alone — the distiller can
   detect "confirmed verdict + partial authority + weight capped at
   ±1" without parsing reasoning prose.
8. **`ceiling_test`** in conclude: `kind: out-of-band-human-contact,
   subject: marcus@company.com`. A future case asking "find ceiling
   escalations needing operator contact" matches the structured enum.
9. **`ceiling_rationale`** still carries the analyst-facing prose,
   including the secondary in-scope test that would narrow further.
10. **No `anchor-source` vertices.** Everything anchor-related lives at
    the lead level.

---

## 14. What you write

1. **Read** the alert and retrieval-sim.
2. **Fill `prologue`** with vertices and edges. Use the action-vertex
   pattern (`command` + `targeted`) for SIEM-observed actions. Use
   `endpoint`, `identity`, `storage`, `database`, `network-device`
   types generically; put vendor specifics in `attributes.kind`.
3. **Decide** whether to hypothesize now or run a mechanical scope
   lead first. If the alert's immediate parent is opaque, leave
   `hypothesize.hypotheses: []` and write the scope lead first.
4. **Write hypotheses lean.** State the immediate next discrimination
   claim, not a deep causal narrative. Predictions should be the
   minimum that captures the discrimination — typically 1-2 per lean
   hypothesis. Don't preempt evidence you haven't gathered yet.
5. **Write each GATHER lead as a self-contained block.** Mechanical
   leads stay within their data source.
6. **Use `outcome.trust_anchor_result`** on every trust-mode lead that
   consulted an anchor. Lift the anchor's answer out of vertex
   attributes; result, authority, and structured fields go in this
   field. Mark `authority_for_question: partial` when the anchor
   covers only some aspects of the question.
7. **Refine lean hypotheses** when a lead materializes evidence that
   splits them. Allocate hierarchical child IDs (`h-{parent}-{ordinal}`);
   shelve the parent in the same lead block.
8. **Cite prediction/refutation IDs** in resolutions; `++` requires
   complete prediction coverage; `partial` `authority_for_question`
   caps weight regardless of prediction coverage (rule 16).
9. **Write `conclude`** with termination, disposition, and (for
   severity-ceiling) the structured `ceiling_test`. The prose
   `ceiling_rationale` remains required.

---

## 15. What v2.3 explicitly does NOT add to the schema

The case-a4 retrieval-needs walk identified ten retrieval needs.
Seven of them (R-1, R-2, R-4, R-5, R-7, R-9, R-10) are derivable
from the existing schema by a distillation/query script. v2.3 does
NOT add fields for these. They are explicitly distiller projects:

- **`trace`** — derivable by traversing `gather` in order and
  serializing as a path expression. Lives in
  `case_index.yaml.trace_string` post-distillation.
- **`prediction_status_at_termination`** — derivable by accumulating
  `matched_prediction_ids` across all resolutions per hypothesis and
  subtracting from the full prediction set. Lives in
  `hypothesis_completion_index.yaml`.
- **`escalation_handoff`** — derivable by joining user-type vertices,
  hypotheses with `+`/`-` weight, supporting edges with strong
  authority, and `ceiling_rationale`. Lives in `escalation_index.yaml`.
- **`final_weight`** per hypothesis — last entry of `weight_history`.
- **`mandatory_adversarial`** flag — distiller heuristic on hypothesis
  name patterns (`?compromised-*`, `?stolen-*`, `?attacker-*`) plus
  the `concerns` field hint about unfalsifiability.
- **`correlated_with`** for sessions on the same host — joinable on
  vertex attributes (host, time-window).
- **Hypothesis lineage chain** — derivable by string-parsing
  hierarchical IDs.
- **`trust_anchor_result.structured_fields`** — removed from the
  writer's schema after the case-a1 v2.3 translation exercise showed
  every field was duplicated from observation vertex attributes. The
  distiller projects per-anchor normalized retrieval indices from
  `observations` + a per-anchor projection schema declared in
  `anchor_manifest.yaml`. What the writer types is a 5-field verdict
  block (`{anchor_id, kind, result, as_of, authority_for_question}`);
  the substantive anchor return is in the graph. Freshness buckets
  relative to the event time are a distiller projection computed from
  `as_of`, not a writer field.

The schema does not bear retrieval load that the distiller can compute
once at case close. This is the central design choice of v2.3.
