# Investigation Language

**Status:** Implemented. Spec v2.9 (rules 24–25 pending implementation; prompt alignment in `agents/analyze.md` pending).
**Query tool:** `soc-agent/scripts/invlang/` — see `cli.py --help`

**v2.9 delta:** validator rules #24 (hypothesis persistence at CONCLUDE) and #25 (same-level sibling rollup for `matched_prediction_ids`). Closes two bias gaps identified during the ANALYZE-phase state-machine cutover: silent hypothesis drop across loops, and cross-sibling prediction-ID citation. See `.claude/skills/migrate-state-machine/SKILL.md` for the design context.

**v2.8 delta:** legitimacy as first-class edge attribute (`edge.legitimacy_resolutions`) driven by hypothesis-declared contracts (`hypothesis.legitimacy_contract`); `attribute_updates` extended to edge targets; validator rules #19–#22; supersedes the former "maintain adversarial hypothesis until `--`" bookkeeping rule.

A structured schema for recording security investigations as graph
traversals. Designed for SOC-level alert triage: the agent works
backward from an observed alert until it reaches trust-authoritative
sources or exhausts available tools.

---

## Goals

**Elegant.** Small number of primitives; everything else derivable.
No field exists solely to carry information already present in the
graph structure.

**Readable.** A companion is a document. An analyst reading it should
be able to follow the investigation's reasoning without parsing schema
headers.

**Writable.** An LLM writing a companion should rarely need to look up
a rule. The schema nudges correct behavior through structure; edge
cases are rare.

**Searchable.** Companions support corpus queries that measure
investigation effectiveness: which hypothesis patterns recur, which
leads are most discriminating, where investigations stall and why.

---

## Philosophy

### The investigation graph

An investigation maintains two layers at all times.

**Confirmed graph** — vertices and edges backed by observation
authority (SIEM events, runtime audit, authoritative sources). Grows
monotonically; nothing is ever mutated.

**Proposed frontier** — candidate graph extensions, one per active
hypothesis. Each hypothesis proposes that a specific upstream vertex
exists, connected to the confirmed graph by one edge. Leads test
whether proposed elements actually exist, moving them from proposed
to confirmed (or refuting them).

The investigation progresses by running leads that collapse the
frontier. It halts when the frontier is empty (all hypotheses
resolved) or the confirmed graph reaches a vertex where no accessible
upstream exists — a **trust root**.

This maps to graph search: the confirmed graph is the explored set;
the proposed frontier is the candidate set; each lead is an edge
measurement. The difference from static graph search is that the
graph is being constructed as it goes — each lead can both test
existing proposals and introduce new vertices that open the next
layer of questions.

### Backward traversal

Investigations look backward: observation → cause → cause-of-cause
→ until a trust root. The driving question at each step is *why does
this edge/vertex exist?* The confirmed answer becomes the new anchor
for the next question.

**Depth is forced by evidence.** Do not propose a deep causal chain
at loop 1. Form the immediate discrimination question; deepen only
when a lead confirms the current anchor and opens the next layer.

### Scale of reasoning

Model at the granularity the investigation reasons at, not finer.
A process vertex is opaque until the investigation needs to
distinguish sub-entities within it — because different sub-entities
would lead to different hypotheses, different leads, different
conclusions. Before that point, the entity is atomic and its
internal structure is transparent to the investigation.

When a lead reveals heterogeneous internal structure that changes
the investigation's trajectory, decompose into sub-vertices linked
by `component_of`. The parent vertex and its existing edges remain
valid; coarse observations are still true. Fine-grained edges
specialize them — they do not replace them.

**Cartography principle.** A world map renders an island opaque; a
city map shows streets; a floor plan shows rooms. The right
resolution depends on the question being asked. Pre-decomposing adds
entities the investigation hasn't needed to reason about — graph
clutter without discrimination value.

### Lean hypotheses

A hypothesis captures the **immediate next discrimination question**,
not a deep causal narrative. A lean hypothesis has 1–2 predictions:
the minimum that distinguishes it from competing hypotheses.

Pre-committing to a deep narrative fragments the hypothesis space
across cases that should match the same retrieval pattern, creates
prediction IDs for facts not yet in evidence, and makes weight
accumulation harder. Refine into more specific children only when
evidence forces the distinction.

### Legitimacy as edge attribute

Legitimacy — is this edge *authorized*? — is a property of the
(`source_vertex`, `edge`, `target_vertex`, `authority`) quadruple at
time T. The same `read` edge from a session to a storage object is
authorized when the session's identity carries the required role and
unauthorized when it does not. The mechanism is identical; only the
verdict differs. Legitimacy therefore lives **on the edge**, not as a
parallel hypothesis.

A hypothesis whose disposition depends on authorization declares a
`legitimacy_contract` naming the edge(s) whose verdict is load-bearing
and the authority that resolves them. When the resolving lead fires,
the edge gains a `legitimacy_resolutions` entry with the verdict and a
back-reference to the contract. Append-only is preserved by backward
traversal: the hypothesis is written once and never mutated; the
materialized edge points backward via `fulfills_contract`.

**Three shapes of adversariness.** Not every adversarial question is a
legitimacy question:

- **Mechanism-level** — enumerate `adversary-controlled` alongside
  benign classifications when they predict observationally distinct
  world-states. Normal mechanism enumeration; no contract needed.
- **Attribute-level (policy authorization)** — same mechanism, same
  observables, but an authority would answer "allowed" differently
  depending on the source identity. This is the legitimacy contract
  case. Common.
- **Future-edge** — the adversarial signal is a separate downstream
  edge (a failed-auth alert followed by an unexpected success). That
  is a topology question; write it as its own hypothesis attached to
  the hypothetical future edge.

**Contracts answer policy, not integrity.** A contract asks "is this
edge allowed by the relevant authority?" It does not ask "was this
edge actually executed as it appears?" Session hijack, token theft,
MFA bypass, process-hollowing, tool-masquerade — all integrity
questions — are mechanism-level discriminations, not contracts. By
construction, if AuthN was bypassed, the IAM anchor still says
"authorized" because the session looks legitimate to it. Integrity is
resolved by behavioral observation (impossible travel, device
fingerprint, anomalous timing), not by anchor lookup. Contracts
therefore bottom out at the authentication edge; below that is
mechanism enumeration.

### Leads as graph operations

A lead is an operation on the investigation graph. Two kinds:

- **Topology-extending** — materializes new vertices and edges
  (confirmed graph grows). When it discriminates between competing
  hypotheses, `tests` names them.
- **Attribute-refining** — enriches existing confirmed vertices
  without adding new topology (`attribute_updates`). No hypothesis
  target; the lead answers "what more do we know about this entity?"

Many leads are both: a trust anchor lookup may enrich an existing
vertex *and* materialize new entities in the same outcome. The
distinction is not categorical — there is no `mode` field. A lead
that produces only `attribute_updates` is implicitly attribute-
refining; one that produces `observations` is topology-extending.
Whether it discriminates between hypotheses is expressed by
`tests`, not by a type label.

### Append-only

Once written, no record is mutated. Sub-vertices are appended when
decomposition is forced; the parent stays. Placeholder vertices are
linked to their real counterpart via `identified_as` when
attribution is recovered; the placeholder stays. The graph
accumulates; it does not revise.

---

## Schema

### Top-level structure

```yaml
prologue:           # CONTEXTUALIZE: vertices + edges derived from the alert
  vertices: [...]
  edges: [...]

hypothesize:        # HYPOTHESIZE: initial proposed frontier (omit for SCREEN-matched cases)
  hypotheses: [...]

gather:             # GATHER + ANALYZE: ordered lead blocks
  - lead: {...}

conclude:           # CONCLUDE
  ...
```

**`hypothesize` is optional.** For SCREEN-matched investigations, no
hypothesis formation step runs — the screen leads encode pattern
evaluation directly, and `outcome.screen_result: match` records the
verdict. Omit the `hypothesize` block in these cases.

For full-loop investigations, `hypothesize` is written once (after
CONTEXTUALIZE, before the first GATHER lead). Subsequent-loop hypothesis
evolution is captured inside leads via `new_hypotheses` (additions) and
`shelved` (retractions). There is no second top-level `hypothesize`
block.

### Vertex

```yaml
vertex:
  id: v-{nonce}                    # local, stable, append-only
  type: <string>                   # from type vocabulary (§Types)
  classification: <string>         # from seed list or {type}:{slug} provisional
  identifier: <string>             # human-readable primary key for this entity
  attributes: {}                   # type-specific key-value pairs; omit if empty
  trust_root: true                 # omit when false
  placeholder: true                # omit when false — unknown endpoint (§Conventions)
  concerns: []                     # reliability, scope, or interpretation traps; omit if empty
  citations: []                    # source references; omit if single or implicit
```

**Sub-vertex IDs.** When a vertex is decomposed inward via
`component_of`, sub-vertices use `v-{parent}-{nonce}` IDs (e.g.,
`v-001-01`, `v-001-02`). This encodes containment in the ID itself,
enabling prefix queries without edge traversal.

**`trust_root: true`** marks where backward traversal halts because
further upstream requires evidence inaccessible to this agent. It is
not a legitimacy claim.

**Placeholder vertices.** When a lifecycle edge requires two
endpoints but one is unobservable, write a placeholder vertex with
`placeholder: true`. If a later lead identifies the real entity,
append a new vertex and link via `identified_as`. Never mutate the
placeholder.

### Edge

```yaml
edge:
  id: e-{nonce}
  relation: <string>               # from relation catalog (§Relations)
  source_vertex: v-{id}
  target_vertex: v-{id}
  when: { timestamp: <iso> }       # omit if not meaningful
  attributes: {}                   # omit if empty
  status: observed                 # omit; emit hypothesized or refuted when non-default
  authority:
    kind: siem-event | runtime-audit | authoritative-source
        | client-asserted | inferred-structural
    source: <string>
    trust_chain: []                # omit if empty
  legitimacy_resolutions: []       # omit when no contract resolves against this edge (§Legitimacy)
  concerns: []                     # omit if empty
```

**Authority is observational, not legitimacy.** It describes how
reliably the source recorded the observation. `siem-event`,
`runtime-audit`, and `authoritative-source` support `++`/`--`
weight. `client-asserted` and `inferred-structural` cap at `+`/`-`.

A `client-asserted` edge on a verified trust chain gets effective
`authoritative-source` authority; record the chain in `trust_chain`.

**`legitimacy_resolutions` is a plural list.** Each entry records one
contract's verdict:

```yaml
legitimacy_resolutions:
  - verdict: authorized | unauthorized | indeterminate
    anchor_kind: <string>           # iam-policy | data-classification-policy | oncall-schedule | deploy-runs | image-baseline | ...
    anchor_query: <string>          # short human-readable record of what was asked
    as_of: <iso>                    # timestamp the answer is authoritative ABOUT
    resolved_by_lead: l-{id}
    fulfills_contract: h-{id}.lc{n} # back-reference to the declaring hypothesis's contract entry
    concerns: []                    # omit if empty; snapshot freshness, partial anchor coverage, etc.
```

Plural because real edges often face parallel policy layers — IAM ×
data-classification × time-of-day — each resolved independently by a
different anchor, any one of which can deny. Do not collapse layered
policies into a single entry; each contract gets its own resolution.

**When `legitimacy_resolutions` appears.** Only on edges that fulfill
a declared contract. Edges not referenced by any contract omit the
field entirely. Do not write speculative verdicts — that is
verdict-on-everything clutter.

**Append-only on existing edges.** If a contract resolves against an
already-confirmed edge (not the proposed edge of its hypothesis), the
resolving lead writes the verdict via `attribute_updates` targeting
the edge — not by mutating the original edge record.

**Per-question authority** (whether a source covers all aspects of
the question being asked) is a property of the lead, not the edge.
It lives in `trust_anchor_result.authority_for_question`.

### Hypothesis

```yaml
hypothesis:
  id: h-{nonce} | h-{parent}-{nonce}   # hierarchical for refinement chains
  name: "?descriptive-slug"

  attached_to_vertex: v-{id}            # anchor: confirmed vertex this extension grafts onto

  proposed_edge:                        # the one-hop upstream extension
    relation: <string>
    parent_vertex:
      type: <string>
      classification: <string>
      attributes: {}                    # omit if empty

  predictions:
    - id: p1
      claim: "<source-agnostic claim about world state>"

  refutation_shape:
    - id: r1
      claim: "<observation that would contradict a core prediction>"

  legitimacy_contract: []               # optional; present when disposition depends on policy authorization (§Legitimacy)

  concerns: []                          # residuals, unfalsifiability caveats; omit if empty
  weight: null | "++" | "+" | "-" | "--"
  weight_history: []                    # omit until transitions exist
  status: active                        # omit; emit confirmed | refuted | shelved when non-default
```

**One-hop discipline.** `proposed_edge.parent_vertex` is the
immediate upstream cause — exactly one hop from `attached_to_vertex`.
Do not propose a distant ancestor.

**Refinement via hierarchical IDs.** When evidence forces a lean
hypothesis into more specific sub-cases, allocate child IDs as
`h-{parent}-{ordinal}` (e.g., `h-001` → `h-001-001`, `h-001-002`).
Write children as full hypothesis records in the lead's
`new_hypotheses`. Shelve the parent in the same block. Children
inherit no weight from the parent; their histories are independent.

**Lean means 1–2 predictions.** A single prediction captures the
core discriminating claim. Add a second only when two independent
facts each partially confirm the hypothesis and neither alone
suffices. Three or more predictions usually signals either a
non-lean hypothesis or a refinement that should be deferred.

**Legitimacy contracts** are declared on the hypothesis when
disposition hinges on an authorization lookup (§Legitimacy). Each
contract entry:

```yaml
legitimacy_contract:
  - id: lc1                             # local to hypothesis; ^lc\d+$
    edge_ref: proposed | e-{id}         # the hypothesis's proposed_edge, or an existing confirmed edge
    anchor_kind: <string>               # which authority resolves it
    predicate: "<natural-language claim — authorized iff ...>"
    on_unauthorized: escalate
    on_indeterminate: escalate
    concerns: []                        # optional; e.g., anchor known to be behind preflight
```

The predicate is natural language. Any AND/OR combination is
permitted — no structured DSL. The agent evaluates the predicate
against anchor data when the resolving lead fires. Declare contracts
only when the mechanism is consistent with both benign and adversarial
readings depending on authorization; when the adversarial reading IS
the mechanism (e.g., `?adversary-controlled-process`), skip the
contract — the classification already carries the claim.

**Behavioral-consistency prediction (optional).** A contract resolved
`authorized` establishes policy compliance, not integrity. The
hypothesis MAY carry one baseline-consistency prediction — positive
("expect corroborating activity X") or negative ("expect NOT to see
>Nσ volume deviation / access outside baseline file set / concurrent
geo-distant sessions"). Gates: baseline queryable, scoped to the
alert's entities, weight-sensitive. Severity caps at `moderate`.
Unavailable baseline → `indeterminate` in `concerns`; do not
confabulate.

### Lead

```yaml
gather:
  - lead:
      id: l-{nonce}
      loop: <int>
      name: <string>
      target: v-{id}                    # vertex this lead operates on / investigates

      selection_rationale: <string>     # optional — 1–3 sentences on why this lead now, not another
      mode: screen                      # omit unless this lead was dispatched by the SCREEN subagent

      tests: [h-{id}, ...]              # optional — hypotheses this lead discriminates.
                                        # Presence ⇒ fork-collapsing; absence ⇒ non-branching.

      observes:                         # optional — explicit prediction/refutation mapping
        - { hypothesis: h-{id}, predictions: [p1], refutations: [r1] }

      predictions:                      # optional — conditional branch plans for
                                        # non-branching but interpretation-vulnerable leads.
                                        # IDs local to the lead (lp1, lp2, …).
        - id: lp1
          if: "<outcome pattern>"
          read_as: "<interpretation>"
          advance_to: "<lead-name | CONCLUDE | HYPOTHESIZE>"

      query_details:
        system: <string>
        template: <string>
        query: <string>
        time_window: <string>
        substitutions: {}

      concerns: []                      # omit if empty

      outcome:
        attribute_updates:              # optional — enriches existing confirmed vertices OR edges
          - target: v-{id} | e-{id}     # vertex or edge id; exactly one
            updates: {}

        observations:
          vertices: []
          edges: []

        trust_anchor_result:            # include when an authority anchor was queried
          anchor_id: <string>
          kind: <string>
          result: confirmed | refuted | partial | no-data
          as_of: <iso>                  # timestamp the answer is authoritative ABOUT
          authority_for_question: full | partial

        trust_root_reached: v-{id}      # omit when null
        failure_reason: <string>        # omit unless errored or degraded
        screen_result: match | no_match # include only when mode: screen

      new_hypotheses: []                # full hypothesis records
      shelved: []                       # hypothesis IDs shelved by this lead

      resolutions:
        - hypothesis: h-{id}
          before: null | "++" | "+" | "-" | "--"
          after: "++" | "+" | "-" | "--"
          severity_of_test: severe | moderate | weak
          matched_prediction_ids: []
          matched_refutation_ids: []
          reasoning: "<string>"
          supporting_edges: []
```

**`selection_rationale` is optional.** Use it to capture the inter-lead
strategic reasoning — why this lead was chosen next given what was
already known. Omit for the first lead of an investigation (choice is
obvious) and for SCREEN leads (subagent-directed). Include when the
choice required weighting competing options: "source-classification
first because IP attribution determines which hypotheses are live
before committing to discriminating queries."

**`mode: screen`** marks leads dispatched by the SCREEN subagent (loop
0). These leads share SCREEN's fast-path purpose — pattern match or
fall through — and are always in `loop: 0`. `outcome.screen_result`
records whether the overall SCREEN matched (`match`) or fell through
(`no_match`). Only the final screen lead in the sequence needs
`screen_result`; omit it from intermediate screen leads.

**`tests` is optional.** Present when the lead is discriminating
between specific competing hypotheses. Absent when the lead is
purely informational (classification lookup, attribute enrichment,
establishing scope). A lead with no `tests` still produces
`resolutions` when its outcome happens to bear on active hypotheses
— the connection is recorded in the resolution, not pre-declared.

**`predictions` is optional — pre-commitment for interpretation-
vulnerable leads.** A lead can be non-branching (same step-1
regardless of which story is true) yet still have outcome fields
whose reading is interpretive — volume anomaly shape, process-name
plausibility, reputation-weight thresholds. For those leads,
pre-register how the outcome will be read as conditional branch
plans: `if <outcome pattern> → read_as <interpretation> →
advance_to <next step>`. The triple is auditable: the actually-run
next lead should match one of the `advance_to` values. If the
observed pattern doesn't fit any `if` branch, that is itself a
signal — HYPOTHESIZE to extend the fork space, don't silently
rationalize.

Lead-level predictions are **not** a substitute for hypothesis-level
predictions. The two are orthogonal commitments:

| Form | Commits to | When to use |
|---|---|---|
| Hypothesis + predictions | Named world models; predictions test them | Multiple plausible explanations, analytically distinct, divergent step-1 leads |
| Lead + predictions | Decision rules on a shared next-step lead | Same step-1 lead regardless; the *reading* determines step-2 |

Interpretation-vulnerability is per-field, not per-lead. A single
lead can mix mechanical fields (UID, count) with interpretive ones
(process-name plausibility, threshold judgment). Pre-register on
the specific fields that carry the judgment.

**`attribute_updates` vs `observations`.** Use `attribute_updates`
when the lead enriches an already-confirmed vertex or edge without
new topology (e.g., a classification lookup adds `classification:
monitoring-host` to an existing endpoint vertex; a legitimacy
resolution adds a `legitimacy_resolutions` entry to an existing edge).
Use `observations` when new vertices or edges enter the confirmed
graph. Both may appear in the same outcome. Each `attribute_updates`
entry targets exactly one of `target: v-{id}` or `target: e-{id}`.

**`trust_anchor_result`.** Include whenever an authority anchor was
queried. Five fields: anchor identity (`anchor_id`, `kind`), verdict
(`result`), temporal validity (`as_of`), and scope (`authority_for_question`).

`as_of` is the timestamp the answer is **authoritative about** — not
the query time unless they coincide:
- Event anchors (did X happen at time T?) → the event timestamp
- Current-state anchors (is property X true now?) → the query time
  or snapshot timestamp
- Slowly-changing references (was status X as of last sync?) → the
  last-modified time, not the query time

`authority_for_question: partial` means the anchor covers only some
aspects of the question. A `partial` anchor cannot push a hypothesis
past `+` or `-` regardless of its verdict (validator rule 14).

**`failure_reason` enum.** `adapter-error` | `attribution-opaque` |
`partial-coverage` | `permission-denied` | `timeout` | `other`

**Severity of test.**

| Severity | Meaning | Max weight effect |
|---|---|---|
| `severe` | Outcome directly confirms or contradicts a core prediction | up to `++` / `--` |
| `moderate` | Constrains plausibility without direct contradiction | one step |
| `weak` | Circumstantial consistency | caps at `+` / `-` |

### Conclude

```yaml
conclude:
  termination:
    category: trust-root | adversarial-refuted | severity-ceiling | exhaustion-escalation
    rationale: <string>
  disposition: benign | true_positive | unclear
  confidence: high | medium | low
  matched_archetype: <name> | null
  surviving_hypotheses: [h-001, h-002]   # IDs of declared hypotheses whose final weight is not `--`; required by rule 24
  ceiling_test:                          # required when category = severity-ceiling
    kind: out-of-band-human-contact | tool-unavailable | legal-authorization | other
    subject: <string>
  ceiling_rationale: <string>            # required when category = severity-ceiling
  summary: <string>
```

**`surviving_hypotheses`.** When a `conclude:` block is written, every
declared hypothesis whose final effective weight is not `--` must appear in
this list (validator rule 24). Empty list is valid — it means every
hypothesis reached `--`. For `disposition: benign` the list is typically
empty; for escalation shapes it names the hypotheses that kept the
investigation from closing and should be included in the analyst handoff.

**Termination categories.**
- `trust-root` — confirmed graph reached a vertex with no accessible
  upstream. Frontier collapsed.
- `adversarial-refuted` — every adversarial hypothesis was explicitly
  refuted by confirmed evidence.
- `severity-ceiling` — live hypotheses remain but their critical
  edges cannot be tested with available tools. `ceiling_test`
  records the out-of-band step that would resolve it.
- `exhaustion-escalation` — loop budget exhausted.

**Legitimacy-gated disposition.** `disposition: benign` requires that
every `legitimacy_contract` on every confirmed-weight hypothesis
(weight `++` or `+`, status `confirmed` or `active`) has at least one
fulfilling `legitimacy_resolutions` entry with `verdict: authorized`
on a contracted edge. Any contract that is unfulfilled, or whose
fulfillment carries `verdict: indeterminate`, caps disposition at
`unclear` with `status: escalated`. Any `verdict: unauthorized` forces
`status: escalated` with disposition ∈ {`unclear`, `true_positive`}
depending on remaining evidence. This replaces the former "maintain
adversarial hypothesis until `--`" bookkeeping rule; teeth are
structural via validator rule #21.

---

## Conventions

### Lifecycle vs action observations

SIEM observations come in two shapes.

**Lifecycle** — a persistent entity that now exists: a process
running on a host, a session that was established, a file that was
written. The entity outlives the event and the investigation will
refer to it as a noun. Model it as a vertex; model the event with an
edge verb (`spawned`, `wrote`, `authenticated_as`, `runs_in`, …).

**Action** — an audit-log record of an invocation: who called what
with which arguments. Model as a `command` vertex carrying the
action's attributes, with `targeted → <thing acted on>` and (when
applicable) `executed_in → session`. Covers cloud API calls, failed
auth attempts, list/enumerate operations, configuration changes.

**Discriminator.** Is the observation's natural noun an invocation?
→ action (`command` vertex). Is it an entity whose later state the
investigation reasons about? → lifecycle (typed vertex + edge verb).

**CRUD is uniformly action-shaped.** `iam:CreateUser`,
`s3:DeleteObject`, `s3:GetObject` all model as `command` vertices.
Promote the target to its own vertex only if later reasoning
references it as a noun.

### Aggregate observations

When an observation describes N occurrences of something (17
ListObjectsV2 calls over a 172-second window), the aggregate belongs
on a single edge with `count` + `window_*` attributes. Do not
materialize one vertex per occurrence. The SIEM's native unit is the
alert; model at that unit.

### Mechanical leads stay within their data source

A scope lead's `outcome.observations` contains only vertices the
data source directly observes. If the raw event stream would not
contain a record naming a vertex by its native identity, do not
materialize it. Causal implication does not count as native naming.

---

## Types

| Type | Replaces | Notes |
|---|---|---|
| `endpoint` | host, device, remote-endpoint, ip | Compute unit with an OS. IP-only sources use `endpoint` with `attributes.knowledge: partial`. Vendor specifics in `attributes.kind`. |
| `process` | — | Running execution unit on an endpoint. |
| `thread` | — | Sub-entity of process; use with `component_of` and hierarchical ID. |
| `memory-region` | — | Sub-entity of process; use with `component_of` and hierarchical ID. |
| `module` | — | Loaded library/DLL; use with `component_of` and hierarchical ID. |
| `container` | — | Runtime container. |
| `session` | — | Authenticated interactive or API session. |
| `identity` | user | Any authenticatable entity. `attributes.kind ∈ {user, group, role, service-account, application}`. |
| `storage` | — | Object/file/blob/secret store. `attributes.kind ∈ {object-store, block, file, secrets, nfs}`. |
| `database` | — | Structured data system with query interface. |
| `network-device` | — | Firewall, switch, router, load balancer, WAF. |
| `file` | — | A specific file artifact. |
| `command` | — | An audited invocation (action-shaped observation). |
| `socket` | — | Network socket (transport-layer). |

Use `unclassified-{type}` when classification is unknown.
Use `ambiguous-{a}-or-{b}` when two classifications are genuinely
indistinguishable.

---

## Relations

| Relation | Source → Target | Notes |
|---|---|---|
| `spawned` | process → process | |
| `executed` | process → file | |
| `loaded_by` | process → file | For modules / libraries. |
| `opened` | process → socket | |
| `connected_to` | socket → endpoint | Transport-layer only. |
| `read` / `wrote` | process → file | |
| `runs_in` | process → container | |
| `runs_on` | process \| container \| database \| session → endpoint | Compute-substrate containment. |
| `authenticated_as` | session → identity | |
| `initiated_by` | session → identity \| endpoint | |
| `triggered_by` | process \| session → process \| session | |
| `escalated_privilege` | session → session | Self-edge. |
| `executed_in` | command → session | |
| `targeted` | command → endpoint \| storage \| database \| identity \| file \| container \| network-device | Action-target for command vertices. Do not use for lifecycle events. |
| `member_of` | identity → identity | User → group, role → role-bundle. |
| `identified_as` | placeholder → real-vertex | Post-hoc attribution. Never mutate the placeholder. |
| `component_of` | vertex → vertex | Part-of for inward decomposition. Sub-entity → containing entity. Vertex type discriminates semantics. |
| `listed` | session \| process → storage \| database | Enumeration/list operation. |
| `modified` | session \| process → storage \| database \| identity \| file | Configuration or state change. |
| `attempted_auth` | endpoint \| process \| session → endpoint | Observed authentication attempt (may be failed). |
| `classified_as` | vertex → classification-value | |

`listed`, `modified`, `attempted_auth` are provisional — in active
use across the pilot corpus but not yet stabilised from wider case
coverage.

---

## Validator rules

1. **Schema validity.** Required fields present, enums valid, IDs
   well-formed (including hierarchical patterns for hypotheses and
   sub-vertices).

2. **Classification vocabulary.** Every `classification` is from the
   seed vocabulary (§Types classification lists) or a
   `{type}:{slug}` provisional.

3. **Relation catalog.** Every `edge.relation` appears in §Relations.

4. **Edge authority rule.** `++` or `--` resolutions cite at least
   one `siem-event`, `runtime-audit`, or `authoritative-source` edge
   in `supporting_edges`.

5. **Refutation ID match.** Every `--` resolution's
   `matched_refutation_ids` is non-empty and references IDs that
   exist in the target hypothesis.

6. **Prediction completeness for `++`.** `matched_prediction_ids`
   across all resolutions on a hypothesis must equal the full
   prediction set. Partial coverage caps at `+`.

7. **ID references resolve.** Every `v-*`, `e-*`, `h-*`, `l-*`
   reference in any field points to a record that exists in the
   companion.

8. **Append-only.** No existing record is mutated.

9. **Lead block self-containment.** Every vertex, edge, or hypothesis
   produced by a lead lives inside that lead's `outcome.observations`,
   `new_hypotheses`, or `shelved`.

10. **Mechanical leads stay within their data source.** A lead's
    `outcome.observations` contains only entities the queried system
    directly observes by native identity.

11. **`trust_anchor_result` completeness.** When present, all five
    fields (`anchor_id`, `kind`, `result`, `as_of`,
    `authority_for_question`) are required.

12. **Hierarchical hypothesis ID consistency.** A hypothesis with ID
    `h-001-002` requires that `h-001` exists in the same companion.

13. **`ceiling_test` requires severity-ceiling.** Required when
    `termination.category: severity-ceiling`; forbidden otherwise.

14. **`partial` authority caps weight.** A resolution grounded solely
    by a `trust_anchor_result` with `authority_for_question: partial`
    cannot push a hypothesis past `+` or `-`.

15. **`component_of` sub-vertex ID convention.** Sub-vertices should
    follow `v-{parent}-{nonce}`. Not mechanically enforced; enforced
    by review.

16. **`screen_result` requires `mode: screen`.** `outcome.screen_result`
    is only valid on leads where `mode: screen` is set. Only the final
    lead in a SCREEN sequence carries `screen_result`; intermediate
    screen leads omit it.

17. **SCREEN-matched companions omit `hypothesize`.** When
    `outcome.screen_result: match` is present on any lead,
    the top-level `hypothesize` block must be absent.

18. **Lead-level predictions structure.** When `lead.predictions` is
    present, each entry has `id` (matching `^lp\d+$`, unique within
    the lead), `if`, `read_as`, `advance_to`. `advance_to` is either
    a lead name appearing elsewhere in the companion, or one of
    `CONCLUDE` / `HYPOTHESIZE`. If the lead is followed by another
    lead in the same companion, the follower's `name` should match
    at least one `advance_to` value — otherwise a route-compliance
    warning is emitted.

19. **Legitimacy contract `edge_ref` resolves.** Every
    `legitimacy_contract[].edge_ref` is either the literal `proposed`
    (referring to the hypothesis's own `proposed_edge`) or an `e-*`
    id that exists in the companion.

20. **Legitimacy back-reference resolves.** Every
    `legitimacy_resolutions[].fulfills_contract` of the form
    `h-{id}.lc{n}` points to an existing hypothesis whose
    `legitimacy_contract` contains an entry with that id.

21. **Legitimacy-gated disposition.** A `conclude.disposition: benign`
    requires every `legitimacy_contract` across all confirmed-weight
    hypotheses (weight `++` or `+`, status `confirmed` or `active`)
    to have at least one fulfilling `legitimacy_resolutions` entry
    with `verdict: authorized`. Unfulfilled contracts, or fulfillments
    with `verdict: indeterminate`, force `status: escalated` and
    disposition ∈ {`unclear`}. Any `verdict: unauthorized` forces
    `status: escalated` with disposition ∈ {`unclear`, `true_positive`}.
    Replaces the former "maintain adversarial hypothesis until `--`"
    bookkeeping rule.

22. **Attribute-update target shape.** Every `attribute_updates` entry
    has exactly one of `target: v-{id}` or `target: e-{id}`, and the
    id exists in the companion.

23. **Hypothesis fork distinctness.** Within a sibling group —
    hypotheses sharing `(parent_hypothesis_id, attached_to_vertex)` —
    no two may share `proposed_edge.parent_vertex.classification`.
    Duplicates propose the same causal upstream under two ids and
    cannot be discriminated by any lead. The HYPOTHESIZE subagent
    applies a story-diff self-check before emitting (each pair of
    active hypotheses must have at least one observable whose
    predicted value differs); this rule is the structural backstop
    when the check is skipped.

24. **Hypothesis persistence — no orphaned hypotheses at CONCLUDE.**
    When a `conclude:` block is present, every hypothesis declared in
    `hypothesize.hypotheses[]` or any prior `lead.outcome.new_hypotheses[]`
    must either (a) have its final effective weight be `--` across the
    resolutions chain, OR (b) be cited in the conclude block (as the
    termination target, as the matched archetype's mechanism, or as a
    surviving-but-indeterminate hypothesis driving `status: escalated`).
    A hypothesis declared and then silently ignored — never refuted,
    never carried into CONCLUDE — fails this rule. Closes the "silent
    hypothesis drop across loops" bias: grading blindness on one
    mechanism cannot be papered over by forgetting the hypothesis
    existed. The ANALYZE subagent is the proximate enforcer (it
    decides when weights are terminal); this rule is the structural
    backstop at the CONCLUDE write boundary.

25. **Same-level sibling rollup — prediction IDs are hypothesis-scoped.**
    On any `gather[i].resolutions[j]` entry for target hypothesis `H`,
    every id in `matched_prediction_ids[]` must appear in `H`'s own
    declared `predictions[]`. Rule 5 already enforces the equivalent
    for `matched_refutation_ids[]` on `--` resolutions; rule 25
    extends coverage to `matched_prediction_ids[]` on every weight
    and closes the same-level sibling-rollup loophole (upgrading `H`
    on the strength of a sibling's confirmed prediction). Rule 6's
    per-hypothesis coverage aggregation would silently ignore a
    mis-cited ID; rule 25 rejects it loudly so the grade is forced
    to rest on this hypothesis's own evidence.
