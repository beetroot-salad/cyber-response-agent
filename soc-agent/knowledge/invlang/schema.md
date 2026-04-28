# Investigation Language — Agent Reference

Schema v2.15. Validator: `hooks/scripts/invlang_validate.py` (PreToolUse hook on investigation.md writes; 29 active rules across numbering 1–36 with seven preserved-as-redirect gaps). Full spec: `docs/investigation-language.md`.

Three orthogonal resolution axes:

- **Authorization** — *is this edge permitted by policy?* Categorical verdict, single-source-of-truth anchors. Declared as `authorization_contract` on a hypothesis, resolved via `authorization_resolutions[]` on the edge.
- **Integrity** — *is the acting entity what it claims to be?* Evidential, composed from observables. No contract; represented as peer mechanism hypotheses (`?adversary-controlled-*`) with predictions on discriminators.
- **Impact** — *does this edge's effect matter enough to escalate?* Quantitative, threshold-gated. Declared as lead-level `impact_predictions[]`, graded at ANALYZE into `impact_resolutions[]` on the lead outcome.

CONCLUDE carries both the authz/mechanism axis (`disposition`) and the impact axis (`impact_verdict` + `impact_severity`). Integrity resolves through normal hypothesis weight machinery.

---

## Principles

**Graph discovery.** An investigation constructs a directed graph by working backward from the alert. Confirmed vertices and edges grow monotonically. The investigation halts when the frontier is empty (all active hypotheses resolved) or a trust root is reached — i.e. the lead reports `outcome.trust_root_reached` and no live hypothesis can extend upstream.

**Entities as vertices.** Every observed entity (endpoint, process, identity, session, file…) becomes a typed vertex with a classification and identifier. Model at the resolution the investigation reasons at — don't decompose finer unless a lead forces it. When it does, append sub-vertices via `component_of` with hierarchical IDs (`v-{parent}-{nonce}`); the parent vertex remains valid.

**Relations as edges.** Observed connections and events between entities become edges. Each edge carries observational authority (how reliably the source recorded it) and — when a contract fulfills against it — one or more `authorization_resolutions[]` entries.

**Hypotheses as proposed edges.** A hypothesis proposes that one specific upstream vertex exists, connected to a confirmed vertex by exactly one edge (`proposed_edge`). Predictions describe what observable evidence would confirm or contradict it; keep to 1–2 predictions — the minimum that distinguishes this hypothesis from competing ones. **Prediction scope is unbounded** — predictions may reference observables from any system or time range. The one-hop discipline governs what extends the confirmed graph on `++`, not where evidence may be queried. Cardinality per PREDICT pass is 0–N (realistically ≤ 3); 0 is legal when the loop is enriching before a fork is possible.

**Attributes.** Facts about a vertex that don't add topology stay as `attributes` on the vertex or as `attribute_updates` in a lead outcome. Don't materialize a vertex just to carry an attribute.

**Leads.** A lead is a graph operation: topology-extending (new vertices/edges enter the confirmed graph via `outcome.observations`) or attribute-refining (existing vertices enriched via `attribute_updates`), or both. `tests` declares which hypotheses it discriminates; `resolutions` records weight effects. A non-branching lead may pre-commit to a reading via lead-level `predictions` (conditional branch plans `if X → read_as Y → advance_to Z`). Leads that measure impact observables carry `impact_predictions[]` (pre-committed thresholds); ANALYZE grades them into `impact_resolutions[]`.

**Corpus.** Past investigations are queryable. Query before PREDICT to calibrate hypothesis names and weights; set `matched_archetype` at REPORT to connect this run.

---

## Phase-to-block map

| Phase | Block written | When |
|---|---|---|
| CONTEXTUALIZE | `prologue:` | end of CONTEXTUALIZE |
| SCREEN | first `findings:` lead with `mode: screen` | after screen subagent returns |
| PREDICT | `hypothesize:` (only when ≥ 1 new hypotheses); lead skeleton with `impact_predictions[]` when applicable | end of PREDICT |
| GATHER | `findings:` lead entry populated with query + observations + consultations + attribute_updates (no resolutions — those are ANALYZE's) | end of GATHER |
| ANALYZE | same-lead merge into `findings[]` adding outcome.resolutions + trust_anchor_result + legitimacy_resolutions + impact_resolutions | end of ANALYZE |
| REPORT | `conclude:` | after the `## REPORT` header + verdict line, before report.md |

Call `invlang --enum` before writing any block that introduces new IDs or references existing ones.

---

## Top-level structure

Every list item below is a flat object — no wrapping key (no `- vertex:`, `- edge:`, `- hypothesis:`, `- lead:`).

```yaml
prologue:       # vertices + edges from alert entities
  vertices:
    - id: v-001          # vertex object fields directly
      type: endpoint
      ...
  edges:
    - id: e-001          # edge object fields directly
      ...

hypothesize:    # proposed frontier; omit when PREDICT authors 0 new hypotheses
  hypotheses:
    - id: h-001          # hypothesis object fields directly
      ...

findings:       # one entry per lead; GATHER populates query + observations; ANALYZE
                # merges in outcome.resolutions + verdicts on the same lead id
  - id: l-001            # lead object fields directly
    loop: 1
    ...

conclude:
  ...
```

Leads in the same iteration share a `loop:` value; there is no grouping wrapper.

---

## Vertex

Fields of a vertex object (list item under `prologue.vertices` or `outcome.observations.vertices`):

```yaml
id: v-{nonce}              # stable, append-only; sub-vertices: v-{parent}-{nonce}
type: <string>             # from type vocabulary
classification: <string>   # from seed list or {type}:{slug} provisional
identifier: <string>       # human-readable primary key
attributes: {}             # type-specific key-value pairs; omit if empty
placeholder: true          # omit when false
concerns: []               # omit if empty
citations: []              # omit if single or implicit
```

Trust-root signaling lives on lead outcomes (`outcome.trust_root_reached: v-{id}`) and CONCLUDE (`termination.category: trust-root`), not on vertices. A vertex does not carry an intrinsic trust-root attribute.

---

## Edge

Fields of an edge object (list item under `prologue.edges` or `outcome.observations.edges`):

```yaml
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
                           # Observational authority — how reliably the source recorded the
                           # observation. Distinct from authz grounding (`authorization_resolutions[].grounding_kind`)
                           # and from anchor consultation kinds (`anchor_consultations[].grounding_kind`).
  source: <string>
  trust_chain: []          # omit if empty
authorization_resolutions: []
                           # one entry per fulfilled authorization_contract; see §Edge authorization below.
                           # Omit when no contract resolves against this edge.
concerns: []               # omit if empty
```

### Edge authorization

When a hypothesis declares an `authorization_contract` and the resolving lead materializes the `proposed_edge`, the new edge carries the verdict inline via `authorization_resolutions[]`. When a contract resolves against an *already-confirmed* edge (not the hypothesis's own proposed edge), the resolving lead writes the verdict via `attribute_updates` targeting that edge — never by mutating the original edge record (append-only).

Each entry:

```yaml
- verdict: authorized | unauthorized | indeterminate
  anchor_kind: <string>           # iam-policy | data-classification-policy | oncall-schedule
                                  # | deploy-runs | approved-monitoring-sources | ...
                                  # The authority surface consulted. Distinct from
                                  # `edge.authority.kind` and `anchor_consultations[].grounding_kind`.
  anchor_id: <string>             # concrete authority identifier
  grounding_kind: org-authority | past-case
                                  # telemetry-baseline NOT admissible — baselines answer
                                  # expectation, not authorization. Baseline queries that
                                  # inform hypothesis weight without fulfilling a contract
                                  # live in `anchor_consultations[]` on the lead outcome.
  authority_for_question: full | partial
                                  # `partial` caps weight effect at `+`/`-` (rule #14).
  anchor_query: <string>          # short human-readable record of what was asked
  as_of: <iso>                    # timestamp the answer is authoritative ABOUT
  effective_window:               # optional; authz grants with explicit time bounds
    start: <iso>                  # (change windows, oncall shifts, travel approvals)
    end: <iso>
  conditioning_context: []        # optional prose list of then-true conditions the
                                  # verdict rests on ("CHG-2041 active", "oncall X")
  cites_past_case:                # required when grounding_kind: past-case
    run_id: <run-id>
    contract_ref: h-{id}.ac{n}
  resolved_by_lead: l-{id}
  fulfills_contract: h-{id}.ac{n} # back-reference to the declaring hypothesis's contract
  concerns: []                    # optional
```

Plural because real edges often face parallel policy layers — IAM × data-classification × time-of-day — each resolved independently by a different anchor, any one of which can deny.

---

## Hypothesis

Fields of a hypothesis object (list item under `hypothesize.hypotheses` or `lead.new_hypotheses`). `proposed_edge.parent_vertex` is the *causal upstream* — the vertex that would explain the confirmed anchor if it existed.

```yaml
id: h-{nonce}              # child refinements: h-{parent}-{nonce}
name: "?descriptive-slug"
attached_to_vertex: v-{id}         # confirmed vertex this one-hop extension grafts onto
proposed_edge:
  relation: <string>
  parent_vertex:
    type: <string>
    classification: <string>
    attributes: {}         # omit if empty
predictions:
  - id: p1
    subject: proposed_parent   # one of: proposed_parent | attached_vertex | proposed_edge
    claim: "<source-agnostic claim about world state>"
attribute_predictions:     # optional; makes implicit classification stereotypes explicit.
                           # IDs local to the hypothesis, pattern ^ap\d+$.
                           # Claim one observable attribute per entry — gather will read
                           # this attribute as part of lead execution, analyze will match.
                           # Load-bearing when (a) the parent-vertex classification carries
                           # non-trivial stereotypes (cmdline shape, running-as user,
                           # parent-process genre) and (b) an observationally similar
                           # peer hypothesis exists that the attribute profile would
                           # discriminate. Omit when the classification is self-evidencing.
  - id: ap1
    target: proposed_parent       # one of: proposed_parent | attached_vertex | proposed_edge
    attribute: <field-name>       # e.g. cmdline, user_loginuid, parent_pname, tty
    claim: "<one observable attribute assertion>"
refutation_shape:          # omit if no clean refutation shape exists
  - id: r1
    refutes_predictions: [p1]  # non-empty list of ids on THIS hypothesis —
                               # may reference both predictions (p*) and
                               # attribute_predictions (ap*)
    claim: "<observation that would contradict a core prediction>"
authorization_contract: [] # optional; present when disposition depends on policy
                           # authorization. Declare when the mechanism is consistent
                           # with both benign and adversarial readings depending on
                           # authorization; skip when the adversarial reading IS
                           # the mechanism (classification already carries the claim).
                           # Per entry (local ids match ^ac\d+$):
                           #   id: ac1
                           #   edge_ref: proposed | e-{id}
                           #   anchor_kind: <iam-policy | approved-monitoring-sources | ...>
                           #   predicate: "<natural-language claim — authorized iff ...>"
                           #   on_unauthorized: escalate
                           #   on_indeterminate: escalate
                           #   concerns: []   # optional
integrity_waived: <string> # optional; required when `authorization_contract` is declared
                           # on a hypothesis whose proposed_edge source is an
                           # acting-entity type (session | identity | process) AND
                           # no peer `?adversary-controlled-*` hypothesis is present.
                           # The string is the rationale (why integrity testing is not
                           # in scope for this case). See §Integrity discipline below.
concerns: []               # omit if empty
weight: null               # null | "++" | "+" | "-" | "--"
weight_history: []         # omit until transitions exist
status: active             # omit; emit confirmed | refuted | shelved when non-default
```

### Integrity discipline

When `authorization_contract` is declared and the `proposed_edge.parent_vertex.type` is an acting-entity type (`session`, `identity`, `process`), a peer integrity hypothesis (`?adversary-controlled-<entity>`) is expected — its predictions test whether the claimed entity is actually the one acting (application-layer correlation, query-shape template match, timing against baseline, device/geo consistency). The peer shares the authz contract's verdict (both `authorized` against IAM) and differs on observables that discriminate routine activity from impostor activity.

Omit the peer only when the integrity premise is out of scope for the case; in that case, declare `integrity_waived: <rationale>` on the contract-carrying hypothesis.

---

## Lead

Fields of a lead object (list item under `findings`):

```yaml
id: l-{nonce}
loop: <int>
name: <string>
target: v-{id}
selection_rationale: <string>   # optional; 1–3 sentences on why this lead now
mode: screen                    # omit unless SCREEN-dispatched
tests: [h-{id}, ...]            # optional; hypotheses this lead discriminates
observes:                       # optional; explicit prediction/refutation mapping
  - { hypothesis: h-{id}, predictions: [p1], refutations: [r1] }
predictions:                    # optional; pre-committed conditional branch plans for
                                # non-branching but interpretation-vulnerable leads.
                                # IDs local to the lead (lp1, lp2, …).
  - id: lp1
    if: "<outcome pattern>"
    read_as: "<interpretation>"
    advance_to: "<lead-name | REPORT | PREDICT>"
impact_predictions:             # optional; pre-registered threshold predicates
                                # authored by PREDICT for leads that measure
                                # impact-relevant observables. See §Impact below.
                                # IDs local to the lead (ip1, ip2, …).
  - id: ip1
    dimension: confidentiality | integrity | availability | scope
    claim: "<threshold predicate — one observable per claim>"
    on_match: within
    on_mismatch: exceeds
    on_indeterminate: indeterminate
    escalation_on: exceeds | indeterminate | none
query_details:
  system: <string>
  template: <string>
  query: <string>
  time_window: <string>
  substitutions: {}
concerns: []                    # omit if empty
outcome:
  attribute_updates:            # enriches existing confirmed vertices OR edges
    - target: v-{id} | e-{id}   # exactly one
      updates: {}               # when target is an edge and updates.authorization_resolutions
                                # is present, each entry is a full authorization_resolutions
                                # shape (see §Edge authorization).
  anchor_consultations:         # optional; structured record of baseline / registry / reference
                                # queries that inform hypothesis weight but do NOT fulfill
                                # an authorization_contract (baselines, registry lookups).
    - anchor_id: <string>
      anchor_kind: <string>     # vendor-level surface: image-baseline, user-cadence,
                                # asset-inventory, sensitive-data-registry, ...
      grounding_kind: org-authority | telemetry-baseline
                                # past-case NOT admissible here — past-case citations
                                # are authz evidence only and live in
                                # authorization_resolutions[].
      result: confirmed | refuted | partial | no-data
      as_of: <iso>              # timestamp the answer is authoritative ABOUT
      authority_for_question: full | partial
      anchor_query: <string>    # optional; human-readable record of what was asked
      effective_window:         # optional; when the consulted record carries time bounds
        start: <iso>
        end: <iso>
      conditioning_context: []  # optional; then-true conditions the verdict rests on
      concerns: []              # optional; snapshot freshness, coverage caveats
  impact_resolutions:           # optional; emitted by ANALYZE against the lead's
                                # pre-registered impact_predictions[]. See §Impact.
    - prediction_ref: ip1
      dimension: confidentiality
      observed_value: <string>  # quantitative or qualitative — e.g.
                                # "180GB (3σ above 30d baseline mean 60GB, σ 40GB)"
      verdict: within | exceeds | indeterminate
      matched_predicate: "<verbatim predicate from ip*>"
      grounded_by_lead: l-{id}
      grounding_kind: telemetry-baseline | business-owner-attestation | dlp-policy
                                # past-case NOT admissible — category reasoning, not
                                # instance reasoning.
      anchor_id: <string>
      anchor_kind: <string>
      authority_for_question: full | partial
      as_of: <iso>
      effective_window:         # optional
        start: <iso>
        end: <iso>
      conditioning_context: []  # optional
      reasoning: <string>
  observations:
    vertices: []
    edges: []
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
    reasoning: "<string>"       # why this evidence moves weight — not a field restatement
    supporting_edges: []
    load_bearing:               # optional; one entry per observation that swayed
                                # the weight. Self-declared observation salience:
                                # the specific field that mattered + a counterfactual
                                # naming the value that would have flipped the grade.
                                # No structural validator runs on this today — the
                                # artifact is captured for downstream perturbation
                                # analysis (Tier 1). Empirical: forcing this field
                                # on every ++/-- via prompt-level discipline
                                # increased false-true-positive rate on
                                # absence-of-confirmation traps (see /tmp/stress
                                # trap-set evaluation, 2026-04-28). Field is
                                # available; do not require it.
      - field: <field-name>     # native field on the cited authority
        source: l-{id} | prologue | e-{id}
        counterfactual: <string>
```

### Impact

Impact is graded at ANALYZE against predicates authored by PREDICT. The commit-before-evidence property transfers: the threshold is written into `impact_predictions[]` before the lead runs, so ANALYZE cannot retroactively shift the bar.

- **`impact_predictions[]`** declares threshold predicates on the lead. One observable per `claim` — split compound AND/OR into multiple `ip*` entries.
- **`impact_resolutions[]`** matches observation against the predicate and emits a verdict. `grounding_kind: telemetry-baseline` is the common case; business-owner attestation and DLP policy lookups are also admissible. Past-case is not — impact reasoning is per-instance, not category-of-event.
- Rule #14 (partial-authority cap) applies — a baseline that covers magnitude but not intent is `partial` and cannot alone force high severity.
- CONCLUDE closes the loop: every declared `impact_predictions[]` entry must either have a fulfilling `impact_resolutions[]` entry, OR appear in `conclude.deferred_impact_predictions[]` with rationale.

Per-signature impact knowledge lives in playbook prose (no new schema artifact in v2.11). Signature-tier `impact_profile.md` is a future promotion if corpus measurements show PREDICT threshold drift; promotion is additive (`impact_predictions[].inherited_from: sig-iq{n}` back-reference).

---

## Conclude

```yaml
conclude:
  termination:
    category: trust-root | adversarial-refuted | severity-ceiling | exhaustion-escalation
    rationale: <string>
  disposition: benign | true_positive | unclear              # authz/mechanism axis
  impact_verdict: none | within | exceeds | indeterminate    # impact axis
  impact_severity: null | low | moderate | high              # present when impact_verdict ∈ {exceeds, indeterminate}
  confidence: high | medium | low
  matched_archetype: <name> | null   # archetype directory name from
                                     # knowledge/signatures/{sig}/archetypes/{name}/
  surviving_hypotheses: [h-001, ...] # IDs of declared hypotheses whose final weight
                                     # is not `--` — validator rule #24 rejects
                                     # silent drops at REPORT write time
  deferred_authorizations:           # required when any declared authorization_contract
                                     # has no fulfilling resolution (rule #26)
    - contract_ref: h-{id}.ac{n}
      rationale: "<why this contract was not resolved>"
  deferred_impact_predictions:       # required when any declared impact_predictions[]
                                     # entry has no fulfilling resolution
    - prediction_ref: l-{id}.ip{n}
      rationale: "<why this impact prediction was not resolved>"
  ceiling_test:                      # required when category = severity-ceiling
    kind: out-of-band-human-contact | tool-unavailable | legal-authorization | other
    subject: <string>
  ceiling_rationale: <string>        # required when category = severity-ceiling
  summary: <string>
```

**Two-axis disposition.** `disposition` and `impact_verdict` combine orthogonally:

| disposition | impact_verdict | Meaning |
|---|---|---|
| benign | within | Routine activity, no escalation |
| benign | exceeds | **Authorized-but-malifying** — mechanism confirmed benign; consequence exceeds threshold. Analyst review on impact |
| true_positive | within | Confirmed threat whose consequence stayed bounded (failed probe, denied access) |
| true_positive | exceeds | Confirmed threat with realized consequence. Highest-severity class |
| unclear | \* | Mechanism indeterminate; impact verdict still recorded for handoff |

`impact_severity` rolls up across fulfilling `impact_resolutions[]`, capped by any `authority_for_question: partial` per rule #14.

**Authorization-gated disposition.** `disposition: benign` requires every `authorization_contract` on a confirmed-weight hypothesis (`++` or `+`, status `confirmed` or `active`) to have at least one fulfilling `authorization_resolutions` entry with `verdict: authorized`. Any unfulfilled contract (absent from `deferred_authorizations`) or `verdict: indeterminate` caps at `unclear`. Any `verdict: unauthorized` forces disposition ∈ {`unclear`, `true_positive`}.

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

Acting-entity types (trigger the §Integrity discipline when an `authorization_contract` is declared on an edge sourced from one of them): `session`, `identity`, `process`.

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

### Hypothesis — lean one-hop predictions with authorization contract

```yaml
- id: h-001
  name: "?scheduled-monitoring-probe"
  attached_to_vertex: v-001          # confirmed source endpoint (172.22.0.10)
  proposed_edge:
    relation: initiated_by
    parent_vertex:
      type: identity
      classification: approved-monitoring-service-account
      attributes: { kind: service-account }
  predictions:
    - id: p1
      subject: proposed_parent
      claim: "source triple (172.22.0.10, monitorprobe, 10.0.7.44) is a registered active probe in approved-monitoring-sources"
  refutation_shape:
    - id: r1
      refutes_predictions: [p1]
      claim: "triple absent or marked inactive/revoked in approved-monitoring-sources"
  authorization_contract:
    - id: ac1
      edge_ref: proposed
      anchor_kind: approved-monitoring-sources
      predicate: "triple (src, user, dst) listed as active approved monitoring probe"
      on_unauthorized: escalate
      on_indeterminate: escalate
  weight: null
  status: active

- id: h-002
  name: "?adversary-controlled-source-session"
  attached_to_vertex: v-001
  proposed_edge:
    relation: initiated_by
    parent_vertex:
      type: process
      classification: non-monitoring-process-on-source
  predictions:
    - id: p1
      subject: proposed_parent
      claim: "no monitoring-system scheduler/audit entry correlates to this tick within ±30s"
  refutation_shape:
    - id: r1
      refutes_predictions: [p1]
      claim: "monitoring-system scheduler/audit entry correlates within ±30s"
  weight: null
  status: active
```

h-002 is the peer integrity hypothesis required by the §Integrity discipline — h-001 carries an `authorization_contract` and the proposed edge sources from an acting-entity type (`identity`).

### Lead — contract resolution on proposed edge

```yaml
- id: l-001
  loop: 1
  name: monitoring-source-registry-lookup
  target: v-001
  tests: [h-001, h-002]
  query_details:
    system: approved-monitoring-sources
    template: triple-lookup
    query: "src=172.22.0.10 user=monitorprobe dst=10.0.7.44"
  outcome:
    observations:
      vertices: []
      edges:
        - id: e-010
          relation: initiated_by
          source_vertex: v-002          # the materialized approved-monitoring-service-account identity
          target_vertex: v-001
          authority:
            kind: authoritative-source
            source: approved-monitoring-sources
          authorization_resolutions:
            - verdict: authorized
              anchor_kind: approved-monitoring-sources
              anchor_id: ams-registry-2026-01
              grounding_kind: org-authority
              authority_for_question: full
              anchor_query: "triple (172.22.0.10, monitorprobe, 10.0.7.44)"
              as_of: 2026-04-23T14:00Z
              effective_window:
                start: 2026-01-01T00:00Z
                end: 2026-06-30T00:00Z
              resolved_by_lead: l-001
              fulfills_contract: h-001.ac1
  resolutions:
    - hypothesis: h-001
      before: null
      after: "+"
      severity_of_test: moderate
      matched_prediction_ids: [p1]
      reasoning: "registry confirms the triple as active registered probe; contract ac1 resolved authorized. Identity-of-use question (is the monitoring daemon actually the actor on this tick?) still open — see h-002."
      supporting_edges: [e-010]
```

### Lead — impact predictions + resolution

```yaml
- id: l-002
  loop: 2
  name: volume-profile
  target: v-003                      # session whose access triggered the DLP alert
  impact_predictions:
    - id: ip1
      dimension: confidentiality
      claim: "session_total_bytes within 30d service-account baseline mean ± 2σ"
      on_match: within
      on_mismatch: exceeds
      on_indeterminate: indeterminate
      escalation_on: exceeds
  query_details:
    system: wazuh-indexer
    template: session-upload-profile
    time_window: "30d"
  outcome:
    observations:
      vertices: []
      edges: []
    anchor_consultations:
      - anchor_id: backup-daemon-30d-baseline
        anchor_kind: session-volume-baseline
        grounding_kind: telemetry-baseline
        result: confirmed
        as_of: 2026-04-23T14:32Z
        authority_for_question: partial
        anchor_query: "30d session_total_bytes mean + σ for service account backup-svc"
        conditioning_context: ["30d window excludes quarter-end surge"]
    impact_resolutions:
      - prediction_ref: ip1
        dimension: confidentiality
        observed_value: "180GB (3σ above 30d baseline mean 60GB, σ 40GB)"
        verdict: exceeds
        matched_predicate: "session_total_bytes within 30d service-account baseline mean ± 2σ"
        grounded_by_lead: l-002
        grounding_kind: telemetry-baseline
        anchor_id: backup-daemon-30d-baseline
        anchor_kind: session-volume-baseline
        authority_for_question: partial
        as_of: 2026-04-23T14:32Z
        conditioning_context: ["30d window excludes quarter-end surge"]
        reasoning: "observed 3σ exceedance; predicate threshold was 2σ. Partial authority (baseline covers magnitude not intent) caps severity at moderate."
```

### Lead — non-branching with pre-committed readings

```yaml
- id: l-003
  loop: 1
  name: access-cadence-profile
  target: v-003
  selection_rationale: "Cadence alone can't collapse a fork at loop 1; the profile shape
    determines the next lead rather than discriminating a hypothesis."
  query_details:
    system: wazuh-indexer
    template: identity-cadence
    time_window: "72h"
  predictions:
    - id: lp1
      if: "access matches identity's prior 72h cadence within 1σ"
      read_as: "periodic tooling pattern"
      advance_to: identity-of-use-lookup
    - id: lp2
      if: "bursty cluster concentrated in last 10 min"
      read_as: "anomalous spike; corroborates the DLP alert"
      advance_to: PREDICT
  outcome:
    attribute_updates:
      - target: v-003
        updates:
          cadence_72h_mean_interval_s: 576
          cadence_72h_stddev_s: 102
    observations:
      vertices: []
      edges: []
  resolutions: []
```

---

## Key rules

The validator enforces **29 active rules** (numbering 1–36). Numbers #10, #12, #15, #16, #19, #20, #22 are gaps — those rules were either merged into a sibling rule (numbering preserved as redirects) or demoted to review-only discipline. Rule #36 (v2.14, affirmative true_positive disposition) is the most recent addition.

1. **Schema validity.** Required fields present, enums valid, IDs well-formed (including hierarchical patterns for hypotheses, sub-vertices `v-{parent}-{nonce}`, and the `attribute_updates.target` exclusivity — exactly one of `v-{id}` / `e-{id}`).
2. **Classification vocabulary.** Every `classification` is from the seed vocabulary or a `{type}:{slug}` provisional.
3. **Relation catalog.** Every `edge.relation` appears in the relation catalog.
4. **Edge authority.** `++`/`--` resolutions must cite at least one `siem-event`, `runtime-audit`, or `authoritative-source` edge in `supporting_edges`.
5. **Refutation IDs.** Every `--` resolution has non-empty `matched_refutation_ids` referencing IDs that exist in the target hypothesis.
6. **Prediction completeness for `++`.** `matched_prediction_ids` across all resolutions on a hypothesis must equal the full prediction set; partial coverage caps at `+`. Early gate at write time; rule #34 is the late closure gate.
7. **Reference resolution.** Every `v-*`, `e-*`, `h-*`, `l-*` reference points to a declared record. Hierarchical hypothesis IDs `h-{parent}-{nonce}` require the parent to exist. `authorization_contract.edge_ref` is `proposed` or an existing `e-*`. `fulfills_contract` of shape `h-{id}.ac{n}` resolves to a declared contract. `attribute_updates.target` of shape `v-{id}` / `e-{id}` resolves. *(Absorbs former #12, #19, #20, and the resolution clause of former #22.)*
8. **Append-only.** No existing record is mutated.
9. **Lead block self-containment.** Every vertex, edge, or hypothesis produced by a lead lives inside that lead's `outcome.observations`, `new_hypotheses`, or `shelved`.
10. *(Demoted to review-only.)* Mechanical leads stay within their data source — semantic guideline retained in the spec, not validator-enforced.
11. **Anchor-query provenance completeness.** Every `authorization_resolutions[]` entry requires `verdict`, `anchor_kind`, `anchor_id`, `grounding_kind`, `authority_for_question`, `as_of`, `resolved_by_lead`, and `fulfills_contract`. When `grounding_kind: past-case`, `cites_past_case.run_id` and `cites_past_case.contract_ref` are required, AND `authority_for_question` must be `partial`. Every `anchor_consultations[]` entry requires `anchor_id`, `anchor_kind`, `grounding_kind`, `result`, `as_of`, and `authority_for_question`. Enum constraints: authz resolutions exclude `telemetry-baseline` from `grounding_kind`; consultations exclude `past-case`. *(Absorbs the past-case ⇒ partial enum clause from former #27a.)*
12. *(Merged into rule #7.)* Hierarchical hypothesis ID consistency.
13. **`ceiling_test` requires severity-ceiling.** Required when `termination.category: severity-ceiling`; forbidden otherwise.
14. **Partial authority caps weight.** A resolution grounded *solely* by `authorization_resolutions[]`, `anchor_consultations[]`, or `impact_resolutions[]` entries with `authority_for_question: partial` cannot push weight past `+` or `-` regardless of verdict or result.
15. *(Merged into rule #1.)* `component_of` sub-vertex `v-{parent}-{nonce}` shape.
16. *(Merged into rule #17.)* `screen_result` scope.
17. **SCREEN structural integrity.** `outcome.screen_result` is only valid on `mode: screen` leads, only on the final lead in a SCREEN sequence. SCREEN-matched companions (any lead with `screen_result: match`) omit the top-level `hypothesize` block. *(Absorbs former #16.)*
18. **Lead-level predictions structure.** Each `predictions[]` entry has `id` (matching `^lp\d+$`, unique within the lead), `if`, `read_as`, `advance_to`. `advance_to` is a lead name in the companion, or one of `REPORT` / `PREDICT`.
19. *(Merged into rule #7.)* Authorization contract `edge_ref` resolves.
20. *(Merged into rule #7.)* Authorization back-reference resolves.
21. **Authorization-gated disposition.** `conclude.disposition: benign` requires every `authorization_contract` across confirmed-weight hypotheses (`++` or `+`, status `confirmed` or `active`) to have at least one fulfilling `authorization_resolutions` entry with `verdict: authorized`. Unfulfilled contracts (and not listed in `deferred_authorizations`, per rule #26), or `verdict: indeterminate`, cap disposition at `unclear`. Any `verdict: unauthorized` forces disposition ∈ {`unclear`, `true_positive`}.
22. *(Merged into rules #1 and #7.)* Attribute-update target shape.
23. **Hypothesis fork distinctness.** Within a sibling group — hypotheses sharing `(parent_hypothesis_id, attached_to_vertex)` — no two may share `proposed_edge.parent_vertex.classification`.
24. **Hypothesis persistence at CONCLUDE.** Every declared hypothesis whose final effective weight is not `--` appears in `conclude.surviving_hypotheses[]`. Silent drops are rejected.
25. **Same-level sibling rollup.** Every id in `matched_prediction_ids[]` on a resolution for hypothesis `H` must appear in `H`'s own `predictions[]`. Cross-sibling citation is rejected.
26. **Authorization contract closure at CONCLUDE.** Every declared `authorization_contract[]` entry must either have a fulfilling `authorization_resolutions[]` entry OR appear in `conclude.deferred_authorizations[]` with a non-empty rationale.
27. **Past-case no-sole-grounding for benign.** On any contract load-bearing for `disposition: benign`, at least one fulfilling resolution must have `grounding_kind: org-authority`. *(Former past-case ⇒ partial enum clause moved to rule #11.)*
28. **Past-case chain depth cap.** An `authorization_resolutions[]` entry with `grounding_kind: past-case` cites a prior contract via `cites_past_case`. The cited resolution must have `grounding_kind: org-authority` — past-case cannot recursively authorize past-case.
29. **Impact prediction structure.** Each `impact_predictions[]` entry has `id` (matching `^ip\d+$`, unique within the lead), `dimension`, `claim`, `on_match`, `on_mismatch`, `on_indeterminate`, `escalation_on`. One observable per `claim` — compound AND/OR predicates split into separate entries.
30. **Impact resolution back-reference and grounding.** Every `impact_resolutions[]` entry has `prediction_ref` pointing to an `impact_predictions[]` id on a lead in the companion, `dimension` matching the prediction's `dimension`, `verdict` ∈ {`within`, `exceeds`, `indeterminate`}, `grounding_kind` ∈ {`telemetry-baseline`, `business-owner-attestation`, `dlp-policy`} (past-case not admissible), `authority_for_question`, `as_of`, and `reasoning`.
31. **Impact closure at CONCLUDE.** Every declared `impact_predictions[]` entry must either have a fulfilling `impact_resolutions[]` entry OR appear in `conclude.deferred_impact_predictions[]` with a non-empty rationale.
32. **Integrity peer discipline.** When an `authorization_contract` is declared on a hypothesis whose `proposed_edge.parent_vertex.type` is an acting-entity type (`session`, `identity`, `process`), either a peer integrity hypothesis (`?adversary-controlled-*` sharing `attached_to_vertex`) must exist in the same sibling group, or the contract-carrying hypothesis must carry `integrity_waived: <rationale>` with a non-empty string.
33. **Attribute-prediction structure.** Each `attribute_predictions[]` entry has `id` (matching `^ap\d+$`, unique within the hypothesis), `target` ∈ {`proposed_parent`, `attached_vertex`, `proposed_edge`}, `attribute` (non-empty string), and `claim` (non-empty string, one observable — compound AND/OR claims split into separate entries). `refutation_shape[].refutes_predictions` may cite `ap*` ids alongside `p*` ids on the same hypothesis. `matched_prediction_ids[]` on a resolution may likewise cite both `p*` and `ap*` ids from the target hypothesis.
34. **Prediction closure at CONCLUDE.** When a `conclude` block is present, every declared `predictions[].id` (`p*`) and `attribute_predictions[].id` (`ap*`) on a hypothesis whose final status is neither `refuted` nor `shelved` must be either (a) cited in some resolution's `matched_prediction_ids[]` with a non-null `after`, OR (b) listed in `conclude.deferred_predictions[]` with a non-empty `rationale`. Each deferred entry has the shape `{prediction_ref: h-{id}.{p|ap}{n}, rationale: "<why this prediction was not graded>"}`. Generalises rule #6 (which only fires on `++`) into a coverage check at REPORT regardless of weight — closes the contract analyze owes predict.
35. **Sibling prediction divergence.** Within a sibling group — hypotheses sharing `(parent_hypothesis_id, attached_to_vertex)` — no two siblings may declare identical prediction signatures. The signature combines `predictions[]` `(subject, claim)` tuples and `attribute_predictions[]` `(target, attribute, claim)` tuples (case-normalised). Identical signatures mean the two hypotheses propose the same observable expectations and ANALYZE has nothing to discriminate them on. Generalises rule #32 (integrity-peer specific, contract-gated) to all sibling forks; complements rule #23 — that rule blocks shared `parent_vertex.classification`, this one blocks shared prediction text.
36. **Affirmative true_positive disposition.** `conclude.disposition: true_positive` requires at least one entry in `conclude.surviving_hypotheses[]` to reference a hypothesis whose `proposed_edge.parent_vertex.classification` OR `name` carries an adversarial token (e.g. `?adversary-controlled-*`, `?attack-*`, `?malware-*`, `?compromise-*`, `?credential-guess-*`, `?exfiltration-*`, `?lateral-*`, `?post-exploit-*`, `?dga-*`, `?beaconing-*`, `?implant-*`) AND whose final weight is `++`. Absence of a surviving benign hypothesis is not affirmative evidence of adversarial activity; it is evidence of unverified authorization, and the honest landing is `disposition: unclear`. When `surviving_hypotheses` is absent, every declared hypothesis is candidate. The token list is matched case-insensitively against the start of the name/classification string (provisional `{type}:{slug}` classifications match on the slug).
