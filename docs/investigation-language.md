# Investigation Language

**Status:** Design proposal. Not implemented.
**Scope:** The structured companion to `investigation.md` and the retrieval substrate it enables.

---

## 1. Motivation

The investigation language is a structured companion to `investigation.md`. It exists so that past investigations are retrievable *by mechanism shape*, not by concrete instance — so the agent can find "past cases where an in-container process opened a socket to an unclassified external endpoint, and a trust lead against a threat-intel anchor resolved it" regardless of which specific container or IP was involved.

The primary motivation is to rescue Sonnet investigations on signatures with thin scaffolding. Sonnet investigates well when the playbook, archetypes, and lead catalog are mature; when they aren't, its investigations become superficial — fewer leads, weaker refutations, more circumstantial findings promoted to strong weights. A mechanically-queryable corpus of past investigations supplies scaffolding regardless of signature-specific knowledge: "at a vertex of this shape, here's what worked before, here's what was a dead end, here's what pitfall bit the last run."

The language is deliberately decoupled from:

- **SIEM vendor** — a Wazuh investigation and a Splunk investigation share the same retrieval substrate because the structured companion is in vendor-neutral terms.
- **Signature ID** — retrieval is over semantic vertex and edge shape, not over `wazuh-rule-5710`. Two different rules that produce the same kind of activity land in the same retrieval space.
- **Concrete entity instances** — classifications are the retrieval key; identifiers are audit metadata.

It lives alongside `investigation.md`, not in place of it. The markdown stays for human review and narrative reasoning. The structured companion carries the typed, queryable representation.

### What it enables

- **Retrieval-augmented reasoning at investigation time.** At HYPOTHESIZE, at lead selection, and at ANALYZE, the agent consults small pre-materialized projections of the corpus to inform the current walk. Projections are flat YAML files — grep-able, diff-able, human-reviewable. Judgment stays live; retrieval provides grounding priors, not decisions.
- **Cross-signature pattern matching.** An investigation of signature A can learn from a past investigation of signature B if they touched similar vertex shapes. A 100007 run benefits from a prior 5710 run on the same in-container parent-opacity trap — not because the signatures share a playbook, but because they share an environment fact about where leads fail.
- **Severity-enforced weight transitions.** Predictions and observations share a schema, and every strong weight transition must cite a supporting edge with strong authority (§4.4) plus a matched refutation or prediction text. The validator enforces "circumstantial evidence cannot earn `++` or `--`" at write time — the class of error observed in eval run #11 becomes structurally impossible.
- **Archetype catalog as pattern queries.** Each archetype becomes a pattern-query over the schema (vertex shape + expected edge shape + trust anchor requirements), replacing hand-written archetype-matching logic with mechanical queries.

### What it is NOT

- **Not a replacement for `investigation.md`.** The markdown remains the primary narrative artifact the agent writes and humans read. The structured companion is a machine-readable projection carried alongside it.
- **Not a ground-truth learning system.** No final dispositions are used as training signal. The quality signal per phase is *local* ("did this move advance hypothesis discrimination by at least one severity-weighted step?"), not outcome-based. This avoids disposition-level overfitting, which is adversarially exploitable.
- **Not a graph database or a full DSL.** The query surface is a small CLI over a flat projection store (v0) or a SQLite index (v1). Agents read projections with grep + yq + a small query helper; they do not execute arbitrary graph queries.
- **Not a replacement for `ticket-context`.** Ticket-context remains instance-indexed ("show me past alerts touching container `a1b2c3d4`"). The investigation language is mechanism-indexed ("show me past cases with this vertex shape and hypothesis set"). Adjacent retrieval spaces serving different questions.

---

## 2. Mental Model: Two Graphs

The investigation language is grounded in a graph mental model, but it requires distinguishing two graphs that coexist in the record.

### 2.1 The activity graph

The activity graph is the real-world structure of what happened on the network and on endpoints during the relevant window. It has two kinds of elements:

- **Vertices are entities.** Processes, files, sockets, IPs, users, hosts, containers, sessions, devices, commands, remote endpoints. Nouns. Each vertex has an `abstract_type` (from a small catalog) and a `classification` (from the vocabulary for that type).
- **Edges are relations.** `spawned`, `opened`, `connected_to`, `executed`, `authenticated_as`, `runs_in`, `loaded_by`, `triggered_by`. Verbs. Most edges carry a timestamp and attributes; an **event** is an edge with a timestamp. Static structural relations (a process runs in a container) use the same shape without a timestamp.

An earlier framing of this section conflated entities with events — "an authentication-success vertex," "a file-execution vertex." That model broke down on chains like `parent-process → child-process → socket → remote-endpoint` where it was ambiguous which was vertex and which was edge. Under the corrected model, all four are vertices; the arrows are edges (`spawned`, `opened`, `connected_to`), and the event of the connection happening at a particular time is an attribute on the `connected_to` edge.

Most of the activity graph is invisible to any individual investigation. What an investigation paints is a subgraph — the vertices and edges that leads have materialized, plus the edges a hypothesis has proposed but not yet materialized.

### 2.2 The investigation graph

The investigation graph is distinct. Its implicit vertices are knowledge-states (the cumulative state of what the agent has painted), and its edges are **lead applications** — operations the agent performed to advance the activity graph. The investigation graph is a walk: a sequence of lead applications, each painting more of the activity graph.

Leads come in three modes:

- **Materialize** — paint a hypothesized vertex or edge into observed status, or refute it. Operates against a hypothesis set on a vertex.
- **Scope** — paint adjacent attributes, edges, or sibling vertices around a known vertex. Expands local structure without committing to backward traversal.
- **Trust** — query a trust anchor to classify a vertex. On success, mark the vertex as a trust root, which terminates backward traversal on that branch.

The activity graph is what the agent *learned about the world*. The investigation graph is what the agent *did*. Both are first-class in the structured companion and both feed retrieval, but they feed different questions: the activity graph populates vertex-shape and hypothesis-shape projections; the investigation graph populates lead-selection and lead-failure projections.

### 2.3 Why backward-mostly

SOC scope is "this alert happened — classify it and recommend action." That is backward traversal: walk from the effect toward the cause. Forward traversal ("what happened after this?") is IR scope and is explicitly out of the agent's mandate.

Scoping leads are the one legitimate lateral direction. They do not commit to backward traversal — they enrich the current vertex's neighborhood (sibling events, attribute detail, blast radius) so that discrimination between candidate backward edges becomes possible. Scoping earns its keep because some hypotheses are only refutable via structural co-occurrence ("the shell opened a socket to the kube-api proxy, which implies kubectl-exec parent even though the direct `spawned` edge is opaque").

Strict forward chasing ("what did the shell do next to see how bad it got") is still out of scope and is handled by chain-of-events flagging, not by lead execution. The chain-of-events discipline already in `soc-agent/skills/investigate/SKILL.md` (note implied stages as follow-up scopes, do not chase them) is the backward-mostly rule expressed operationally.

### 2.4 Why abstract classifications matter

Two investigations on different concrete entities with the same classification-level shape are *the same case* for mechanism-discovery purposes. A 5710 alert with source IP `10.0.50.23` classified as `internal-monitoring-host` authenticating to `target-endpoint` is, from a mechanism-retrieval standpoint, identical to a 5710 alert with source IP `10.0.50.24` and the same classification. The concrete IP is audit trail; the classification is the key.

Without classifications — if the retrieval key were concrete identifiers — every case would be unique and retrieval would return nothing. With classifications, the key space collapses to O(100) meaningful distinctions and retrieval works.

Contextualization ("have we seen this specific attacker before?") stays in ticket-context, which is instance-indexed. Mechanism discovery ("what kind of thing is this?") is what the investigation language is for. They are different retrieval spaces serving different questions.

---

## 3. Schema

The structured companion has five top-level collections: `vertices`, `edges`, `hypotheses`, `leads`, and `revisions`. Cross-referencing is by stable IDs. Everything is append-only; corrections are expressed as revisions, not mutations.

### 3.1 Vertices — entities

A vertex is an entity the investigation touches.

```yaml
vertex:
  id: v-{nonce}
  abstract_type: process | socket | file | ip | user | host | container
               | session | remote-endpoint | device | command | anchor-source | ...
  classification: <string>          # from §4 — the primary retrieval key
  identifier: <string>              # human-readable handle (§4.5)
  attributes: <object>              # type-specific: pid, cmdline, path, port, etc.
  trust_root: false | true          # set true when a successful trust lead terminates the walk here
  data_quality: complete | partial | degraded
  first_observed:
    phase: CONTEXTUALIZE | SCREEN | HYPOTHESIZE | GATHER | ANALYZE
    loop: <int>
    lead: l-{id} | "inline"
  citations: [<string>]             # e.g., "wazuh:rule.id=100007:event=abc"
```

A vertex is *observed* when a lead materializes it into the subgraph. Before that, it may be referenced by a hypothesis's `proposed_edge.parent_vertex` (§3.3) without existing as a real vertex record. When the parent is eventually materialized, the agent creates the vertex record and the hypothesis's weight is updated accordingly.

`trust_root: true` is set only by a successful trust lead (§3.4). It signals "backward traversal from this vertex is terminated by authority" and is consulted by the termination logic in §3.6.

### 3.2 Edges — relations (events are temporally-instantiated edges)

An edge is a typed, attributed relation between two vertices. An **event** is an edge with a `when.timestamp`. Static structural relations (like "process runs in container") use the same shape without a timestamp. Extended relations (sessions with duration, beaconing patterns) use `duration_sec` or `distribution`.

```yaml
edge:
  id: e-{nonce}
  relation: spawned | opened | connected_to | read | wrote | executed
          | runs_in | authenticated_as | initiated_by | triggered_by
          | escalated_privilege | executed_in | loaded_by | posted_in
          | classified_as | attested_by | ...                # from §4.3
  source_vertex: v-{id}
  target_vertex: v-{id}
  when:
    timestamp: <ISO8601>             # instantaneous edges
    # OR
    duration_sec: <float>            # extended edges (sessions, connections)
    # OR
    distribution:                    # repeated edges
      pattern: single | periodic | burst | sporadic | continuous
      count: <int>
      span_sec: <int>
      period_sec: <int>              # periodic only
      jitter_sd_sec: <float>         # periodic only
    context: <string>                # loose narrative — surrounding temporal context
  attributes: <object>              # relation-specific: cmdline, outcome, bytes_out, protocol, uid, ...
  status: observed | hypothesized | refuted
  authority:
    kind: siem-event | runtime-audit | anchor-backed | client-asserted | inferred-structural
    source: <string>                 # e.g., "wazuh:rule.id=100007:event=abc"
    trust_chain: [<anchor-id>, ...]  # optional — see §4.4
  first_observed:
    phase: ...
    loop: <int>
    lead: l-{id}
```

`status` tracks whether the edge has been materialized (`observed`), proposed by a hypothesis but not yet confirmed (`hypothesized`), or contradicted by a subsequent lead (`refuted`).

`authority.kind` determines which hypothesis weights this edge can support in a resolution. The rule, validator-enforced: a strong weight transition (`++` or `--` with `severity: severe`) must cite at least one edge with `siem-event`, `runtime-audit`, or `anchor-backed` authority. Weak-authority edges alone can never support strong weights. See §4.4 for the authority catalog and trust-chain promotion rule.

### 3.3 Hypotheses — candidate edge-attachments to a vertex

A hypothesis proposes that a specific vertex has a specific backward edge to a parent vertex with a specific classification. Hypotheses are attached to a vertex; multiple hypotheses on the same vertex form a **discrimination set**.

```yaml
hypothesis:
  id: h-{nonce}
  name: "?descriptive-mechanism-name"
  canonical: true | false           # true iff declared in the signature's playbook
  attached_to_vertex: v-{id}        # the vertex whose parentage/attribution is being explained

  proposed_edge:
    relation: <string>              # e.g., spawned, authenticated_as, connected_to
    parent_vertex:                  # what the parent would look like if this hypothesis held
      abstract_type: <string>
      classification: <string>      # the discriminating field
      attributes: <object>          # expected attribute shape (optional)
    attributes: <object>            # expected edge attributes

  predictions:                      # typed expectations for adjacent evidence
    - for: v-{id} | e-{id} | vertex-shape | edge-shape
      expected: <object>
    - for_absence: "<what should NOT be observed if true>"

  refutation_shape:                 # concrete observations that would directly contradict
    - "<observation contradicting a core prediction>"

  pitfalls:                         # alert-specific traps, not static lead-level pitfalls
    - "<trap that could falsely confirm or refute>"

  refutation_pivots_to: [h-{id}, ...]   # optional — hypotheses to activate if this one refutes
                                         # captures adversarial-pivot relationships

  weight: "++" | "+" | "-" | "--" | null
  weight_history:
    - { before, after, by_lead: l-{id}, severity: severe | moderate | weak, at_phase, loop }
  status: active | confirmed | refuted | shelved
```

**Hypotheses relocate as the walk advances.** When a lead materializes the parent vertex and the discrimination question pivots to "what triggered the parent," new hypotheses attach to the newly materialized parent. Old hypotheses transition to `confirmed`, `refuted`, or `shelved`. This expresses the backward walk as a sequence of discrimination sets, each attached to a progressively deeper vertex. The shell-in-container case in Appendix A walks this explicitly.

**Refutation shape is strict.** For a weight to transition to `--` with `severity: severe`, at least one entry in `refutation_shape` must match a concrete observation from a lead resolution. The schema enforces this: a `--` resolution must reference the matched refutation entry by text (`matched_refutation_text` in §3.4). Soft reasoning ("the evidence leans against this") without a matched refutation caps at `-`.

**Refutation cascades via `refutation_pivots_to`.** When refuting a hypothesis should cause the agent to activate a successor hypothesis, the original lists the successor in `refutation_pivots_to`. Example: refuting `?monitoring-probe` because the prober attempted multiple distinct usernames should activate `?sanctioned-host-compromised` — the prober is being used as a pivot point, and the refutation of the benign story is *evidence for* the compromised-pivot story. The field is advisory: the agent still has to gather evidence for the activated hypothesis before it can carry weight. But it makes the cascade explicit in the log and lets retrieval projections pre-load likely-next hypotheses for similar walks. Appendix A.5 (Case 2) walks this explicitly.

### 3.4 Leads — graph-painting operations

A lead is an operation the agent performs to paint more of the activity graph. Leads are first-class records in the structured companion, separate from the narrative log.

```yaml
lead:
  id: l-{nonce}
  name: <string>                    # from knowledge/common-investigation/leads/{name}/definition.md
  mode: materialize | scope | trust
  target_vertex: v-{id}             # the vertex this lead acts on
  intended_hypothesis_set: [h-{id}, ...]   # materialize mode — hypotheses being discriminated

  query_details:                    # environment-specific — logged, NOT indexed for retrieval
    system: <string>                # wazuh, kube-audit, splunk, ...
    template: <string>              # e.g., "leads/host-auth-history/templates/wazuh.md"
    query: <string>                 # the actual query as issued
    time_window: <string>
    substitutions: <object>         # values plugged into the template

  execution:
    phase: SCREEN | GATHER
    loop: <int>
    dispatched_via: inline | subagent
    dispatcher_prompt_ref: <string> # optional — pointer to the subagent prompt used
    model_override: <string | null>
    duration_ms: <int>

  outcome:
    status: complete | empty | degraded | error
    vertices_materialized: [v-{id}, ...]
    edges_materialized: [e-{id}, ...]
    attributes_updated:
      - { target: v-{id} | e-{id}, field: <dotted-path>, from: <old>, to: <new> }
    trust_root_reached: v-{id} | null
    failure_reason: <string | null> # populated on empty/degraded/error — feeds dead_leads_index

  resolution:                       # how outcome affected hypothesis weights
    - hypothesis: h-{id}
      before: "+" | "-" | ...
      after: "++" | "+" | "-" | "--"
      severity_of_test: severe | moderate | weak
      matched_refutation_text: "<text>" # required when after == "--"
      matched_prediction_text: "<text>" # required when after == "++"
      reasoning: "<what prediction, what observation, what contradicted or confirmed what>"
      supporting_edges: [e-{id}, ...]
```

**The three modes:**

- **`materialize`** — paints a hypothesized vertex or edge into observed status. Operates against an `intended_hypothesis_set`; every resolution must name at least one hypothesis. Typical examples: `process-lineage` (materializes `spawned(parent, child)` edge), `host-auth-history` (materializes upstream auth-success vertices and their edges), `file-write-origin` (materializes the process that wrote a file).
- **`scope`** — paints adjacent attributes, edges, or sibling vertices around a known vertex. Does not directly resolve hypotheses but may reveal new edges that become materialization targets for subsequent leads. Typical examples: `session-command-history` (paints `executed_in(cmd, session)` edges), `blast-radius-files` (paints sibling `opened(process, *)` edges), `concurrent-communication-scope` (paints `posted_in(user, channel)` edges for human-presence evidence).
- **`trust`** — queries a trust anchor to classify a vertex. Typical examples: `anchor-lookup(inventory, ip)`, `anchor-lookup(kube-audit, container, action, time)`, `anchor-lookup(mdm-registry, device)`. On success, sets `trust_root: true` on the target vertex. A trust-root reached is a termination condition on that branch, distinct from a hypothesis refuted.

**`severity_of_test`** is required on every resolution and is the schema-level enforcement of the "circumstantial vs authoritative" rule:

| Severity   | Meaning                                                                       | Max weight effect                    |
|------------|-------------------------------------------------------------------------------|--------------------------------------|
| `severe`   | Outcome could directly contradict (or directly confirm) a core prediction    | up to `++` / `--`                    |
| `moderate` | Outcome constrains plausibility without directly contradicting any prediction | at most one step (e.g. `+` → `-`)    |
| `weak`     | Circumstantial consistency — evidence leans but does not constrain            | caps at `+` or `-`; never `++` / `--`|

The validator enforces:

- A `--` weight requires `severity: severe` AND a matched `refutation_shape` entry (by text, populated into `matched_refutation_text`) AND at least one supporting edge of strong authority (§4.4).
- A `++` weight requires `severity: severe` AND **complete** prediction match AND strong-authority grounding. Complete prediction match means every clause of the hypothesis's `predictions` block must be observable and supported in the evidence — not just some. If any clause is unmet (evidence absent, contradictory, or untested), the weight caps at `+` regardless of how severe the supporting lead was.

These rules collectively make the class of error behind eval run #11 (circumstantial findings promoted to strong weights) structurally impossible. The complete-match clause also prevents the subtler failure where a hypothesis reaches `++` because the agent stopped testing once some predictions confirmed — complete match forces the agent to pursue every predicted clause or escalate. Appendix A.4 (Case 1, the S3 list burst) walks an example where `?ad-hoc-operator-run` has partial prediction match (human presence confirmed; change-context clause unmet) and correctly caps at `+`.

### 3.5 Revisions — append-only corrections

Vertices, edges, and hypotheses are immutable after creation. Information learned later that changes a classification, attribute value, or prediction is expressed as a revision.

```yaml
revision:
  id: r-{nonce}
  target: v-{id} | e-{id} | h-{id}
  field: <dotted-path>              # e.g., "classification", "attributes.outcome"
  from: <old-value>
  to: <new-value>
  reason: <string>
  evidence_refs: [l-{id}, ...]      # leads whose outcomes drove the revision
  produced_at: { phase, loop }
  revised_by: agent | post-mortem | analyst-override
```

Retrieval resolves revisions by default — queries return the latest effective value. The `--as-of-phase PHASE` flag returns pre-revision state, which matters for post-mortem analysis where the question is "what did the agent know at phase X," not "what do we know now."

Valid revision sources:

- **agent** — the agent learned something mid-run that updates an earlier classification or value.
- **post-mortem** — a scheduled cleanup pass normalized names, corrected stale classifications, or updated a field based on later evidence.
- **analyst-override** — a human analyst corrected a classification. This is the only path for ground-truth corrections; it requires an analyst feedback system that does not yet exist.

Append-only makes the companion: auditable (reconstruct what the agent knew at each phase), safe under concurrency (writes don't corrupt earlier records), easy to replay (resumption reads the latest state without partial-mutation concerns), and composable with post-mortem (normalization is additive).

### 3.6 Termination conditions

A backward walk terminates in one of four distinct ways. The distinction matters because the Stop-hook distiller (§5.4) tags each run with its termination category, and the projections treat the four categories differently.

1. **Trust-root termination.** A trust lead succeeds and sets `trust_root: true` on the branch's current vertex. No further backward traversal is required on that branch because authority has confirmed the vertex. Other branches may still be live; the overall investigation terminates when all branches are either trust-terminated or refuted.
2. **Adversarial-refuted termination.** All adversarial hypotheses are refuted to `--` via severe-severity resolutions with matched refutation shapes and strong-authority supporting edges. A non-adversarial hypothesis has reached `++` under the same discipline, and the archetype+grounding legs of SKILL.md's resolution rule are satisfied.
3. **Severity-ceiling termination.** The walk has run every in-scope severe lead available for the current discrimination set, and adversarial hypotheses remain at `-` (not `--`) because no in-scope lead can provide the direct contradiction their refutation shapes require. This is structurally distinct from ordinary escalation: the agent knows which severe test *would* resolve it (often out-of-band human confirmation, cross-system correlation not available to the agent, or an anchor the environment doesn't provide), but cannot execute it. The projection `lead_selection_index` records this as a ceiling — future runs on the same vertex shape inherit the knowledge that in-scope leads cap at a known maximum weight, so they don't thrash. Escalation is the correct handoff; the analyst workflow for a ceiling-escalation differs from an exhaustion-escalation because the analyst is told exactly which out-of-scope test to run. Appendix A.4 (Case 1) walks an example.
4. **Exhaustion escalation.** The walk has consumed its loop budget, or the hypothesis space is incomplete, or evidence leaves significant observations unexplained, or no archetype exists for the shape even when the security disposition is clear. Unlike severity-ceiling termination, the agent does NOT know which specific test would resolve it — the hypothesis space itself is the problem. Produces a structured handoff and is a legitimate termination, not a failure.

A trust-root termination has `trust_root_reached: v-id` somewhere in the lead history. An adversarial-refuted termination has all `?adversarial-*` hypotheses at `status: refuted` with severe resolutions. A severity-ceiling termination has adversarial hypotheses at `weight: -` with `weight_history` entries showing every in-scope severe lead was attempted, plus a `ceiling_rationale` field in the report frontmatter naming the out-of-scope test that would resolve it. An exhaustion escalation has `status: escalated` in the report frontmatter with a specific rationale category (loop budget, incomplete hypothesis space, archetype gap).

---

## 4. Classification Vocabulary

The classification of a vertex is the primary retrieval key. The taxonomy must be stable, enumerable, mechanism-discriminating, and authoritative.

### 4.1 Classifications are vertex properties

Only vertices are classified. Edges carry `attributes` (relation-specific fields) and an `authority` field (§4.4) but no classification. When a relation has semantic sub-patterns — a `connected_to` edge distinguishing periodic-heartbeat from interactive — those patterns live in `edge.attributes.pattern` as structured fields, not a classification enum.

Rationale: retrieval value comes from classifying *what things are*, not *what relationships look like*. The shape of a relation is captured by its `relation` name and its attribute distribution. Adding a second classification vocabulary for edges would double maintenance for unclear retrieval gain. Every hypothesis discrimination key in the walks of Appendix A keys on either vertex classifications or edge attributes, never on edge classifications.

### 4.2 Abstract types and vocabularies

Each vertex `abstract_type` has a classification vocabulary declared in `soc-agent/knowledge/environment/context/`:

| Abstract type      | Vocabulary file                               |
|--------------------|-----------------------------------------------|
| `process`          | `context/process-classifications.md`          |
| `socket`           | `context/socket-classifications.md`           |
| `file`             | `context/file-classifications.md`             |
| `ip`               | `context/ip-classifications.md`               |
| `user`             | `context/user-classifications.md`             |
| `host`             | `context/host-classifications.md`             |
| `container`        | `context/container-classifications.md`        |
| `session`          | `context/session-classifications.md`          |
| `remote-endpoint`  | `context/remote-endpoint-classifications.md`  |
| `device`           | `context/device-classifications.md`           |
| `command`          | `context/command-classifications.md`          |
| `anchor-source`    | `context/anchor-source-classifications.md`    |

Each file declares: (1) the full enum of classification values, (2) application rules mapping raw observable fields to a classification, (3) an `unclassified-{abstract_type}` fallback treated as a first-class retrieval key, (4) an `ambiguous-{a}-or-{b}` convention for unresolved candidates (§4.7).

Existing `knowledge/environment/context/*.md` files (`ip-ranges.md`, `identity-patterns.md`) already do most of this work for `ip` and `user`. Migration is primarily renaming and adding explicit enum headers.

**The abstract-type catalog is NOT a vertex-type catalog in the old sense of "types of events."** Under this model, file execution is not a vertex type — it is an `executed` edge between a `process` vertex and a `file` vertex. Abstract types are entity kinds only.

### 4.3 Relations — catalog, not classification

Edges have a `relation` field drawn from `soc-agent/knowledge/environment/context/relations.md`. Relations are verbs; the catalog is small and grows slowly.

Seed catalog:

| Relation               | Source → Target                  | Notes                                          |
|------------------------|----------------------------------|------------------------------------------------|
| `spawned`              | process → process                | parent-child process creation                  |
| `executed`             | process → file                   | execve target                                  |
| `loaded_by`            | process → library-file           | dynamic link / runtime load                    |
| `opened`               | process → socket                 | socket creation                                |
| `connected_to`         | socket → remote-endpoint         | network connection (directional)               |
| `read`                 | process → file                   | file read                                      |
| `wrote`                | process → file                   | file write/create                              |
| `runs_in`              | process → container              | container membership (static)                  |
| `authenticated_as`     | session → user                   | auth identity binding                          |
| `initiated_by`         | session → user \| device         | session origin attribution                     |
| `triggered_by`         | process → process \| edge → edge | runtime-API-mediated causation                 |
| `escalated_privilege`  | session → session (self-edge)    | sudo/setuid; attributes carry uid_before/after |
| `executed_in`          | command → session                | command vertex lives inside a session          |
| `posted_in`            | user → channel                   | communication observable (Slack, email)        |
| `classified_as`        | vertex → classification-value    | materialized by a trust lead                   |
| `attested_by`          | vertex → anchor-source           | trust attestation (dual of classified_as)      |

Each relation declares in `relations.md`: expected source/target abstract types (advisory), required and optional `attributes` fields, which authority levels it can carry, and human description.

The validator rejects companion files that reference a relation name not in `relations.md`. A new relation is added by editing the catalog and bumping its schema version; runs written before the version bump continue to parse.

### 4.4 Edge authority — the parallel typed thing

Classifications attach to vertices; the parallel typed field on edges is **authority**. Authority gates the hypothesis weights a resolution can produce.

| Authority kind        | Meaning                                                                    | Max weight supportable |
|-----------------------|----------------------------------------------------------------------------|------------------------|
| `siem-event`          | Backed by a SIEM / audit log event; immutable, source-of-truth for the data source | `++` / `--`            |
| `runtime-audit`       | Backed by a runtime or OS audit stream (execve feed, kernel audit, cadvisor) | `++` / `--`            |
| `anchor-backed`       | Materialized or classified via a trust anchor lookup                       | `++` / `--`            |
| `client-asserted`     | Derived from a self-reported field (TLS SNI, HTTP user-agent, argv claims) | `+` / `-`              |
| `inferred-structural` | Inferred from co-occurrence, not directly materialized                     | `+` / `-`              |

**Validator rule:** a weight transition to `++` or `--` with `severity: severe` must cite at least one `supporting_edges` entry whose `authority.kind` is `siem-event`, `runtime-audit`, or `anchor-backed`. Weak-authority edges alone can never support strong weights, regardless of count.

**Trust chain promotion.** A `client-asserted` edge can be promoted in effective authority when it sits on a verified trust chain. Slack messages are `client-asserted` by the user's client, but Slack's audit log is itself backed by SSO+MFA, so the edge's effective authority is `anchor-backed` via `trust_chain: [slack-audit, sso-mfa]`. The `edge.authority.trust_chain` field is optional and lists the anchors that promote the edge. The validator checks each chain element exists in `anchor_manifest.yaml` (a projection maintained by the corpus distiller, §5).

**Anchor authority is per-question, not global.** An anchor can be authoritative for some questions and only partially authoritative for others. `ec2-instance-integrity` is authoritative for "is the kernel module set known-clean" (auditd + osquery have direct visibility) but only partial-authority for "is the instance compromised at any layer" — a sophisticated compromise can piggyback on a legitimate process, which the anchor doesn't see. `configuration-management` is authoritative for "what is the prober's configured username set" but silent on "is the configuration fresh." The `anchor_manifest.yaml` projection (§5.1) carries this explicitly: each anchor entry has an `answers` field listing `{question, authority_for_question}` pairs. When an edge is materialized via a trust lead, its authority kind is determined by the specific question the lead asked, not by a global anchor label.

**Partial anchor authority — open sub-question.** When an anchor gives a partial-authority answer, what authority kind does the resulting edge carry? Two options under consideration:
- **Option A:** Add `anchor-backed-partial` as a sixth authority kind with the same weight-cap as `client-asserted` (`+` / `-`). Keeps validator rules simple (one more row in the authority table); keeps the edge schema unchanged.
- **Option B:** Keep five authority kinds; let `anchor-backed` edges carry a per-edge `authority_for_question` field that the validator uses to determine weight cap. Preserves the enum but complicates the validator rule.

Current lean: Option A. Decided when the `anchor_manifest.yaml` schema is finalized. Case 1 in Appendix A.4 exercises this — the `ec2-instance-integrity` anchor returns clean but only caps `?compromised-instance` at `-` because the anchor's answer is partial-authority for the "any layer" question being asked.

### 4.5 Identifiers — single stable handle

Each vertex has a single `identifier` string for human traceback and audit. Preference order:

1. **Semantic name from the environment knowledge base.** If `ip-classifications.md` maps `192.168.50.14` to `ansible-control-node-east`, the identifier is `ansible-control-node-east`. Less temporal, more readable, often more stable.
2. **Raw value fallback.** `192.168.50.14`, `/tmp/update.sh`, `545933e88cfc`.
3. **Avoid ephemeral values.** Never pid, port, or session token alone unless the entity is inherently that thing. When in doubt, qualify: `"bash (container 545933e88cfc, pid 1247)"`.

**The identifier is NOT the retrieval key.** Retrieval keys are `(abstract_type, classification)` tuples and vertex-shape tuples built from classifications. Identifiers exist for audit trace only. Two vertices with different identifiers but the same classification are retrieval-equivalent; two vertices with the same identifier in different runs are NOT assumed to be the same entity (cross-run identity is out of scope, §10).

### 4.6 Co-design rule — classifications, relations, projections

> **A classification value, relation, or projection key exists if and only if at least one archetype, lead, hypothesis, or projection uses it to discriminate.**

If `internal-monitoring-host` distinguishes `?monitoring-probe` from `?scan-in-progress`, it's valid. If `internal-server-east` is not referenced anywhere, it's over-splitting and should collapse into `internal-server` or be deleted.

Same rule for relations: `executed_in` stays if session-command scoping uses it; drops otherwise. Same for projection keys: a `dead_leads_index` entry keyed on a vertex shape that no future run keys against is dead weight.

**The rule implies classifications, relations, hypotheses, archetypes, leads, and projections are co-designed.** Adding a new archetype may require a new classification, a new relation, or a new projection key. Edits propagate through the co-design graph.

Enforcement is at review time, not mechanical. The Tier 1 validator can check every referenced classification/relation/projection-key exists in its catalog; it cannot detect orphaned entries. A scheduled cleanup pass walks the catalogs and the corpus, flagging candidates for removal; humans approve pruning.

### 4.7 Ambiguous and unclassified values

- **`unclassified-{abstract_type}`** — no basis to classify yet. Retrieval treats this as a first-class key. Prior walks starting from unclassified vertices populate a cold-start retrieval arm that's especially valuable for novel signatures.
- **`ambiguous-{a}-or-{b}`** — two or more candidates, decisive narrowing not possible. Retrieval supports queries for ambiguous keys, which surfaces vocabulary gaps.

Frequency analysis of these values reveals taxonomy issues:

- High `ambiguous-X-or-Y` frequency where the two candidates lead to the same disposition → collapse.
- High `unclassified-{type}` frequency → application rules have coverage gaps.

**A classification upgrade is always a revision (§3.5), never a mutation.** The first observation of an IP may be `unclassified-ip`; a subsequent trust lead triggers a revision `{from: unclassified-ip, to: external-sanctioned-automation}`. The original value is preserved for `--as-of-phase` queries.

---

## 5. Retrieval Projections

The structured per-run companion file is the source of truth. At investigation time, however, the agent does NOT query companions directly — that would be expensive and require joins across thousands of files. Instead, a **Stop-hook distiller** materializes a small number of **retrieval projections** after each run. Projections are flat YAML files keyed for fast lookup. Agents read them via the CLI in §6 or directly with grep + yq.

Projections are the runtime retrieval surface. Per-run companions are for post-mortem and for feeding the distiller.

### 5.1 The projections

Seven projections are maintained by the distiller. Six are agent-readable retrieval indices; the seventh is a human-readable review queue.

| Projection                  | Retrieval key                                    | Answers                                                                               |
|-----------------------------|--------------------------------------------------|---------------------------------------------------------------------------------------|
| `hypothesis_index.yaml`     | `(vertex_shape)`                                 | What candidate backward-edge hypotheses did prior walks instantiate on this vertex shape? |
| `lead_selection_index.yaml` | `(hypothesis_set_shape, vertex_shape)`           | What leads historically discriminated this fork, with severity, historical rate, and ceiling notes |
| `dead_leads_index.yaml`     | `(lead_name, vertex_shape)`                      | What leads are known to fail on this vertex shape, and why?                           |
| `anchor_manifest.yaml`      | `(classifies_vertex_type, context)`              | What trust anchors classify vertices of this type, with per-question authority levels (§4.4) |
| `data_source_manifest.yaml` | `(produces_vertex_type, context)`                | What telemetry sources materialize vertices of this type?                             |
| `pitfall_index.yaml`        | `(lead_name \| hypothesis_name, vertex_shape)`   | What gotcha has bitten prior runs? `authority: learned \| curated`                    |
| `review_queue.yaml`         | `(run_id, reason, related_runs)`                 | Precedent contradictions flagged for analyst review — populated when a run overturns or contradicts a past fast-resolve decision |

Each of the first six files is a shallow YAML map growing by at most one entry per run (often zero). Writes are merge-on-write: duplicate keys update an `n` counter and a `last_observed` timestamp; new keys append. A `history[]` list inside each entry carries `run_id` references for audit traceback.

`review_queue.yaml` is different from the other six projections in two ways. First, it is not grep-keyed on vertex shape — it is an **append-only review queue** of flagged precedent contradictions, keyed on run ID for audit, meant to be consumed by analyst workflow rather than by the agent at investigation time. Second, it triggers human review asynchronously: when a run refutes a hypothesis at severity `severe` and that hypothesis matches the fast-resolve precedent of an earlier run retrieved via ticket-context, the distiller appends a `review_queue` entry with the earlier run's ID and a `reason: possible_missed_threat` note. The analyst is alerted out-of-band to re-examine the earlier runs with fresh scrutiny. Case 2 in Appendix A.5 (the sanctioned prober bait) is the canonical example: when the current run refutes `?monitoring-probe` for a source IP whose three prior 5710 alerts were fast-resolved as monitoring probes, those three prior runs become suspect and are flagged.

`review_queue` reasons, seed set (expect this to grow):

- `possible_missed_threat` — current run refutes what a prior run confirmed
- `precedent_anchor_stale` — current run confirmed an anchor state that contradicts a prior run's cached anchor answer
- `taxonomy_drift` — distiller detected classification/relation usage that suggests vocabulary evolution review is needed

Projections are **environment-universal**. A dead-lead entry for `(process-lineage, process:runs_in=runtime-workload;parent=null)` applies to any alert on an in-container process, regardless of signature — which is the cross-signature value that rescues Sonnet investigations with thin scaffolding.

### 5.2 Retrieval value is decomposable

A prior case does not have one retrieval key. It contributes to several projections independently.

The shell-in-container walk (Appendix A.1) contributes strongly to `dead_leads_index` (process-lineage is attribution-opaque on in-container processes with `parent=null`), `anchor_manifest` (kube-audit classifies exec actions on containers), and `data_source_manifest` (runtime-audit-execve-feed produces process vertices inside containers). It contributes **nothing** to `hypothesis_index` for an egress question because its hypothesis set was about parentage, not egress.

The egress walk (Appendix A.2) contributes to `hypothesis_index` for `(connected_to, runtime-workload-source, unknown-external-target)`, to `lead_selection_index` for benign-vs-c2 discrimination, and to `anchor_manifest` for `threat-intel-feed`. It does NOT contribute to anything the shell case already covered — the dead-leads entry for in-container processes already exists.

**The insight:** most of the retrieval value from a case is in orthogonal projections, not in case-shaped recall. A case's single most valuable contribution to the next run is often a one-line entry in `dead_leads_index` that transfers an environment fact across signatures and vendors.

### 5.3 Vertex-shape canonicalization

The projection retrieval key depends on **deterministic** canonicalization of vertex shape. Two runs that derive the same conceptual shape must produce the same string key, or grep fails to find prior wisdom.

Canonicalization rules, enforced by the distiller:

1. **Attribute whitelist.** Only whitelisted attributes enter the shape key. For `process` the whitelist is `{runs_in_classification, parent_presence}`; for `session` it is `{target_host_classification, source_user_classification, privilege_escalation}`; etc. Non-whitelisted attributes (pid, cmdline, specific identifiers) never enter the key.
2. **Alphabetical ordering.** Attributes in the key string are sorted alphabetically before joining.
3. **Classification at a defined specificity.** If an IP is classified `external-sanctioned-automation` (specific) and also has a broader class `external-sanctioned` (specificity parent), the key uses the specific value. Specificity parents are declared in the classification vocabulary file.
4. **Relaxation for fallback queries.** If a query at full specificity returns `insufficient`, the retrieval CLI tries a relaxed key (one whitelist attribute dropped at a time, then classifications moved to their specificity parents). Relaxation stops at the first non-empty result or at a documented minimum key shape.

The canonicalizer is a single function in the distiller. It has a test suite of known shapes and is the one place vertex-shape string format is defined. All projection writes and all retrieval reads go through it.

### 5.4 Distiller write path

After each investigation terminates, a Stop hook runs `distill_corpus.py`. The distiller:

1. Reads the run's structured companion file, `state.json`, and `report.md`.
2. Iterates leads, hypotheses, and outcomes. For each projection-relevant event, canonicalizes the key and emits a write record.
3. For each projection file: reads the current state, merges the new record (append-or-update), writes back atomically with a file lock.
4. Appends one audit line to `runs/_corpus/distill.jsonl` summarizing what the run contributed.

The agent never writes to projections. The distiller is deterministic Python — no LLM in the hot write path. LLMs enter only in the optional canonicalization-assist step (§5.5).

### 5.5 Lead and hypothesis name canonicalization

To prevent drift across similar-sounding lead and hypothesis names:

1. **Lead names are enumerated.** The canonical enum lives in `knowledge/common-investigation/leads/{name}/definition.md` — one directory per lead. The distiller rejects lead names that don't map to an existing catalog entry. Ad-hoc leads (leads without a catalog directory) are emitted with `name: "ad-hoc:{slug}"` and flagged for review.
2. **Hypothesis names are advisory.** Playbook hypothesis seeds are curated; emergent hypotheses carry a descriptive name the agent authored. The distiller does not block emergent names, but runs a post-hoc Haiku-based canonicalization pass that proposes merges when two runs instantiate conceptually-equivalent hypotheses with different names. Merges are emitted as revision records with `revised_by: post-mortem`.
3. **Same-model-same-mode tends to collapse drift naturally.** Sonnet reasoning about Sonnet-produced runs tends to pick similar wording; observed drift concentrates in the `ad-hoc` tail. The Haiku canonicalizer is the belt-and-suspenders layer for that tail.

Canonicalization failures (ad-hoc leads that never merge, hypothesis names Haiku flags as ambiguous) accumulate in a review file for human curation. The cleanup pass in §4.6 processes this alongside orphan detection.

---

## 6. The Query Script

Projections are the retrieval substrate; `soc-agent/scripts/query_corpus.py` is the CLI. Small subcommand surface, structured JSON output, stateless.

### 6.1 Subcommands

```
query-corpus <subcommand> [flags]

hypothesis-seeds
  --vertex-shape SHAPE              # canonical shape string (§5.3)
  --relax N                         # allow N relaxation steps
  → {seeds: [...], confidence, n_supporting}

leads-for
  --discriminates H1,H2,...
  --vertex-shape SHAPE
  --severity-min severe | moderate | weak
  → [{name, mode, severity, historical_rate, discriminates_between}, ...]

dead-leads
  --vertex-shape SHAPE
  → [{lead_name, outcome, n, last_observed, note}, ...]

anchors-for
  --classifies-vertex-type TYPE
  --context CONTEXT
  → [{anchor, authority, answers, last_observed}, ...]

data-sources-for
  --produces-vertex-type TYPE
  --context CONTEXT
  → [{source, query_primitive, discovered_in}, ...]

pitfalls-for
  --lead LEAD | --hypothesis HYP
  --vertex-shape SHAPE
  → [{note, authority: learned|curated, n, last_observed}, ...]

Global flags:
  --format json | yaml
  --corpus PATH                     # override default projection dir
```

### 6.2 Cold-start and graceful degradation

Every subcommand returns a `confidence` field:

- `high` — ≥20 matching entries; results statistically meaningful
- `low` — 3–19 matching entries; directional signal only
- `insufficient` — fewer than 3 matching entries; anecdotal
- `empty` — no matching entries; retrieval contributes nothing

The agent checks `confidence` before relying on output. On `empty`, it reasons from first principles. On `insufficient`, it may use the result as a weak prior but not as a decision driver. Relaxation (§5.3 rule 4) is applied automatically when the un-relaxed query returns `empty` or `insufficient`, up to a `--relax` ceiling.

### 6.3 Implementation path

- **v0:** Python script reads the flat YAML projection files at every invocation. Slow but correct. Ships first.
- **v1:** SQLite index over the projections, rebuilt by the distiller. Fast for thousands of runs. Ships when v0 profiling shows slowness.
- **v2:** Optional embedding augmentation for pitfall text similarity. Only if structured filters prove insufficient.

### 6.4 What the query script is not

- **Not a graph database.** Projections are key-value shallow maps; retrieval is lookup with relaxation, not graph traversal.
- **Not a DSL.** Filter syntax is stringly-typed and narrow. New subcommands are added as needs emerge.
- **Not stateful.** Each invocation reads and returns. Agents call it repeatedly as needed.

---

## 7. How Vertices, Edges, and Leads Are Produced and Written

### 7.1 Who writes what

- **Main agent (inline)** — at CONTEXTUALIZE, derives initial vertices and edges from the alert record. At HYPOTHESIZE, authors hypotheses. At ANALYZE, authors resolution entries on leads. May also trigger inline trust leads during CONTEXTUALIZE when the SKILL.md preload step runs (ticket-context, cheap anchor lookups).
- **Lead subagents** — at GATHER, execute the selected leads against SIEM/anchors and return structured lead records including `outcome.vertices_materialized`, `outcome.edges_materialized`, and `outcome.attributes_updated`. The main agent integrates these into the companion file and attaches `resolution` entries.
- **Anchor lookups** — trust leads produce both a lead record (with `mode: trust`) and a `classified_as` edge from the target vertex to its classification value. The edge's authority is `anchor-backed`.

### 7.2 Lead subagent return contract

Extends `design-v3-tool-execution.md §5.1`. The existing input is `{ lead, goal, investigation_log, notes?, vocabulary? }`. The return shape adds structured companion fields:

```yaml
response:
  narrative: <string>               # human-readable characterization (existing)
  lead_record:                      # NEW — structured lead for the companion file
    id: l-{nonce}
    name: <string>
    mode: materialize | scope | trust
    query_details: {...}
    outcome:
      status: ...
      vertices_materialized: [<vertex records>]
      edges_materialized: [<edge records>]
      attributes_updated: [...]
      trust_root_reached: v-id | null
  field_glossary: <object>          # field name → meaning (existing, unchanged)
```

The main agent validates the lead record against the schema, assigns resolution entries (it owns hypothesis weights, not the subagent), and appends to the companion file.

### 7.3 Writing to the companion file

**Open Question (§11.1).** Two options for where structured data lives per run:

- **(a) Separate file `investigation.structured.yaml`** alongside `investigation.md`. Clean parsing; drift risk if the agent writes only one.
- **(b) Fenced YAML blocks embedded in `investigation.md`.** Single source of truth; harder to parse; narrative and structure co-edited.

Current lean: (a), because the distiller is load-bearing and parser simplicity matters. Decide after stress-testing how often the agent produces malformed structured blocks under (a) vs (b).

### 7.4 Write-time enforcement

A PostToolUse hook validates every `Write` / `Edit` to the structured companion (or the embedded blocks, under option b):

- **Schema validity** — required fields present, enum values valid, IDs well-formed
- **Classification vocabulary** — every `classification` appears in the corresponding `context/*-classifications.md`
- **Relation catalog** — every `edge.relation` appears in `relations.md`
- **Authority rule** — every `resolution` with `after: ++` or `--` and `severity: severe` cites at least one strong-authority supporting edge
- **Refutation shape match** — every `--` resolution names a `matched_refutation_text` that appears in the target hypothesis's `refutation_shape` list
- **Prediction match** — every `++` resolution names a `matched_prediction_text` that appears in the target hypothesis's `predictions`
- **Trust chain validity** — every `edge.authority.trust_chain` element exists in `anchor_manifest.yaml`
- **Immutability** — no mutation of existing vertex / edge / hypothesis records (only new records and revisions)
- **ID references** — every `v-id` / `e-id` / `h-id` / `l-id` reference resolves to an existing record

Violations are reported to the agent as structured errors, matching the existing `validate_report.py` pattern. The hook blocks the write on violation; the agent must fix and retry.

---

## 8. Revisions and Immutability

### 8.1 What is immutable

- **Vertices** are immutable after creation except via revision. Their `id`, `first_observed`, `abstract_type`, and `citations` never change. `classification`, `attributes`, and `trust_root` change only via revision records.
- **Edges** are immutable except for `status` transitions and revisions. A `hypothesized` edge can transition to `observed` (confirmation) or `refuted` (contradiction) exactly once; further corrections go through revisions.
- **Hypotheses** are immutable in `name`, `proposed_edge`, and `refutation_shape`. `weight` and `status` are advanced via `weight_history` entries (append-only). `pitfalls` may be appended but not retroactively rewritten.
- **Leads** are immutable after their resolution is recorded.

### 8.2 What changes via revisions

- **Vertex classifications** when a later trust lead upgrades a previously unclassified entity.
- **Edge attributes** when a later lead reveals a field that wasn't available at first observation.
- **Hypothesis pitfalls** via append-only addition, not rewrite.
- **Post-mortem normalization** of hypothesis names via the Haiku canonicalizer (§5.5), recorded as revisions with `revised_by: post-mortem`.

### 8.3 Retrieval semantics on revised data

By default, retrieval returns the **current effective** value (latest revision applied). The `--as-of-phase PHASE` flag returns state as of a particular phase for audit queries that need the pre-revision value.

### 8.4 Why append-only

- **Auditable** — reconstruct what the agent knew at each phase
- **Safe under concurrency** — multiple writes don't corrupt earlier records
- **Easy to replay** — resumption reads the latest state without partial-mutation concerns
- **Composable with post-mortem** — normalization is additive

---

## 9. Relationship to Existing Structures

### 9.1 `investigation.md`

The structured companion is a projection of what the agent writes in `investigation.md`, not a replacement. Humans read markdown; machines read the companion. The two must be consistent; enforcement is the write-time hook (§7.4).

### 9.2 `design-v3-tool-execution.md`

The `vocabulary` field in design-v3 §5.1 is the seed of per-run naming conventions. The investigation language extends it: per-run vocabulary is a local naming convention; classifications in `context/*.md` are the global retrieval substrate. The subagent return contract in design-v3 §5.1 extends with the `lead_record` field described in §7.2.

Design-v3 §5.3's fact-vs-interpretation boundary carries forward intact: vertices and edges are facts (or quantified characterizations of facts); hypotheses are interpretation. The language makes the split syntactic — vertices and edges have observed attributes, hypotheses have `predictions`.

### 9.3 Archetype catalog

Under this language, an archetype is a **pattern query**: a vertex shape, an expected backward edge shape, and a grounding requirement. The `monitoring-probe` archetype becomes:

```yaml
archetype:
  name: monitoring-probe
  signature: wazuh-rule-5710
  pattern:
    alert_vertex:
      abstract_type: session
      attributes:
        outcome: failed
    expected_backward_edge:
      relation: initiated_by
      parent_vertex:
        abstract_type: ip
        classification: internal-monitoring-host
    edge_attributes:
      attempts_5min: "==1"
      successful_after_60s: "==false"
  grounding:
    required_anchors: [approved-monitoring-sources]
    anchor_predicate: "confirms (parent_vertex.identifier, edge.user_attempted, session.target.identifier)"
```

The archetype README stays as the human-facing narrative; the machine-readable pattern lives in `pattern.yaml` alongside it. Archetype matching at CONCLUDE becomes a query execution: run the pattern against the run's vertices/edges, check if grounding holds, return PASS/FAIL. This replaces most of `validate_report.py`'s archetype-matching logic.

### 9.4 `ticket-context` subagent

Ticket-context is the **instance-indexed** retrieval path: "show me past alerts involving container `a1b2c3d4`." It remains unchanged. Its job is contextualization (has this specific entity been seen before), not mechanism discovery.

The investigation language is the **mechanism-indexed** retrieval path: "show me past cases with this vertex shape and hypothesis set regardless of entity." CONTEXTUALIZE typically uses both: ticket-context for "has this specific actor been here before," mechanism-retrieval for "what kind of thing is this historically."

**Fast-resolve paths do not bypass the validator.** SKILL.md's `CONTEXTUALIZE → CONCLUDE` shortcut (via ticket-context fast-resolve) is structurally a CONCLUDE with a shorter lead history. Everything that gates a normal CONCLUDE also gates the shortcut: `matched_prediction_text` must be complete (§3.4), `refutation_shape` must be matched for any adversarial refutation (§3.3), and `pitfall_index` entries matching the current observation shape must be consulted before committing. A pitfall entry that fires during fast-resolve blocks the shortcut and forces a full investigation loop. Appendix A.5 (Case 2) walks this: the prior `pitfall_index` entry fires at CONTEXTUALIZE time, the fast-resolve shortcut is blocked, and the full loop catches a prober-host compromise that would otherwise have been missed. Without this gating, fast-resolve would be a structural attack surface — a single well-crafted bait could be resolved benign in CONTEXTUALIZE and never see the refutation discipline.

### 9.5 Playbooks

Playbook structure shifts slightly:

- **Hypothesis seeds** are per-signature, but the seed list is drawn from the canonical hypothesis catalog (cross-signature shared).
- **Archetype catalog** is per-signature, each archetype a pattern query (§9.3).
- **Starter lead order** is advisory; at runtime, `query-corpus leads-for` provides data-driven ordering based on historical discrimination rate.
- **Screen table** is unchanged by this proposal.

Playbooks become less procedural and more declarative: they declare what the signature *means* (vertex shapes it produces, edge shapes it clusters around) rather than what the agent *does*.

### 9.6 Security model

The investigation language does not replace the safety architecture. Tier 1 and Tier 2 validation still run on `report.md`. The two-leg resolution requirement still applies. Adversarial hypothesis maintenance is still the agent's rule. The language adds structural checks (schema validity, authority rule, refutation-shape match) that strengthen the existing gates; it removes none.

---

## 10. Non-Goals

- **Cross-run graph links are not supported in v0/v1.** All references are within a single run. Cross-run semantic linking ("this vertex is the same entity as in past run SEC-2026-0310-045") may be added later.
- **Embedding-based similarity is not in initial scope.** Retrieval is structured-filter-based. Embeddings may augment later if structured filters prove insufficient for pitfall text.
- **Outcome-level learning is not in scope.** Quality signal is local ("did this move advance discrimination?"), not outcome-based. Outcome-level learning requires analyst feedback infrastructure that does not exist.
- **Analyst feedback integration is out of scope.** The language leaves a `revised_by: analyst-override` hook for future use.
- **A full graph-query DSL is explicitly not in scope.** The subcommand surface covers known use cases. Expansion requires concrete query patterns that can't be expressed in the current shape.
- **Real-time index updates.** Projection updates happen via the Stop hook after investigation completion, not during. Mid-investigation retrieval sees the projection state as of the most recent completed run.
- **Multi-tenant isolation.** The corpus is a single flat space. Multi-tenancy becomes a query filter if needed.
- **Projection retirement.** Deferred. Projection entries grow without automatic pruning; periodic human-approved cleanup passes handle retirement.

---

## 11. Open Questions

Two decisions are deferred. They require more data or implementation experience.

### 11.1 Companion file location

**Question:** Does the structured companion live in a separate file (`investigation.structured.yaml`) or as fenced YAML blocks inside `investigation.md`?

- **(a) Separate file.** Pro: parser-simple; clean indexing; parallel to `state.json`. Con: two sources of truth; drift risk.
- **(b) Embedded blocks.** Pro: single source of truth; no drift. Con: extractor needs correct delimiter handling; index-build is more complex; agent must keep blocks well-formed under edits.

**Current lean:** (a). Decide after stress-testing how often the agent gets structured blocks slightly wrong and needs error-recovery rounds.

### 11.2 Command as a vertex type vs an attribute

**Question:** Is `command` its own abstract type, or a structured attribute of `session`?

- **(a) Vertex.** Pro: cross-run command-shape retrieval ("has this `curl | sh` pattern appeared before"); clean `executed_in` edges. Con: more vertices per run, more schema maintenance.
- **(b) Attribute.** Pro: cheap. Con: no cross-run retrieval on command shapes.

**Current lean:** (a). The sudo walk in Appendix A.3 shows real discrimination value in command-shape keying. Revisit if storage becomes a concern.

**Previously open, now resolved:**

- *Classification taxonomy initial scope* — resolved in favor of bootstrap from existing archetypes per §4.6.
- *Vertex type catalog starting scope* — dissolved. Under the new model there is no vertex-type catalog; there are abstract types (§4.2, ~12 entries) and relations (§4.3, ~15 entries). Both grow additively.
- *Projection entry retirement* — deferred to periodic cleanup (§4.6), not mechanical.

---

## 12. Recommended Next Steps

Ordered by dependency:

1. **Resolve §11.1 (companion file location)** via a small stress test — emit both forms for two runs and measure how often each is produced correctly.
2. **Implement the vertex-shape canonicalizer (§5.3)** with a test suite of known shapes. Single function, small blast radius.
3. **Retrofit one signature's observations to the new schema.** Probably 5710 (most eval history). Do not change narrative markdown; add the companion in parallel. Validates the schema against real investigations.
4. **Stub `distill_corpus.py`** to emit entries for the six projections from the retrofitted signature. No LLM; deterministic Python.
5. **Stub `query_corpus.py` v0** — in-memory iteration over the projections, supporting the six subcommands. Validates the query surface.
6. **Design the stress-test alert set** — 5–8 deliberately hard alerts (novel shapes, degraded data, ambiguous anchors, cross-signature chains). Not implementation work; alert crafting and grading rubric.
7. **Run Sonnet on the stress set** with the current architecture (no investigation language) to establish baseline failure rates and modes.
8. **Add companion-writing to `skills/investigate/SKILL.md`** for the retrofitted signature. Extend CONTEXTUALIZE and GATHER to write structured records alongside the narrative.
9. **Add retrieval calls to `skills/investigate/SKILL.md`** — `hypothesis-seeds` at HYPOTHESIZE, `leads-for` at lead selection, `dead-leads` and `pitfalls-for` at both phases. Each call is optional and gated on the returned `confidence`.
10. **Rerun the stress set** with the investigation language active. Measure whether failure modes from step 7 are caught or prevented.
11. **Go/no-go** — decide whether to build v1 SQLite and expand to more signatures, or iterate on the language design.

Total effort: ~4–6 weeks of focused work if the open questions resolve cleanly. The go/no-go gate at step 11 is the key checkpoint.

---

## Appendix A — Worked Examples

Three cases, progressively illustrating different model features.

### A.1 Shell spawned in a runtime container

**Scenario:** Falco rule fires when `bash` spawns inside container `a1b2c3d4` (runtime-workload, running a python API service entrypoint). `parent=null`, `uid=0`, `loginuid=-1`, t=14:03:27Z weekday afternoon.

**Model features:** vertex / edge separation on a drop-and-execute-adjacent case; hypotheses relocating as parent vertices materialize; trust-root termination via the kube-audit anchor.

**Initial subgraph from the alert:**

```yaml
vertices:
  v-001: { abstract_type: process, classification: unclassified-process,
           identifier: bash,
           attributes: { uid: 0, loginuid: -1, tty: false, cmdline: "/bin/bash" } }
  v-002: { abstract_type: container, classification: runtime-workload, identifier: a1b2c3d4 }
edges:
  e-001: { relation: runs_in, source_vertex: v-001, target_vertex: v-002,
           status: observed,
           authority: { kind: siem-event, source: "falco:rule.id=shell-in-container:event=abc" } }
```

**Hypotheses attached to `v-001`:** `?kubectl-exec-operator`, `?ci-pipeline-maintenance`, `?service-dropped-to-shell`, `?post-exploit-shell`.

**Retrieval at CONTEXTUALIZE:** `dead-leads --vertex-shape "process:parent_presence=null;runs_in_classification=runtime-workload"` returns `process-lineage → attribution_opaque` (because Falco delivers `parent=null` for in-container processes in this environment). The agent silently removes `process-lineage` from the candidate pool.

**Loop 1 — scope lead `container-exec-history(v-002, ±5s)`** materializes `v-003` (`runc:[2:INIT]`, lives on host) and `e-002: spawned(v-003, v-001)` with `authority: runtime-audit`. Refutes `?service-dropped-to-shell` (parent is runc, not the python service). Hypotheses relocate to `v-003`: `?triggered-by-kube-api`, `?triggered-by-docker-cli`, `?triggered-by-host-compromise`.

**Loop 2 — trust lead `anchor-lookup(kube-audit, v-002, exec, t≈14:03:27)`** returns: `alice@company.com` via `kubectl/v1.28.3` from corp-VPN IP, RBAC `service-debug-operator`. Materializes `v-004` (user alice, classified via the kube-audit anchor as `employee-with-debug-rbac`), `v-005` (corp-VPN source IP), and the full edge chain `triggered_by → initiated_by → authenticated_as`. Sets `v-004.trust_root: true`. Backward walk terminates at `v-004`.

**ANALYZE:** `?kubectl-exec-operator` → `++` with severity `severe`, matched prediction, three-layer grounding (kube-audit + corp-vpn + employee RBAC, all `anchor-backed`). `?post-exploit-shell` → `--` with severity `severe`, matched `refutation_shape` entry: "authenticated employee via legitimate RBAC channel." **CONCLUDE:** resolved / benign / high.

**Distiller contributions:**

- `dead_leads_index`: `(process-lineage, process:parent_presence=null;runs_in_classification=runtime-workload) → attribution_opaque`
- `data_source_manifest`: `runtime-audit-execve-feed → container-exec-history produces process and spawned-edge`
- `anchor_manifest`: `kube-audit → classifies session for exec actions in runtime-container context`
- `lead_selection_index`: `(discriminate ?kubectl-exec-*,?post-exploit-*, process:runs_in=runtime-workload) → [container-exec-history:scope:severe, anchor-lookup(kube-audit):trust:severe]`

### A.2 Unexpected outbound connection from runtime container

**Scenario:** Falco rule `egress_anomaly` at 09:17:11Z. Container `b9e4f1aa` (runtime-workload, java API service). Process `java`, pid=7210, `parent=null`. Destination `185.220.101.34:443`.

**Model features:** cross-signature retrieval transfer from A.1 (the dead-lead entry fires silently, removing `process-lineage` from consideration); severity-of-test enforcement prevents the class of error observed in eval run #11; a walk that escalates with strong benign signal because no archetype matches.

**Retrieval at CONTEXTUALIZE:** A.1's `dead_leads_index` entry fires; `process-lineage(P)` is removed from the candidate pool. `anchor-manifest` for `remote-endpoint` classification returns `egress-allowlist`, `threat-intel-feed`, `corp-dns-reverse`.

**Initial hypotheses** attached to the `connected_to` edge: `?sanctioned-egress`, `?misconfig-telemetry`, `?c2-beacon`, `?data-exfil`.

**Loop 1 — composite:** `anchor-lookup(egress-allowlist, EP)` (trust) + `connection-profile(P, EP, ±1h)` (scope). Egress-allowlist returns empty (EP not listed). Connection-profile returns: single tcp, 184 bytes out, 0 in, TLS SNI `updates.example-lib.io`. The SNI-derived edge carries `authority: client-asserted`.

**Loop 2 — trust lead `anchor-lookup(threat-intel-feed, EP)`** returns: clean, classified `known-library-telemetry`, last-verified 2d ago. Classifies `EP` with `anchor-backed` authority.

**Critical ANALYZE step.** Under the old model one might resolve `?c2-beacon` to `--` here, arguing "destination classified as benign." Under the severity rule, this fails:

- `?c2-beacon`'s refutation shape requires direct contradiction of a core prediction. "Destination is categorized as library telemetry" is consistent with the beacon being benign but does not directly contradict the beacon hypothesis — beacons routinely use legitimate infrastructure. No matched `refutation_shape` entry. The validator rejects a `--` resolution. Honest weight: `-` (moderate severity, one-step reduction).
- Same for `?data-exfil`: small volume is weak evidence, not direct contradiction.

**Loop 3 required** to actually refute adversarial. Candidates: `scope(P, loaded-libraries)` + `anchor-lookup(corp-sbom, container-image)`. Three-layer runtime + deployment + destination check. Only when all three align does `?c2-beacon` hit matched refutation "library is actually loaded at runtime AND declared in the deployment SBOM AND destination is a registered library endpoint."

**Outcome (in the scenario where loop 3 confirms):** escalated / benign / high confidence on disposition, `matched_archetype: null`. The governance gap (no archetype for "legitimate connection missing from egress allowlist") is the escalation reason, not evidential uncertainty. Analyst recommendation: create `library-telemetry-allowlist-gap` archetype.

**Distiller contributions:**

- `hypothesis_index`: new entry for `(connected_to vertex-shape, runtime-workload source)` → the four seed hypotheses
- `anchor_manifest`: `threat-intel-feed` added
- `pitfall_index`: `(?c2-beacon, remote-endpoint) → "destination threat-intel classification is not sufficient refutation; beacons use legitimate infrastructure. Require runtime-loaded-library evidence + SBOM for severe refutation"` (`authority: learned`)
- `lead_selection_index`: flags `connection-profile` as `moderate` for `?c2-beacon` refutation and `severe` only for `?data-exfil` at specific volume thresholds

### A.3 Anomalous sudo-to-root on a production host

**Scenario:** Wazuh auditd alert, `sudo -i` succeeds on `prod-app-03` by user `bob`; bob is a valid user on the host but is NOT in the current on-call rotation. t=16:42:08Z weekday afternoon.

**Model features:** no clean trust-root terminator available; walk concludes by severely refuting adversarial via three-layer evidence; trust chain promotion for Slack messages (`client-asserted` → effective `anchor-backed` via `trust_chain: [slack-audit, sso-mfa]`); legitimate escalation on a clean-benign disposition because no archetype exists for "policy violation but benign."

**Retrieval at CONTEXTUALIZE:** `anchor_manifest` for `(sudo-authorization, production-host)` returns available anchors (`oncall-schedule`, `change-management`, `hr-system`, `mdm-device-registry`, `vpn-mfa-logs`) but marks each as `authority: partial` — no anchor directly authorizes production sudo. The walk must discriminate.

**Hypotheses attached to the sudo session:** `?incident-shadow`, `?ad-hoc-ops`, `?compromised-cred`, `?insider-threat`. Cheap trust probes (`oncall=false`, `change-mgmt=no-ticket`, `hr=active-employee`) narrow plausibilities but terminate nothing.

**Loop 1 — composite severe leads:**

- `session-command-history(session)` — scope, `severity: moderate` (commands can be faked as cover)
- `session-chain-materialize(session)` — materialize, `severity: severe` (auth chain back to device)
- `concurrent-communication-scope(user)` — scope, `severity: severe` (human-presence evidence)

`lead_selection_index` explicitly flags `session-command-history` as moderate severity, so the agent doesn't rely on it alone for adversarial refutation.

**GATHER results:** Commands are debug-and-restart pattern (consistent with benign, moderate evidence). Session chain: MFA at 16:37:04Z via MDM-enrolled compliant device `macbook-bob-2021` from corp-VPN. Slack shows bob posting in `#ops-prod` at 16:41:32Z ("looking at app-backend, error rate spiked") and 16:46:33Z ("restarted, looks healthy now"), bracketing the sudo session with natural incident-handling language.

**Trust chain promotion:** Slack messages are `client-asserted` by bob's Slack client, but Slack's audit log is itself `anchor-backed` via SSO+MFA. The edges carry `trust_chain: [slack-audit, sso-mfa]`, which promotes their effective authority to `anchor-backed` and allows them to support strong weights.

**ANALYZE:**

- `?compromised-cred` → `--`. Matched refutation: "auth chain back to bob's MFA-verified compliant device AND concurrent human communication consistent with observed actions." Both conditions materially met. Severity: severe. Supporting edges: MDM anchor, VPN-MFA anchor, Slack (trust-chain-promoted).
- `?insider-threat` → `--` under the strict threat model (open communication rules out "acting maliciously in secret"). Pitfall noted: "insider-as-cover-for-something-else" is unfalsifiable by observation alone and is explicitly NOT claimed to be refuted — only "insider acting maliciously in this specific session" is refuted.
- `?ad-hoc-ops` → `++`. Matched prediction. Three-layer grounding.

**CONCLUDE:** escalated / benign / high. `matched_archetype: null` — no archetype on disk for "ad-hoc ops work outside change-management on a minor fix." Rationale: "strong benign technical signal; governance decision (policy violation, not security incident) requires analyst review." Recommendation includes creating the archetype.

**Distiller contributions:**

- `hypothesis_index`: `(sudo-session, production-host, source=employee) → [?ad-hoc-ops, ?incident-shadow, ?compromised-cred, ?insider-threat]`
- `lead_selection_index`: three-lead composite with severities for future severe-refutation scenarios
- `anchor_manifest`: MDM, VPN-MFA, slack-audit entries with their authority levels and trust-chain eligibility
- `pitfall_index`: `(?insider-threat, sudo-session) → "unfalsifiable by session observation alone; severe refutation requires evidence incompatible with the insider-as-cover framing"` (`authority: learned`)

### A.4 S3 list burst from a shared service role (genuinely ambiguous — severity ceiling)

**Scenario:** AWS CloudTrail fires on role `data-pipeline-svc` performing 17 `ListObjectsV2` calls on `s3://company-customer-exports/` in a 3-minute burst from EC2 instance `i-0a1b2c3d`. The role has S3:List permission on this bucket; ~30 batch jobs share this role; the time (02:17 UTC) is inside the nightly batch window. The bucket holds customer PII and is outside the role's typical access pattern.

**Model features exercised:**

- **Severity-ceiling termination (§3.6 #3).** No in-scope lead can refute adversarial hypotheses to `--`, and the agent knows which out-of-scope test would resolve it (out-of-band contact with the human attributed to the session).
- **Complete-match rule for `++` (§3.4).** `?ad-hoc-operator-run` has partial prediction match — human presence via MFA+MDM is confirmed, but the change-context clause (ticket or comms) is unmet. Weight caps at `+`, not `++`.
- **Per-question anchor authority (§4.4).** `ec2-instance-integrity` returns clean but is only partial-authority for "is the instance compromised at any layer" — caps `?compromised-instance` at `-`.

**Abridged walk:**

1. CONTEXTUALIZE retrieval. `dead_leads_index` drops `iam-session-origination-chain` from the pool (attribution-opaque on EC2 instance profiles). `anchor_manifest` returns available anchors all marked `authority: partial` for the "was this batch authorized" question. `hypothesis_index` seeds `?scheduled-batch-run`, `?ad-hoc-operator-run`, `?compromised-instance`, `?compromised-iam-credential`.
2. Loop 1. `anchor-lookup(job-scheduler)` — no registered job (severe, h₁: `+` → `-`). `scope(instance, concurrent-ssh)` — marcus@company.com's SSH session materialized. `scope(instance, process-tree)` — commands attributable to marcus's bash.
3. Loop 2. `anchor-lookup(vpn-mfa)` — marcus MFA'd from compliant MDM device. `anchor-lookup(ec2-instance-integrity)` — partial-authority clean return. `scope(marcus, concurrent-communication)` — nothing. `scope(marcus, s3-access-history, 30d)` — first-ever access to this bucket. `anchor-lookup(change-management)` — no ticket.
4. ANALYZE. `?ad-hoc-operator-run` caps at `+` (partial prediction match: human presence yes, change-context no). `?compromised-instance` caps at `-` (partial-authority anchor). `?compromised-iam-credential` caps at `-` (session-hijack pivot requires out-of-band confirmation). No hypothesis reaches `--` on adversarial.

**Termination:** severity-ceiling. The walk has exhausted in-scope severe leads without reaching `--` on adversarial, and the agent recognizes this as a ceiling rather than an exhaustion. Report includes `ceiling_rationale: "adversarial refutation requires out-of-band confirmation from marcus; no anchor can substitute"`.

**Distiller contributions:**

- `lead_selection_index`: composite set flagged with `max_in_scope_weight: {adversarial: -}` — future runs on the same vertex shape inherit the ceiling knowledge and don't thrash
- `pitfall_index`: three new learned entries capturing the partial-prediction, partial-anchor, and pivot-to-out-of-band traps
- `anchor_manifest`: `ec2-instance-integrity` per-question authority note added

### A.5 Wazuh 5710 multi-username from a sanctioned monitoring prober (bait)

**Scenario:** Wazuh rule 5710 fires: `10.50.30.42 → target-endpoint`, 3 SSH auth failures in 2 minutes. Username attempts in order: `monitor-svc`, `monitor`, `monitoring`. Source IP is in `monitoring-subnet` range. `approved-monitoring-sources.md` anchor lists `10.50.30.42` as `netops-prober-01` (permanent, confirmed 14d ago). `ticket-context` finds 3 prior 5710 runs from this IP in the last 7d, all fast-resolved as `?monitoring-probe`.

**Model features exercised:**

- **Fast-resolve discipline (§9.4).** Ticket-context suggests fast-resolve; `pitfall_index` has a prior-learned entry that blocks it because the observation shape has `distinct_usernames > 1`, which fails the `?monitoring-probe` prediction.
- **Refutation cascade via `refutation_pivots_to` (§3.3).** `?monitoring-probe` carries `refutation_pivots_to: [?sanctioned-host-compromised]` from a prior bait run. When the archetype refutes, the pivot hypothesis is activated immediately.
- **`review_queue.yaml` contribution (§5.1).** The three prior fast-resolved runs become suspect once the current run refutes their shared archetype.

**Abridged walk:**

1. CONTEXTUALIZE. `ticket-context` recommends fast-resolve (3 matching priors). BEFORE committing, the agent consults `pitfalls-for --hypothesis ?monitoring-probe --vertex-shape "session:classification=ssh-failed-sequence"` — which returns a prior learned entry: *"multi-username attempts from a sanctioned prober refute `?monitoring-probe`; pivot to `?sanctioned-host-compromised`"* (`authority: learned`, `n=2`). The current observation has `distinct_usernames=3`, which matches the pitfall trigger. **Fast-resolve is blocked.** The agent proceeds to the full loop with hypotheses `?monitoring-probe` + `?sanctioned-host-compromised` pre-activated.
2. Loop 1. `anchor-lookup(configuration-management, v-001, field=configured_usernames)` — severe — returns `["monitor-svc"]`. Matched refutation text for `?monitoring-probe`: "only configured monitoring username is attempted." Weight: `+` → `--`. The `refutation_pivots_to` relation auto-activates `?sanctioned-host-compromised`.
3. Loop 2. `scope(v-001, recent-ssh-sessions, 01:00-03:00)` — materializes an unauthorized SSH session on the prober from `185.204.88.12` (non-corp, flagged by threat-intel as credential-spray-associated) started at 02:37:04. `scope(v-001, recent-process-activity)` — bash spawned by that session issued the three outbound SSH commands. `anchor-lookup(change-management)` — no ticket. `scope(v-001, prober-baseline, 7d)` — no historical interactive bash or outbound SSH to non-configured targets.
4. ANALYZE. `?sanctioned-host-compromised` → `++` with complete prediction match: unauthorized session from threat-intel-flagged IP, interactive processes spawning outbound SSH to unrelated targets, session activity attributable to the probe failures. Three supporting edges at strong authority (`siem-event`, `runtime-audit`, `anchor-backed`).

**Termination:** adversarial-confirmed. Report: `status: escalated, disposition: true_positive, confidence: high, matched_archetype: sanctioned-host-compromised`. Recommendations: isolate prober, credential rotation, hunt for related activity.

**Distiller contributions:**

- `pitfall_index`: the `(?monitoring-probe, session:distinct_usernames>1)` entry increments `n: 2 → 3`. Each bait-catch strengthens it.
- `hypothesis_index`: `refutation_pivots_to` relation is recorded permanently, so future runs pre-load the pivot.
- `review_queue.yaml`: **three new entries** for the prior 5710 runs fast-resolved from this source IP, each with `reason: possible_missed_threat` and `related_runs: [SEC-2026-04-11-223, SEC-2026-04-08-102, SEC-2026-04-06-317]`. The analyst is alerted to re-examine them — the compromise may have been active longer than the current alert suggests.
- `lead_selection_index`: `anchor-lookup(configuration-management)` recorded as severity-severe for this discrimination pair.

**Without the pitfall entry in the corpus**, this case would fast-resolve benign and the compromise would go undetected. The entire value of the rewritten model on this case is concentrated in one YAML line learned from a prior run.

---

## Appendix B — Glossary

- **Abstract type** — an entity category (`process`, `socket`, `file`, `ip`, `user`, `host`, `container`, `session`, `remote-endpoint`, `device`, `command`, `anchor-source`).
- **Activity graph** — vertices + edges; the subgraph of reality the investigation has painted.
- **Anchor** — a trust source. A successful trust lead against an anchor sets `trust_root: true` on its target vertex.
- **Authority** — a typed field on edges (`siem-event`, `runtime-audit`, `anchor-backed`, `client-asserted`, `inferred-structural`) that gates the hypothesis weights a resolution can produce.
- **Classification** — a value from a vertex's abstract-type vocabulary, declared in `environment/context/{type}-classifications.md`. The primary retrieval key.
- **Discrimination set** — the set of hypotheses attached to a single vertex, competing to explain its parentage or attribution.
- **Distiller** — the Stop-hook script that reads a completed run's companion file and emits entries into the retrieval projections.
- **Edge** — a typed, attributed relation between two vertices. Events are edges with timestamps.
- **Hypothesis** — a candidate backward-edge-plus-parent-vertex attachment to a vertex, with predictions and a refutation shape.
- **Identifier** — a single stable string handle for an entity instance. Audit metadata, not a retrieval key.
- **Investigation graph** — the sequence of lead applications the agent performed; distinct from the activity graph.
- **Lead** — an operation the agent performs to paint more of the activity graph. Three modes: materialize, scope, trust.
- **Projection** — a flat YAML retrieval index maintained by the distiller (e.g., `dead_leads_index.yaml`). The runtime retrieval surface.
- **Refutation cascade** — the relationship captured by `refutation_pivots_to`: refuting hypothesis A should activate hypothesis B because A and B are adversarial counterparts on the same vertex. The refutation of A is *evidence for* B in the cascade pattern.
- **Refutation shape** — concrete observations declared on a hypothesis that would directly contradict it. A `--` resolution must name the matched entry by text.
- **Relation** — the verb type on an edge (`spawned`, `connected_to`, `authenticated_as`, ...). Drawn from a catalog; co-designed with classifications and leads.
- **Review queue** — the seventh projection (`review_queue.yaml`), append-only, keyed on run ID. Carries flagged precedent contradictions surfaced when a run overturns a prior fast-resolve decision. Consumed by analyst workflow, not by the agent at investigation time.
- **Revision** — an append-only record that updates a specific field of an earlier vertex, edge, or hypothesis.
- **Severity ceiling** — a termination category (§3.6 #3) where the walk has exhausted in-scope severe leads without reaching `--` on adversarial hypotheses, and the agent knows which out-of-scope test would resolve it. Distinct from exhaustion escalation.
- **Severity of test** — a required field on lead resolutions (severe, moderate, weak). Gates which weight transitions are allowed.
- **Trust chain** — an optional list of anchors on an edge's authority field that promotes a `client-asserted` edge to effective `anchor-backed` authority.
- **Trust root** — a vertex classified by an anchor-backed trust lead, at which backward traversal terminates.
- **Vertex** — an entity in the activity graph. Classified, not typed by event shape.
- **Vertex shape** — the canonical retrieval key derived from a vertex's abstract_type + whitelisted attributes + classification at defined specificity.
- **Walk** — the sequence of lead applications forming a single investigation's path through the activity graph.