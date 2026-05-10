# Investigation Language — Condensed Spec v2.2 (pilot, harder-case ready)

Revised from v2.1 after design discussion on hypothesis/lead/observation
semantics. **Six material changes** from v2.1. The v2.2 version is intended
as the locked baseline for harder-case pilots (A.3 / A.4).

---

## §A — Changes from v2.1 (read first if you know v2.1)

1. **Prediction IDs; ID-based rule 6.** Predictions and refutation shapes
   now carry explicit `id` fields. Resolutions cite predictions/refutations
   by ID via `matched_prediction_ids` / `matched_refutation_ids` arrays
   instead of literal text substrings. The literal-text rule is retired —
   ID matching is mechanical and paraphrase-free. This also decouples
   predictions from specific telemetry sources: predictions describe
   world-state, leads observe them.
2. **`abstract_type` → `type`.** Simpler field name, same enum.
3. **`outcome.produced` → `outcome.observations`.** Clarifies that the
   block contains the lead's observations (what the query found), not a
   separate kind of record.
4. **`anchor-backed` → `authoritative-source`. Authority is observation-
   only.** Rename removes the implicit legitimacy claim. Explicit spec
   language (§11) clarifies: authority describes how reliably the source
   recorded the observation, NOT whether the observed action was
   legitimate. Legitimacy is always an agent-level derivation from
   multiple edges plus the `concerns` on the records. `trust_root: true`
   is a walk-termination heuristic, not a legitimacy certification.
5. **`lead.observes: [p-id, ...]` optional field.** Leads may declare
   which prediction IDs they can test. Advisory for lead selection,
   enforced by rule 12 when present (cited IDs must be in `observes`).
6. **`proposed_edge.parent_vertex` clarification: one backward hop only.**
   If a hypothesis is attached to a runtime-shim process, its
   `parent_vertex` is the one immediate upstream — typically a session
   via `triggered_by` — NOT a user two hops away via authenticated_as.
   Carried through the worked example (§13).

---

## §B — Five v2 changes (recap)

If you know v2, skip. If not, the core shape of the companion is:

1. **Journal form.** Four top-level keys in time order: `prologue`,
   `hypothesize`, `gather`, `conclude`.
2. **Implicit defaults.** Fields at their default are omitted.
3. **Discrimination-level hypothesis rule.** Run mechanical scope leads
   first if the immediate parent is opaque; form hypotheses at the
   deepest materialized vertex where explanations genuinely fork.
4. **Host context is attributes on the container, not a separate vertex.**
5. **Mechanical leads stay within their data source.** A scope lead's
   `outcome.observations` contains only vertices the data source
   directly observes.

---

## §C — Four v2.1 changes (recap)

1. `intended_hypothesis_set` required on materialize/trust, omitted on scope.
2. No `execution` block on leads.
3. No `outcome.status` field.
4. No `source_lead` field; structural position is authoritative.
5. Unified `concerns` field (replaces `pitfalls` and `data_quality_note`).

---

## 1. Top-level structure

```yaml
prologue:                 # CONTEXTUALIZE, loop 0 — records derived inline from the alert
  vertices: [...]
  edges: [...]

hypothesize:              # HYPOTHESIZE — often empty if mechanical leads run first
  hypotheses: [...]

gather:                   # GATHER — ordered list of self-contained lead blocks
  - lead: {...}
  - lead: {...}

conclude:                 # ANALYZE + CONCLUDE — termination, disposition, summary
  ...
```

Everything is append-only. You never mutate earlier records.

---

## 2. Common record conventions

**IDs.** Stable and local: `v-{nonce}`, `e-{nonce}`, `h-{nonce}`,
`l-{nonce}` for the five top entity kinds. **Predictions and refutation
shapes within a hypothesis** carry their own IDs: `p1`, `p2`, … for
predictions; `r1`, `r2`, … for refutation shapes. These are scoped to
their containing hypothesis.

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
| `lead.observes`                  | omitted        | you want to declare testable prediction IDs      |
| `lead.outcome.failure_reason`    | omitted        | lead errored or returned degraded data           |
| `lead.outcome.trust_root_reached`| omitted        | a trust lead succeeded                           |

There is no `execution` block, no `outcome.status` field, and no
`source_lead` field on any record. Structural position is authoritative.

---

## 3. Prologue block

Records derived directly from the alert, before any lead runs.

```yaml
prologue:
  vertices:
    - id: v-001
      type: process                           # was abstract_type in v2.1
      classification: interactive-shell-in-workload
      identifier: "bash (container <short-id>, pid <pid>)"
      attributes:
        pid: 2881
        uid: 0
        cmdline: "/bin/bash"
      concerns:
        - "Falco reports parent=null because the host-side parent is outside the container pid namespace"

    - id: v-002
      type: container
      classification: runtime-workload
      identifier: "<pod-name>"
      attributes:
        container_id: "<short-id>"
        image: "<image>"
        namespace: "<ns>"
        host_name: "<host>"
        host_role: "kubernetes-worker-node"

  edges:
    - id: e-001
      relation: runs_in
      source_vertex: v-001
      target_vertex: v-002
      when: { timestamp: "<iso>" }
      authority:
        kind: siem-event
        source: "siem:event=<event-id>"
```

Host context lives in v-002 attributes, not as a separate vertex.

---

## 4. Vertex schema

```yaml
vertex:
  id: v-{nonce}
  type: process | socket | file | ip | user | host | container
      | session | remote-endpoint | device | command | anchor-source
  classification: <string>
  identifier: <string>
  attributes: <object>           # omit if empty
  trust_root: true               # omit when false
  concerns: [<string>, ...]      # omit if empty
  citations: [<string>]          # emit when evidence traces to multiple sources
```

**Classifications are retrieval keys.** Use `unclassified-{type}` or
`ambiguous-{a}-or-{b}` when applicable.

**`trust_root: true`** marks a vertex where backward traversal halts
because further traversal requires evidence we don't have access to.
It is **not** a legitimacy certification — see §11.

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

## 6. Hypothesis schema and the discrimination-level rule

### The discrimination-level rule (recap)

A hypothesis lives at the **deepest materialized vertex where
explanations genuinely fork**. If the alert's immediate parent is
opaque, run a mechanical scope lead first; hypothesize at the deeper
vertex it materializes. No relocation machinery.

### `proposed_edge.parent_vertex` is exactly one backward hop

The `parent_vertex` inside `proposed_edge` describes the **immediate
upstream vertex**, not a distant ancestor. If your hypothesis attaches
to a runtime-shim process (like runc), the one backward hop via
`triggered_by` lands on the session that commanded the exec — not on
the user two hops further upstream via `authenticated_as`.

Check when writing: count the edges from `attached_to_vertex` to the
`parent_vertex.type`. It must be exactly one. If you'd need an
intermediate edge, your `parent_vertex.type` is wrong — use the
immediate one and leave further ancestors for predictions.

In practice, at a runtime-shim process attached to a session via
`triggered_by`, multiple competing hypotheses typically share the
same one-hop shape (`type: session`) and differ in the session's
**classification and attributes** or in the **predictions** they make
about further upstream evidence. This is fine — discrimination often
lives in predictions, not in the immediate edge shape.

### Mechanical leads stay within their data source (recap)

A scope lead's `outcome.observations` contains only vertices the data
source directly observes. Causally-implied parents, sessions, or users
remain unmaterialized until a trust lead confirms them.

### Schema

```yaml
hypothesis:
  id: h-{nonce}
  name: "?descriptive-mechanism-name"
  canonical: true | false
  attached_to_vertex: v-{id}

  proposed_edge:
    relation: <string>            # exactly one backward hop
    parent_vertex:
      type: <string>
      classification: <string>
      attributes: <object>        # optional

  # Predictions are world-state claims with stable IDs. Source-agnostic.
  # Resolutions cite these IDs via matched_prediction_ids.
  predictions:
    - id: p1
      claim: "<source-agnostic claim about world state>"
    - id: p2
      claim: "<another claim>"

  # Refutation shapes are world-state observations that would contradict
  # the hypothesis. Also ID'd.
  refutation_shape:
    - id: r1
      claim: "<observation contradicting a core prediction>"
    - id: r2
      claim: "<another contradicting observation>"

  concerns: []                    # omit if empty
  weight: "++" | "+" | "-" | "--" | null
  weight_history: []              # omit until there are transitions
  status: active                  # omit; emit when non-default
```

**Predictions are source-agnostic.** Write them as claims about what
would be true in the world if the hypothesis held, not as claims about
what a specific source would return. "A kube-api pods/exec request
caused the runc exec" (good). "Kube-audit returns an exec record in the
±5s window" (bad — source-coupled).

**Every prediction must be ID'd.** Predictions without IDs are a
schema error. IDs are scoped to the containing hypothesis; `h-001.p1`
and `h-002.p1` are different predictions. Resolutions always cite by
fully-qualified reference through `hypothesis` + `matched_prediction_ids`.

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

      # Optional: which hypothesis prediction/refutation IDs this lead
      # can test. Used for lead selection and validator check (rule 12).
      # If present, all cited IDs in resolutions must be a subset of this.
      observes:
        - { hypothesis: h-{id}, predictions: [p1, p2], refutations: [r1] }
        - { hypothesis: h-{id}, predictions: [p1], refutations: [] }

      query_details:
        system: <string>
        template: <string>
        query: <string>
        time_window: <string>
        substitutions: <object>

      concerns: [<string>, ...]   # omit if empty

      outcome:
        observations:              # renamed from `produced` in v2.1
          vertices: [<full vertex records>]
          edges: [<full edge records>]
        trust_root_reached: v-{id}            # omit when null
        failure_reason: <string>               # omit unless error/degraded

      new_hypotheses: [<full hypothesis records>]   # omit if empty
      shelved: [h-{id}, ...]                        # omit if empty

      resolutions:
        - hypothesis: h-{id}
          before: "+" | "-" | "++" | "--" | null
          after: "+" | "-" | "++" | "--"
          severity_of_test: severe | moderate | weak
          matched_prediction_ids: [p1, p2, ...]     # cite by ID, not by text
          matched_refutation_ids: [r1, ...]          # same
          reasoning: "<what observations, which predictions, what confirmed or contradicted>"
          supporting_edges: [e-{id}, ...]
```

**`intended_hypothesis_set` is required for `materialize` and `trust`
modes, and must be omitted for `scope` mode.**

**`observes` is optional but enforced when present.** Its shape is a
list of per-hypothesis entries, each naming a hypothesis ID and the
predictions/refutations this lead can test for that hypothesis. When
present, rule 12 enforces that the lead's resolutions only cite
prediction/refutation IDs inside the `observes` list.

**`outcome.observations` replaces v2.1's `outcome.produced`.** Same
content (vertices and edges materialized by this lead), clearer
semantics — a lead's observations are what the query found.

**Severity of test:**

| Severity   | Meaning                                                                       | Max weight effect                    |
|------------|-------------------------------------------------------------------------------|--------------------------------------|
| `severe`   | Outcome could directly contradict (or directly confirm) a core prediction    | up to `++` / `--`                    |
| `moderate` | Outcome constrains plausibility without directly contradicting                 | one step                             |
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
  ceiling_rationale: <string>       # required if severity-ceiling
  summary: <string>
```

Four termination categories, same as v2. When multiple conditions fire
in the same loop, pick the one that explains **why** the backward walk
halted.

---

## 9. Classifications (seed vocabulary)

Unchanged from v2.1.

- **Process**: `service-entrypoint-process`, `service-child-process`,
  `interactive-shell-in-workload`, `host-runtime-shim`,
  `operator-tool-invocation`, `automation-pipeline-process`,
  `unclassified-process`
- **Container**: `runtime-workload`, `sidecar-workload`, `build-container`,
  `debug-container`, `unclassified-container`
- **User**: `employee-with-exec-rbac`, `employee-without-exec-rbac`,
  `automation-identity`, `unknown-attacker`, `unclassified-user`
- **Session**: `kubectl-exec-session`, `ssh-session`, `service-session`,
  `unclassified-session`
- **IP**: `corp-vpn-egress`, `internal-cluster-node`,
  `internal-corp-network`, `external-sanctioned-automation`,
  `unclassified-ip`

Use `unclassified-{type}` or `ambiguous-{a}-or-{b}` when applicable.
Host vertices are generally NOT created — host context lives as
attributes on the container.

---

## 10. Relation catalog

| Relation               | Source → Target                  |
|------------------------|----------------------------------|
| `spawned`              | process → process                |
| `executed`             | process → file                   |
| `loaded_by`            | process → library-file           |
| `opened`               | process → socket                 |
| `connected_to`         | socket → remote-endpoint         |
| `read` / `wrote`       | process → file                   |
| `runs_in`              | process → container              |
| `authenticated_as`     | session → user                   |
| `initiated_by`         | session → user \| device         |
| `triggered_by`         | process → process \| session     |
| `escalated_privilege`  | session → session (self-edge)    |
| `executed_in`          | command → session                |
| `classified_as`        | vertex → classification-value    |
| `attested_by`          | vertex → anchor-source           |

---

## 11. Authority table — OBSERVATIONAL ONLY, NOT LEGITIMACY

| Authority kind           | Meaning                                                                    | Max weight supportable |
|--------------------------|----------------------------------------------------------------------------|------------------------|
| `siem-event`             | Backed by a SIEM / audit log event                                         | `++` / `--`            |
| `runtime-audit`          | Backed by a runtime or OS audit stream                                     | `++` / `--`            |
| `authoritative-source`   | From a source authoritative for this observation question (e.g., kube-audit for API requests, pam-audit for session auth, mdm-registry for device posture). **Authoritative for WHAT was observed — NOT a certification of legitimacy.** | `++` / `--`            |
| `client-asserted`        | From a self-reported field (TLS SNI, HTTP user-agent, argv claims)         | `+` / `-`              |
| `inferred-structural`    | Inferred from co-occurrence, not directly materialized                     | `+` / `-`              |

**Explicit clarification — read carefully.** Authority describes how
reliably the source **recorded the observation**. It does NOT claim
that the observed action was authorized, benign, or correctly
interpreted. Kube-audit faithfully logs API calls; it does not certify
whether the caller had legitimate intent, whether credentials were
stolen, or whether RBAC rules correctly encoded organizational intent.
Legitimacy is **always** an agent-level derivation from:

1. Multiple corroborating observational edges
2. Residual trust assumptions captured in `concerns` fields on vertices
   and hypotheses
3. Domain knowledge about the source's coverage gaps

**`trust_root: true` is a walk-termination heuristic**, not a
legitimacy certification. It means "backward traversal halts here
because further traversal would require evidence we don't have access
to, and nothing in current evidence warrants digging further." The
residual trust assumptions (stolen credentials, coerced actor,
credential theft not yet detected) live in `concerns` on the vertex
and/or the refuting hypotheses.

**Validator rule 4 (strong weights):** a resolution with `after ∈
{++, --}` and `severity_of_test: severe` must cite at least one
supporting edge whose `authority.kind` is `siem-event`, `runtime-audit`,
or `authoritative-source`.

**Trust chain promotion** (unchanged from v2): a `client-asserted`
edge sitting on a verified trust chain gets effective
`authoritative-source` authority. Example: Slack messages are
client-asserted by the user's client, but Slack's audit log is
`authoritative-source` backed by SSO+MFA, so
`trust_chain: [slack-audit, sso-mfa]` promotes the edge.

---

## 12. Write-time validator rules

1. **Schema validity.** Required fields present, enum values valid,
   IDs well-formed.
2. **Classification vocabulary.** Every `classification` in §9 or a
   `{type}:{slug}` provisional.
3. **Relation catalog.** Every `edge.relation` in §10.
4. **Authority rule.** Strong-weight resolutions cite at least one
   strong-authority supporting edge (§11).
5. **Refutation ID match.** Every `--` resolution's
   `matched_refutation_ids` is non-empty, and every ID in it exists in
   the target hypothesis's `refutation_shape` list.
6. **Prediction ID match + completeness for `++`.** Every `++`
   resolution's `matched_prediction_ids` is non-empty, and every ID
   in it exists in the target hypothesis's `predictions` list. The
   union of `matched_prediction_ids` across **all resolutions on this
   hypothesis's history** up to the `++` transition must equal the
   full set of prediction IDs on the hypothesis. Partial coverage
   caps the weight at `+`.
7. **ID references resolve.** All `v-*`, `e-*`, `h-*`, `l-*`
   references point to records that exist. All prediction IDs in
   `matched_prediction_ids` and refutation IDs in
   `matched_refutation_ids` point to entries in the named hypothesis.
8. **Append-only.** No record is mutated after it is written.
9. **Self-containment of lead blocks.** Every vertex / edge /
   hypothesis produced by a lead lives inside that lead's
   `outcome.observations`, `new_hypotheses`, or `shelved`.
10. **Scope leads omit `intended_hypothesis_set`.**
11. **Mechanical leads stay within their data source.** A scope lead's
    `outcome.observations.vertices` contains only vertices the data
    source directly observes. Session/user vertices from causal
    implication are validator errors on scope leads.
12. **`observes` subset (when present).** If a lead declares `observes`,
    every `matched_prediction_ids` / `matched_refutation_ids` cited in
    its resolutions must appear in the corresponding entry of
    `observes`. Resolutions cannot cite prediction/refutation IDs the
    lead didn't declare it would test.

### Why rule 6 is mechanical now

v2.1 required `matched_prediction_text` to be a literal substring of
the predictions list. This was a paraphrase-prevention hack, and the
v2.1 pilot still had one arm pick a list entry that didn't fit the
observation (H3's semantic mismatch). Under v2.2, resolutions cite
prediction IDs directly. The validator check is:

```
matched_prediction_ids ⊆ target_hypothesis.predictions[].id
```

This is a set-membership check — trivially mechanical, no paraphrase
possible. The `reasoning` field carries the semantic link between the
observation and the cited prediction, and if the agent cites the
wrong ID, the mismatch is explicit (the reasoning says one thing,
the IDs point to another) rather than hidden in a text-substring
ambiguity. Semantic mismatch is still possible but is cleanly
catchable by a Haiku judge layered on top, or by human review.

---

## 13. Worked example — file write to sensitive path (NOT your case)

Deliberately different scenario, updated for v2.2 conventions:
prediction IDs, `type` rename, `observations` rename, and the
one-hop parent discipline.

**Scenario:** A SIEM alert fires when a process writes to `/etc/passwd`
on host `prod-db-04`. Alert names the writing process (`tee`, pid=4410)
but no ancestor chain.

```yaml
prologue:
  vertices:
    - id: v-001
      type: process
      classification: unclassified-process
      identifier: "tee (host prod-db-04, pid 4410)"
      attributes: { pid: 4410, cmdline: "tee -a /etc/passwd" }
      concerns:
        - "ancestor chain not populated in the alert; process-lineage scope lead required before hypothesizing"
      citations: ["siem:rule.id=120042:event=xyz"]
    - id: v-002
      type: file
      classification: sensitive-credential-file
      identifier: "/etc/passwd"
      citations: ["siem:rule.id=120042:event=xyz"]
  edges:
    - id: e-001
      relation: wrote
      source_vertex: v-001
      target_vertex: v-002
      when: { timestamp: "2026-04-14T08:51:03Z" }
      authority: { kind: siem-event, source: "siem:rule.id=120042:event=xyz" }

hypothesize:
  hypotheses: []

gather:
  - lead:
      id: l-001
      loop: 1
      name: process-lineage
      mode: scope
      target: v-001
      # No intended_hypothesis_set — scope mode.
      query_details:
        system: host-audit
        template: "leads/process-lineage/templates/auditd.md"
        query: "auditd execve lineage for pid=4410 on host prod-db-04 at t=2026-04-14T08:51:03Z"
        time_window: "±30s"
        substitutions: { pid: 4410, host: prod-db-04, t: "2026-04-14T08:51:03Z" }
      outcome:
        observations:
          vertices:
            # Mechanical lead materializes only what host-audit directly sees:
            # the process ancestor chain and the pts session metadata. It does
            # NOT materialize the user — that's the job of l-002 (pam-audit).
            - id: v-003
              type: process
              classification: interactive-shell-in-workload
              identifier: "bash (host prod-db-04, pid 4200)"
              attributes: { pid: 4200, cmdline: "-bash", tty: "pts/1" }
            - id: v-004
              type: session
              classification: ssh-session
              identifier: "pts/1 session on prod-db-04"
              attributes: { tty: "pts/1" }
          edges:
            - id: e-002
              relation: spawned
              source_vertex: v-003
              target_vertex: v-001
              when: { timestamp: "2026-04-14T08:51:03Z" }
              authority: { kind: runtime-audit, source: "host-audit:execve:4410" }
            - id: e-003
              relation: executed_in
              source_vertex: v-003
              target_vertex: v-004
              authority: { kind: runtime-audit, source: "host-audit:session:pts1" }

      # Discrimination level advances to v-004 (the session).
      # One-hop parent via authenticated_as goes to a user — that's the
      # immediate upstream we're asking about.
      new_hypotheses:
        - id: h-001
          name: "?sanctioned-admin-session"
          canonical: true
          attached_to_vertex: v-004
          proposed_edge:
            relation: authenticated_as
            parent_vertex:
              type: user
              classification: employee-with-exec-rbac
          predictions:
            - id: p1
              claim: "the pts/1 session is authenticated as an employee with PAM-enforced sudo or sensitive-file write permission"
            - id: p2
              claim: "no anomalous concurrent network session exists to v-004's origin in the ±5m window"
          refutation_shape:
            - id: r1
              claim: "the pts/1 session is authenticated as an automation identity or an unknown user"
            - id: r2
              claim: "no PAM authorization record exists for sensitive-file write in the ±5m window around the write event"
          weight: null

        - id: h-002
          name: "?post-exploit-shell"
          canonical: true
          attached_to_vertex: v-004
          proposed_edge:
            relation: authenticated_as
            parent_vertex:
              type: user
              classification: unknown-attacker
          predictions:
            - id: p1
              claim: "no PAM authorization record exists for a legitimate user at session start"
          refutation_shape:
            - id: r1
              claim: "the pts/1 session is authenticated as an employee-with-exec-rbac user with a matching PAM authorization record"
          concerns:
            - "stolen-credential scenario unfalsifiable without MDM device-posture trust-chain; refutation here is 'no current evidence of credential compromise', not 'credential theft ruled out'"
          weight: null

  - lead:
      id: l-002
      loop: 2
      name: "anchor-lookup(pam-audit)"
      mode: trust
      target: v-004
      intended_hypothesis_set: [h-001, h-002]

      # Declare which prediction/refutation IDs this trust lead can test.
      # The pam-audit query can observe who authenticated the session and
      # whether a PAM authorization record exists, so it covers h-001.p1,
      # h-001.r1, h-001.r2, h-002.p1, h-002.r1. It cannot observe the
      # concurrent-network-session clause (h-001.p2), which would need a
      # separate scope lead.
      observes:
        - hypothesis: h-001
          predictions: [p1]
          refutations: [r1, r2]
        - hypothesis: h-002
          predictions: [p1]
          refutations: [r1]

      query_details:
        system: pam-audit
        template: "leads/anchor-lookup/templates/pam.md"
        query: "pam authorization records for session pts/1 on prod-db-04 at ±5m"
        time_window: "±5m"
        substitutions: { session: "pts/1", host: prod-db-04 }
      outcome:
        observations:
          vertices:
            - id: v-005
              type: user
              classification: employee-with-exec-rbac
              identifier: "carol@company.com"
              attributes: { rbac_sudoers: true, mfa_verified: true }
              trust_root: true
          edges:
            - id: e-004
              relation: authenticated_as
              source_vertex: v-004
              target_vertex: v-005
              authority: { kind: authoritative-source, source: "pam-audit:auth:pts1:carol" }
        trust_root_reached: v-005
      resolutions:
        - hypothesis: h-001
          before: null
          after: "+"
          severity_of_test: severe
          matched_prediction_ids: [p1]
          reasoning: "pam-audit returned carol@company.com with rbac_sudoers: true and MFA verified — prediction p1 (employee with PAM-enforced sudo) is confirmed. Supporting edge e-004 is authoritative-source. Prediction p2 (no anomalous concurrent network session) is NOT tested by this lead; it is observable only via a concurrent-network-scope lead. Without p2 coverage, the weight caps at + rather than ++."
          supporting_edges: [e-004]

        - hypothesis: h-002
          before: null
          after: "--"
          severity_of_test: severe
          matched_refutation_ids: [r1]
          reasoning: "pam-audit returned carol@company.com, classified employee-with-exec-rbac with a matching PAM authorization record — refutation r1 (employee-with-exec-rbac user with matching PAM record) is directly satisfied. Supporting edge e-004 is authoritative-source. Residual stolen-credential concern remains in h-002.concerns."
          supporting_edges: [e-004]

  # At this point h-001 is at + (not ++) because p2 is untested. If the
  # walk terminates here on trust-root, h-001 is "benign with incomplete
  # positive evidence." If a further scope lead runs and confirms p2,
  # h-001 advances to ++.
  #
  # For this worked example we assume a follow-up scope lead exists but
  # is omitted for brevity; a real walk would run it and include the
  # resolution advancing h-001 to ++.

conclude:
  termination:
    category: trust-root
    rationale: "pam-audit anchor set trust_root=true on v-005 (carol@company.com)"
  disposition: benign
  confidence: high
  matched_archetype: sensitive-file-write-by-authorized-admin
  summary: "tee appended to /etc/passwd as carol@company.com in a PAM-authorized pts/1 session with MFA. h-002 (?post-exploit-shell) refuted via r1 literal ID match; h-001 at + pending p2 confirmation via concurrent-network scope. Trust-root termination on authoritative-source-backed user classification. Residual stolen-credential concern tracked in h-002.concerns."
```

**Things to notice:**

1. **`type` not `abstract_type` everywhere.**
2. **`outcome.observations` not `outcome.produced`.**
3. **Predictions and refutation shapes have IDs.** `p1`, `p2`, `r1`, `r2`.
4. **Resolutions cite prediction/refutation IDs**, not literal text
   substrings. No paraphrase failure mode.
5. **`observes` on l-002** declares which prediction/refutation IDs
   this lead can test. Rule 12 enforces that resolutions only cite
   IDs from this declaration.
6. **`authoritative-source`** replaces `anchor-backed` on edges.
   Notice the spec language in §11 about this being observational,
   not legitimacy.
7. **h-001 caps at `+` because p2 (concurrent network session absence)
   is not tested by l-002.** This is rule 6's completeness check in
   action: `matched_prediction_ids: [p1]` doesn't cover all of h-001's
   predictions, so the weight transition caps at `+` rather than `++`.
   A follow-up scope lead would test p2.
8. **h-002 refutes cleanly** because r1 is ID'd, the cited ID exists,
   and the supporting edge is authoritative-source.
9. **`trust_root: true` on v-005** is a walk-termination heuristic.
   The residual concern (stolen credentials) is explicit in
   h-002.concerns. Legitimacy is derived, not certified.

---

## 14. What you write

1. **Read** the alert record and the retrieval-sim.
2. **Fill `prologue`** with vertices and edges derived from the alert.
   Host context lives in container attributes. Emit `concerns` on
   any record with a telemetry limitation worth flagging.
3. **Decide** whether to hypothesize now or run a mechanical scope lead
   first. If the alert's immediate parent is opaque, leave
   `hypothesize.hypotheses: []` and write the mechanical lead as the
   first GATHER block.
4. **Write each GATHER lead as a self-contained block.** Under
   `outcome.observations`, inline only what the lead's data source
   directly observes. Sessions and users from causal implication wait
   for a trust lead.
5. **When the discrimination level advances, form hypotheses with
   ID'd predictions and ID'd refutation shapes.** Write predictions as
   source-agnostic world-state claims.
6. **In resolutions, cite prediction/refutation IDs**, not literal
   text. For `++`, make sure every prediction ID on the hypothesis is
   covered by the accumulated `matched_prediction_ids` across
   resolutions. Partial coverage caps at `+`.
7. **Omit `intended_hypothesis_set` on scope leads; include on
   materialize/trust leads.** Optionally emit `observes` on any lead
   to declare testable prediction IDs — rule 12 enforces the subset.
8. **Write `conclude`** with termination, disposition, and a 2-3
   sentence summary.

Every validator rule in §12 must pass. Rule 6 is no longer a
paraphrase hazard under v2.2 — it's a mechanical ID-set membership
check. Rule 11 (mechanical leads stay in data source) and rule 12
(`observes` subset) are the new things to watch.

**Output path** is specified in your task prompt.
