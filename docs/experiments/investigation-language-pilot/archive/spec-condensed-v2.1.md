# Investigation Language — Condensed Spec v2.1 (pilot rerun)

Revised from v2 after a second round of pilot findings. **Seven material
changes** from v2, plus the five v2 changes you need to know about if you
haven't seen v2. If you've seen v2, read §A for the deltas; otherwise
read the whole document.

---

## §A — Changes from v2 (read first if you know v2)

1. **`intended_hypothesis_set` applies only to `materialize` and `trust`
   leads.** Scope leads do not carry it. Scope leads enrich the graph
   without actively testing a hypothesis set.
2. **The `execution` block is dropped.** `dispatched_via` and `duration_ms`
   were operational telemetry, not investigation substance. Concerns about
   a lead's reliability or cost live in the new `concerns` field.
3. **`outcome.status` is dropped.** Presence of `produced` with no
   `failure_reason` implies success. `failure_reason` alone expresses
   the negative cases.
4. **`source_lead` is dropped from all records.** Under the journal form,
   a record's *structural position* tells you which lead produced it
   (or whether it's `inline` from the prologue). The distiller assigns
   `source_lead` at ingest from the enclosing block; agents never write
   this field.
5. **Unified `concerns` field** replaces `pitfalls` (on hypotheses),
   `data_quality_note` (on vertices), and introduces the same field on
   edges and leads. Semantics: "if you take this record at face value,
   here are the limitations or traps." Arrays of strings, omitted when
   empty.
6. **"Mechanical leads stay within their data source" rule** (spec §6).
   A scope lead's `outcome.produced` contains only vertices the data
   source directly observes. Causally-implied parents or sessions
   remain unmaterialized until a trust lead confirms them.
7. **Rule 6 now includes a negative example.** The single most
   common v1/v2 failure was writing `matched_prediction_text` as a
   paraphrase of the observation instead of a literal substring. §12 now
   shows a wrong/right pair inline.

---

## §B — Five v2 changes (recap, for completeness)

If you know v2, skip. If not, the core shape of the companion is:

1. **Journal form.** Four top-level keys in time order: `prologue`,
   `hypothesize`, `gather`, `conclude`. Each `gather` entry is a
   self-contained lead block.
2. **Implicit defaults.** Fields at their default are omitted.
3. **Discrimination-level hypothesis rule.** Run mechanical scope leads
   first if the immediate parent is opaque; form hypotheses at the
   deepest materialized vertex where explanations genuinely fork. No
   relocation machinery.
4. **Host context is attributes on the container, not a separate vertex.**
5. **Rules 5 and 6 are literal copy-paste.** Refutation and prediction
   text matches are character-for-character substrings from the target
   hypothesis's own lists. Not paraphrases.

---

## 1. Top-level structure

```yaml
prologue:                 # CONTEXTUALIZE, loop 0 — records derived inline from the alert
  vertices: [...]
  edges: [...]

hypothesize:              # HYPOTHESIZE — may be empty if mechanical leads run first
  hypotheses: [...]

gather:                   # GATHER — ordered list of self-contained lead blocks
  - lead: {...}
  - lead: {...}

conclude:                 # ANALYZE + CONCLUDE — termination, disposition, summary
  termination: ...
  disposition: ...
  matched_archetype: ...
  summary: ...
```

Everything is append-only. You never mutate earlier records.

---

## 2. Common record conventions

**IDs.** `v-{nonce}`, `e-{nonce}`, `h-{nonce}`, `l-{nonce}`. Short numeric
nonces.

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
| `hypothesis.concerns`            | `[]`           | an alert-specific trap or unfalsifiable residual |
| `hypothesis.weight_history`      | `[]`           | there are recorded transitions                   |
| `hypothesis.status`              | `active`       | `confirmed`, `refuted`, or `shelved`             |
| `lead.concerns`                  | `[]`           | the lead has a reliability, cost, or data-quality concern |
| `lead.outcome.failure_reason`    | omitted        | the lead errored or returned degraded data       |
| `lead.outcome.trust_root_reached`| omitted        | a trust lead succeeded                           |

**There is no `execution` block on leads**, no `outcome.status` field,
and no `source_lead` field on any record. The distiller assigns
`source_lead` from structural position (enclosing lead block, or `inline`
for prologue records). Agents never write it.

**`concerns` is a single field name everywhere.** Arrays of strings.
Omit when empty. One entry per distinct concern.

---

## 3. Prologue block

Records derived directly from the alert, before any lead runs. Usually
2–4 vertices and 1–2 edges.

```yaml
prologue:
  vertices:
    - id: v-001
      abstract_type: process
      classification: interactive-shell-in-workload
      identifier: "bash (container <short-id>, pid <pid>)"
      attributes:
        pid: 2881
        uid: 0
        cmdline: "/bin/bash"
      concerns:
        - "Falco reports parent=null because the host-side parent is outside the container pid namespace"

    - id: v-002
      abstract_type: container
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

Note: no `source_lead`, no `data_quality_note` (replaced by `concerns`),
no `trust_root: false` (default omitted), no `citations` on records that
only cite the alert event (pull from the authority.source field instead,
or emit explicitly if you prefer — see §4).

---

## 4. Vertex schema

```yaml
vertex:
  id: v-{nonce}
  abstract_type: process | socket | file | ip | user | host | container
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

**`trust_root: true`** is set only by a successful trust lead. Emit the
field only when setting true.

**`concerns`** replaces the v2 `data_quality_note` field with a unified
name. Emit when a specific telemetry limitation, classification
uncertainty, or interpretive caveat is worth recording. Examples:
`"Falco reports parent=null because the host-side parent is outside the container pid namespace"`,
`"IP classification is provisional — anchor lookup failed and fallback heuristics were used"`.

---

## 5. Edge schema

```yaml
edge:
  id: e-{nonce}
  relation: <string>
  source_vertex: v-{id}
  target_vertex: v-{id}
  when:                          # optional
    timestamp: <ISO8601>
    # OR duration_sec / distribution
  attributes: <object>           # omit if empty
  status: observed | hypothesized | refuted   # omit when observed
  authority:
    kind: siem-event | runtime-audit | anchor-backed | client-asserted | inferred-structural
    source: <string>
    trust_chain: [<anchor-id>, ...]   # omit if empty
  concerns: [<string>, ...]      # omit if empty
```

**Edge `concerns`** is new in v2.1. Use it to flag disputed authority
interpretations, trust-chain caveats, or inferred-structural edges whose
derivation might deserve second-look at analyst review.

---

## 6. Hypothesis schema and the discrimination-level rule

### The rule

A hypothesis describes a **discriminating** backward explanation: an edge
the walk could observe that would materially distinguish one explanatory
story from another. Hypotheses live at the **deepest materialized vertex
where the chain of explanations genuinely forks** — the *discrimination
level*.

- If the alert's immediate parent is already mechanically knowable (e.g.,
  you have a pid tree), form hypotheses at CONTEXTUALIZE.
- If the immediate parent is opaque, the discrimination level is not yet
  visible. **Run a mechanical scope lead first.** Hypothesize after it
  materializes the deeper vertex.
- If mid-walk you discover the discrimination has shifted further down,
  shelve existing hypotheses (`status: shelved`) and form a new set at
  the new level. No relocation machinery — just fresh records.

### Mechanical leads stay within their data source — NEW IN v2.1

A scope lead's `outcome.produced` contains only vertices that its data
source **directly observes**. Causally-implied parents, sessions, or
users remain unmaterialized until a trust lead (against an appropriate
anchor) confirms them.

Example: the runtime-audit execve feed observes host-side process spawn
events. It sees that `runc:[2:INIT]` was invoked with arguments
`exec -c <container-id> bash`. It does NOT see the kubectl exec session
that caused the runc invocation — that's one API layer up, observable
only by kube-audit.

A mechanical scope lead against the execve feed must therefore produce
`v-003: runc` and `e-002: spawned(runc → bash)`. It must NOT produce
`v-004: kubectl-exec-session` — that vertex is the job of a later trust
lead against kube-audit. If the scope lead's cmdline text mentions
kubectl, that's context, not a materialization license.

This rule eliminates the class of v2 error where mechanical scope leads
materialized session/user vertices that their data source couldn't
directly observe.

### Schema

```yaml
hypothesis:
  id: h-{nonce}
  name: "?descriptive-mechanism-name"
  canonical: true | false
  attached_to_vertex: v-{id}

  proposed_edge:
    relation: <string>
    parent_vertex:
      abstract_type: <string>
      classification: <string>
      attributes: <object>        # optional

  predictions:
    - for: v-{id} | e-{id} | vertex-shape | edge-shape
      expected: <object or string>
    - for_absence: "<what should NOT be observed if true>"

  refutation_shape:
    - "<observation contradicting a core prediction>"

  concerns: []                    # omit if empty (was `pitfalls` in v1/v2)
  weight: "++" | "+" | "-" | "--" | null
  weight_history: []              # omit until there are transitions
  status: active                  # omit; emit when confirmed/refuted/shelved
```

**Refutation shape is strict — literal text match.** See §12 rule 5.
**Prediction completeness for `++` — literal text match.** See §12 rule 6.

---

## 7. Lead block

Each entry in `gather:` is a lead block containing everything the lead
did. Self-contained: vertices/edges/hypotheses it produced live inside
the block.

```yaml
gather:
  - lead:
      id: l-{nonce}
      loop: <int>
      name: <string>
      mode: materialize | scope | trust
      target: v-{id}
      intended_hypothesis_set: [h-{id}, ...]   # REQUIRED for materialize and trust; OMIT for scope

      query_details:
        system: <string>
        template: <string>
        query: <string>
        time_window: <string>
        substitutions: <object>

      concerns: [<string>, ...]   # omit if empty

      outcome:
        produced:
          vertices: [<full vertex records>]
          edges: [<full edge records>]
        trust_root_reached: v-{id}            # omit when null
        failure_reason: <string>               # omit unless error or degraded

      new_hypotheses: [<full hypothesis records>]   # omit if empty
      shelved: [h-{id}, ...]                        # omit if empty

      resolutions:
        - hypothesis: h-{id}
          before: "+" | "-" | "++" | "--" | null
          after: "+" | "-" | "++" | "--"
          severity_of_test: severe | moderate | weak
          matched_refutation_text: "<LITERAL substring from target hypothesis's refutation_shape>"
          matched_prediction_text: "<LITERAL substring from target hypothesis's predictions>"
          reasoning: "<prediction, observation, what confirmed or contradicted what>"
          supporting_edges: [e-{id}, ...]
```

**No `execution` block.** Operational telemetry (dispatched_via,
duration_ms) is not recorded. If a lead had an operational concern worth
flagging — slow, retried, anchor-stale — emit it in `concerns`.

**No `outcome.status` field.** Success is implied by `produced` records
with no `failure_reason`. Empty is implied by empty/absent `produced`
with no `failure_reason`. Degraded and error states are expressed by
`failure_reason` presence.

**`intended_hypothesis_set` is required for `materialize` and `trust`
modes, and MUST be omitted for `scope` mode.** A scope lead that emits
the field is a schema error.

**`concerns`** on a lead flags:
- Reliability issues ("anchor returned 4x slower than normal; may
  indicate index pressure")
- Cost concerns ("this scope lead pulled 18MB of execve records;
  consider tighter time_window on reuse")
- Data-source limitations specific to this invocation ("index was
  incomplete for the requested time window due to retention policy")

Omit when there's nothing to flag. The agent's cost/efficiency record is
not tracked elsewhere; this is the only place to surface it.

### Severity of test

| Severity   | Meaning                                                                       | Max weight effect                    |
|------------|-------------------------------------------------------------------------------|--------------------------------------|
| `severe`   | Outcome could directly contradict (or directly confirm) a core prediction    | up to `++` / `--`                    |
| `moderate` | Outcome constrains plausibility without directly contradicting                 | one step (e.g. `+` → `-`)            |
| `weak`     | Circumstantial consistency                                                     | caps at `+` or `-`; never `++` / `--`|

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

## 9. Classifications

Same seed vocabulary as v2 (unchanged).

**Process classifications:**
`service-entrypoint-process`, `service-child-process`,
`interactive-shell-in-workload`, `host-runtime-shim`,
`operator-tool-invocation`, `automation-pipeline-process`,
`unclassified-process`

**Container classifications:**
`runtime-workload`, `sidecar-workload`, `build-container`,
`debug-container`, `unclassified-container`

**User classifications:**
`employee-with-exec-rbac`, `employee-without-exec-rbac`,
`automation-identity`, `unknown-attacker`, `unclassified-user`

**Session classifications:**
`kubectl-exec-session`, `ssh-session`, `service-session`,
`unclassified-session`

**IP classifications:**
`corp-vpn-egress`, `internal-cluster-node`, `internal-corp-network`,
`external-sanctioned-automation`, `unclassified-ip`

(Host vertices are generally NOT created — host context lives as
attributes on the container.)

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

No `runs_in container → host` — host lives in container attributes.

---

## 11. Authority table

| Authority kind        | Meaning                                                                    | Max weight supportable |
|-----------------------|----------------------------------------------------------------------------|------------------------|
| `siem-event`          | Backed by a SIEM / audit log event                                         | `++` / `--`            |
| `runtime-audit`       | Backed by a runtime or OS audit stream                                     | `++` / `--`            |
| `anchor-backed`       | Materialized via a trust anchor lookup                                     | `++` / `--`            |
| `client-asserted`     | From a self-reported field                                                  | `+` / `-`              |
| `inferred-structural` | Inferred from co-occurrence                                                | `+` / `-`              |

Strong-weight transitions (`++`/`--` with severity `severe`) must cite
at least one strong-authority supporting edge.

---

## 12. Write-time validator rules

1. **Schema validity.** Required fields present; enum values valid;
   IDs well-formed.
2. **Classification vocabulary.** Every `classification` in §9 or a
   `{type}:{slug}` provisional.
3. **Relation catalog.** Every `edge.relation` in §10.
4. **Authority rule.** Strong-weight resolutions cite at least one
   strong-authority supporting edge.
5. **Refutation text match — LITERAL COPY-PASTE from the target
   hypothesis's OWN `refutation_shape`.** Every `--` resolution sets
   `matched_refutation_text` to a substring that appears
   **character-for-character** in the TARGET hypothesis's
   `refutation_shape` list. Not another hypothesis's list. Not a
   paraphrase. Copy exactly. If no entry fits, the weight caps at `-`.
6. **Prediction text match — LITERAL COPY-PASTE from the target
   hypothesis's OWN `predictions`.** Every `++` resolution sets
   `matched_prediction_text` to a substring that appears
   **character-for-character** in the target hypothesis's `predictions`
   list.

   **Negative example — this is WRONG, it will fail the validator:**
   ```yaml
   # h-001's predictions contain:
   #   - "kube-audit returns an exec action on the container in the ±5s window"
   # A WRONG resolution:
   matched_prediction_text: "kube-audit confirms an exec API call at the alert time"
   # Wrong because it's a paraphrase of what was observed, not a
   # substring of the predictions list.
   ```
   **This is RIGHT:**
   ```yaml
   matched_prediction_text: "kube-audit returns an exec action on the container in the ±5s window"
   # Character-for-character from h-001.predictions. Copy-paste.
   ```
   If you find yourself rewording what the evidence showed, STOP.
   Find the prediction in the list and paste it. If no prediction in
   the list matches what you observed, your hypothesis's predictions
   were incomplete — either amend them (if you haven't written the
   resolution yet) or cap the weight at `+`.

   Every clause of `predictions` must be observationally supported, or
   the weight caps at `+`.

7. **ID references resolve.**
8. **Append-only.** No mutation of existing records.
9. **Self-containment of lead blocks.** Every vertex / edge / hypothesis
   produced by a lead lives inside that lead's `outcome.produced`,
   `new_hypotheses`, or `shelved` — not in any other block.
10. **Scope leads omit `intended_hypothesis_set`.** Materialize and trust
    leads include it.
11. **Mechanical leads within their data source.** A scope lead's
    `outcome.produced.vertices` contains only vertices the data source
    directly observes. Session/user vertices from causal implication
    are validator errors on scope leads — they belong to a subsequent
    trust lead.

---

## 13. Worked example — file write to sensitive path (NOT your case)

Deliberately different scenario. Same shape as v2's example, updated for
v2.1 conventions (no `source_lead`, no `execution`, no `outcome.status`,
`concerns` unified, mechanical-lead discipline applied).

**Scenario:** A SIEM alert fires when a process writes to `/etc/passwd`
on host `prod-db-04`. Alert names the writing process (`tee`, pid=4410)
but no ancestor chain. Parent is opaque.

```yaml
prologue:
  vertices:
    - id: v-001
      abstract_type: process
      classification: unclassified-process
      identifier: "tee (host prod-db-04, pid 4410)"
      attributes: { pid: 4410, cmdline: "tee -a /etc/passwd" }
      concerns:
        - "ancestor chain not populated in the alert; process-lineage scope lead required before hypothesizing"
      citations: ["siem:rule.id=120042:event=xyz"]
    - id: v-002
      abstract_type: file
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
      # NO intended_hypothesis_set — scope mode
      query_details:
        system: host-audit
        template: "leads/process-lineage/templates/auditd.md"
        query: "auditd execve lineage for pid=4410 on host prod-db-04 at t=2026-04-14T08:51:03Z"
        time_window: "±30s"
        substitutions: { pid: 4410, host: prod-db-04, t: "2026-04-14T08:51:03Z" }
      outcome:
        produced:
          vertices:
            # Mechanical lead materializes only what host-audit directly sees:
            # the process ancestor chain and the pts session metadata. It does
            # NOT materialize the user — that's the job of l-002 against PAM.
            - id: v-003
              abstract_type: process
              classification: interactive-shell-in-workload
              identifier: "bash (host prod-db-04, pid 4200)"
              attributes: { pid: 4200, cmdline: "-bash", tty: "pts/1" }
            - id: v-004
              abstract_type: session
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

      new_hypotheses:
        - id: h-001
          name: "?sanctioned-admin-session"
          canonical: true
          attached_to_vertex: v-004
          proposed_edge:
            relation: authenticated_as
            parent_vertex: { abstract_type: user, classification: employee-with-exec-rbac }
          predictions:
            - for: vertex-shape
              expected: "session authenticates to an employee user with PAM-enforced sudo or sensitive-file write permission"
            - for_absence: "no concurrent anomalous network session to v-004's origin"
          refutation_shape:
            - "session authenticates to an automation identity or unknown user"
            - "no PAM authorization record for sensitive-file write in the ±5m window"
          weight: null

        - id: h-002
          name: "?post-exploit-shell"
          canonical: true
          attached_to_vertex: v-004
          proposed_edge:
            relation: authenticated_as
            parent_vertex: { abstract_type: user, classification: unknown-attacker }
          predictions:
            - for_absence: "no PAM authorization record for a legitimate user at session start"
          refutation_shape:
            - "session authenticates to an employee-with-exec-rbac user with matching PAM authorization record"
          concerns:
            - "stolen-credential scenario unfalsifiable without MDM device-posture trust-chain"
          weight: null

  - lead:
      id: l-002
      loop: 2
      name: "anchor-lookup(pam-audit)"
      mode: trust
      target: v-004
      intended_hypothesis_set: [h-001, h-002]
      query_details:
        system: pam-audit
        template: "leads/anchor-lookup/templates/pam.md"
        query: "pam authorization records for session pts/1 on prod-db-04 at ±5m"
        time_window: "±5m"
        substitutions: { session: "pts/1", host: prod-db-04 }
      outcome:
        produced:
          vertices:
            - id: v-005
              abstract_type: user
              classification: employee-with-exec-rbac
              identifier: "carol@company.com"
              attributes: { rbac_sudoers: true, mfa_verified: true }
              trust_root: true
          edges:
            - id: e-004
              relation: authenticated_as
              source_vertex: v-004
              target_vertex: v-005
              authority: { kind: anchor-backed, source: "pam-audit:auth:pts1:carol" }
        trust_root_reached: v-005
      resolutions:
        - hypothesis: h-001
          before: null
          after: "++"
          severity_of_test: severe
          matched_prediction_text: "session authenticates to an employee user with PAM-enforced sudo or sensitive-file write permission"
          reasoning: "pam-audit returned carol@company.com with rbac_sudoers: true and MFA. This literally matches the prediction clause above. Remaining clause (for_absence of anomalous concurrent network session) observationally supported by scope lead output."
          supporting_edges: [e-004]
        - hypothesis: h-002
          before: null
          after: "--"
          severity_of_test: severe
          matched_refutation_text: "session authenticates to an employee-with-exec-rbac user with matching PAM authorization record"
          reasoning: "pam-audit returned carol@company.com, classification employee-with-exec-rbac, with a matching PAM authorization record — literal match to the refutation_shape entry. Anchor-backed supporting edge e-004. Residual stolen-credential concern remains in h-002.concerns; not closed without MDM device-posture evidence."
          supporting_edges: [e-004]

conclude:
  termination:
    category: trust-root
    rationale: "pam-audit anchor set trust_root=true on v-005"
  disposition: benign
  confidence: high
  matched_archetype: sensitive-file-write-by-authorized-admin
  summary: "tee appended to /etc/passwd as carol@company.com in an MFA-verified pts/1 session with PAM sudoers authorization. No adversarial signal; trust-root termination on anchor-backed user classification."
```

**Things to notice in the example:**

1. **No `source_lead` on any record.** Structural position tells you where
   each record was produced.
2. **No `execution` block** on either lead.
3. **No `outcome.status` field** — success is implied by `produced` with
   no `failure_reason`.
4. **`l-001` omits `intended_hypothesis_set`** (it's a scope lead).
5. **`l-001` materializes v-003 (bash) and v-004 (session) from
   host-audit**, but NOT v-005 (user). The user is the job of l-002
   against pam-audit. The host-audit feed can see the session metadata
   (tty, pts) but not the authenticated identity — that's a PAM
   observation. This is the mechanical-lead-stays-in-data-source rule in
   action.
6. **`concerns` on v-001** replaces what v2 called `data_quality_note`.
7. **`concerns` on h-002** captures the unfalsifiable stolen-credential
   residual — what v2 called `pitfalls`.
8. **Literal prediction text** on h-001's resolution is the exact string
   from the predictions list. Not paraphrased.

---

## 14. What you write

1. **Read** the alert record and the retrieval-sim.
2. **Fill `prologue`** with vertices and edges derived from the alert.
   Host context lives in container attributes, not as a separate vertex.
   Emit `concerns` on any record where a telemetry limitation is worth
   flagging.
3. **Decide** whether to hypothesize now or run a mechanical scope lead
   first. If the alert's immediate parent is opaque, leave
   `hypothesize.hypotheses: []` and write the mechanical lead as the
   first GATHER block.
4. **Write each GATHER lead as a self-contained block.** Inline vertices
   and edges the lead materializes under `outcome.produced` — but only
   what the lead's data source directly observes. Causally-implied
   vertices (sessions, users from execve-feed context, etc.) wait for a
   trust lead. If the lead advances the discrimination level, put the
   first hypothesis set in `new_hypotheses`. If the lead discriminates,
   put weight transitions in `resolutions` with literal text matches.
5. **Omit `intended_hypothesis_set` on scope leads.** Include it on
   materialize and trust leads.
6. **Write `conclude`** with termination, disposition, and a 2–3 sentence
   summary.

Every validator rule in §12 must pass. Rules 5 and 6 (literal
copy-paste text match) are the single most likely failure points —
watch them carefully. Read the negative example in §12 before writing
resolutions.

**Output path** is specified in your task prompt.
