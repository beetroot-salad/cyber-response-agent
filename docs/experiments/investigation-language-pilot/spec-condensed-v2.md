# Investigation Language — Condensed Spec v2 (pilot rerun)

Revised from v1 after pilot findings. **Five material changes**, each numbered
so you can see where they land in the schema.

1. **Journal form.** The companion is a time-ordered log of the walk (prologue
   → hypotheses → per-lead blocks → conclude), not flat collections. Records
   live inside the block that produced them. The distiller flattens to
   collections at ingest; you write in time order.
2. **Implicit defaults.** Fields with a near-constant default are OMITTED
   when at default. Explicit list in §2. You write only what differs from
   the default.
3. **Hypotheses live at the discrimination level.** Run mechanical scope
   leads first to paint the immediate parent chain; only then hypothesize
   at the deepest materialized vertex where explanations genuinely fork.
   No relocation machinery.
4. **Host context is attributes on the container, not a separate vertex.**
   Unless the investigation actually queries host-level evidence, the host is
   a field, not a node.
5. **Rule 6 is explicit: literal copy-paste, not paraphrase.** Prediction
   text in a `++` resolution must be a substring from the hypothesis's
   `predictions` list, character-for-character. Same for rule 5 and
   refutation text. This is emphasized because v1 pilot runs all failed it.

---

## 1. Top-level structure

The companion is a single YAML file with four top-level keys in time order:

```yaml
prologue:                 # CONTEXTUALIZE, loop 0 — records derived inline from the alert
  vertices: [...]
  edges: [...]

hypothesize:              # HYPOTHESIZE — may be empty at first if mechanical leads run first
  hypotheses: [...]

gather:                   # GATHER — ordered list of leads, each a self-contained block
  - lead: {...}
  - lead: {...}
  ...

conclude:                 # ANALYZE + CONCLUDE — termination, disposition, summary
  termination: ...
  disposition: ...
  matched_archetype: ...
  summary: ...
```

**Writing order matches the investigation:** you fill `prologue` from the
alert, then decide whether to hypothesize immediately or run a mechanical
scope lead first (see §6). Each GATHER block is written as it executes.
`conclude` is written last.

Everything is append-only. You never mutate an earlier record; to correct
something, write a later record that references it (see §8 on revisions —
short section, rarely needed).

---

## 2. Common record conventions

**IDs.** Stable and local to this run: `v-{nonce}`, `e-{nonce}`, `h-{nonce}`,
`l-{nonce}`. Use short numeric nonces (`v-001`, `v-002`, ...).

**Implicit defaults — omit when at default.** The following fields are
omitted unless they differ from their default:

| Field                                | Default          | Emit when                                       |
|--------------------------------------|------------------|--------------------------------------------------|
| `vertex.trust_root`                  | `false`          | a successful trust lead sets it `true`          |
| `vertex.attributes`                  | `{}`             | there are type-specific attributes to record     |
| `vertex.data_quality_note`           | omitted          | telemetry has a specific limitation worth flagging (free text) |
| `edge.attributes`                    | `{}`             | there are relation-specific attributes           |
| `edge.when`                          | omitted          | the relation is instantaneous or extended        |
| `edge.authority.trust_chain`         | `[]`             | a client-asserted edge sits on a promotion chain |
| `hypothesis.pitfalls`                | `[]`             | an alert-specific trap needs to be flagged       |
| `hypothesis.weight_history`          | `[]`             | there are recorded transitions (kept minimal)    |
| `hypothesis.status`                  | `active`         | `confirmed`, `refuted`, or `shelved`             |
| `lead.execution.dispatched_via`      | `inline`         | the lead was dispatched to a subagent            |
| `lead.outcome.failure_reason`        | omitted          | outcome status is `empty`, `degraded`, or `error` |
| `lead.outcome.trust_root_reached`    | omitted          | a trust lead succeeded                           |

**Rule of thumb:** if the field is constant for this record, omit it. The
distiller fills defaults at ingest.

**Source traceability.** Every vertex, edge, and hypothesis carries
`source_lead: l-{id} | inline`. `inline` means "derived from the alert at
CONTEXTUALIZE" and applies to records in the `prologue` block. Otherwise
`source_lead` names the lead whose block produced the record. There is no
separate `first_observed` metadata — phase and loop are recoverable from
the lead record.

---

## 3. Prologue block

Records from the alert itself, before any lead runs. Usually 2–4 vertices
and 1–2 edges.

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
      source_lead: inline
      citations: ["siem:event=<event-id>"]

    - id: v-002
      abstract_type: container
      classification: runtime-workload
      identifier: "<pod-name>"
      attributes:
        container_id: "<short-id>"
        image: "<image>"
        namespace: "<ns>"
        host_name: "<host>"        # host context lives here, per change 4
        host_role: "kubernetes-worker-node"
      source_lead: inline
      citations: ["siem:event=<event-id>"]

  edges:
    - id: e-001
      relation: runs_in
      source_vertex: v-001
      target_vertex: v-002
      when: { timestamp: "<iso>" }
      authority:
        kind: siem-event
        source: "siem:event=<event-id>"
      source_lead: inline
```

Note: `trust_root`, `data_quality_note`, and empty `attributes` are omitted
per §2.

---

## 4. Vertex schema

```yaml
vertex:
  id: v-{nonce}
  abstract_type: process | socket | file | ip | user | host | container
               | session | remote-endpoint | device | command | anchor-source
  classification: <string>       # from §9 — the retrieval key
  identifier: <string>           # human-readable handle; semantic name preferred
  attributes: <object>           # type-specific; omit if empty
  trust_root: true               # omit when false
  data_quality_note: <string>    # optional; emit ONLY when flagging a telemetry limitation
  source_lead: l-{id} | inline
  citations: [<string>]
```

**Classifications are retrieval keys.** Use `unclassified-{type}` if you
cannot classify yet; use `ambiguous-{a}-or-{b}` for two candidates and no
basis to narrow.

**`trust_root: true`** is set only by a successful trust lead. It signals
"backward traversal from this vertex is terminated by authority." Emit the
field only when setting true.

**`data_quality_note`** replaces the v1 `data_quality` enum. Emit it when
there's a *specific* limitation worth recording — missing fields, truncated
evidence, a known telemetry blind spot. Example:
`data_quality_note: "Falco reports parent=null because the host-side parent is outside the container pid namespace"`.
If there's nothing specific to say, omit the field.

---

## 5. Edge schema

```yaml
edge:
  id: e-{nonce}
  relation: <string>             # from §10
  source_vertex: v-{id}
  target_vertex: v-{id}
  when:                          # optional — omit for purely structural relations
    timestamp: <ISO8601>         # instantaneous edges
    # OR
    duration_sec: <float>        # extended edges
    # OR
    distribution:                # repeated edges
      pattern: single | periodic | burst | sporadic | continuous
      count: <int>
      span_sec: <int>
  attributes: <object>           # optional; omit if empty
  status: observed | hypothesized | refuted   # omit when observed (the default)
  authority:
    kind: siem-event | runtime-audit | anchor-backed | client-asserted | inferred-structural
    source: <string>
    trust_chain: [<anchor-id>, ...]   # optional
  source_lead: l-{id} | inline
```

---

## 6. Hypothesis schema + the discrimination-level rule

**The rule — new in v2, read carefully.**

A hypothesis describes a **discriminating** backward explanation: an edge
the walk could observe that would materially distinguish one explanatory
story from another. Hypotheses live at the **deepest materialized vertex
where the chain of explanations genuinely forks** — call this the
*discrimination level*.

In practice:

- At CONTEXTUALIZE, the deepest materialized vertex is the alert vertex
  itself. If the **immediate parent** of that vertex is already mechanically
  knowable (e.g., you have a pid tree from the SIEM), form hypotheses now.
- If the **immediate parent is unknown** (e.g., `parent=null` on a Falco
  in-container process because the host-side parent is out of namespace),
  the discrimination level is not yet visible. **Run the mechanical scope
  lead first.** Hypothesize after it materializes the deeper vertex.
- If mid-walk you discover the discrimination has actually shifted further
  down (a scope lead reveals an unexpected intermediate), shelve existing
  hypotheses (`status: shelved`) and form a new set at the new level. No
  relocation machinery — just a fresh set of records.

**Why this rule.** The v1 pilot showed that three of three Haiku runs
formed four hypotheses at the shallowest alert vertex and never moved
them. The resulting companions were internally inconsistent (hypotheses
about "who triggered the kubectl exec" attached to a process vertex whose
immediate parent is actually runc). Under the discrimination-level rule,
that failure mode is structural — you form hypotheses once, at the right
level, and you don't need to track relocation.

**When in doubt, run a mechanical scope lead first.** It's cheaper than
forming speculative hypotheses that will need to be shelved.

### Schema

```yaml
hypothesis:
  id: h-{nonce}
  name: "?descriptive-mechanism-name"
  canonical: true | false         # true iff drawn from the signature's playbook / retrieval seeds
  attached_to_vertex: v-{id}      # the vertex whose backward explanation is being proposed

  proposed_edge:
    relation: <string>            # from §10
    parent_vertex:
      abstract_type: <string>
      classification: <string>    # the discriminating field
      attributes: <object>        # optional expected attributes

  predictions:                    # typed expectations for adjacent evidence
    - for: v-{id} | e-{id} | vertex-shape | edge-shape
      expected: <object>
    - for_absence: "<what should NOT be observed if true>"

  refutation_shape:               # concrete observations that would directly contradict
    - "<observation contradicting a core prediction>"

  pitfalls: []                    # omit if empty
  weight: "++" | "+" | "-" | "--" | null
  weight_history: []              # omit until there are transitions
  status: active                  # omit (default); emit when confirmed/refuted/shelved
```

**Refutation shape is strict.** For a weight to transition to `--` with
`severity: severe`, at least one entry in `refutation_shape` must match
a concrete observation from a lead resolution. The resolution must
populate `matched_refutation_text` with **the exact substring** from the
`refutation_shape` list. No paraphrase.

**Prediction completeness for `++`.** Every clause of `predictions` must be
observationally supported. The lead resolution must populate
`matched_prediction_text` with **the exact substring** from the
`predictions` list. No paraphrase. See §12 rule 6 — **COPY-PASTE, not
restate**. This rule is the single largest source of v1 validator
failures.

---

## 7. Lead block — the central unit of the journal

This is the biggest structural change. Each entry in `gather:` is a lead
block containing everything the lead did: what it queried, what it
materialized, which hypotheses it resolved, and (rarely) what it shelved.

```yaml
gather:
  - lead:
      id: l-{nonce}
      loop: <int>
      name: <string>              # from the lead catalog
      mode: materialize | scope | trust
      target: v-{id}
      intended_hypothesis_set: [h-{id}, ...]   # required for materialize and discrimination-level trust leads

      query_details:
        system: <string>          # wazuh, kube-audit, falco, ...
        template: <string>
        query: <string>
        time_window: <string>
        substitutions: <object>

      execution:
        dispatched_via: inline | subagent       # omit if inline
        duration_ms: <int>

      outcome:
        status: complete | empty | degraded | error
        produced:
          vertices: [<full vertex records>]    # vertices materialized by THIS lead live inline here
          edges: [<full edge records>]         # same for edges
        trust_root_reached: v-{id}             # omit when null
        failure_reason: <string>               # omit unless status is not complete

      # Newly-formed hypotheses — usually populated after a mechanical scope
      # lead advances the discrimination level, or when shelving happens.
      new_hypotheses: [<full hypothesis records>]   # omit if empty

      # Hypothesis shelving — when the discrimination level has moved past
      # existing hypotheses (rare; see §6).
      shelved: [h-{id}, ...]       # omit if empty

      resolutions:                 # weight transitions on hypotheses in intended_hypothesis_set
        - hypothesis: h-{id}
          before: "+" | "-" | "++" | "--" | null
          after: "+" | "-" | "++" | "--"
          severity_of_test: severe | moderate | weak
          matched_refutation_text: "<literal substring from target hypothesis's refutation_shape>"
          matched_prediction_text: "<literal substring from target hypothesis's predictions>"
          reasoning: "<prediction, observation, what contradicted or confirmed>"
          supporting_edges: [e-{id}, ...]
```

**Severity of test** — required on every resolution:

| Severity   | Meaning                                                                       | Max weight effect                    |
|------------|-------------------------------------------------------------------------------|--------------------------------------|
| `severe`   | Outcome could directly contradict (or directly confirm) a core prediction    | up to `++` / `--`                    |
| `moderate` | Outcome constrains plausibility without directly contradicting any prediction | at most one step (e.g. `+` → `-`)    |
| `weak`     | Circumstantial consistency — evidence leans but does not constrain            | caps at `+` or `-`; never `++` / `--`|

**Self-contained blocks.** Every vertex and edge the lead materialized is
written inside `outcome.produced`, not in a separate top-level section. A
reader of the file walks lead blocks in order and reconstructs the full
graph. The distiller does the same at ingest.

**Inline hypothesis creation for post-mechanical-lead hypothesize.** If a
lead is a mechanical scope lead that advances the discrimination level,
its `new_hypotheses` contains the first real hypothesis set for the walk.
The `hypothesize:` top-level block is empty in that case; the block exists
primarily for walks where hypotheses are formed at CONTEXTUALIZE.

---

## 8. Conclude block

Written last. Short, structured.

```yaml
conclude:
  termination:
    category: trust-root | adversarial-refuted | severity-ceiling | exhaustion-escalation
    rationale: <string>             # one sentence
  disposition: benign | true_positive | unclear
  confidence: high | medium | low
  matched_archetype: <name> | null  # null with a reason if no archetype fits
  ceiling_rationale: <string>        # required if termination.category == severity-ceiling
  summary: <string>                  # 2-3 sentences on the whole walk
```

**Four termination categories, same as v1:**

1. **trust-root** — a trust lead set `trust_root: true` on a branch; that
   branch is authoritatively terminated.
2. **adversarial-refuted** — all adversarial hypotheses at `--` via severe
   resolutions with matched refutations; a non-adversarial hypothesis at `++`.
3. **severity-ceiling** — every in-scope severe lead ran; adversarial
   hypotheses remain at `-`. Must include `ceiling_rationale`.
4. **exhaustion-escalation** — loop budget consumed or hypothesis space
   incomplete. Legitimate termination, handoff to analyst.

When multiple termination conditions fire in the same loop, pick the one
that explains **why backward walk halted** — usually trust-root dominates
adversarial-refuted on a clean benign case.

---

## 9. Classifications (seed vocabulary for this case)

Unchanged from v1. Use `unclassified-{type}` or `ambiguous-{a}-or-{b}` when
applicable. Every `classification` value must appear in one of the catalogs
below, or be a provisional `{type}:{slug}` with a classification_rationale
in `attributes`.

**Process classifications:**
- `service-entrypoint-process` — the primary command the container image declares
- `service-child-process` — a child of the entrypoint
- `interactive-shell-in-workload` — a shell spawned inside a runtime workload container
- `host-runtime-shim` — runc, containerd-shim, kubelet child (lives on host)
- `operator-tool-invocation` — kubectl, docker, crictl
- `automation-pipeline-process` — CI, scheduled job, configuration-management agent
- `unclassified-process`

**Container classifications:**
- `runtime-workload` | `sidecar-workload` | `build-container` | `debug-container` | `unclassified-container`

**User classifications:**
- `employee-with-exec-rbac` | `employee-without-exec-rbac` | `automation-identity` | `unknown-attacker` | `unclassified-user`

**Session classifications:**
- `kubectl-exec-session` | `ssh-session` | `service-session` | `unclassified-session`

**IP classifications:**
- `corp-vpn-egress` | `internal-cluster-node` | `internal-corp-network` | `external-sanctioned-automation` | `unclassified-ip`

(Host vertices are generally NOT created — see change 4. If needed, host
classifications: `kubernetes-worker-node`, `kubernetes-control-plane-node`,
`build-infrastructure-host`, `developer-workstation`, `unclassified-host`.)

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

**Note on `triggered_by`:** v2 explicitly allows `process → session` as a
valid shape. The v1 catalog row was restrictive and caused stretching.

**Note on the absence of `hosted_on` or `runs_in container→host`:** there
is no such relation. Host context is carried as attributes on the container
vertex (`host_name`, `host_role`). Only create a `host` vertex if the
investigation actually materializes host-level evidence (a host-side
process, a host-side file, etc.).

---

## 11. Authority table

Unchanged from v1.

| Authority kind        | Meaning                                                                    | Max weight supportable |
|-----------------------|----------------------------------------------------------------------------|------------------------|
| `siem-event`          | Backed by a SIEM / audit log event                                         | `++` / `--`            |
| `runtime-audit`       | Backed by a runtime or OS audit stream                                     | `++` / `--`            |
| `anchor-backed`       | Materialized via a trust anchor lookup                                     | `++` / `--`            |
| `client-asserted`     | From a self-reported field                                                  | `+` / `-`              |
| `inferred-structural` | Inferred from co-occurrence                                                | `+` / `-`              |

Strong-weight transitions (`++` or `--` with `severity: severe`) must cite
at least one supporting edge with `siem-event`, `runtime-audit`, or
`anchor-backed` authority.

---

## 12. Write-time validator rules

A PostToolUse hook validates every write. Violations block and return an
error; fix and retry.

1. **Schema validity.** Required fields present; enum values valid; IDs
   well-formed.
2. **Classification vocabulary.** Every `classification` value is in §9 or
   is a `{type}:{slug}` provisional.
3. **Relation catalog.** Every `edge.relation` is in §10.
4. **Authority rule.** Every resolution with `after ∈ {++, --}` and
   `severity_of_test: severe` cites at least one strong-authority
   supporting edge.
5. **Refutation text match — LITERAL COPY-PASTE.** Every `--` resolution
   sets `matched_refutation_text` to a substring that appears
   **character-for-character** in the target hypothesis's `refutation_shape`
   list. Do not paraphrase. Do not summarize. Do not restate in your own
   words. Copy the exact entry. If no entry fits, the weight caps at `-`.
6. **Prediction text match — LITERAL COPY-PASTE.** Every `++` resolution
   sets `matched_prediction_text` to a substring that appears
   **character-for-character** in the target hypothesis's `predictions`
   list. Copy-paste. If you find yourself rewording what you observed,
   stop and copy the exact prediction text instead. Every clause of
   `predictions` must also be observationally supported, or the weight
   caps at `+`.
7. **ID references.** Every `v-*`, `e-*`, `h-*`, `l-*` reference resolves.
8. **Append-only.** No record is edited after it's written. Shelving a
   hypothesis is expressed by emitting a new lead block with that hypothesis
   in `shelved`, not by rewriting the hypothesis.
9. **Self-containment of lead blocks.** Every vertex / edge / hypothesis
   produced by a lead lives inside that lead's `outcome.produced`,
   `new_hypotheses`, or `shelved` — not in any other block.

**On rules 5 and 6 specifically:** the v1 pilot showed that all three Haiku
runs wrote paraphrased prediction text instead of literal substrings. The
rule is mechanical: **find the exact text in the hypothesis's predictions
list, and paste it.** This is deliberately strict — it forces you to link
your observation back to a pre-declared prediction rather than to restate
the observation itself.

---

## 13. Worked example — file write to sensitive path (NOT your case)

A deliberately different scenario, so you see how the discrimination-level
rule plays out. **Do not copy this structure verbatim — the scenario is
different from yours.**

**Scenario:** A SIEM alert fires when a process writes to `/etc/passwd` on
host `prod-db-04`. Alert record names the writing process (`tee`, pid=4410)
but no ancestor chain. Parent is opaque.

```yaml
prologue:
  vertices:
    - id: v-001
      abstract_type: process
      classification: unclassified-process
      identifier: "tee (host prod-db-04, pid 4410)"
      attributes: { pid: 4410, cmdline: "tee -a /etc/passwd" }
      source_lead: inline
      citations: ["siem:rule.id=120042:event=xyz"]
    - id: v-002
      abstract_type: file
      classification: sensitive-credential-file
      identifier: "/etc/passwd"
      source_lead: inline
      citations: ["siem:rule.id=120042:event=xyz"]
  edges:
    - id: e-001
      relation: wrote
      source_vertex: v-001
      target_vertex: v-002
      when: { timestamp: "2026-04-14T08:51:03Z" }
      authority: { kind: siem-event, source: "siem:rule.id=120042:event=xyz" }
      source_lead: inline

# No hypotheses at CONTEXTUALIZE — the immediate parent of v-001 is unknown
# (the alert has no ancestor chain). Run the mechanical scope lead first.
hypothesize:
  hypotheses: []

gather:
  - lead:
      id: l-001
      loop: 1
      name: process-lineage
      mode: scope
      target: v-001
      intended_hypothesis_set: []
      query_details:
        system: host-audit
        template: "leads/process-lineage/templates/auditd.md"
        query: "auditd execve lineage for pid=4410 on host prod-db-04 at t=2026-04-14T08:51:03Z"
        time_window: "±30s"
        substitutions: { pid: 4410, host: prod-db-04, t: "2026-04-14T08:51:03Z" }
      execution: { duration_ms: 340 }
      outcome:
        status: complete
        produced:
          vertices:
            - id: v-003
              abstract_type: process
              classification: interactive-shell-in-workload
              identifier: "bash (host prod-db-04, pid 4200)"
              attributes: { pid: 4200, cmdline: "-bash", tty: "pts/1" }
              source_lead: l-001
              citations: ["host-audit:execve:4200"]
            - id: v-004
              abstract_type: session
              classification: ssh-session
              identifier: "ssh session (pts/1, host prod-db-04)"
              attributes: { tty: "pts/1" }
              source_lead: l-001
              citations: ["host-audit:session:pts1"]
          edges:
            - id: e-002
              relation: spawned
              source_vertex: v-003
              target_vertex: v-001
              when: { timestamp: "2026-04-14T08:51:03Z" }
              authority: { kind: runtime-audit, source: "host-audit:execve:4410" }
              source_lead: l-001
            - id: e-003
              relation: executed_in
              source_vertex: v-003
              target_vertex: v-004
              authority: { kind: runtime-audit, source: "host-audit:session:pts1" }
              source_lead: l-001

      # Discrimination level is now at v-003 / v-004 (the interactive shell
      # session). Form hypotheses here, not at v-001.
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
          weight: null

      # No resolutions on this lead — it was mechanical, not discriminating.

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
      execution: { duration_ms: 180 }
      outcome:
        status: complete
        produced:
          vertices:
            - id: v-005
              abstract_type: user
              classification: employee-with-exec-rbac
              identifier: "carol@company.com"
              attributes: { rbac_sudoers: true, mfa_verified: true }
              trust_root: true
              source_lead: l-002
              citations: ["pam-audit:auth:pts1:carol"]
          edges:
            - id: e-004
              relation: authenticated_as
              source_vertex: v-004
              target_vertex: v-005
              authority: { kind: anchor-backed, source: "pam-audit:auth:pts1:carol" }
              source_lead: l-002
        trust_root_reached: v-005
      resolutions:
        - hypothesis: h-001
          before: null
          after: "++"
          severity_of_test: severe
          matched_prediction_text: "session authenticates to an employee user with PAM-enforced sudo or sensitive-file write permission"
          reasoning: "pam-audit returned carol@company.com as the session initiator with rbac_sudoers: true and MFA verified. This observation is an anchor-backed match for h-001's prediction clause (verbatim above). All remaining prediction clauses observationally supported."
          supporting_edges: [e-004]
        - hypothesis: h-002
          before: null
          after: "--"
          severity_of_test: severe
          matched_refutation_text: "session authenticates to an employee-with-exec-rbac user with matching PAM authorization record"
          reasoning: "pam-audit returned carol@company.com, classification employee-with-exec-rbac, with a matching PAM authorization record — literal match to the refutation_shape entry. Anchor-backed supporting edge e-004."
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

1. **Prologue has no hypotheses.** The immediate parent of v-001 was
   unknown, so the walk ran a mechanical scope lead before forming
   hypotheses.
2. **`new_hypotheses` on l-001** is where the first hypothesis set appears.
   The lead advanced the discrimination level; hypotheses attach to the
   newly-materialized session vertex, not to v-001.
3. **No relocation anywhere.** Hypotheses are formed once, at the right
   level, and resolved there.
4. **Refutation text on h-002 is a literal substring** of the
   `refutation_shape` list — the rule 6 discipline. Every character
   matches.
5. **Prediction text on h-001 is literal.** The `matched_prediction_text`
   is the exact string from h-001's predictions list, not a paraphrase.
6. **Implicit defaults omitted.** `trust_root`, empty `attributes`,
   `status`, and `pitfalls` are not written unless they differ from
   default.
7. **No host vertex** for prod-db-04 — the host is identified in
   identifiers and citations but isn't a graph node.

---

## 14. What you write

For the pilot case:

1. **Read** the alert record and the retrieval-sim.
2. **Fill `prologue`** with vertices and edges you can derive directly
   from the alert — usually 2-4 records. Do NOT create a separate host
   vertex.
3. **Decide** whether to hypothesize now or run a mechanical scope lead
   first. If the alert's immediate parent is opaque (e.g., `parent=null`
   in a Falco in-container alert), the discrimination level is not yet
   visible — leave `hypothesize.hypotheses: []` and write the mechanical
   lead as the first GATHER block.
4. **Write each GATHER lead as a self-contained block.** Inline the
   vertices/edges it materializes under `outcome.produced`. If the lead
   is mechanical and advances the discrimination level, put the first
   hypothesis set in `new_hypotheses`. If the lead is discriminating,
   put the resolutions in `resolutions`.
5. **Write `conclude`** with termination category, disposition, and a
   2-3 sentence summary.

Every validator rule in §12 must pass. Rule 6 (literal prediction text
match) is the single most likely place to fail — watch it carefully.

**Output path** is specified in your task prompt.