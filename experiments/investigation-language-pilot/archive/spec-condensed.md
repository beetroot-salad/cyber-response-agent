# Investigation Language — Condensed Spec (for pilot experiment)

You are investigating a security alert and writing a **structured companion file**
alongside the narrative. The companion carries the typed, machine-readable record
of what you observed, what you proposed, and how you resolved it. A PostToolUse
hook validates every write.

This spec covers: the five collections, the field schemas, the classification and
relation catalogs you'll need for this case, the authority and severity tables,
the write-time validator rules, and hypothesis relocation rules. Nothing else.

---

## 1. Top-level collections

The companion is a single YAML file with five top-level keys:

```yaml
vertices: [...]         # entities (nouns) — processes, containers, users, sessions, IPs, hosts, files, ...
edges: [...]            # typed relations (verbs) — spawned, opened, authenticated_as, runs_in, ...
hypotheses: [...]       # candidate backward-edge attachments to a vertex
leads: [...]            # operations you performed to paint more of the graph
revisions: [...]        # append-only corrections to earlier records (usually empty)
```

Everything is append-only. You never mutate a record; to change something, you
append a revision. IDs are stable: `v-{nonce}`, `e-{nonce}`, `h-{nonce}`,
`l-{nonce}`, `r-{nonce}`. Use short numeric nonces (`v-001`, `v-002`, …).

---

## 2. Vertex schema

A vertex is an **entity** you touch. Processes, containers, users, sessions,
sockets, files, IPs, hosts, commands — all vertices.

```yaml
vertex:
  id: v-{nonce}
  abstract_type: process | socket | file | ip | user | host | container
               | session | remote-endpoint | device | command | anchor-source
  classification: <string>       # from §6 — the retrieval key
  identifier: <string>           # human-readable handle; semantic name preferred over raw value
  attributes: <object>           # type-specific: pid, cmdline, image, port, etc.
  trust_root: false | true       # set true when a successful trust lead terminates backward walk here
  data_quality: complete | partial | degraded
  first_observed:
    phase: CONTEXTUALIZE | SCREEN | HYPOTHESIZE | GATHER | ANALYZE
    loop: <int>                  # 0 at CONTEXTUALIZE; 1, 2, … during GATHER
    lead: l-{id} | "inline"      # which lead produced this vertex; "inline" if derived from the alert record
  citations: [<string>]          # e.g., "falco:event=b8e2c4d9", "kube-audit:request-id=abc"
```

**A vertex is *observed* when a lead materializes it into the graph.** Before
that, a hypothesis may reference a future parent vertex shape (see §4) without
the vertex existing yet. When the parent is eventually materialized, you create
a new vertex record — you do not retroactively edit the hypothesis.

**`trust_root: true`** is set only by a successful trust lead (§5). It signals
"backward traversal from this vertex is terminated by authority."

---

## 3. Edge schema

An edge is a typed, attributed **relation** between two vertices. An event is an
edge with a timestamp. Static structural relations (process runs in container)
use the same shape without a timestamp.

```yaml
edge:
  id: e-{nonce}
  relation: <string>             # from §7 — see relation catalog
  source_vertex: v-{id}
  target_vertex: v-{id}
  when:
    timestamp: <ISO8601>         # instantaneous edges
    # OR
    duration_sec: <float>        # extended edges
    # OR
    distribution:                # repeated edges
      pattern: single | periodic | burst | sporadic | continuous
      count: <int>
      span_sec: <int>
    context: <string>            # optional, loose narrative
  attributes: <object>           # relation-specific: cmdline, outcome, bytes_out, uid, ...
  status: observed | hypothesized | refuted
  authority:
    kind: siem-event | runtime-audit | anchor-backed | client-asserted | inferred-structural
    source: <string>             # e.g., "falco:event=abc", "kube-audit:request-id=xyz"
    trust_chain: [<anchor-id>, ...]   # optional; promotes client-asserted to anchor-backed
  first_observed:
    phase: ...
    loop: <int>
    lead: l-{id}
```

`status`:
- `observed` — materialized by a lead, directly confirmed.
- `hypothesized` — proposed by a hypothesis but not yet confirmed.
- `refuted` — contradicted by a later lead.

---

## 4. Hypothesis schema

A hypothesis proposes that a specific vertex has a specific **backward edge** to
a parent vertex with a specific classification. Hypotheses are attached to a
vertex. Multiple hypotheses on the same vertex form a **discrimination set**.

```yaml
hypothesis:
  id: h-{nonce}
  name: "?descriptive-mechanism-name"
  canonical: true | false                 # true iff declared in the signature's playbook
  attached_to_vertex: v-{id}

  proposed_edge:
    relation: <string>                    # spawned, authenticated_as, triggered_by, ...
    parent_vertex:
      abstract_type: <string>
      classification: <string>            # the discriminating field
      attributes: <object>                # optional expected attributes

  predictions:                            # typed expectations for adjacent evidence
    - for: v-{id} | e-{id} | vertex-shape | edge-shape
      expected: <object>
    - for_absence: "<what should NOT be observed if true>"

  refutation_shape:                       # concrete observations that would directly contradict
    - "<observation contradicting a core prediction>"

  pitfalls:                               # alert-specific traps, not static lead-level pitfalls
    - "<trap that could falsely confirm or refute>"

  refutation_pivots_to: [h-{id}, ...]     # optional — hypotheses to activate if this one refutes

  weight: "++" | "+" | "-" | "--" | null
  weight_history:
    - before: <weight>
      after: <weight>
      by_lead: l-{id}
      severity: severe | moderate | weak
      at_phase: <phase>
      loop: <int>
  status: active | confirmed | refuted | shelved
```

**Hypotheses relocate as the walk advances.** When a lead materializes a parent
vertex and the discrimination question shifts one step deeper (from "what spawned
this process" to "what triggered the host-side parent"), **new hypotheses attach
to the newly materialized parent**. Old hypotheses transition to `confirmed`,
`refuted`, or `shelved` — they do not follow the walk. This expresses the
backward walk as a sequence of discrimination sets, each attached to a
progressively deeper vertex.

**Refutation shape is strict.** For a weight to transition to `--` with
`severity: severe`, at least one entry in `refutation_shape` must match a
concrete observation. The resolution on the lead that drove the transition must
name the matched refutation entry by text in `matched_refutation_text`. Soft
reasoning ("the evidence leans against this") without a matched refutation caps
at `-`.

**Prediction completeness for `++`.** Every clause of the hypothesis's
`predictions` block must be observable and supported before a transition to
`++` is allowed. Partial confirmation caps at `+`.

---

## 5. Lead schema

A lead is an operation you performed to paint more of the graph. Three modes:

- **`materialize`** — paint a hypothesized vertex or edge into observed status,
  or refute it. Operates against a hypothesis set.
- **`scope`** — paint adjacent attributes, edges, or sibling vertices around a
  known vertex. Does not directly resolve hypotheses but may reveal edges that
  become materialization targets for subsequent leads.
- **`trust`** — query a trust anchor to classify a vertex. On success, sets
  `trust_root: true` on the target vertex.

```yaml
lead:
  id: l-{nonce}
  name: <string>                          # from the lead catalog; e.g., container-exec-history
  mode: materialize | scope | trust
  target_vertex: v-{id}
  intended_hypothesis_set: [h-{id}, ...]  # required for materialize mode

  query_details:
    system: <string>                      # wazuh, kube-audit, falco, etc.
    template: <string>                    # e.g., leads/container-exec-history/templates/kube-audit.md
    query: <string>                       # the actual query as issued
    time_window: <string>
    substitutions: <object>

  execution:
    phase: SCREEN | GATHER
    loop: <int>
    dispatched_via: inline | subagent
    duration_ms: <int>

  outcome:
    status: complete | empty | degraded | error
    vertices_materialized: [v-{id}, ...]
    edges_materialized: [e-{id}, ...]
    attributes_updated:
      - target: v-{id} | e-{id}
        field: <dotted-path>
        from: <old>
        to: <new>
    trust_root_reached: v-{id} | null
    failure_reason: <string | null>

  resolution:
    - hypothesis: h-{id}
      before: "+" | "-" | "++" | "--" | null
      after: "+" | "-" | "++" | "--"
      severity_of_test: severe | moderate | weak
      matched_refutation_text: "<text>"    # REQUIRED when after == "--"
      matched_prediction_text: "<text>"    # REQUIRED when after == "++"
      reasoning: "<prediction, observation, contradiction or confirmation>"
      supporting_edges: [e-{id}, ...]
```

**Severity of test** is required on every resolution:

| Severity   | Meaning                                                                       | Max weight effect                    |
|------------|-------------------------------------------------------------------------------|--------------------------------------|
| `severe`   | Outcome could directly contradict (or directly confirm) a core prediction    | up to `++` / `--`                    |
| `moderate` | Outcome constrains plausibility without directly contradicting any prediction | at most one step (e.g. `+` → `-`)    |
| `weak`     | Circumstantial consistency — evidence leans but does not constrain            | caps at `+` or `-`; never `++` / `--`|

---

## 6. Classifications (seed vocabulary for this case)

Every vertex has a `classification` from a vocabulary for its abstract type.
Classifications are the retrieval key — they must be stable and mechanism-
discriminating. Use `unclassified-{type}` if you cannot classify yet; use
`ambiguous-{a}-or-{b}` if you have two candidates and cannot narrow.

**Process classifications:**
- `service-entrypoint-process` — the primary command the container image declares (e.g., gunicorn, java -jar, node index.js)
- `service-child-process` — a child of the entrypoint, part of normal service operation
- `interactive-shell-in-workload` — a shell process spawned inside a runtime workload container
- `host-runtime-shim` — runc, containerd-shim, kubelet child, etc. (lives on host, manages containers)
- `operator-tool-invocation` — kubectl, docker, crictl, … invoked by an operator
- `automation-pipeline-process` — CI, scheduled job, configuration-management agent
- `unclassified-process`

**Container classifications:**
- `runtime-workload` — a production application container
- `sidecar-workload` — observability, proxy, or adjacent helper in the same pod
- `build-container` — used for image construction, not runtime
- `debug-container` — ephemeral debug target
- `unclassified-container`

**User classifications:**
- `employee-with-exec-rbac` — an employee whose RBAC permits kubectl exec on this workload
- `employee-without-exec-rbac` — employee, but lacks exec permission on this workload
- `automation-identity` — a non-human identity for CI/CD, configuration management, etc.
- `unknown-attacker` — no classification basis; default adversarial
- `unclassified-user`

**Session classifications:**
- `kubectl-exec-session` — session initiated via kube-apiserver exec subresource
- `ssh-session` — interactive SSH
- `service-session` — session originated by the service itself (e.g., application spawning a subprocess)
- `unclassified-session`

**IP classifications:**
- `corp-vpn-egress` — known corporate VPN egress range
- `internal-cluster-node` — a node inside the same Kubernetes cluster
- `internal-corp-network` — the broader corporate network
- `external-sanctioned-automation` — third-party services on a sanctioned allowlist
- `unclassified-ip`

**Host classifications:**
- `kubernetes-worker-node` — a worker node in a production cluster
- `kubernetes-control-plane-node`
- `build-infrastructure-host`
- `developer-workstation`
- `unclassified-host`

Classifications you can invent if the seed vocabulary doesn't cover: use
`unclassified-{type}` or compose `{type}:{descriptive-slug}` as a provisional
value and note it in `attributes.classification_rationale`. The validator will
accept provisional values but they get flagged for post-run curation.

---

## 7. Relation catalog

Edges draw their `relation` field from this list:

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
| `triggered_by`         | process → process                | runtime-API-mediated causation (e.g., kube-exec-to-process) |
|                        | edge → edge                      | e.g., "this exec was triggered by that API call" |
| `escalated_privilege`  | session → session (self-edge)    | sudo/setuid; attributes carry uid_before/after |
| `executed_in`          | command → session                | command vertex lives inside a session          |
| `posted_in`            | user → channel                   | Slack/email observables                        |
| `classified_as`        | vertex → classification-value    | materialized by a trust lead                   |
| `attested_by`          | vertex → anchor-source           | trust attestation (dual of classified_as)      |

---

## 8. Authority table

Every edge's `authority.kind` gates the hypothesis weights a resolution can
produce using it as a supporting edge.

| Authority kind        | Meaning                                                                    | Max weight supportable |
|-----------------------|----------------------------------------------------------------------------|------------------------|
| `siem-event`          | Backed by a SIEM / audit log event; immutable, source-of-truth             | `++` / `--`            |
| `runtime-audit`       | Backed by a runtime or OS audit stream (execve, kernel audit, cadvisor)    | `++` / `--`            |
| `anchor-backed`       | Materialized via a trust anchor lookup                                     | `++` / `--`            |
| `client-asserted`     | From a self-reported field (TLS SNI, HTTP user-agent, argv claims)          | `+` / `-`              |
| `inferred-structural` | Inferred from co-occurrence, not directly materialized                     | `+` / `-`              |

**Validator rule:** a resolution with `after: ++` or `after: --` and
`severity_of_test: severe` must cite at least one `supporting_edges` entry whose
authority kind is `siem-event`, `runtime-audit`, or `anchor-backed`. Weak-authority
edges alone can never support strong weights.

**Trust chain promotion.** A `client-asserted` edge sitting on a verified trust
chain gets effective `anchor-backed` authority. Example: Slack messages are
`client-asserted` by the user's client, but Slack's audit log is SSO+MFA-backed,
so `trust_chain: [slack-audit, sso-mfa]` promotes the edge. Not relevant for
this case.

---

## 9. Write-time validator rules

A PostToolUse hook validates every write to the companion. Violations block the
write and return a structured error. Fix and retry.

1. **Schema validity.** Required fields present, enum values valid, IDs
   well-formed.
2. **Classification vocabulary.** Every `classification` value appears in §6 or
   is a `{type}:{slug}` provisional.
3. **Relation catalog.** Every `edge.relation` appears in §7.
4. **Authority rule.** Every resolution with `after ∈ {++, --}` and
   `severity_of_test: severe` cites at least one strong-authority
   supporting edge.
5. **Refutation shape match.** Every `--` resolution sets
   `matched_refutation_text` to text that appears in the target hypothesis's
   `refutation_shape` list.
6. **Prediction match.** Every `++` resolution sets `matched_prediction_text` to
   text that appears in the target hypothesis's `predictions` block AND every
   clause of `predictions` is either observationally supported or the weight is
   capped at `+`.
7. **ID references.** Every `v-*`, `e-*`, `h-*`, `l-*` reference resolves to an
   existing record.
8. **Immutability.** No mutation of existing vertices / edges / hypotheses /
   leads; changes go through `revisions`.

---

## 10. Termination categories

A backward walk terminates in one of four ways. You will record the termination
category at CONCLUDE time.

1. **Trust-root termination.** A trust lead succeeded and set `trust_root: true`.
2. **Adversarial-refuted termination.** All adversarial hypotheses are at `--`
   via severe resolutions with matched refutation shapes; a non-adversarial
   hypothesis has reached `++`.
3. **Severity-ceiling termination.** Every in-scope severe lead ran and
   adversarial hypotheses remain at `-`. Report includes `ceiling_rationale`.
4. **Exhaustion escalation.** Loop budget consumed, or hypothesis space
   incomplete.

---

## 11. Shape example (for format only — NOT this case)

A tiny example on a completely different scenario, so you see the format shape:
a file-write alert where a process writes to `/etc/shadow`.

```yaml
vertices:
  - id: v-100
    abstract_type: process
    classification: unclassified-process
    identifier: "unknown (pid 4410)"
    attributes: { pid: 4410, cmdline: "tee /etc/shadow" }
    trust_root: false
    data_quality: partial
    first_observed: { phase: CONTEXTUALIZE, loop: 0, lead: "inline" }
    citations: ["wazuh:rule.id=100020:event=zzz"]
  - id: v-101
    abstract_type: file
    classification: sensitive-credential-file
    identifier: "/etc/shadow"
    attributes: { path: "/etc/shadow" }
    trust_root: false
    data_quality: complete
    first_observed: { phase: CONTEXTUALIZE, loop: 0, lead: "inline" }
    citations: ["wazuh:rule.id=100020:event=zzz"]

edges:
  - id: e-100
    relation: wrote
    source_vertex: v-100
    target_vertex: v-101
    when: { timestamp: "2026-04-14T09:00:00Z" }
    attributes: { bytes: 2048 }
    status: observed
    authority: { kind: siem-event, source: "wazuh:rule.id=100020" }
    first_observed: { phase: CONTEXTUALIZE, loop: 0, lead: "inline" }

hypotheses:
  - id: h-100
    name: "?sanctioned-config-tool"
    canonical: true
    attached_to_vertex: v-100
    proposed_edge:
      relation: spawned
      parent_vertex: { abstract_type: process, classification: automation-pipeline-process }
    predictions:
      - for: vertex-shape
        expected: { abstract_type: process, classification: automation-pipeline-process }
      - for_absence: "no concurrent interactive shell sessions on this host"
    refutation_shape:
      - "parent process is an interactive shell, not an automation tool"
    pitfalls: []
    weight: null
    weight_history: []
    status: active

leads: []
revisions: []
```

(This is format only. Your case is different — do not copy the field values.)

---

## 12. What you write

Produce a single YAML file with the five collections filled in for this case.
Walk the case through CONTEXTUALIZE, HYPOTHESIZE, GATHER (one or more loops),
and ANALYZE, recording vertices/edges/hypotheses/leads as you go. Write leads
and their resolutions as soon as each loop "executes" (the retrieval results
file tells you what leads would have returned). End with a short CONCLUDE
section at the bottom as a YAML comment block recording termination category
and disposition.

**You are walking the investigation yourself.** The retrieval sim tells you
what prior runs know; the alert tells you the starting observation; you decide
which leads to run (picking from the lead catalog implied by the retrieval sim)
and what they would have returned. Be realistic: if a trust lead against
kube-audit succeeds, write down what it would plausibly return, matching the
shape of the classification catalog.

Keep the YAML compact but complete. Every validator rule in §9 must pass.
