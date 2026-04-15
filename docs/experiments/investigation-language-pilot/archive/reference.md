# Sonnet Reference Companion — Pilot Case (A.1 shell-in-container)

This is the reference walkthrough for the pilot experiment on the investigation
language. It has two parts:

1. **Running commentary** — the pauses, backtracks, and schema fights I hit while
   writing the companion. This is the primary qualitative data for the
   experiment.
2. **The companion YAML itself** — one walkable record of the A.1 case.

Inputs used: `alert.json`, `spec-condensed.md`, `retrieval-sim.yaml`. I did
**not** read the full `investigation-language.md` during the walk.

---

## Part 1 — Friction log

### Setup observations

- The condensed spec is dense but coherent. §6 (classifications) and §7
  (relations) are where I looked most often.
- Having the retrieval sim pre-populated removed a large source of ambiguity —
  in a real run, the retrieval keys I'd build would themselves be a friction
  point. This pilot isolates write burden.

### Pauses, numbered as they surfaced

**P1 — Host vertex: model or drop.** The alert names `k8s-worker-07` as the
host. The relation catalog has `runs_in: process → container` but nothing for
`container → host`. I considered inventing `hosted_on`, but decided the host is
context for this walk, not structure: the investigation doesn't touch host-level
evidence. Dropped `v-host` entirely; left `host_name` as an attribute on v-002
(container). **Resolution:** modeling choice, not a schema bug, but the gap is
real and would bite a case that actually queries host-level evidence.

**P2 — Retrieval key attribute names.** For CONTEXTUALIZE retrieval I needed
to build a vertex shape key. The retrieval-sim uses
`process:parent_presence=null;runs_in_classification=runtime-workload` — I
matched its format. The spec (§5.3 in the full doc, not in condensed) defines
canonicalization rules, but the condensed version doesn't surface them. An
agent without the retrieval sim would have to guess the attribute whitelist.
**Action for spec:** condensed version should include a short "retrieval key
cheat sheet" with the whitelist per abstract type.

**P3 — First hypothesis attachment level.** The four seeds talk about
*ultimate* causes (operator, CI, service, attacker), but §4 says a hypothesis
proposes a *single backward edge* to a parent vertex. At v-001 the immediate
parent will be runc (host-side shim) regardless of which seed is right — the
immediate edge doesn't discriminate. Two interpretations:

- **(a)** Hypotheses at loop 0 propose the *semantic cause* and the walk
  confirms via relocation.
- **(b)** Hypotheses at loop 0 propose only the immediate parent (all four
  predict runc — no discrimination). Real discrimination starts at loop 1 on
  v-003.

I went with (a) because that's what the seeds clearly intend, but had to bend
the "single backward edge" framing: each hypothesis's `proposed_edge.parent_vertex`
describes the *effective* causer (kubectl session, CI automation, service
process, unknown attacker), not the literal immediate parent. The spec doesn't
pick a side here. **This is the first thing I'd want clarified in the full
spec.**

**P4 — `triggered_by` catalog row.** The relation catalog says
`triggered_by: process → process | edge → edge`. I need an edge from v-003
(runc process) to v-004 (kubectl-exec-session). Session is not in the catalog
row. I stretched — it's either "stretch triggered_by to allow → session" or
"invent an intermediate process vertex for the kube-apiserver call." The
intermediate is overengineering for a pilot; I stretched and noted it. **Real
agents will stretch or invent constantly until the catalog is complete.**

**P5 — Hypothesis relocation: bookkeeping cost.** After loop 1 materializes
runc as v-003, three of the four hypotheses need to relocate from v-001 to
v-003. The spec says "new hypotheses attach to the newly materialized parent;
old hypotheses transition to shelved." So I need **new records** h-005/h-006/h-007
carrying successor semantics of h-001/h-002/h-004, and I need to mark the
originals as `shelved`. There's no schema field to link original→successor;
I wrote the linkage into the lead's `resolution.reasoning` text. **The spec
should have a `relocated_to: h-id` field on hypothesis, or say explicitly that
relocation linkage is narrative-only.**

**P6 — Relocated hypothesis predictions: fresh or inherited?** When h-005
takes over from h-001 on v-003, do its predictions carry over wholesale?
Some of h-001's predictions are now trivially true ("host-side parent is a
runtime shim" — v-003 IS the runtime shim). Carrying them over would make
prediction-completeness for `++` trivially easier. I chose to drop them and
write h-005's predictions fresh. **The spec doesn't address this; I'd expect
real agents to inherit by default (cheaper) and lose the completeness
protection.**

**P7 — Pre-declaring refutation text.** For h-006 (?ci-pipeline) to refute at
loop 2 with `matched_refutation_text`, its `refutation_shape` must contain
the matching text. I had to write h-006's refutation shape in loop 1
*anticipating* what the loop 2 anchor lookup would return. This isn't
unnatural — you write refutation shapes when you write hypotheses — but it
forces you to think about outcomes one loop ahead of the actual evidence. A
real agent writing in-phase will sometimes need to **amend a hypothesis's
refutation_shape** after observing a lead outcome, which the append-only rule
makes awkward (you can append pitfalls but not refutation entries).

**P8 — Lead target_vertex vs. hypothesis attached_to_vertex.** `l-002`
(anchor-lookup kube-audit) has `target_vertex: v-002` (the container — that's
what the anchor is asked about), but its resolutions touch h-005/h-006/h-007
which attach to v-003 (runc). The spec doesn't say these must match, but the
mismatch is real: the lead acts on one vertex and advances hypotheses on a
different vertex. I left it as-is. **This is fine in principle but will
confuse the state machine if any validator ever checks target alignment.**

**P9 — Trust-root vertex choice.** The kube-audit lookup returns both a user
(v-005, alice) and a source IP (v-006, corp-vpn-egress). Both are anchor-backed
classifications — either could be a trust root. I set `trust_root: true` only
on v-005 because that's the authenticated identity. But v-006 is equally
"authority has confirmed what this is." **The spec's definition of trust-root
is "backward traversal is terminated here by authority" — for the user, yes;
for the IP, also yes (we wouldn't walk backward from the corp-VPN IP). Both
qualify. I kept v-005 only by convention.**

**P10 — Termination category overlap.** The walk terminates via trust-root on
v-005 AND all three live adversarial hypotheses refuted to `--`. The spec
lists four categories as alternatives, not a priority order. I called it
"trust-root termination" because that's the *reason* backward walk halts.
Either label is defensible. **Minor spec gap: clarify precedence when
multiple termination conditions fire in the same loop.**

**P11 — No `v-host` but I still want the edge `runs_in` for v-001 → v-002.**
The spec's `runs_in: process → container` cleanly covers this one. ✓ No issue.

**P12 — `data_quality` and `citations` fields.** On v-001 (bash), loginuid=-1
and parent=null both mean the telemetry is degraded in a specific way. I
wrote `data_quality: partial` and added a note in `attributes`. The enum
(`complete|partial|degraded`) doesn't distinguish "some fields missing" from
"some fields untrustworthy." Good enough for this case but will need more
granularity later.

**P13 — Weight history: before vs. null.** For hypotheses at loop 0, their
first weight transition has `before: null`. I'm not sure whether `null` is
schema-valid or whether I should omit the field. I wrote `null` explicitly
for clarity; a strict schema might reject it.

### Running count

- **13 pauses** across a two-loop walk.
- **Of those:** 4 are spec gaps (P1, P2, P4, P5), 3 are interpretation calls
  the spec doesn't make (P3, P6, P10), 2 are append-only tensions (P6, P7),
  4 are minor or "this is fine" (P8, P9, P11, P12, P13 — counting generously).
- None blocked me outright. All were resolvable by committing to an
  interpretation and moving on. **But** in a production run with a strict
  validator, P6 (amending refutation shape post-hoc) would fail the append-only
  rule and force a retry or a workaround.

### Top write-burden observations

1. **Hypothesis bookkeeping (P3, P5, P6) is the heaviest thing.** Attachment
   level, relocation, pre-declaring refutation text. On a 2-loop walk this
   is tolerable; on a 5-loop walk with multiple relocations it will be the
   dominant cost.
2. **Catalog completeness (P1, P4) is the next heaviest.** Stretching
   `triggered_by` and dropping the host vertex were both "good enough for the
   pilot" decisions. A real agent walking an unfamiliar case will stretch,
   invent, or get stuck — in all three cases the corpus gets less canonical.
3. **Append-only vs. natural writing order (P6, P7).** The spec's immutability
   is clean in principle but forces you to write refutation shapes before you
   know what the evidence will say, which is the opposite of how investigation
   reasoning naturally flows.
4. **Everything else was minor or tolerable.**

### Validator rule sanity-check on my output

- ✓ Schema validity: fields populated, enum values valid.
- ✓ Classifications: all from §6 seed vocabulary.
- ✓ Relations: all from §7, except the `triggered_by` process→session stretch
  I flagged in P4.
- ✓ Authority rule: all ++/-- with severity=severe cite at least one
  strong-authority supporting edge (`runtime-audit` for e-002, `anchor-backed`
  for e-003/e-004/e-005).
- ✓ Refutation shape match: all `--` resolutions name `matched_refutation_text`
  whose text appears verbatim in the target hypothesis's `refutation_shape`.
- ✓ Prediction completeness for `++`: h-005's four predictions are each
  traceable to an observed edge.
- ✓ ID references: all `v-*`, `e-*`, `h-*`, `l-*` references resolve.
- ✓ Append-only: no mutations (one relocation via new records, not edit).

One latent violation: the `triggered_by` stretch (P4) would fail validator
rule 3 (relation-catalog conformance) on a strict check. A real agent would
loop on that retry until it either found a catalog-clean encoding or
gave up.

---

## Part 2 — The companion

```yaml
# Structured companion for FALCO-2026-04-14-140327-a1b2c3d4
# Walk: CONTEXTUALIZE → HYPOTHESIZE → GATHER (loops 1-2) → ANALYZE → CONCLUDE

vertices:
  # ── CONTEXTUALIZE, loop 0 (inline from alert) ──
  - id: v-001
    abstract_type: process
    classification: interactive-shell-in-workload
    identifier: "bash (container a1b2c3d4, pid 2881)"
    attributes:
      pid: 2881
      ppid: 0
      uid: 0
      loginuid: -1
      tty: false
      cmdline: "/bin/bash"
      parent_presence: null
      classification_rationale: "bash spawned inside a runtime-workload container with tty=false and loginuid=-1 — interactive-capable shell, no login context"
    trust_root: false
    data_quality: partial
    first_observed: { phase: CONTEXTUALIZE, loop: 0, lead: inline }
    citations:
      - "falco:event=b8e2c4d9-0abf-4d2e-9a71-cc1ea8df2d44"

  - id: v-002
    abstract_type: container
    classification: runtime-workload
    identifier: "payments-api-7b9d8f4c8-xk2qm"
    attributes:
      container_id: a1b2c3d4
      image: "registry.internal/payments-api:v1.44.2"
      pod: "payments-api-7b9d8f4c8-xk2qm"
      namespace: "payments-prod"
      workload_kind: Deployment
      workload_name: payments-api
      host_name: "k8s-worker-07"
      host_role: "kubernetes-worker-node"
    trust_root: false
    data_quality: complete
    first_observed: { phase: CONTEXTUALIZE, loop: 0, lead: inline }
    citations:
      - "falco:event=b8e2c4d9-0abf-4d2e-9a71-cc1ea8df2d44"

  # ── GATHER, loop 1: materialized by l-001 container-exec-history ──
  - id: v-003
    abstract_type: process
    classification: host-runtime-shim
    identifier: "runc:[2:INIT] (host k8s-worker-07)"
    attributes:
      comm: "runc:[2:INIT]"
      cmdline: "runc init"
      host: "k8s-worker-07"
      runtime: "containerd"
      host_pid: 184733
    trust_root: false
    data_quality: complete
    first_observed: { phase: GATHER, loop: 1, lead: l-001 }
    citations:
      - "runtime-audit-execve-feed:host=k8s-worker-07:event=execve-184733"

  # ── GATHER, loop 2: materialized by l-002 anchor-lookup(kube-audit) ──
  - id: v-004
    abstract_type: session
    classification: kubectl-exec-session
    identifier: "kubectl-exec alice→payments-api-7b9d8f4c8-xk2qm @14:03:25Z"
    attributes:
      subresource: "pods/exec"
      target_pod: "payments-api-7b9d8f4c8-xk2qm"
      target_container: "a1b2c3d4"
      kube_api_request_id: "7c1f8a22-...kube-audit"
      client_user_agent: "kubectl/v1.28.3"
      rbac_role: "service-debug-operator"
    trust_root: false
    data_quality: complete
    first_observed: { phase: GATHER, loop: 2, lead: l-002 }
    citations:
      - "kube-audit:request-id=7c1f8a22"

  - id: v-005
    abstract_type: user
    classification: employee-with-exec-rbac
    identifier: "alice@company.com"
    attributes:
      email: "alice@company.com"
      rbac_role_on_workload: "service-debug-operator"
      employment_status: "active"
    trust_root: true
    data_quality: complete
    first_observed: { phase: GATHER, loop: 2, lead: l-002 }
    citations:
      - "kube-audit:request-id=7c1f8a22"
      - "hr-directory:alice@company.com"

  - id: v-006
    abstract_type: ip
    classification: corp-vpn-egress
    identifier: "corp-vpn-east-gw-3 (10.200.14.77)"
    attributes:
      ip: "10.200.14.77"
      vpn_session_id: "vpn-sess-9f3e1b"
      mfa_verified: true
    trust_root: false
    data_quality: complete
    first_observed: { phase: GATHER, loop: 2, lead: l-002 }
    citations:
      - "kube-audit:request-id=7c1f8a22"
      - "corp-vpn-registry:vpn-sess-9f3e1b"

edges:
  # ── inline from alert ──
  - id: e-001
    relation: runs_in
    source_vertex: v-001
    target_vertex: v-002
    when: { timestamp: "2026-04-14T14:03:27.412Z" }
    attributes: {}
    status: observed
    authority:
      kind: siem-event
      source: "falco:event=b8e2c4d9-0abf-4d2e-9a71-cc1ea8df2d44"
    first_observed: { phase: CONTEXTUALIZE, loop: 0, lead: inline }

  # ── loop 1: l-001 container-exec-history ──
  - id: e-002
    relation: spawned
    source_vertex: v-003
    target_vertex: v-001
    when: { timestamp: "2026-04-14T14:03:27.398Z" }
    attributes:
      uid: 0
      cap_set: "CAP_SYS_ADMIN,CAP_NET_ADMIN,..."
    status: observed
    authority:
      kind: runtime-audit
      source: "runtime-audit-execve-feed:host=k8s-worker-07:event=execve-184733"
    first_observed: { phase: GATHER, loop: 1, lead: l-001 }

  # ── loop 2: l-002 anchor-lookup(kube-audit) ──
  # NOTE: triggered_by stretched process → session (catalog row lists
  # process → process | edge → edge; session not listed). See reference
  # commentary P4 — this is a known catalog gap.
  - id: e-003
    relation: triggered_by
    source_vertex: v-003
    target_vertex: v-004
    when: { timestamp: "2026-04-14T14:03:25.810Z" }
    attributes:
      kube_api_request_id: "7c1f8a22-...kube-audit"
      causation_note: "kube-apiserver pods/exec request caused host-side runc to spawn bash in container a1b2c3d4"
    status: observed
    authority:
      kind: anchor-backed
      source: "kube-audit:request-id=7c1f8a22"
    first_observed: { phase: GATHER, loop: 2, lead: l-002 }

  - id: e-004
    relation: authenticated_as
    source_vertex: v-004
    target_vertex: v-005
    when: { timestamp: "2026-04-14T14:03:25.810Z" }
    attributes:
      auth_mechanism: "kube-apiserver-bearer-token"
      sso_backed: true
    status: observed
    authority:
      kind: anchor-backed
      source: "kube-audit:request-id=7c1f8a22"
    first_observed: { phase: GATHER, loop: 2, lead: l-002 }

  - id: e-005
    relation: initiated_by
    source_vertex: v-004
    target_vertex: v-006
    when: { timestamp: "2026-04-14T14:03:25.810Z" }
    attributes:
      client_ip: "10.200.14.77"
      network_path: "corp-vpn-east → kube-apiserver-ingress"
    status: observed
    authority:
      kind: anchor-backed
      source: "kube-audit:request-id=7c1f8a22"
    first_observed: { phase: GATHER, loop: 2, lead: l-002 }

hypotheses:
  # ── HYPOTHESIZE, loop 0: attached to v-001 (bash process) ──
  # Seeded from retrieval-sim (four canonical hypothesis seeds). All four
  # frame ultimate causation, which the spec's "single backward edge"
  # framing doesn't cleanly express; I interpret each proposed_edge as
  # effective causer, not literal immediate parent. See P3.
  - id: h-001
    name: "?kubectl-exec-operator"
    canonical: true
    attached_to_vertex: v-001
    proposed_edge:
      relation: triggered_by
      parent_vertex:
        abstract_type: session
        classification: kubectl-exec-session
    predictions:
      - for: edge-shape
        expected: "host-side parent of v-001 is a runtime shim (runc or containerd-shim)"
      - for: edge-shape
        expected: "kube-audit returns an exec action on v-002 within ±5s of the alert"
      - for: vertex-shape
        expected: "exec initiator classifies as employee-with-exec-rbac"
      - for: vertex-shape
        expected: "source IP of the kube-api call classifies as corp-vpn-egress or internal-corp-network"
    refutation_shape:
      - "host-side parent is the service entrypoint process (not a runtime shim)"
      - "kube-audit returns no exec action on the container in the ±5s window"
      - "kube-audit initiator classifies as automation-identity, not employee-with-exec-rbac"
    pitfalls:
      - "stolen operator credentials: employee + sanctioned source does NOT by itself rule out ?post-exploit-shell; only combined with a refutation of ?post-exploit"
    refutation_pivots_to: [h-004]
    weight: null
    weight_history: []
    status: active

  - id: h-002
    name: "?ci-pipeline-maintenance"
    canonical: true
    attached_to_vertex: v-001
    proposed_edge:
      relation: triggered_by
      parent_vertex:
        abstract_type: session
        classification: kubectl-exec-session
        attributes: { initiator_kind: automation-identity }
    predictions:
      - for: edge-shape
        expected: "host-side parent of v-001 is a runtime shim"
      - for: edge-shape
        expected: "kube-audit returns an exec action on v-002 within ±5s of the alert"
      - for: vertex-shape
        expected: "exec initiator classifies as automation-identity (CI service account)"
      - for: vertex-shape
        expected: "source IP is an internal-cluster-node or build-infrastructure-host"
    refutation_shape:
      - "kube-audit returns no exec action on the container in the ±5s window"
      - "kube-audit initiator classifies as employee-with-exec-rbac (a human employee), not automation-identity"
    pitfalls: []
    refutation_pivots_to: []
    weight: null
    weight_history: []
    status: active

  - id: h-003
    name: "?service-dropped-to-shell"
    canonical: true
    attached_to_vertex: v-001
    proposed_edge:
      relation: spawned
      parent_vertex:
        abstract_type: process
        classification: service-entrypoint-process
    predictions:
      - for: edge-shape
        expected: "host-side parent of v-001 is the service entrypoint process (e.g., gunicorn/python)"
      - for_absence: "no concurrent kube-audit exec action on this container"
    refutation_shape:
      - "host-side parent is a runtime shim (runc/containerd), not the service entrypoint"
    pitfalls: []
    refutation_pivots_to: []
    weight: null
    weight_history: []
    status: active

  - id: h-004
    name: "?post-exploit-shell"
    canonical: true
    attached_to_vertex: v-001
    proposed_edge:
      relation: triggered_by
      parent_vertex:
        abstract_type: user
        classification: unknown-attacker
    predictions:
      - for: edge-shape
        expected: "either host-side parent is a runtime shim with anomalous kube-audit attribution, or host-side parent is the service entrypoint reached via application RCE"
      - for: vertex-shape
        expected: "kube-audit initiator is unclassified-user or employee-without-exec-rbac, or preceding network window shows anomalous ingress to v-002"
    refutation_shape:
      - "kube-audit returns an exec action with an authenticated employee-with-exec-rbac from a sanctioned network source"
    pitfalls:
      - "stolen-credential scenario defeats sanctioned-source refutation; trust-chain promotion (MDM device posture) would strengthen refutation but is out of scope for this pilot"
    refutation_pivots_to: []
    weight: null
    weight_history: []
    status: active

  # ── GATHER, loop 1: relocated hypotheses attached to v-003 (runc) ──
  # h-001/h-002/h-004 shelve on v-001 and respawn as h-005/h-006/h-007 on v-003
  # with fresh predictions (the "host-side parent is runtime shim" clause is
  # trivially satisfied at v-003 itself and drops out). See P5, P6.
  - id: h-005
    name: "?kubectl-exec-operator"
    canonical: true
    attached_to_vertex: v-003
    proposed_edge:
      relation: triggered_by
      parent_vertex:
        abstract_type: session
        classification: kubectl-exec-session
    predictions:
      - for: edge-shape
        expected: "kube-audit returns an exec action on v-002 within ±5s of the alert"
      - for: vertex-shape
        expected: "exec initiator classifies as employee-with-exec-rbac"
      - for: vertex-shape
        expected: "source IP of the kube-api call classifies as corp-vpn-egress or internal-corp-network"
    refutation_shape:
      - "kube-audit returns no exec action on the container in the ±5s window"
      - "kube-audit initiator classifies as automation-identity, not employee-with-exec-rbac"
    pitfalls: []
    refutation_pivots_to: [h-007]
    weight: null
    weight_history: []
    status: active

  - id: h-006
    name: "?ci-pipeline-maintenance"
    canonical: true
    attached_to_vertex: v-003
    proposed_edge:
      relation: triggered_by
      parent_vertex:
        abstract_type: session
        classification: kubectl-exec-session
        attributes: { initiator_kind: automation-identity }
    predictions:
      - for: edge-shape
        expected: "kube-audit returns an exec action on v-002 within ±5s of the alert"
      - for: vertex-shape
        expected: "exec initiator classifies as automation-identity"
      - for: vertex-shape
        expected: "source IP is an internal-cluster-node or build-infrastructure-host"
    refutation_shape:
      - "kube-audit returns no exec action on the container in the ±5s window"
      - "kube-audit initiator classifies as employee-with-exec-rbac, not automation-identity"
    pitfalls: []
    refutation_pivots_to: []
    weight: null
    weight_history: []
    status: active

  - id: h-007
    name: "?post-exploit-shell"
    canonical: true
    attached_to_vertex: v-003
    proposed_edge:
      relation: triggered_by
      parent_vertex:
        abstract_type: user
        classification: unknown-attacker
    predictions:
      - for: vertex-shape
        expected: "kube-audit initiator is unclassified-user or employee-without-exec-rbac"
      - for_absence: "no sanctioned-network source and no matching employee-with-exec-rbac identity"
    refutation_shape:
      - "kube-audit returns an exec action with an authenticated employee-with-exec-rbac from a sanctioned network source"
    pitfalls:
      - "stolen-credential bypass unfalsifiable without MDM trust-chain; refutation here is 'no current evidence of credential compromise' not 'credential theft ruled out'"
    refutation_pivots_to: []
    weight: null
    weight_history: []
    status: active

leads:
  # ── GATHER, loop 1 ──
  - id: l-001
    name: container-exec-history
    mode: scope
    target_vertex: v-002
    intended_hypothesis_set: [h-001, h-002, h-003, h-004]
    query_details:
      system: runtime-audit-execve-feed
      template: "leads/container-exec-history/templates/execve-feed.md"
      query: "execve events where cgroup_container_id=a1b2c3d4 AND t ∈ [14:03:22, 14:03:32]"
      time_window: "±5s around alert"
      substitutions: { container_id: "a1b2c3d4", t: "2026-04-14T14:03:27.412Z" }
    execution:
      phase: GATHER
      loop: 1
      dispatched_via: subagent
      duration_ms: 420
    outcome:
      status: complete
      vertices_materialized: [v-003]
      edges_materialized: [e-002]
      attributes_updated: []
      trust_root_reached: null
      failure_reason: null
    resolution:
      - hypothesis: h-003
        before: null
        after: "--"
        severity_of_test: severe
        matched_refutation_text: "host-side parent is a runtime shim (runc/containerd), not the service entrypoint"
        reasoning: "container-exec-history materialized v-003 (runc:[2:INIT], host-runtime-shim classification) as the spawner of v-001 via e-002 (runtime-audit authority). This directly matches h-003's refutation_shape entry. h-001/h-002/h-004 are consistent with the observation (runtime-shim is expected for all three) and RELOCATE to v-003 as h-005/h-006/h-007 — discrimination question moves one step deeper on the backward walk. h-001/h-002/h-004 transition to status=shelved as part of the relocation, not refuted."
        supporting_edges: [e-002]

  # ── GATHER, loop 2 ──
  - id: l-002
    name: "anchor-lookup(kube-audit)"
    mode: trust
    target_vertex: v-002
    intended_hypothesis_set: [h-005, h-006, h-007]
    query_details:
      system: kube-audit
      template: "leads/anchor-lookup/templates/kube-audit-exec.md"
      query: "kube-audit entries: subresource=pods/exec AND target_container=a1b2c3d4 AND t ∈ [14:03:22, 14:03:32]"
      time_window: "±5s around alert"
      substitutions: { container_id: "a1b2c3d4", t: "2026-04-14T14:03:27.412Z" }
    execution:
      phase: GATHER
      loop: 2
      dispatched_via: inline
      duration_ms: 210
    outcome:
      status: complete
      vertices_materialized: [v-004, v-005, v-006]
      edges_materialized: [e-003, e-004, e-005]
      attributes_updated:
        - target: v-005
          field: trust_root
          from: false
          to: true
      trust_root_reached: v-005
      failure_reason: null
    resolution:
      - hypothesis: h-005
        before: null
        after: "++"
        severity_of_test: severe
        matched_prediction_text: "kube-audit returns an exec action on v-002 within ±5s of the alert"
        reasoning: "kube-audit returned exec action (request 7c1f8a22) at 14:03:25.810Z targeting pod payments-api-7b9d8f4c8-xk2qm container a1b2c3d4. Initiator is alice@company.com with RBAC role service-debug-operator (classifies as employee-with-exec-rbac per §6). Source IP 10.200.14.77 classifies as corp-vpn-egress with MFA-verified VPN session. All four predictions of h-005 observed and supported by anchor-backed edges e-003/e-004/e-005. Complete prediction match satisfied; strong-authority grounding satisfied."
        supporting_edges: [e-003, e-004, e-005]
      - hypothesis: h-006
        before: null
        after: "--"
        severity_of_test: severe
        matched_refutation_text: "kube-audit initiator classifies as employee-with-exec-rbac, not automation-identity"
        reasoning: "kube-audit initiator is alice@company.com (employee-with-exec-rbac), directly contradicting h-006's prediction that the initiator would classify as automation-identity. Refutation shape matched verbatim. Supporting edge e-004 is anchor-backed."
        supporting_edges: [e-004]
      - hypothesis: h-007
        before: null
        after: "--"
        severity_of_test: severe
        matched_refutation_text: "kube-audit returns an exec action with an authenticated employee-with-exec-rbac from a sanctioned network source"
        reasoning: "All three elements of the refutation shape match: (a) kube-audit returned a valid exec action, (b) initiator is employee-with-exec-rbac alice@company.com, (c) source is corp-vpn-egress with MFA. Supporting edges e-003/e-004/e-005 are all anchor-backed. NOTE: this refutes 'post-exploit via kube-exec with observable anomaly'; it does NOT refute 'post-exploit via stolen credentials' — that residual is captured in h-007.pitfalls and requires MDM trust-chain to close (out of pilot scope)."
        supporting_edges: [e-003, e-004, e-005]

revisions: []

# ─────────────────────────────────────────────────────────────────
# CONCLUDE
#
# termination_category: trust-root  (v-005 alice@company.com set
#   trust_root=true via anchor-backed kube-audit classification;
#   adversarial-refuted also satisfied on h-006/h-007 in the same
#   loop — see P10 for the precedence call)
#
# disposition: benign
#
# confidence: high (with a narrow residual on stolen-credential
#   scenario — captured in h-007.pitfalls, unclosed without MDM
#   trust-chain evidence)
#
# matched_archetype: kubectl-exec-by-authorized-operator
#   (assumed to exist in payments-prod archetype catalog; if absent,
#   escalate with recommendation to create the archetype — the
#   evidence is clean but the governance artifact may be missing)
#
# analytic summary:
#   Bash was spawned in runtime-workload container payments-api-...-xk2qm
#   by host-side runc (runtime-audit) because kube-apiserver received a
#   pods/exec request from alice@company.com over corp VPN with
#   service-debug-operator RBAC (kube-audit). Trust-root termination at
#   v-005. All three adversarial hypotheses refuted via severe-severity
#   resolutions with strong-authority supporting edges.
# ─────────────────────────────────────────────────────────────────
```

---

## Part 3 — Closing observations

- **Total write effort:** ~40 minutes including commentary, for a 2-loop walk
  with 6 vertices, 5 edges, 7 hypotheses, 2 leads. Without commentary I
  estimate 15–20 minutes for the YAML alone.
- **Where it felt heavy:** hypothesis relocation bookkeeping (P5/P6) and
  the catalog gap on `triggered_by` (P4). If the agent had to fight the
  validator on these, the 15-minute baseline doubles.
- **Where it felt natural:** vertices and edges came out cleanly, once I
  committed to dropping the host vertex. Authority and severity labeling
  was mechanical after the first resolution entry.
- **The single thing I'd change about the spec:** add a `relocated_to:
  h-id` field on hypothesis, or say explicitly that relocation linkage is
  narrative-only in `reasoning`. This one bit of ambiguity drove two
  separate pauses (P5, P6) and would confuse any agent writing without
  worked examples.
- **Validator strictness dial:** with a lenient validator (warn on catalog
  stretch, accept "inherited" predictions on relocation), this walk is
  writable in one pass. With the strict validator described in §9, I'd
  expect 1–2 retry loops on `triggered_by` catalog conformance alone.
