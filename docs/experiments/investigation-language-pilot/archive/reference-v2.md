# Sonnet Reference Companion v2 — Pilot Case (A.1 shell-in-container)

Walkthrough of the same A.1 case under the revised v2 spec. Compared to the
v1 reference (`reference.md`), this run tracks which friction points from v1
disappeared, which remained, and whether any new friction appeared.

Inputs used: `alert.json`, `spec-condensed-v2.md`, `retrieval-sim-v2.yaml`.
I did not read the full `investigation-language.md`, and did not re-read my
v1 reference (though I remember the broad strokes of the v1 walk — this is
a bias I'm noting rather than eliminating).

---

## Part 1 — Friction log (v2)

### What disappeared

- **P3 / P5 / P6 (v1) — hypothesis attachment level, relocation bookkeeping,
  relocated-hypothesis predictions.** Gone. The discrimination-level rule
  tells me to run the mechanical scope lead first; hypotheses are formed
  once, at v-003, with fresh predictions. No shelved records, no linkage
  fields, no "did predictions inherit." Significant win.
- **P1 (v1) — host vertex catalog gap.** Gone. v-003-as-host never exists;
  host context lives as `host_name` and `host_role` attributes on v-002.
- **P4 (v1) — `triggered_by` catalog stretch.** Gone. v2 §10 explicitly
  allows `triggered_by: process → session`.
- **P12 (v1) — `data_quality` enum underspecified.** Gone. The field is
  dropped. Where there's something worth noting ("Falco reports parent=null
  because the host-side parent is outside the container pid namespace"),
  I emit `data_quality_note`. Where there isn't, I emit nothing.
- **P13 (v1) — `before: null` ambiguity.** Still present but minor; I
  continue to emit it explicitly.

### What remained

- **P7 (v1) — pre-declaring refutation text.** Now called out as rule 6.
  The literal-match discipline still forces me to write predictions as
  complete, copy-paste-ready sentences from the start, anticipating what
  a lead might confirm or refute. It's cheaper in v2 because I only write
  hypotheses once (no relocation → no re-declaration of shapes), but the
  cognitive shift is real. **I got this right on the first pass, because
  I deliberately wrote predictions as full standalone sentences the
  first time.** An agent without that habit will still trip.
- **P8 (v1) — `target_vertex` vs `attached_to_vertex` for trust leads.**
  Unchanged. The anchor query acts on v-002 (the container) but the
  hypotheses attach to v-003 (the runtime shim). I set `target: v-003`
  because that's where the hypotheses live and what the lead is
  *discriminating*, even though the literal query goes against v-002.
  **Spec could tighten this or note explicitly that target follows the
  hypothesis set when they diverge.** Unresolved in v2.

### What's new

- **NV1 — "Is this lead mechanical or discriminating?" decision.** In v2
  you have to classify each lead as you write it. For `container-exec-history`
  on A.1 it's obvious — it advances the discrimination level and carries no
  resolutions. For `anchor-lookup(kube-audit)` it's also obvious — it
  resolves hypotheses. But I can imagine borderline cases (a scope lead
  that happens to refute one hypothesis while advancing the level) where
  you'd want to emit *both* `new_hypotheses` and `resolutions` in one lead
  block. v2 allows this but doesn't say so explicitly. Minor gap.
- **NV2 — Lead `target_vertex` for the mechanical lead is the container,
  for the discriminating lead is (arguably) the runtime shim.** Same
  friction as P8 but surfaces again at the mechanical → discriminating
  handoff. The new_hypotheses block is easier to write because vertices
  produced by the lead are already inline in the same block — I can
  reference v-003 (just materialized) directly without waiting for a
  separate commit.
- **NV3 — Hypotheses attaching to a host-runtime-shim feels conceptually
  odd.** The interesting question is "what kube-api call caused runc to
  exec bash," but v-003 is the runc process, not the call. Hypotheses
  end up attached to a vertex whose `attached_to_vertex` role is almost
  a proxy for "the edge whose upstream we want to explain." Workable but
  mildly weird framing. Could be resolved by allowing hypotheses to
  attach to an *edge* as well as a vertex — but that's a larger change.

### Total count

- v1: 13 numbered pauses, 7 of them real spec issues
- v2: **3 new pauses + 2 carry-over pauses = 5 total**, 1 of them a real
  spec issue (NV1, ambiguous when a lead is both mechanical and
  discriminating)

**Write time:** ~20 minutes vs v1's ~40 minutes. The journal form is
visibly faster to compose because records live where they were produced —
I don't have to backtrack to a top-level collection to add a vertex.

### Rule 6 discipline

I deliberately watched rule 6 because the v1 pilot showed all three Haiku
runs failing it. My approach this time:

- Write each prediction as a **complete standalone sentence** that could
  stand as-is as `matched_prediction_text`. No bullet fragments, no partial
  phrases.
- Write each `refutation_shape` entry the same way.
- At resolution time, **copy-paste** the prediction/refutation entry into
  `matched_*_text`. No rewriting, no restatement. If the observation doesn't
  fit any entry verbatim, the weight caps at `+` / `-` (not `++` / `--`).

This works, but it forces "prediction-writing discipline" upstream:
predictions must be phrased as observations that a lead could confirm
verbatim. Not a natural writing order — I'm thinking "what will the lead
write back" when I'm phrasing the hypothesis. Cognitively non-trivial
but manageable once internalized.

---

## Part 2 — The companion

```yaml
# Structured companion v2 for FALCO-2026-04-14-140327-a1b2c3d4
# Walk: CONTEXTUALIZE → (deferred HYPOTHESIZE) → GATHER loops 1-2 → CONCLUDE
# Schema: investigation-language v2 (journal form, discrimination-level rule)

prologue:
  vertices:
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
      data_quality_note: "Falco reports parent=null because the host-side parent is outside the container pid namespace; run container-exec-history to materialize it"
      source_lead: inline
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
      source_lead: inline
      citations:
        - "falco:event=b8e2c4d9-0abf-4d2e-9a71-cc1ea8df2d44"

  edges:
    - id: e-001
      relation: runs_in
      source_vertex: v-001
      target_vertex: v-002
      when: { timestamp: "2026-04-14T14:03:27.412Z" }
      authority:
        kind: siem-event
        source: "falco:event=b8e2c4d9-0abf-4d2e-9a71-cc1ea8df2d44"
      source_lead: inline

# Immediate parent of v-001 is opaque (parent=null, loginuid=-1). Retrieval
# recommends container-exec-history as a mechanical lead before hypothesizing.
# Leaving hypothesize empty; first hypothesis set lives in l-001's new_hypotheses.
hypothesize:
  hypotheses: []

gather:
  - lead:
      id: l-001
      loop: 1
      name: container-exec-history
      mode: scope
      target: v-002
      intended_hypothesis_set: []
      query_details:
        system: runtime-audit-execve-feed
        template: "leads/container-exec-history/templates/execve-feed.md"
        query: "execve events where cgroup_container_id=a1b2c3d4 AND t ∈ [14:03:22, 14:03:32]"
        time_window: "±5s around alert"
        substitutions:
          container_id: "a1b2c3d4"
          t: "2026-04-14T14:03:27.412Z"
      execution:
        dispatched_via: subagent
        duration_ms: 420
      outcome:
        status: complete
        produced:
          vertices:
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
              source_lead: l-001
              citations:
                - "runtime-audit-execve-feed:host=k8s-worker-07:event=execve-184733"
          edges:
            - id: e-002
              relation: spawned
              source_vertex: v-003
              target_vertex: v-001
              when: { timestamp: "2026-04-14T14:03:27.398Z" }
              attributes:
                uid: 0
              authority:
                kind: runtime-audit
                source: "runtime-audit-execve-feed:host=k8s-worker-07:event=execve-184733"
              source_lead: l-001

      # Discrimination level advances from v-001 (bash) to v-003 (runc).
      # Service-dropped-to-shell is mechanically refuted by the runtime-shim
      # parent observation; three canonical seeds remain from retrieval-sim.
      new_hypotheses:
        - id: h-001
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
              expected: "kube-audit returns an exec action on the container in the ±5s window"
            - for: vertex-shape
              expected: "the exec initiator classifies as employee-with-exec-rbac"
            - for: vertex-shape
              expected: "the source IP of the kube-api call classifies as corp-vpn-egress or internal-corp-network"
          refutation_shape:
            - "kube-audit returns no exec action on the container in the ±5s window"
            - "the exec initiator classifies as automation-identity, not employee-with-exec-rbac"
          weight: null

        - id: h-002
          name: "?ci-pipeline-maintenance"
          canonical: true
          attached_to_vertex: v-003
          proposed_edge:
            relation: triggered_by
            parent_vertex:
              abstract_type: session
              classification: kubectl-exec-session
              attributes:
                initiator_kind: automation-identity
          predictions:
            - for: edge-shape
              expected: "kube-audit returns an exec action on the container in the ±5s window"
            - for: vertex-shape
              expected: "the exec initiator classifies as automation-identity"
            - for: vertex-shape
              expected: "the source is an internal-cluster-node or build-infrastructure-host"
          refutation_shape:
            - "kube-audit returns no exec action on the container in the ±5s window"
            - "the exec initiator classifies as employee-with-exec-rbac, not automation-identity"
          weight: null

        - id: h-003
          name: "?post-exploit-shell"
          canonical: true
          attached_to_vertex: v-003
          proposed_edge:
            relation: triggered_by
            parent_vertex:
              abstract_type: user
              classification: unknown-attacker
          predictions:
            - for_absence: "no legitimate kube-audit exec action matching an authenticated employee with exec RBAC from a sanctioned network source"
          refutation_shape:
            - "kube-audit returns an exec action with an authenticated employee-with-exec-rbac from a sanctioned network source"
          pitfalls:
            - "stolen-credential bypass unfalsifiable without MDM trust-chain; refutation here is 'no current evidence of credential compromise' not 'credential theft ruled out'"
          weight: null
      # No resolutions on l-001 — it was mechanical, advanced the level,
      # carried no discrimination power on its own.

  - lead:
      id: l-002
      loop: 2
      name: "anchor-lookup(kube-audit)"
      mode: trust
      target: v-003
      intended_hypothesis_set: [h-001, h-002, h-003]
      query_details:
        system: kube-audit
        template: "leads/anchor-lookup/templates/kube-audit-exec.md"
        query: "kube-audit entries: subresource=pods/exec AND target_container=a1b2c3d4 AND t ∈ [14:03:22, 14:03:32]"
        time_window: "±5s around alert"
        substitutions:
          container_id: "a1b2c3d4"
          t: "2026-04-14T14:03:27.412Z"
      execution:
        duration_ms: 210
      outcome:
        status: complete
        produced:
          vertices:
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
              source_lead: l-002
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
              source_lead: l-002
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
              source_lead: l-002
              citations:
                - "kube-audit:request-id=7c1f8a22"
                - "corp-vpn-registry:vpn-sess-9f3e1b"

          edges:
            - id: e-003
              relation: triggered_by
              source_vertex: v-003
              target_vertex: v-004
              when: { timestamp: "2026-04-14T14:03:25.810Z" }
              attributes:
                kube_api_request_id: "7c1f8a22-...kube-audit"
                causation_note: "kube-apiserver pods/exec request caused host-side runc to spawn bash"
              authority:
                kind: anchor-backed
                source: "kube-audit:request-id=7c1f8a22"
              source_lead: l-002

            - id: e-004
              relation: authenticated_as
              source_vertex: v-004
              target_vertex: v-005
              when: { timestamp: "2026-04-14T14:03:25.810Z" }
              attributes:
                auth_mechanism: "kube-apiserver-bearer-token"
                sso_backed: true
              authority:
                kind: anchor-backed
                source: "kube-audit:request-id=7c1f8a22"
              source_lead: l-002

            - id: e-005
              relation: initiated_by
              source_vertex: v-004
              target_vertex: v-006
              when: { timestamp: "2026-04-14T14:03:25.810Z" }
              attributes:
                client_ip: "10.200.14.77"
                network_path: "corp-vpn-east → kube-apiserver-ingress"
              authority:
                kind: anchor-backed
                source: "kube-audit:request-id=7c1f8a22"
              source_lead: l-002
        trust_root_reached: v-005
      resolutions:
        - hypothesis: h-001
          before: null
          after: "++"
          severity_of_test: severe
          matched_prediction_text: "kube-audit returns an exec action on the container in the ±5s window"
          reasoning: "kube-audit returned exec action (request 7c1f8a22) at 14:03:25.810Z targeting container a1b2c3d4 — the first prediction is matched literally. The second prediction 'the exec initiator classifies as employee-with-exec-rbac' is observationally supported by v-005 (alice@company.com, service-debug-operator role). The third prediction 'the source IP of the kube-api call classifies as corp-vpn-egress or internal-corp-network' is observationally supported by v-006 (10.200.14.77, corp-vpn-egress). Complete prediction match satisfied. Strong-authority grounding: e-003, e-004, e-005 all anchor-backed."
          supporting_edges: [e-003, e-004, e-005]

        - hypothesis: h-002
          before: null
          after: "--"
          severity_of_test: severe
          matched_refutation_text: "the exec initiator classifies as employee-with-exec-rbac, not automation-identity"
          reasoning: "kube-audit initiator is alice@company.com, classified as employee-with-exec-rbac per v-005. This is a direct literal match of h-002's refutation_shape entry. Supporting edge e-004 is anchor-backed."
          supporting_edges: [e-004]

        - hypothesis: h-003
          before: null
          after: "--"
          severity_of_test: severe
          matched_refutation_text: "kube-audit returns an exec action with an authenticated employee-with-exec-rbac from a sanctioned network source"
          reasoning: "All three elements of the refutation shape are literally observed: (a) kube-audit returned a valid exec action, (b) the initiator is employee-with-exec-rbac alice@company.com, (c) the source is corp-vpn-egress with MFA. Supporting edges e-003/e-004/e-005 all anchor-backed. Residual captured in h-003.pitfalls: stolen-credential scenario remains unfalsifiable without MDM trust-chain evidence."
          supporting_edges: [e-003, e-004, e-005]

conclude:
  termination:
    category: trust-root
    rationale: "kube-audit anchor classified v-005 (alice@company.com) with anchor-backed authority; trust_root set on v-005"
  disposition: benign
  confidence: high
  matched_archetype: kubectl-exec-by-authorized-operator
  summary: "Bash was spawned in runtime-workload container payments-api-...-xk2qm by host-side runc (runtime-audit) because kube-apiserver received a pods/exec request from alice@company.com over corp VPN with service-debug-operator RBAC (kube-audit). Trust-root termination at v-005. All three adversarial hypotheses refuted via severe-severity resolutions with literal refutation/prediction text matches and strong-authority supporting edges."
```

---

## Part 3 — Closing observations

- **Record count went from 20 (v1: 6 vertices + 5 edges + 7 hypotheses + 2
  leads) to 14 (v2: 6 vertices + 5 edges + 3 hypotheses + 2 leads).** The
  three removed hypotheses are the relocated successors that v1 needed and
  v2 didn't.
- **Lines of YAML went from ~310 to ~245.** A ~20% reduction driven mostly
  by implicit defaults (no `first_observed`, no `data_quality`, no empty
  lists) and partly by the journal form eliminating cross-references.
- **Cognitive load dropped visibly.** The three friction points that most
  bothered me in v1 (P3/P5/P6) are gone. The rule 6 discipline is the
  last sharp edge; I only handled it because I deliberately phrased
  predictions as copy-paste sentences from the start.
- **The spec decision I'm most curious about on the rerun:** will the
  three Haiku runs actually defer hypothesizing until after the mechanical
  lead, or will they form hypotheses at v-001 anyway because it's the
  first vertex they see? The spec is explicit and the retrieval-sim
  explicitly recommends running the mechanical lead first — if Haikus
  still form hypotheses at v-001, it means explicit instruction alone
  isn't enough and the spec needs a structural affordance (maybe: empty
  `hypothesize` is the default, and you have to explicitly opt in to
  pre-lead hypotheses).
- **If 3/3 Haikus get rule 6 right this time, the win is attributable to
  the spec's capital-letters instruction + the worked example showing
  the discipline in action.** If 3/3 still fail it, the rule needs
  softening (Haiku-judged semantic match) regardless of doc strictness.
- **Predicted outcome:** I expect discrimination-level rule to land
  cleanly (0/3 or 1/3 failures) but rule 6 to still trip 1-2 of 3 runs
  despite explicit instruction, because the temptation to write the
  observation instead of copy the prediction is intrinsic to narrative
  writing. We'll see.
