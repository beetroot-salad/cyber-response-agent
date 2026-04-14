# Sonnet Reference Companion v2.1 — Pilot Case (A.1 shell-in-container)

Third walk through the same A.1 case, now under v2.1. Compared to v2 this
is a smaller delta — seven subtractive-or-consolidating changes, no
structural upheaval.

Inputs: `alert.json`, `spec-condensed-v2.1.md`, `retrieval-sim-v2.yaml`.
I did not re-read the full `investigation-language.md` or the v2
reference (though I remember its broad shape — a bias I note rather than
eliminate).

---

## Part 1 — Friction log (v2.1)

### What disappeared since v2

- **`source_lead` field removal.** Zero cost, zero confusion. Every
  vertex/edge record is simpler. The field was always deducible from
  structural position — dropping it is pure cleanup. I did not hit a
  single moment where I missed it.
- **`execution` block removal.** Same. I was emitting `dispatched_via:
  subagent` or `dispatched_via: inline` in v2 because the spec asked
  for it, but I never used the value again. Gone, not missed.
- **`outcome.status` removal.** Same story. v2's value was always
  `complete` unless I had something to say about failure, in which case
  `failure_reason` was doing the work anyway. The enum was bookkeeping
  that duplicated presence information.
- **Concerns unification.** Nice simplification. In v2 I had to remember
  that hypotheses carry `pitfalls` but vertices carry `data_quality_note`
  — two names for "the caveat on this record." v2.1 has one name.
  Cognitive tax drops slightly.
- **`intended_hypothesis_set` scope-only omission.** I was emitting
  `intended_hypothesis_set: []` on the mechanical scope lead in v2
  because the spec required the field. Now the field is disallowed on
  scope mode, and that's exactly the right call — it was vacuous
  metadata every time.

### What remained

- **Rule 6 literal copy-paste discipline.** Still the sharpest edge. I
  still wrote predictions as complete standalone sentences from the
  start so they'd be copy-paste-ready at resolution time. The negative
  example in §12 is a real help — it makes the failure mode concrete
  and I re-checked my `matched_prediction_text` against it before
  committing. No change in cost but slightly lower anxiety that I might
  be doing it wrong.
- **P8 (v1) / NV2 (v2) — `target` vs `attached_to_vertex` mismatch on
  trust leads.** Unchanged. The anchor query acts on v-002 (the
  container) but the hypotheses attach to v-003 (runc). I continue to
  set `target: v-003` for the trust lead because that's where the
  hypotheses live. Spec still doesn't pin this down explicitly; I'd
  want a one-sentence clarification in a hypothetical v2.2.

### What's new in v2.1

- **NV2.1-a — "Is this vertex observed by my data source?" as a first-
  class design question.** Under the new rule 11 (mechanical leads stay
  in their data source), I have to actively ask: does the runtime-audit
  execve feed directly see a kubectl-exec session? No — that's a
  kube-audit observation. So v-004 must not appear in l-001's produced
  vertices. This is the right rule — it matches how the telemetry
  actually works — but it's one more thing to check per vertex
  materialization. In a case where the line is less clear, I can imagine
  pausing. Not here.
- **NV2.1-b — Per-record `concerns` encourages more commentary than v2.**
  In v2 I had `pitfalls` on hypotheses (familiar) and `data_quality_note`
  on vertices (rarely used because the enum framing felt weird).
  Unifying to `concerns` on all record types reads as an invitation to
  flag more subtleties. I caught myself writing a concern on the runc
  vertex ("this is the container-runtime shim; its only role is to
  exec the commanded process") that I'd have skipped in v2. Not bad,
  just a pattern shift. The distiller will need to handle this
  gracefully — more concerns text to canonicalize for projections.

### Running count

- v1: 13 pauses, 7 real spec issues
- v2: 5 pauses, 1 real spec issue (NV1)
- v2.1: **3 pauses, 0 real spec issues.** NV2.1-a and NV2.1-b are
  pattern shifts, not ambiguities. P8 (target vs attached_to_vertex)
  is the only remaining carry-over and it's ancient.

**Write time: ~15 minutes for the companion, ~10 minutes for this
commentary.** The companion itself feels very close to "what I'd write
naturally" rather than "what the spec forces me to write." That's the
point of the subtractive changes.

### Rule 6 discipline check

Walking through my resolutions to verify literal substring match:

- **h-001 → ++, matched_prediction_text:**
  `"kube-audit returns an exec action on the container in the ±5s window"`
  — confirmed as the first entry of `h-001.predictions`. ✓ Literal.
- **h-002 → --, matched_refutation_text:**
  `"the exec initiator classifies as employee-with-exec-rbac, not automation-identity"`
  — confirmed as the second entry of `h-002.refutation_shape`. ✓ Literal.
- **h-003 → --, matched_refutation_text:**
  `"kube-audit returns an exec action with an authenticated employee-with-exec-rbac from a sanctioned network source"`
  — confirmed as the first entry of `h-003.refutation_shape`. ✓ Literal.

All three are character-for-character substrings from the target
hypothesis's own list.

---

## Part 2 — The companion

```yaml
# Structured companion v2.1 for FALCO-2026-04-14-140327-a1b2c3d4
# Walk: CONTEXTUALIZE → (deferred HYPOTHESIZE) → GATHER loops 1-2 → CONCLUDE
# Schema: investigation-language v2.1

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
      concerns:
        - "Falco reports parent=null because the host-side parent is outside the container pid namespace; container-exec-history is required to materialize the parent chain"
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

# Immediate parent of v-001 is opaque. Retrieval-sim recommends
# container-exec-history as a mechanical scope lead before hypothesizing.
# First hypothesis set will live in l-001.new_hypotheses.
hypothesize:
  hypotheses: []

gather:
  - lead:
      id: l-001
      loop: 1
      name: container-exec-history
      mode: scope
      target: v-002
      # No intended_hypothesis_set — scope mode forbids it in v2.1.
      query_details:
        system: runtime-audit-execve-feed
        template: "leads/container-exec-history/templates/execve-feed.md"
        query: "execve events where cgroup_container_id=a1b2c3d4 AND t ∈ [14:03:22, 14:03:32]"
        time_window: "±5s around alert"
        substitutions:
          container_id: "a1b2c3d4"
          t: "2026-04-14T14:03:27.412Z"
      outcome:
        produced:
          # Only what the execve feed directly observes: host-side runc
          # process and the spawned edge. The kubectl-exec session and
          # the user are NOT materialized here — those are observable
          # only via kube-audit (l-002 below).
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

      # Discrimination level advances from v-001 (bash) to v-003 (runc).
      # Service-dropped-to-shell is mechanically refuted by the runtime-shim
      # parent observation; three canonical seeds remain (per retrieval-sim).
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
          concerns:
            - "stolen-credential bypass unfalsifiable without MDM trust-chain evidence; refutation here is 'no current evidence of credential compromise' not 'credential theft ruled out'"
          weight: null

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
      outcome:
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
              authority:
                kind: anchor-backed
                source: "kube-audit:request-id=7c1f8a22"

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
        trust_root_reached: v-005
      resolutions:
        - hypothesis: h-001
          before: null
          after: "++"
          severity_of_test: severe
          matched_prediction_text: "kube-audit returns an exec action on the container in the ±5s window"
          reasoning: "kube-audit returned exec action (request 7c1f8a22) at 14:03:25.810Z targeting container a1b2c3d4 — the first prediction clause is literally matched. Second clause 'the exec initiator classifies as employee-with-exec-rbac' observationally supported by v-005 (alice@company.com, service-debug-operator role). Third clause 'the source IP of the kube-api call classifies as corp-vpn-egress or internal-corp-network' observationally supported by v-006 (corp-vpn-egress, 10.200.14.77). Complete prediction match satisfied; strong-authority grounding via e-003/e-004/e-005 (all anchor-backed)."
          supporting_edges: [e-003, e-004, e-005]

        - hypothesis: h-002
          before: null
          after: "--"
          severity_of_test: severe
          matched_refutation_text: "the exec initiator classifies as employee-with-exec-rbac, not automation-identity"
          reasoning: "kube-audit initiator is alice@company.com, classified employee-with-exec-rbac per v-005. Literal match to h-002's refutation_shape second entry. Supporting edge e-004 is anchor-backed."
          supporting_edges: [e-004]

        - hypothesis: h-003
          before: null
          after: "--"
          severity_of_test: severe
          matched_refutation_text: "kube-audit returns an exec action with an authenticated employee-with-exec-rbac from a sanctioned network source"
          reasoning: "All three clauses of the refutation shape are literally observed in the kube-audit return: (a) valid exec action present, (b) initiator is employee-with-exec-rbac alice@company.com, (c) source is corp-vpn-egress with MFA. Supporting edges e-003/e-004/e-005 all anchor-backed. Residual stolen-credential concern remains in h-003.concerns; not closed without MDM trust-chain evidence."
          supporting_edges: [e-003, e-004, e-005]

conclude:
  termination:
    category: trust-root
    rationale: "kube-audit anchor classified v-005 (alice@company.com) with anchor-backed authority; trust_root set on v-005 terminates backward walk"
  disposition: benign
  confidence: high
  matched_archetype: kubectl-exec-by-authorized-operator
  summary: "Bash was spawned in runtime-workload container payments-api-...-xk2qm by host-side runc (runtime-audit) because kube-apiserver received a pods/exec request from alice@company.com over corp VPN with service-debug-operator RBAC (kube-audit). Trust-root termination at v-005. All three adversarial hypotheses refuted via severe-severity resolutions with literal text matches and anchor-backed grounding."
```

---

## Part 3 — Closing observations

- **Line count: ~215 YAML lines** vs v2's ~245 and v1's ~310. Each
  subtractive change removed a few lines per record; unification removed
  a field-name distinction. Companion is visibly leaner.
- **Cognitive load dropped further from v2.** The three v2 pauses were
  either about residual rule 6 anxiety or about the mechanical-lead
  discipline's edge cases. v2.1 dissolved the mechanical-lead ambiguity
  via an explicit rule, and the rule 6 negative example reduced the
  anxiety. Net: this was the easiest of the three walks to write.
- **The four subtractive changes are each individually small, but they
  compound.** Drop source_lead → 1 line per record. Drop execution → 2-3
  lines per lead. Drop outcome.status → 1 line per lead. Drop
  intended_hypothesis_set on scope leads → 1 line per scope lead. Rename
  pitfalls/data_quality_note → concerns → zero lines but one less
  mental distinction. Compounded over a typical walk (6 vertices, 5
  edges, 2 leads, 3 hypotheses), ~15-20 line reduction. At scale, the
  distiller and ingest code get simpler too.
- **The single residual carry-over (P8: target vs attached_to_vertex)
  is small enough that I wouldn't block v2.1 on it.** A one-sentence
  spec clarification in §7 would close it if we ever do a v2.2.
- **Predicted rerun outcome:** I expect 2/3 to 3/3 Haiku first-pass
  clean on v2.1. The rule-6 failure in H3 should be mitigated by the
  negative example. The mechanical-lead mistake in H1/H2 should be
  mitigated by the explicit rule 11. If any Haiku still hits rule 6,
  it'll be a paraphrase in the `reasoning` field (not the match field)
  which isn't a validator violation but indicates the paraphrase
  instinct is still strong.
