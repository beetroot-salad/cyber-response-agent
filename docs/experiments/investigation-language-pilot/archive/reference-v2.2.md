# Sonnet Reference Companion v2.2 — Pilot Case (A.1 shell-in-container)

Fourth walk through the same A.1 case, now under v2.2. This is a
smaller delta than v2→v2.1 in structural terms — six targeted changes,
no journal-form upheaval — but two of the changes (prediction IDs,
one-hop parent discipline) required deliberate re-thinking during writing.

Inputs: `alert.json`, `spec-condensed-v2.2.md`, `retrieval-sim-v2.yaml`.
Prior reference (`reference-v2.1.md`) and comparison (`comparison-v2.1.md`)
consulted only for friction tracking.

---

## Part 1 — Friction log (v2.2)

### What disappeared since v2.1

- **P-gone-1 — Rule 6 literal text discipline.** Gone entirely. Writing
  predictions now, I never paused to ask "is this copy-paste-ready?" I
  wrote `p1`, `p2`, `p3` as natural sentences describing world-state. At
  resolution time, I cited `matched_prediction_ids: [p1, p2, p3]` and
  moved on. The paraphrase-prevention discipline — which was the sharpest
  remaining edge in v2.1 — simply does not exist under v2.2. No copy-
  paste rehearsal, no anxiety about whether my reasoning field would
  match a literal substring. The prediction text is the authoritative
  claim; the ID is the match key. These roles are no longer conflated.
  *Classification: disappeared.*

- **P-gone-2 — "Is the matched text a literal substring of the list?"
  verification pass.** In v2.1, I added a separate Rule 6 discipline
  check section at the end of the friction log, walked all three
  resolutions character-for-character, and confirmed literal substring
  matches. Under v2.2 this verification pass does not exist. The
  validator check is set membership on IDs — trivially verifiable by
  inspection. I did not do a separate pass.
  *Classification: disappeared.*

### What remained

- **P-remain-1 — `target` vs `attached_to_vertex` ambiguity on trust
  leads.** Same carry-over from v1/v2/v2.1. The kube-audit anchor query
  physically targets v-002 (the container), but the hypotheses attach to
  v-003 (runc). I set `target: v-003` for l-002 on the grounds that
  `target` follows the hypothesis set, not the query system's natural
  object. The spec still doesn't pin this down explicitly. Not blocking,
  but present.
  *Classification: remaining.*

### What's new in v2.2

- **P-new-1 — h-003 `parent_vertex` one-hop recalibration.** The v2.1
  reference set `parent_vertex.type: user` for h-003 (?post-exploit-shell)
  attached to v-003 (runc). The spec now clarifies: `parent_vertex`
  is exactly one backward hop from `attached_to_vertex`, and runc's one-
  hop upstream via `triggered_by` is a session, not a user. Under v2.2 I
  had to recalibrate: h-003's `parent_vertex.type` is `session`, with
  classification reflecting an attacker-controlled session shape
  (`unclassified-session`). The user-level claim ("no legitimate
  user initiated this") migrates into predictions and refutation_shape.
  This required deliberate thought — I had to resist the v2.1 muscle
  memory of writing `type: user` at the runc vertex. Once I had the
  one-hop principle in view, the correct shape was immediate.
  *Classification: new. Mild pause (~30s) on correct first write.*

- **P-new-2 — Prediction ID scoping discipline.** `p1`, `p2`, etc. are
  scoped to their containing hypothesis. h-001 has `p1`, `p2`, `p3`.
  h-002 has `p1`, `p2`. h-003 has `p1`, `p2`. Resolution fields say
  `matched_prediction_ids: [p1, p2]` without a hypothesis-qualifying
  prefix; the hypothesis is implicit from the wrapping `hypothesis: h-{n}`
  key. This is the right design but I paused once to confirm: if two
  hypotheses both have `p1`, do the resolution fields distinguish them?
  Answer: yes, because each resolution block wraps exactly one
  `hypothesis:` field that scopes the IDs. No ambiguity, but worth
  noting as a first-encounter friction point.
  *Classification: new. One-time mental check (~20s), not a real issue.*

- **P-new-3 — `lead.observes` on l-002.** I used the optional `observes`
  field on the kube-audit trust lead. Writing it was natural: I was already
  reasoning about which prediction/refutation IDs the kube-audit query
  could test, and making that reasoning explicit in the schema felt
  clarifying rather than burdensome. The note I wrote in the field
  effectively doubles as lead-selection documentation. One observation:
  for a case where all predictions on all hypotheses are testable by one
  lead, `observes` is somewhat verbose (three hypothesis entries, each
  listing the full ID set). In a harder case (A.4, partial anchor
  authority, severity ceiling) where some predictions explicitly fall
  outside the lead's reach, `observes` would carry more diagnostic weight.
  Here it's net-positive but mildly over-specified.
  *Classification: new. No friction; minor "is this worth the lines?"
  question resolved in favor of including it for this pilot.*

- **P-new-4 — `authoritative-source` rename internalization.** I wrote
  `anchor-backed` twice in a draft before catching myself. The rename is
  simple but `anchor-backed` is deeply embedded from three prior walks.
  Once I consciously registered the new name, it stuck. The §11 distinction
  (authority describes reliable recording, NOT legitimacy) landed cleanly
  — I had already been treating it as observational in practice; the
  explicit spec language confirms the intent without adding a new cognitive
  load. The rename is the friction; the clarification is a net win.
  *Classification: new. Two muscle-memory slips in drafting, both caught.*

### Running pause count

- v1: 13 pauses, 7 real spec issues
- v2: 5 pauses, 1 real spec issue (NV1)
- v2.1: 3 pauses, 0 real spec issues (NV2.1-a/b are pattern shifts)
- v2.2: **4 pauses, 0 real spec issues.**

P-remain-1 carries over (unresolved spec ambiguity, non-blocking).
P-new-1/2/3/4 are all first-encounter orientation costs, not structural
defects. P-new-1 is the most substantive: the one-hop discipline is a
real rule that required deliberate application. P-new-4 is pure muscle-
memory debt from three prior walks and will not affect Haiku first-runs.

The pause count went from 3 to 4, but the nature of the pauses shifted:
v2.1's residual pause was a real spec ambiguity (rule 6 copy-paste
anxiety). v2.2's new pauses are orientation costs on new conventions,
all resolved on first encounter without spec consultation.

---

## Part 2 — The companion

```yaml
# Structured companion v2.2 for FALCO-2026-04-14-140327-a1b2c3d4
# Walk: CONTEXTUALIZE → (deferred HYPOTHESIZE) → GATHER loops 1-2 → CONCLUDE
# Schema: investigation-language v2.2

prologue:
  vertices:
    - id: v-001
      type: process
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
        - "Falco reports parent=null because the host-side parent is outside the container pid namespace; container-exec-history is required to materialize the parent chain before hypothesizing"
      citations:
        - "falco:event=b8e2c4d9-0abf-4d2e-9a71-cc1ea8df2d44"

    - id: v-002
      type: container
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

# Immediate parent of v-001 is opaque (parent=null in Falco output; confirmed
# by retrieval-sim: process-lineage is a dead lead for in-container processes,
# container-exec-history required). Discrimination deferred until l-001
# materializes the host-side parent and advances the level.
hypothesize:
  hypotheses: []

gather:
  - lead:
      id: l-001
      loop: 1
      name: container-exec-history
      mode: scope
      target: v-002
      # No intended_hypothesis_set — scope mode.
      query_details:
        system: runtime-audit-execve-feed
        template: "leads/container-exec-history/templates/execve-feed.md"
        query: "execve events where cgroup_container_id=a1b2c3d4 AND t ∈ [14:03:22, 14:03:32]"
        time_window: "±5s around alert"
        substitutions:
          container_id: "a1b2c3d4"
          t: "2026-04-14T14:03:27.412Z"
      outcome:
        observations:
          # Only what the execve feed directly observes: host-side runc process
          # and the spawned edge into the container pid namespace.
          # The kubectl-exec session and the initiating user are NOT materialized
          # here — those are observable only via kube-audit (l-002).
          vertices:
            - id: v-003
              type: process
              classification: host-runtime-shim
              identifier: "runc:[2:INIT] (host k8s-worker-07)"
              attributes:
                comm: "runc:[2:INIT]"
                cmdline: "runc init"
                host: "k8s-worker-07"
                runtime: "containerd"
                host_pid: 184733
              concerns:
                - "runc:[2:INIT] is the container-runtime exec shim; its own parent (containerd-shim) is not relevant to the discrimination question and is omitted"
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

      # Discrimination level advances from v-001 (bash) to v-003 (runc shim).
      # ?service-dropped-to-shell is mechanically refuted: the in-container bash
      # was spawned by the host-side runtime shim, not by the container's own
      # service process. Three canonical seeds remain (from retrieval-sim).
      #
      # One-hop parent discipline for all three hypotheses: v-003 (runc) connects
      # upstream via triggered_by to a session — that one-hop relation lands on a
      # session vertex, not a user. The user-level distinctions live in predictions.
      new_hypotheses:
        - id: h-001
          name: "?kubectl-exec-operator"
          canonical: true
          attached_to_vertex: v-003
          proposed_edge:
            relation: triggered_by
            parent_vertex:
              type: session
              classification: kubectl-exec-session
              attributes:
                initiator_kind: employee-with-exec-rbac
          predictions:
            - id: p1
              claim: "a kube-api pods/exec request targeting container a1b2c3d4 exists in the ±5s window, establishing a causal link between the API call and the runc exec"
            - id: p2
              claim: "the pods/exec request was initiated by an identity classified as employee-with-exec-rbac (not an automation identity)"
            - id: p3
              claim: "the source IP of the kube-api call classifies as corp-vpn-egress or internal-corp-network"
          refutation_shape:
            - id: r1
              claim: "no pods/exec request for container a1b2c3d4 appears in kube-audit in the ±5s window"
            - id: r2
              claim: "the pods/exec initiator classifies as automation-identity, not employee-with-exec-rbac"
          weight: null

        - id: h-002
          name: "?ci-pipeline-maintenance"
          canonical: true
          attached_to_vertex: v-003
          proposed_edge:
            relation: triggered_by
            parent_vertex:
              type: session
              classification: kubectl-exec-session
              attributes:
                initiator_kind: automation-identity
          predictions:
            - id: p1
              claim: "a kube-api pods/exec request targeting container a1b2c3d4 exists in the ±5s window"
            - id: p2
              claim: "the pods/exec initiator classifies as an automation-identity (service account or CI bot), not a human employee"
          refutation_shape:
            - id: r1
              claim: "no pods/exec request for container a1b2c3d4 appears in kube-audit in the ±5s window"
            - id: r2
              claim: "the pods/exec initiator classifies as employee-with-exec-rbac, not automation-identity"
          weight: null

        - id: h-003
          name: "?post-exploit-shell"
          canonical: true
          attached_to_vertex: v-003
          proposed_edge:
            # One backward hop from runc (v-003) is via triggered_by to a session.
            # The attacker-vs-legitimate distinction is expressed in predictions,
            # not in the parent_vertex.type — user is two hops upstream (session →
            # authenticated_as → user).
            relation: triggered_by
            parent_vertex:
              type: session
              classification: unclassified-session
              attributes:
                attacker_controlled: true
          predictions:
            - id: p1
              claim: "no pods/exec request for container a1b2c3d4 appears in kube-audit in the ±5s window (exec was not initiated via the legitimate API path)"
            - id: p2
              claim: "if a kube-audit exec record exists, the initiating identity is not associated with a sanctioned employee-with-exec-rbac role from a recognized network source"
          refutation_shape:
            - id: r1
              claim: "kube-audit returns a pods/exec request for container a1b2c3d4 initiated by an identity classified as employee-with-exec-rbac from a corp-vpn-egress or internal-corp-network source"
          concerns:
            - "stolen-credential bypass is unfalsifiable without MDM trust-chain evidence; refutation via r1 is 'no current evidence of credential compromise', not 'credential theft ruled out'"
          weight: null

  - lead:
      id: l-002
      loop: 2
      name: "anchor-lookup(kube-audit)"
      mode: trust
      target: v-003
      intended_hypothesis_set: [h-001, h-002, h-003]

      # Declare which prediction/refutation IDs this lead can test.
      # kube-audit observes: whether a pods/exec request exists for this container
      # (h-001.p1, h-002.p1, h-003.p1, plus all r1s that cite "no exec record");
      # the initiator identity and classification (h-001.p2, h-001.r2, h-002.p2,
      # h-002.r2, h-003.p2, h-003.r1); the source IP (h-001.p3).
      # kube-audit does NOT observe MDM device posture (h-003.concerns residual).
      observes:
        - hypothesis: h-001
          predictions: [p1, p2, p3]
          refutations: [r1, r2]
        - hypothesis: h-002
          predictions: [p1, p2]
          refutations: [r1, r2]
        - hypothesis: h-003
          predictions: [p1, p2]
          refutations: [r1]

      query_details:
        system: kube-audit
        template: "leads/anchor-lookup/templates/kube-audit-exec.md"
        query: "kube-audit entries: subresource=pods/exec AND target_container=a1b2c3d4 AND t ∈ [14:03:22, 14:03:32]"
        time_window: "±5s around alert"
        substitutions:
          container_id: "a1b2c3d4"
          t: "2026-04-14T14:03:27.412Z"
      outcome:
        observations:
          vertices:
            - id: v-004
              type: session
              classification: kubectl-exec-session
              identifier: "kubectl-exec alice→payments-api-7b9d8f4c8-xk2qm @14:03:25Z"
              attributes:
                subresource: "pods/exec"
                target_pod: "payments-api-7b9d8f4c8-xk2qm"
                target_container: "a1b2c3d4"
                kube_api_request_id: "7c1f8a22-kube-audit"
                client_user_agent: "kubectl/v1.28.3"
                rbac_role: "service-debug-operator"
              citations:
                - "kube-audit:request-id=7c1f8a22"

            - id: v-005
              type: user
              classification: employee-with-exec-rbac
              identifier: "alice@company.com"
              attributes:
                email: "alice@company.com"
                rbac_role_on_workload: "service-debug-operator"
                employment_status: "active"
              trust_root: true
              concerns:
                - "kube-audit faithfully records that alice@company.com held service-debug-operator RBAC and passed bearer-token auth; it does not certify that credentials were not stolen or coerced — residual stolen-credential concern tracked in h-003.concerns"
              citations:
                - "kube-audit:request-id=7c1f8a22"
                - "hr-directory:alice@company.com"

            - id: v-006
              type: ip
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
                kube_api_request_id: "7c1f8a22-kube-audit"
              authority:
                kind: authoritative-source
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
                kind: authoritative-source
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
                kind: authoritative-source
                source: "kube-audit:request-id=7c1f8a22"

        trust_root_reached: v-005

      resolutions:
        - hypothesis: h-001
          before: null
          after: "++"
          severity_of_test: severe
          matched_prediction_ids: [p1, p2, p3]
          reasoning: "kube-audit returned exec request 7c1f8a22 at 14:03:25.810Z targeting container a1b2c3d4 — p1 (pods/exec request in window) is confirmed via e-003. Alice@company.com holds service-debug-operator RBAC, classified employee-with-exec-rbac — p2 (employee initiator) is confirmed via e-004 (v-005). Source IP 10.200.14.77 classifies as corp-vpn-egress with MFA — p3 (sanctioned network source) is confirmed via e-005 (v-006). All three prediction IDs covered; strong-authority grounding via authoritative-source on e-003/e-004/e-005; weight transitions to ++."
          supporting_edges: [e-003, e-004, e-005]

        - hypothesis: h-002
          before: null
          after: "--"
          severity_of_test: severe
          matched_refutation_ids: [r2]
          reasoning: "kube-audit initiator is alice@company.com, classified employee-with-exec-rbac per v-005. Refutation r2 (initiator classifies as employee-with-exec-rbac, not automation-identity) is directly satisfied. Supporting edge e-004 is authoritative-source. r1 (no exec record in window) is not cited because the exec record was found; r2 is the operative refutation."
          supporting_edges: [e-004]

        - hypothesis: h-003
          before: null
          after: "--"
          severity_of_test: severe
          matched_refutation_ids: [r1]
          reasoning: "kube-audit returned a pods/exec request for container a1b2c3d4 initiated by alice@company.com (employee-with-exec-rbac) from 10.200.14.77 (corp-vpn-egress, MFA). Refutation r1 (pods/exec initiated by employee-with-exec-rbac from corp-vpn-egress or internal-corp-network) is fully satisfied by e-003/e-004/e-005. All three clauses of r1's claim are observationally grounded on authoritative-source edges. Residual stolen-credential concern remains in h-003.concerns; not falsified without MDM trust-chain evidence."
          supporting_edges: [e-003, e-004, e-005]

conclude:
  termination:
    category: trust-root
    rationale: "kube-audit (authoritative-source) classified v-005 (alice@company.com) as employee-with-exec-rbac with trust_root=true; backward traversal halts at v-005 — further traversal would require SSO/IdP logs not in scope"
  disposition: benign
  confidence: high
  matched_archetype: kubectl-exec-by-authorized-operator
  summary: "Bash was spawned in runtime-workload payments-api-...-xk2qm by host-side runc (runtime-audit, e-002) because kube-apiserver received a pods/exec request from alice@company.com over corp VPN with service-debug-operator RBAC (kube-audit, request 7c1f8a22). h-001 (?kubectl-exec-operator) confirmed ++ via all three prediction IDs matched with authoritative-source grounding. h-002 (?ci-pipeline-maintenance) refuted -- via r2 (human employee, not automation). h-003 (?post-exploit-shell) refuted -- via r1 (sanctioned exec path confirmed); stolen-credential residual noted in h-003.concerns. Trust-root termination at v-005."
```

---

## Part 3 — Closing observations

- **Line count: ~225 YAML lines** vs v2.1's ~215. The increase comes
  from two sources: (1) predictions now each carry an `id` field, adding
  ~9 lines across all hypotheses; (2) refutation shapes similarly gain
  `id` fields, adding ~6 lines. The `observes` block on l-002 adds ~15
  lines. Offset by no copy-paste rehearsal verbiage in the companion
  itself. Net: v2.2 is slightly longer than v2.1 in raw line count but
  the extra lines carry information (ID declarations), not ceremony.

- **Approximate write time: ~20 minutes for the companion, ~15 minutes
  for this commentary.** The companion write time is slightly longer than
  v2.1's ~15 minutes because of the h-003 parent_vertex recalibration
  (P-new-1) and the prediction ID scoping pause (P-new-2). Neither was
  a spec consultation — both resolved by re-reading the spec section I
  had already read. The authoritative-source rename (P-new-4) cost two
  draft corrections. Net: about 5 minutes slower than v2.1, all
  attributable to first-encounter orientation on new conventions.

- **Predictions for Haiku outcomes (three arms run in parallel):**

  - **H1 (likely cleaner than v2.1 on rule 6, possible friction on h-003
    parent_vertex):** ID-based rule 6 removes the literal-match failure
    mode entirely. The main new risk is h-003's one-hop parent discipline
    — Haiku may revert to `type: user` on h-003 based on v2.1 training
    signal. If H1 gets h-003 wrong, it will be `type: user` at the runc
    vertex, which violates the one-hop rule. Prediction: 85% clean pass,
    15% h-003 parent_vertex error. All other rules should be clean.

  - **H2 (likely minimal clean pass, same risk profile):** H2 tends to
    produce the minimal correct answer (v2.1 evidence). ID-based rule 6
    is strictly easier for a minimal-writer because there's less text to
    match. Same h-003 risk. Prediction: 85% clean pass, 15% h-003 error.

  - **H3 (benefits most from ID rule 6, carries the semantic-mismatch
    risk from v2.1):** v2.1's soft issue (H3 cited a refutation text that
    didn't fit the observation) was specifically a rule-6-adjacent
    failure. Under v2.2, ID-based matching removes the surface on which
    that particular failure occurred. H3 can still make a semantic error
    — cite r1 (no exec record found) when the observation is "exec record
    found" — but it's now explicit: if H3 cites `matched_refutation_ids:
    [r1]` while also reporting that the exec record was found, the mismatch
    between the reasoning field and the cited ID is unambiguous and
    catchable by a Haiku judge. The soft issue doesn't disappear; it
    becomes explicit. Prediction: H3's systematic risk drops from
    "subtle semantic mismatch at literal match" to "explicit ID mismatch
    visible in reasoning field" — a better failure mode. 75% clean pass,
    25% explicit ID mismatch or h-003 parent error.

  - **Aggregate prediction:** 2/3 to 3/3 clean pass on first run.
    The new failure surface is h-003's parent_vertex shape; the retired
    failure surface is rule 6 literal text. Net risk approximately
    stable, but v2.2's failures will be more explicit and catchable.

- **The `observes` field on l-002 felt useful but is underloaded in
  this case.** Because all predictions on all three hypotheses are
  testable by kube-audit, the `observes` block lists everything — it
  reads as "this lead can test everything." The field will carry more
  weight in A.4 (S3 list burst), where partial anchor authority and
  severity-ceiling termination require explicitly declaring which
  predictions a lead CAN'T test. Recommend including it here (and
  including it in the Haiku prompt) so the convention is established
  before the harder case exercises it.

- **The `authoritative-source` §11 clarification is the cleanest win in
  v2.2 for correctness semantics.** The rename is a minor friction cost;
  the clarification — authority is observational, legitimacy is derived
  — is conceptually important for harder cases. In A.1, alice@company.com
  is benign and the distinction doesn't matter. In A.4 or a stolen-
  credential scenario, the distinction is load-bearing: kube-audit is
  authoritative for the API call it recorded, but whether that call was
  by the legitimate account owner requires MDM + SSO trust-chain
  evidence. The explicit §11 language prepares the companion writer for
  that case without adding cost to the simple case.

- **One-line verdict: v2.2 is ready to lock and move to A.4.** The six
  changes all land — none introduced validator-violation risk, the ID-
  based rule 6 is strictly better than literal-text discipline, and the
  h-003 parent_vertex correction is conceptually right (and testable in
  the Haiku arms). The observes field and §11 clarification are net
  additions that earn their lines. Proceed to A.4 (S3 list burst) as the
  severity-ceiling stress test.
