# Sonnet Reference Companion v2.3 — Pilot Case (A.1 shell-in-container)

Translation of the A.1 case to v2.3. **This is a regression check, not
a stress test** — A.1 is too narrow to exercise most of v2.3's new
mechanisms. The translation is mostly backward-compatible and mostly
clean. What's interesting is the difficulties I hit, several of which
are spec-clarity opportunities worth fixing before lock.

Inputs: `alert.json`, `spec-condensed-v2.3.md`, `retrieval-sim-v2.yaml`.
I consulted `reference-v2.2.md` for friction-log delta tracking.

---

## Part 1 — What changed, what was hard

### What A.1 did NOT exercise

Calibration first. A.1 is the backward-compatibility floor, not the
test bench for v2.3's new mechanisms:

- **Hierarchical hypothesis IDs** (`h-001-001`, etc.) — A.1 terminates
  at loop 2 on trust-root; no hypothesis is ever refined into children.
  The convention is inert on this case.
- **New types `database`, `storage`, `network-device`, `endpoint`
  as focus** — A.1 uses `process`, `container`, `session`, `identity`,
  `ip`. The only new type that shows up is `identity` (replacing `user`).
- **Action-as-vertex pattern (`command` + `targeted`)** — A.1's
  SIEM-observed events are runtime process lifecycle (Falco execve,
  kube-audit pods/exec) which I modeled with the process-entity /
  edge-verb pattern. See D1.
- **Partial authority cap (rule 16)** — kube-audit is full-authority
  for "who called pods/exec at this time." No cap fires.
- **Severity-ceiling termination and `ceiling_test`** — A.1 terminates
  on trust-root.
- **Lean methodology's full payoff** — A.1 already had fairly lean
  hypotheses in v2.2; the deepest leanness move would collapse the
  three hypotheses into one or two, which I rejected (see D3).

**Translation verdict on A.1 specifically:** v2.3 does not break A.1.
The walk produces the same hypothesis resolutions (++/--/--), the same
disposition (benign), the same matched archetype. The v2.3 additions
that do apply (`identity` rename, `trust_anchor_result` lift, dropped
`canonical`) are surgical and clean.

**What A.1 cannot validate about v2.3:** whether the refinement-chain
convention works in practice, whether `command`-as-action generalizes
across real SIEM observation classes, whether hierarchical IDs stay
readable at depth ≥3, whether the new types feel natural on cases
that need them. The A.4 walk (case-a4) and the rule-5710 case-real
translation are the right stress tests. A v2.3 lock based on a clean
A.1 regression alone is under-scoped.

### What changed vs v2.2 on this specific case

- **`type: user` → `type: identity`** with `attributes.kind: user`. The
  only type rename that fires. Alice moves from `v-005: user` to
  `v-005: identity, attributes.kind: user, provider: corp-sso`. Clean.
- **`anchor-source` vertex → `outcome.trust_anchor_result` field.** The
  v2.2 walk did not actually materialize anchor-source vertices for
  kube-audit (it materialized session/identity/ip directly), so there's
  nothing to delete — but there's a new field to fill in.
- **Dropped `canonical: true` on the three hypotheses.** The retrieval-
  sim still marks them canonical; the agent just doesn't copy the flag.
- **Lean predictions.** v2.2 had 3 predictions per benign hypothesis
  and 1 for h-003. I wrote 2 per benign and 1 for h-003 — leaner but
  not maximally lean. See D3.
- **Rule 16** (partial authority caps weight) is trivially satisfied —
  kube-audit's `authority_for_question: full` lets h-001 reach ++.

### Difficulties encountered

**D1 — `command` vs edge-verb ambiguity for runtime observations.**
v2.3 §10 says `targeted` is "the new generic action-target relation
for command vertices. Use it for SIEM-observed actions (CloudTrail,
kube-audit, pam-audit, sshd-audit, **file-write events**, etc.)" —
the parenthetical explicitly includes file-write events. But the v2.2
worked example modeled file writes with `process → wrote → file` (edge
verb). **Which applies to Falco's process-spawn observation?**

I chose process-entity + edge-verb (`v-003 process(runc) → spawned →
v-001 process(bash)`) for two reasons: (a) a process is an entity with
a lifetime, not a one-shot action — the observation describes an
entity's birth, not an action distinct from its effect; (b) the prior
walks used this pattern. But the spec's explicit mention of file-write
events under `command`+`targeted` muddies the rule.

**Proposed spec clarification:** command vertices are for actions
that don't leave a persistent entity to model as a vertex — API calls,
auth attempts, SQL queries, list operations, cloud control-plane
invocations. Runtime lifecycle observations of process/file/socket
(where the observation creates a first-class entity in the graph)
stay on edge verbs. Drop "file-write events" from the §10 examples.
**This is a clarity bug in v2.3 that should be fixed before lock.**

**D2 — Host context decision.** v2.3 §B says the host may be a
first-class `endpoint` vertex "when the host itself is the focus."
In A.1, the host (`k8s-worker-07`) is incidental — the investigation
focuses on the container. I kept the host as container attributes.
But "when the host is the focus" is a judgment call the spec doesn't
tightly define. A.1 didn't force the call, but a case where a host-
scoped lead runs (e.g., `host_query` against the worker node for
process list) would. **Propose:** add a one-paragraph note in §3 or
§9 about when host-as-attribute is preferred vs. host-as-vertex.

**D3 — Retrieval-sim's three seeds vs lean methodology's "write fewer"
ethos.** The retrieval-sim for A.1's post-scope vertex shape suggests
three canonical hypothesis names. Lean methodology wants fewer and
simpler hypotheses. The deepest lean version collapses to either:

- **Two hypotheses:** `?sanctioned-kube-exec` (benign) + `?unsanctioned-
  kube-exec` (adversarial). Clean, but loses the operator-vs-automation
  discrimination as a named distinction.
- **One hypothesis:** `?kube-triggered-exec` with predictions about
  presence + sanctioned-identity + corp-source. Cleanest but loses
  the adversarial-as-separate-hypothesis discipline.

I stayed with three named hypotheses (to preserve cross-case retrieval
matching on hypothesis name), but wrote each with 1-2 predictions
instead of v2.2's 3. This is a compromise.

**The spec doesn't resolve this tension.** When retrieval-sim suggests
N seeds but lean methodology suggests fewer, what should the agent do?
Three candidate answers:

1. **Retrieval-sim wins on names, lean wins on predictions.** Write
   the named hypotheses but make each one as lean as possible. (What
   I did.)
2. **Lean wins on count.** Collapse to one or two lean hypotheses and
   let retrieval miss on name. Prior-case matching degrades.
3. **Use hierarchical IDs.** Write one lean parent (`h-001: ?kube-
   triggered-exec`) at loop 1, let the trust lead confirm it, then
   refine into `h-001-001` (operator) / `h-001-002` (automation) /
   `h-001-003` (compromised) as refinements at loop 2.

Option 3 is actually the cleanest and most v2.3-idiomatic, but it
over-engineers A.1 (the refinements would all resolve in the same
lead that created the parent). **Worth a spec section on "when to
use hierarchical refinement vs parallel hypotheses at the same level."**

**D4 — `observations` vs `trust_anchor_result.structured_fields`
overlap.** The kube-audit trust lead materializes three vertices
(session, identity, ip) with full attributes in `outcome.observations`.
Under v2.3 rule 13, it MUST also emit `trust_anchor_result.structured_
fields`. Writing the file, I found that every field I put in
`structured_fields` was ALREADY in the vertex attributes:

- `structured_fields.user` = `v-005.identifier`
- `structured_fields.user_classification` = `v-005.classification`
- `structured_fields.source_ip` = `v-006.attributes.ip`
- `structured_fields.source_ip_classification` = `v-006.classification`
- `structured_fields.request_id` = `v-004.attributes.kube_api_request_id`
- `structured_fields.verb, target_resource` = `v-004.attributes.subresource`

**Every single field is duplicated.** The writer types the same facts
twice. This is a real friction.

**Two resolutions:**

1. **Accept the duplication** and document it as "graph observations
   are for the ontology, structured_fields are for the retrieval
   index — they serve different consumers."
2. **Derive `structured_fields` in the distiller** from observations
   + a per-anchor schema. Drop it from the writer's responsibility.
   Keep `trust_anchor_result: {anchor_id, kind, result,
   authority_for_question}` as the writer's minimum — that's what's
   NEW. The normalized fields projection is distiller work.

**I'd strongly recommend (2).** It's consistent with v2.3's north
star of "push retrieval load to the distiller." The writer types
the minimum; the distiller projects the normalized view. **This
should be fixed before v2.3 locks.**

**D5 — Adversarial hypothesis as a single-prediction negation.**
Under lean methodology, `?post-exploit-shell` naturally has one
prediction, but that prediction is an absence claim: "no legitimate
kube-audit record matching a sanctioned employee from a corp network
source." Rule 6 completeness treats this uniformly (one prediction,
one match or not), but the framing is awkward — the refutation_shape
is the POSITIVE observation ("kube-audit returns a sanctioned exec")
and the prediction is its NEGATION. Writing both feels redundant,
and the reasoning for a `--` resolution points at the refutation_shape
rather than the prediction.

This isn't a v2.3 regression — v2.2 had the same shape — but the
leanness rule surfaces it more sharply. **Small spec note:** for
adversarial hypotheses whose entire content is "the benign
observation is absent," consider allowing a hypothesis with ONLY
refutation_shape (empty predictions). Currently rule 6 requires
non-empty `matched_prediction_ids` for `++`, which is fine, but
doesn't require non-empty `predictions` for the hypothesis record
itself. If the hypothesis has empty predictions, `++` is
unreachable — which is actually the right semantics for a purely
adversarial hypothesis (it can only reach `--`, not `++`). Worth
calling out in §6.

### Running count

| Version | Pauses | Real spec issues | Judgment calls |
|---------|--------|------------------|----------------|
| v1      | 13     | 7                | —              |
| v2      | 5      | 1                | —              |
| v2.1    | 3      | 0                | —              |
| v2.2    | 4      | 0                | 4 (orientation) |
| v2.3    | 5      | **2 (D1, D4)**   | **3 (D2, D3, D5)** |

D1 and D4 are real spec bugs that should be fixed before v2.3 locks.
D2/D3/D5 are clarity notes — things the spec doesn't resolve that
careful writers will hit on real cases.

---

## Part 2 — The companion

```yaml
# Structured companion v2.3 for FALCO-2026-04-14-140327-a1b2c3d4
# Walk: CONTEXTUALIZE → (deferred HYPOTHESIZE) → GATHER loops 1-2 → CONCLUDE
# Schema: investigation-language v2.3

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
        - "Falco reports parent=null because the host-side parent is outside the container pid namespace; container-exec-history scope lead required before hypothesizing"
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
        # D2: host context as container attributes. The host (k8s-worker-07) is
        # not the focus of this investigation; the container is. Under v2.3 this
        # is still the right call, but the spec doesn't tightly define the
        # threshold.
        host_name: "k8s-worker-07"
        host_role: "kubernetes-worker-node"
        cluster: "prod-us-east-1"
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

# Immediate parent of v-001 is opaque (parent=null in Falco output because
# the host-side parent lives in a different pid namespace). Discrimination
# deferred until l-001 materializes the host-side parent.
hypothesize:
  hypotheses: []

gather:
  - lead:
      id: l-001
      loop: 1
      name: container-exec-history
      mode: scope
      target: v-002
      # D1: Falco's execve observation is modeled as a process entity (v-003) plus a
      # spawned edge (e-002), NOT as a command vertex + targeted edge. A process is
      # an entity with a lifetime, not a one-shot action. The v2.3 §10 mention of
      # "file-write events" under `command+targeted` is inconsistent with this choice
      # and should be clarified.
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
          # Mechanical lead materializes only what the execve feed directly observes:
          # the host-side runc process and the spawned edge into the container.
          # The kubectl-exec session and initiating identity are NOT materialized here
          # — those are observable only via kube-audit (l-002).
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
      # Three hypothesis seeds per retrieval-sim, each written LEAN (1-2 predictions
      # minimal). No `canonical` field under v2.3.
      #
      # D3: Lean methodology tension — retrieval-sim suggests three canonical names,
      # lean ethos would collapse them or refine hierarchically. I kept three named
      # hypotheses to preserve cross-case retrieval matching, and wrote each lean.
      new_hypotheses:
        - id: h-001
          name: "?kubectl-exec-operator"
          attached_to_vertex: v-003
          proposed_edge:
            relation: triggered_by
            parent_vertex:
              type: session
              classification: kubectl-exec-session
          predictions:
            - id: p1
              claim: "a kube-api pods/exec request targeting container a1b2c3d4 exists in the ±5s window, initiated by an identity classified as employee-with-exec-rbac"
            - id: p2
              claim: "the source IP of that kube-api call classifies as corp-vpn-egress or internal-corp-network"
          refutation_shape:
            - id: r1
              claim: "no pods/exec request for container a1b2c3d4 appears in kube-audit in the ±5s window"
            - id: r2
              claim: "the pods/exec initiator classifies as automation-identity, not employee-with-exec-rbac"
          weight: null

        - id: h-002
          name: "?ci-pipeline-maintenance"
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
              claim: "a kube-api pods/exec request targeting container a1b2c3d4 exists in the ±5s window, initiated by an identity classified as automation-identity (service account or CI bot)"
            - id: p2
              claim: "the source of the kube-api call is an internal-cluster-node or build-infrastructure endpoint"
          refutation_shape:
            - id: r1
              claim: "no pods/exec request for container a1b2c3d4 appears in kube-audit in the ±5s window"
            - id: r2
              claim: "the pods/exec initiator classifies as employee-with-exec-rbac, not automation-identity"
          weight: null

        # D5: adversarial hypothesis with a single absence-claim prediction.
        # The framing is awkward — the refutation_shape (positive observation)
        # carries the information, the prediction is its negation.
        - id: h-003
          name: "?post-exploit-shell"
          attached_to_vertex: v-003
          proposed_edge:
            relation: triggered_by
            parent_vertex:
              type: session
              classification: unclassified-session
              attributes:
                attacker_controlled: true
          predictions:
            - id: p1
              claim: "no legitimate kube-api pods/exec record matches the shape of an authenticated employee-with-exec-rbac initiator from a corp-network source; either no record exists or the initiator and source are unsanctioned"
          refutation_shape:
            - id: r1
              claim: "kube-audit returns a pods/exec request for container a1b2c3d4 authenticated as employee-with-exec-rbac from a corp-vpn-egress or internal-corp-network source"
          concerns:
            - "stolen-credential bypass is unfalsifiable without MDM trust-chain evidence; refutation here is 'no current evidence of credential compromise', not 'credential theft ruled out'"
          weight: null

  - lead:
      id: l-002
      loop: 2
      name: "anchor-lookup(kube-audit)"
      mode: trust
      target: v-003
      intended_hypothesis_set: [h-001, h-002, h-003]
      observes:
        - hypothesis: h-001
          predictions: [p1, p2]
          refutations: [r1, r2]
        - hypothesis: h-002
          predictions: [p1, p2]
          refutations: [r1, r2]
        - hypothesis: h-003
          predictions: [p1]
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

            # v-005 uses the new `identity` type (was `user` in v2.2).
            - id: v-005
              type: identity
              classification: employee-with-exec-rbac
              identifier: "alice@company.com"
              attributes:
                kind: user                         # new v2.3: kind attribute
                provider: corp-sso                 # new v2.3: provider attribute
                email: "alice@company.com"
                rbac_role_on_workload: "service-debug-operator"
                employment_status: "active"
              trust_root: true
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

        # D4: every field in structured_fields below is already carried in
        # v-004/v-005/v-006 attributes and classifications. The writer types
        # the same facts twice. Recommend: distiller derives structured_fields
        # from observations; remove from writer-side schema.
        trust_anchor_result:
          anchor_id: kube-audit
          kind: kube-audit
          result: confirmed
          as_of: "2026-04-14T14:03:25.810Z"   # event anchor: audit-log event time
          authority_for_question: full
          # structured_fields dict removed (v2.3 spec change): substantive anchor
          # return is already materialized as v-004/v-005/v-006 + e-003/e-004/e-005
          # in the graph; the dict was pure duplication.

        trust_root_reached: v-005

      resolutions:
        - hypothesis: h-001
          before: null
          after: "++"
          severity_of_test: severe
          matched_prediction_ids: [p1, p2]
          reasoning: "kube-audit returned exec request 7c1f8a22 at 14:03:25.810Z targeting container a1b2c3d4, authenticated as alice@company.com (employee-with-exec-rbac via SSO+service-debug-operator RBAC). p1 (pods/exec request + employee-with-exec-rbac initiator) satisfied via v-004+v-005+e-004. p2 (corp-network source) satisfied via v-006+e-005 (10.200.14.77 classifies corp-vpn-egress, MFA-verified). Both prediction IDs covered; authority_for_question=full; strong-authority grounding via e-003/e-004/e-005 (all authoritative-source). Weight transitions to ++."
          supporting_edges: [e-003, e-004, e-005]

        - hypothesis: h-002
          before: null
          after: "--"
          severity_of_test: severe
          matched_refutation_ids: [r2]
          reasoning: "kube-audit initiator is alice@company.com, classified employee-with-exec-rbac — not automation-identity. r2 directly satisfied. Supporting edge e-004 is authoritative-source. Weight transitions to --."
          supporting_edges: [e-004]

        - hypothesis: h-003
          before: null
          after: "--"
          severity_of_test: severe
          matched_refutation_ids: [r1]
          reasoning: "kube-audit returned a pods/exec request for container a1b2c3d4 authenticated as alice@company.com (employee-with-exec-rbac) from 10.200.14.77 (corp-vpn-egress, MFA-verified). r1 fully satisfied — all three clauses (exec record present, sanctioned employee initiator, corp network source) met on authoritative-source edges e-003/e-004/e-005. Residual stolen-credential concern remains in h-003.concerns; not falsified without MDM trust-chain evidence."
          supporting_edges: [e-003, e-004, e-005]

conclude:
  termination:
    category: trust-root
    rationale: "kube-audit (authority_for_question=full) classified v-005 (alice@company.com) as employee-with-exec-rbac with trust_root=true; backward traversal halts at v-005 — further traversal would require SSO/IdP logs not in scope"
  disposition: benign
  confidence: high
  matched_archetype: kubectl-exec-by-authorized-operator
  summary: "Bash was spawned in runtime-workload payments-api-...-xk2qm by host-side runc (runtime-audit, e-002) because kube-apiserver received a pods/exec request from alice@company.com over corp VPN with service-debug-operator RBAC (kube-audit, request 7c1f8a22). h-001 (?kubectl-exec-operator) confirmed ++ with full prediction coverage and authoritative-source grounding. h-002 (?ci-pipeline-maintenance) refuted -- via r2 (human initiator, not automation). h-003 (?post-exploit-shell) refuted -- via r1 (sanctioned exec path). Trust-root termination at v-005. Residual stolen-credential concern tracked in h-003.concerns."
```

---

## Part 3 — Closing observations

- **Line count: ~275** vs v2.2's ~215. The +60 lines come from
  `trust_anchor_result` (~18 lines, of which ~12 are the duplicated
  `structured_fields` dict flagged in D4), the `observes` block
  being more explicit, and translation-note comments. If D4 is fixed
  (distiller derives `structured_fields`), v2.3 companion drops to
  ~260 lines — a ~20-line tax for `trust_anchor_result.anchor_id +
  kind + result + authority_for_question`, which is a reasonable cost
  for the retrieval lift.
- **No validator violations.** All 16 rules satisfied on first write.
  Rules 13-16 (the new v2.3 rules) are either satisfied trivially
  (13 on l-002) or not exercised (14/15/16).
- **A.1 is not where v2.3 earns its keep.** The rule-5710 case
  (stranded anchor results) and the A.4 case (partial authority,
  severity ceiling, ID burst on a database) are where the v2.3
  additions pay off. A clean A.1 regression says "v2.3 doesn't
  break backward compatibility" — nothing more.
- **D1 and D4 are spec-clarity bugs worth fixing before lock.**
  D1 (command vs edge-verb) is a choice the spec text doesn't
  currently make consistently. D4 (`structured_fields` duplication)
  violates the "push retrieval load to the distiller" north star
  that the rest of v2.3 follows cleanly. Both fixes are small.
- **D2/D3/D5 are clarity notes.** Not blockers; spec could address
  them with short paragraphs.
- **The difficulty count rose (v2.2 had 4 pauses, 0 real spec issues;
  v2.3 has 5 pauses, 2 real spec issues).** This is not alarming —
  v2.3 adds material (new types, action-vertex pattern,
  `trust_anchor_result`, hierarchical IDs, partial authority) and
  every new mechanism introduces decision points. The right measure
  is whether the real issues are small (yes, D1 and D4 are) and
  whether they're caught by the fidelity/retrieval experiments
  rather than by in-production pain (yes).
