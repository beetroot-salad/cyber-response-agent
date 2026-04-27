## Shape A — worked examples

You've already decided Shape A: mechanism is pinned, authorization is the open question. The craft questions are **anchor selection** (which authority's record actually answers the predicate?), **predicate phrasing** (one observable check the anchor can categorically resolve), and **integrity bundling** (does the anchor's verdict cover identity-of-use too, or do you need a peer hypothesis?).

### Example 1 — IAM policy modification by a service account

**Alert:** cloud audit log shows `account-svc-deploy` modified IAM policy on `resource-bucket-prod` 2 minutes ago. Prologue carries `v-actor-svc-deploy`, `v-resource-bucket-prod`, and a `modified_policy` edge. The mechanism is fully pinned by the audit log itself — the API call, the actor identity, and the target resource are all in the alert. The open question is purely *was this change authorized*.

**Anchor selection.** Candidates:
- `iam-policy-history` — tells you what changed, not whether it was approved. Wrong question.
- `change-management-tickets` — the org's record of approved changes. Authoritative for "was this change approved" *if* the org operates with change-management discipline.
- `deploy-pipeline-runs` — the CI/CD record of deploys that touched this resource in the relevant window. Authoritative if the actor is a deploy-pipeline service account.

`account-svc-deploy` is a deploy-pipeline identity by name and prior usage; `deploy-pipeline-runs` is the right anchor. The predicate becomes: *"a deploy-pipeline run owned by an authorized initiator executed against `resource-bucket-prod` in the ±5min window of the policy change, and the run's manifest declares an IAM-policy mutation on that resource"*.

**Integrity bundling.** A deploy-run record names its initiator (the human or CI trigger that opened the run) — confirming the run answers both *was the change authorized* and *who actually did it*. No peer hypothesis needed; the contract's anchor closes both questions. Document the bundling with `integrity_waived`.

```yaml
hypothesize:
  hypotheses:
    - id: h-001
      name: "?deploy-pipeline-initiated-policy-change"
      attached_to_vertex: v-resource-bucket-prod
      proposed_edge:
        relation: modified_policy
        parent_vertex: {type: deploy_run, classification: deploy-pipeline-run-on-resource}
      story: |
        A deploy-pipeline run owned by an authorized initiator
        executed against `resource-bucket-prod` in a window
        bracketing the policy change, and the run's manifest
        declared the policy mutation as part of its planned
        actions. The audit log records `account-svc-deploy` as
        the on-wire actor because deploy runs execute under
        that service identity.
      predictions:
        - id: p1
          subject: proposed_edge
          claim: "deploy-pipeline-runs records an active run against `resource-bucket-prod` whose execution window contains the policy-change timestamp"
          from_story_link: "deploy-pipeline run executed against the resource in a window bracketing the change"
        - id: p2
          subject: proposed_edge
          claim: "the matching run's manifest declares an IAM-policy mutation on `resource-bucket-prod`"
          from_story_link: "the run's manifest declared the policy mutation"
      refutation_shape:
        - id: r1
          refutes_predictions: [p1]
          claim: "no deploy-pipeline run's execution window contains the policy-change timestamp"
        - id: r2
          refutes_predictions: [p2]
          claim: "a matching run exists but its manifest does not declare an IAM-policy mutation on the resource"
      authorization_contract:
        - id: ac1
          edge_ref: proposed
          anchor_kind: deploy-pipeline-runs
          predicate: "an active deploy run with a matching execution window and a manifest declaring this resource's policy mutation, owned by an authorized initiator"
          on_unauthorized: escalate
          on_indeterminate: escalate
      integrity_waived: "deploy-pipeline-runs records the initiator that opened the run; confirming the run authorizes the change and identifies the responsible actor in one resolution."
      weight: null
```

**Selected lead:** `deploy-pipeline-run-lookup` — query the deploy-pipeline-runs anchor for runs against `resource-bucket-prod` with an execution window covering the change timestamp; verify manifest. Resolves `h-001.ac1`.

**Pitfalls:**
- Don't add a peer `?stolen-credentials-modified-policy` — its predictions are just negations of h-001's, and its refutations duplicate h-001's. That's the invoker-identity anti-pattern; rule #32 will reject it. The authorization contract handles the adversarial case via `on_unauthorized: escalate`.
- Don't anchor against `change-management-tickets` instead of `deploy-pipeline-runs` for a deploy-service-account actor — change-management tickets cover human-initiated changes; pipeline runs are the closer record for automated actors. Pick the anchor whose grain matches the actor.

---

### Example 2 — privileged container exec under a build orchestrator

**Alert:** container runtime auditor reports a privileged exec inside container `container-build-7f2a` with parent process `runc`, child cmdline `/bin/sh -c "tar -xzf …"`. Prologue carries `v-container-build-7f2a`, the parent-process vertex, and a `privileged_exec` edge. Loop 1 confirmed via process-lineage that `runc`'s grandparent is the build-orchestrator daemon on the host (`v-build-orchestrator`). Mechanism is pinned: a host-side build job crossed the container boundary via runc-exec, which is the orchestrator's documented execution model. The open question is whether *this specific exec* was an approved build run.

**Anchor selection.** The build-orchestrator emits a `build-runs` log per job with the run-id, the initiating identity (a developer, a scheduled trigger, or a CI webhook), and the script body. Anchor against `build-runs` with a predicate matching execution-time window plus the script body the runc-exec invoked.

**Integrity bundling.** Build-runs records the initiator — same pattern as Example 1. One hypothesis with the contract; no peer.

```yaml
hypothesize:
  hypotheses:
    - id: h-001
      name: "?orchestrator-initiated-build-exec"
      attached_to_vertex: v-container-build-7f2a
      proposed_edge:
        relation: privileged_exec
        parent_vertex: {type: build_run, classification: build-orchestrator-run}
      story: |
        The build orchestrator on the host opened a build run
        targeting `container-build-7f2a` and dispatched a script
        step that invoked the observed `tar -xzf …` command
        through runc-exec. Loop 1 confirmed the parent runc's
        grandparent is the orchestrator daemon, which matches
        the orchestrator's documented exec path. The build-runs
        log should record an active run whose dispatched script
        body matches the observed cmdline.
      predictions:
        - id: p1
          subject: proposed_edge
          claim: "build-runs records an active run targeting `container-build-7f2a` whose execution window contains the exec timestamp"
          from_story_link: "the build orchestrator opened a build run targeting the container"
        - id: p2
          subject: proposed_edge
          claim: "the matching run's dispatched script body contains the observed cmdline as one of its steps"
          from_story_link: "dispatched a script step that invoked the observed command"
      refutation_shape:
        - id: r1
          refutes_predictions: [p1]
          claim: "no build run's execution window contains the exec timestamp"
        - id: r2
          refutes_predictions: [p2]
          claim: "a matching run exists but its dispatched script body does not contain the observed cmdline"
      authorization_contract:
        - id: ac1
          edge_ref: proposed
          anchor_kind: build-runs
          predicate: "an active build run targeting this container with a matching execution window and a dispatched script body containing the observed cmdline"
          on_unauthorized: escalate
          on_indeterminate: escalate
      integrity_waived: "build-runs records the initiator that opened the run (developer, scheduled trigger, or CI webhook); confirming the run authorizes the exec and identifies the responsible actor in one resolution."
      weight: null
```

**Selected lead:** `build-run-lookup` — query the build-orchestrator anchor for runs against `container-build-7f2a` covering the exec timestamp; verify script body matches cmdline. Resolves `h-001.ac1`.

**Pitfalls:**
- Don't loosen the predicate to *"any active build run"* without the script-body match — an unrelated concurrent build run would falsely satisfy the contract. Two predictions (p1 window-match, p2 body-match) keep the anchor honest.
- Don't pre-write the script body as a literal regex in the predicate — predicates are natural-language; the lead handles the comparison. Pinning a regex at PREDICT time leaks foreground state into the contract.
