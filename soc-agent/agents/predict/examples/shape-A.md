## Shape A — worked examples

You've already decided Shape A: mechanism is pinned, authorization is the open question. The craft questions are **anchor selection** (which authority's record actually answers the predicate?), **predicate phrasing** (one observable check the anchor can categorically resolve), and **integrity bundling** (does the anchor's verdict cover identity-of-use too, or do you need a peer hypothesis?).

Shape A is wrong when the focus unknown is still mechanism-shaped. If SCREEN or a prior loop surfaced an unmodeled event-shape dimension (burst geometry, process lineage, session-origin, source-port/session geometry), first cover that dimension with Shape E readings or include it as a prediction on the story. An authorization anchor confirms permission for a proposed edge; it does not prove that the alert-time event shape came from that edge.

The dense form for Shape A is one or more `:H` rows (metadata-only — id, name, attached_to, edge geometry, parent attrs, integrity_waived rationale, weight=null, status=active), per-hypothesis sub-blocks `:P h-{id}.preds` / `.refuts` / `.authz` (and `.attr_preds`, `.comparisons` when relevant), the matching `### story h-{id}` prose with sentence IDs (`s1.`, `s2.`, ...), and the always-required `:R routing` block. No `:L lead_preds`.

### Example 1 — IAM policy modification by a service account

**Alert:** cloud audit log shows `account-svc-deploy` modified IAM policy on `resource-bucket-prod` 2 minutes ago. Prologue carries `v-actor-svc-deploy`, `v-resource-bucket-prod`, and a `modified_policy` edge. The mechanism is fully pinned by the audit log itself — the API call, the actor identity, and the target resource are all in the alert. The open question is purely *was this change authorized*.

**Anchor selection.** Candidates:
- `iam-policy-history` — tells you what changed, not whether it was approved. Wrong question.
- `change-management-tickets` — the org's record of approved changes. Authoritative for "was this change approved" *if* the org operates with change-management discipline.
- `deploy-pipeline-runs` — the CI/CD record of deploys that touched this resource in the relevant window. Authoritative if the actor is a deploy-pipeline service account.

`account-svc-deploy` is a deploy-pipeline identity by name and prior usage; `deploy-pipeline-runs` is the right anchor. The predicate becomes: *"a deploy-pipeline run owned by an authorized initiator executed against `resource-bucket-prod` in the ±5min window of the policy change, and the run's manifest declares an IAM-policy mutation on that resource"*.

**Integrity bundling.** A deploy-run record names its initiator (the human or CI trigger that opened the run) — confirming the run answers both *was the change authorized* and *who actually did it*. No peer hypothesis needed; the contract's anchor closes both questions. Document the bundling with `integrity_waived` on the `:H` row.

```
predict loop=1 shape=A

### story h-001
s1. A deploy-pipeline run owned by an authorized initiator executed against `resource-bucket-prod` in a window bracketing the policy change.
s2. The run's manifest declared the IAM-policy mutation as part of its planned actions.
s3. The audit log records `account-svc-deploy` as the on-wire actor because deploy runs execute under that service identity.

:H hypotheses [id|name|attached_to|rel|parent_type|parent_class|parent_attrs?|integrity_waived?|weight|status]
h-001|?deploy-pipeline-initiated-policy-change|v-resource-bucket-prod|modified_policy|deploy_run|deploy-pipeline-run-on-resource||"deploy-pipeline-runs records the initiator that opened the run; confirming the run authorizes the change and identifies the responsible actor in one resolution"|null|active

:P h-001.preds [id|subject|kind|from_story|claim]
p1|proposed_edge|absolute|s1|"deploy-pipeline-runs records an active run against `resource-bucket-prod` whose execution window contains the policy-change timestamp"
p2|proposed_edge|absolute|s2|"the matching run's manifest declares an IAM-policy mutation on `resource-bucket-prod`"

:P h-001.refuts [id|refutes|kind|claim]
r1|p1|absolute|"no deploy-pipeline run's execution window contains the policy-change timestamp"
r2|p2|absolute|"a matching run exists but its manifest does not declare an IAM-policy mutation on the resource"

:P h-001.authz [id|edge_ref|anchor_kind|predicate|on_unauth|on_indet]
ac1|proposed|deploy-pipeline-runs|"an active deploy run with a matching execution window and a manifest declaring this resource's policy mutation, owned by an authorized initiator"|esc|esc

:R routing
selected_lead         deploy-pipeline-run-lookup
composite_secondary   -
override_data_source  -
rationale             "anchor query against deploy-pipeline-runs resolves both authorization and identity-of-use in one trip; integrity_waived bundles the actor identification under the same record"
```

**Pitfalls:**
- Don't add a peer `?stolen-credentials-modified-policy` — its predictions are just negations of h-001's, and its refutations duplicate h-001's. That's the invoker-identity anti-pattern; rule #32 will reject it. The authorization contract handles the adversarial case via `on_unauth=esc`.
- Don't anchor against `change-management-tickets` instead of `deploy-pipeline-runs` for a deploy-service-account actor — change-management tickets cover human-initiated changes; pipeline runs are the closer record for automated actors. Pick the anchor whose grain matches the actor.
- Don't omit `integrity_waived` when bundling integrity into the contract — it documents *why* one anchor closes both authorization and identity-of-use questions, which is the audit trail for skipping a peer hypothesis.

---

### Example 2 — privileged container exec under a build orchestrator

**Alert:** container runtime auditor reports a privileged exec inside container `container-build-7f2a` with parent process `runc`, child cmdline `/bin/sh -c "tar -xzf …"`. Prologue carries `v-container-build-7f2a`, the parent-process vertex, and a `privileged_exec` edge. Loop 1 confirmed via process-lineage that `runc`'s grandparent is the build-orchestrator daemon on the host (`v-build-orchestrator`). Mechanism is pinned: a host-side build job crossed the container boundary via runc-exec, which is the orchestrator's documented execution model. The open question is whether *this specific exec* was an approved build run.

**Anchor selection.** The build-orchestrator emits a `build-runs` log per job with the run-id, the initiating identity (a developer, a scheduled trigger, or a CI webhook), and the script body. Anchor against `build-runs` with a predicate matching execution-time window plus the script body the runc-exec invoked.

**Integrity bundling.** Build-runs records the initiator — same pattern as Example 1. One hypothesis with the contract; no peer.

```
predict loop=2 shape=A

### story h-002
s1. The build orchestrator on the host opened a build run targeting `container-build-7f2a` and dispatched a script step that invoked the observed `tar -xzf …` command through runc-exec.
s2. Loop 1 confirmed the parent runc's grandparent is the orchestrator daemon, which matches the orchestrator's documented exec path.
s3. The build-runs log should record an active run whose dispatched script body matches the observed cmdline.

:H hypotheses [id|name|attached_to|rel|parent_type|parent_class|parent_attrs?|integrity_waived?|weight|status]
h-002|?orchestrator-initiated-build-exec|v-container-build-7f2a|privileged_exec|build_run|build-orchestrator-run||"build-runs records the initiator that opened the run (developer, scheduled trigger, or CI webhook); confirming the run authorizes the exec and identifies the responsible actor in one resolution"|null|active

:P h-002.preds [id|subject|kind|from_story|claim]
p1|proposed_edge|absolute|s1|"build-runs records an active run targeting `container-build-7f2a` whose execution window contains the exec timestamp"
p2|proposed_edge|absolute|s3|"the matching run's dispatched script body contains the observed cmdline as one of its steps"

:P h-002.refuts [id|refutes|kind|claim]
r1|p1|absolute|"no build run's execution window contains the exec timestamp"
r2|p2|absolute|"a matching run exists but its dispatched script body does not contain the observed cmdline"

:P h-002.authz [id|edge_ref|anchor_kind|predicate|on_unauth|on_indet]
ac1|proposed|build-runs|"an active build run targeting this container with a matching execution window and a dispatched script body containing the observed cmdline"|esc|esc

:R routing
selected_lead         build-run-lookup
composite_secondary   -
override_data_source  -
rationale             "build-runs anchor closes authorization + actor-identification in one query against the orchestrator's authoritative log of dispatched runs"
```

**Pitfalls:**
- Don't loosen the predicate to *"any active build run"* without the script-body match — an unrelated concurrent build run would falsely satisfy the contract. Two predictions (p1 window-match, p2 body-match) keep the anchor honest.
- Don't pre-write the script body as a literal regex in the predicate — predicates are natural-language; the lead handles the comparison. Pinning a regex at PREDICT time leaks foreground state into the contract.

### When to pull `:P h-{id}.attr_preds` in

Only when the parent_vertex `classification` carries a non-trivial stereotype (cmdline shape, running-as user, parent-process genre) AND a peer hypothesis exists whose predictions diverge on those attributes. Single-hypothesis Shape A doesn't need attr_preds — the classification is a label, not a discriminator.

If you do add attr_preds, every row carries a `kind` (same enum as `:P preds`), and `:P h-{id}.refuts` rows can cite both `p*` and `ap*` in their `refutes` cell.

### When to pull `:P h-{id}.comparisons` in

Only when at least one `p*` or `r*` row carries a deviation kind (`geometry|cadence|novel-artifact|absence`). Both worked examples above are pure `absolute` and don't need a comparisons block. If a prediction asks "is this exec on-cadence with the orchestrator's prior runs?", that's `kind=cadence` and pulls in a `:P h-{id}.comparisons` row declaring the historical-self selector.
