# Arm A training: 05-terraform-iam-mass-change

### Defender

- cost: $0.0983
- tokens: in=2 out=1571 cache_read=11896 cache_create=18691

```
### TRIAGE

**Claim:** This is an authorized, fully-anticipated Terraform apply executed by the correct OIDC principal against a reviewed, human-approved changeset.

**Reasoning:**
- The causal chain is complete and corroborated at every link: PR merge at 14:21:55Z triggered run 7799123 seconds later; OIDC token claims (repo, ref, workflow, run_id) all match; no out-of-band assume-role calls.
- Plan-to-apply fidelity is the strongest signal — the CI artifact listed exactly 47 changes, no others, and the post-apply state diff matches the plan byte-for-byte. Deviation here would be the fingerprint of a compromised runner or provider injection.
- The role has no history of console logins or manual CLI use in 90 days and has never been assumed from outside the canonical runner instance — eliminating the "stolen long-lived credentials" branch.
- Business hours + PR #4421 reviewed by two platform-team approvers establishes human authorization of the intended scope, including the `UpdateAssumeRolePolicy` operations.

**Disposition:** `benign`

**Load-bearing assumption:** The terraform plan artifact stored in CI was generated from the reviewed PR #4421 code and was not tampered with between plan generation and apply consumption. If an adversary could inject operations into the plan artifact (or if a compromised Terraform provider executed out-of-band changes while reporting expected state), the byte-for-byte state match could be fabricated and the 2-approver review would be meaningless — they reviewed code, not the applied plan.

---

### DIRECTIVE-TO-CRITIC

When an investigation closes `benign` on high-volume privileged-API activity attributed to an IaC pipeline, prioritize attacking the artifact-chain integrity rather than re-auditing individual change items. The threat surface in these cases is not *what* changed but *whether the reviewed artifact is what actually ran* — specifically, the plan-generation-to-apply bridge. Probe whether the plan was generated from reviewed code or could have been substituted, whether provider or module supply-chain compromise could produce operations invisible to the plan output, and whether the review gate was substantive (approvers read the plan diff) or rubber-stamp. Byte-for-byte state matches are strong but not unforgeable if the attacker controls plan storage.
```
### Critic

- cost: $0.1253
- tokens: in=2 out=3147 cache_read=11896 cache_create=19398

```
### VERDICT

**CRITIQUE**

**Assumption attacked:** "post-apply state diff matches plan diff byte-for-byte"

The defender conflates two distinct artifacts: the human-readable plan output reviewers saw in CI, and the binary `.tfplan` file the apply step executed. These are generated together but stored separately. In a split plan/apply workflow (common in production pipelines requiring gating), the apply job downloads the binary artifact and runs `terraform apply planfile.tfplan` — not a fresh plan from source. If a principal with write access to GitHub Actions artifact storage (or the runner itself) replaced the binary between upload and download, the apply executes the tampered binary. Terraform state is then written by *that apply*, so state would match the tampered binary, not the reviewed HCL — the byte-for-byte match would hold against the wrong plan.

**Observable consequence:** Query the GitHub API for run 7799123 artifacts (`GET /repos/org/infra/actions/runs/7799123/artifacts`). If a `.tfplan` binary artifact exists (separate from human-readable output), retrieve its `created_at` timestamp and compare to the plan job's completion time and apply job's start time. Then check the `tf-apply` workflow YAML: does the apply step invoke `terraform apply <planfile>` or `terraform apply -auto-approve` from source? If the former, verify the workflow logs the plan binary SHA256 at upload and re-verifies it at download. Absence of hash logging is the observable gap.

**Lead:** Inspect run 7799123 artifact list via GitHub API + workflow YAML apply step invocation.

**Prediction:** Either (a) the workflow re-plans from source (gap closed, CONCEDE warranted) or (b) it uses a saved binary with no hash verification logged (integrity link unverified, CRITIQUE stands).

---

### DIRECTIVE-TO-DEFENDER

For credentialed-action alerts where disposition rests on artifact-chain integrity — IaC apply, container image build, package publish — probe the *execution path*, not just the output match. The attack surface in split workflows (plan/apply, build/deploy, sign/release) is the handoff point between jobs: human-readable output and the binary artifact consumed by the executing step are generated together but live separately. Before closing benign, verify: does the workflow execute from a saved binary or re-derive from source? If from a saved artifact, is the binary hash logged at upload and explicitly verified at download? State-match and output-match checks validate consistency with the *consumed* artifact — they do not prove the consumed artifact is the reviewed one.
```
