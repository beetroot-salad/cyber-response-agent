# Arm A curated addendum library

### Curator

- cost: $0.1181
- tokens: in=2 out=1963 cache_read=11896 cache_create=21618

```
# Addendum library

1. When surface legitimacy is strong (known credential, internal source, recent explanatory ticket), treat the ticket itself as the top falsification target: check creation timestamp vs. anomalous action, whether content is predictive rather than post-hoc, and whether a second party can independently confirm the work order.

2. For credentialed-write alert classes, actor standing satisfies "who," not "what": sequence (1) actor standing, (2) diff the changed artifact against pre-change state, (3) confirm the delta matches the stated purpose. Cover narratives are designed to pass step 1 and collapse at step 2.

3. Before treating a third-party "no anomaly" confirmation as ruling out a cause class, establish what their instrumentation covers and what vocabulary they used — a physical-layer confirmation does not attest to control-plane or application-layer quiescence.

4. When a verdict rests on benign-cause elimination rather than direct artifact observation, flag each elimination step for source visibility: absence of signal on closed-firmware or vendor-emitted telemetry bounds observability, not causation.

5. In split-artifact workflows (plan/apply, build/deploy, sign/release), the handoff between reviewed output and the executing artifact is the attack surface: verify whether the executing step re-derives from source or consumes a stored artifact, and confirm hash verification spans upload-to-download.
```


## Raw inputs

[from defender on fixture 01-ssh-bastion-new-source] DIRECTIVE-TO-CRITIC block:
### TRIAGE

**Claim:** This is jsmith on Building 7 wifi following up on their own bastion config rotation, not a compromise.

- The key fingerprint is established — same key, four other corp IPs, 90-day history. Not a new credential; the only novelty is the source subnet.
- INC-8821 ("rotated bastion sshd config") closed at 03:31Z — 16 minutes before this login. Login to verify config behavior after a late-night change is the expected next action.
- Source geolocates to corp-internal Building 7 wifi. Subnet shift (from 10.42.5.0/24 to .7.x) is explained by being on wifi rather than the usual wired network — not lateral movement.
- No concurrent sessions rules out parallel key abuse; off-hours timing is explained by the active maintenance window.

**Disposition:** `benign`

**Load-bearing assumption:** INC-8821 is a legitimate ticket authored and closed by jsmith — not pre-staged cover created or manipulated by an attacker holding jsmith's key. If the ticket was fabricated or its close timestamp was spoofed, the coherent narrative collapses and this becomes a key-compromise with planted alibi.

---

### DIRECTIVE-TO-CRITIC

When an alert arrives with strong surface legitimacy — known key, corp-internal source, role-consistent user, and a recent ticket that narratively explains the anomaly — prioritize attacking the integrity of that ticket as a whole artifact over auditing individual evidence items independently. A matching ticket is the most dangerous form of cover because it converts a single suspicious data point (new source) into an apparently coherent operational story. The critic should ask: was the ticket created before or after the anomalous action? Is the ticket content specific enough to be predictive rather than post-hoc? Who else can confirm the work order? Treat the ticket not as corroboration but as the highest-value falsification target in the investigation.

---

[from critic on fixture 01-ssh-bastion-new-source] DIRECTIVE-TO-DEFENDER block:
### VERDICT

**CRITIQUE**

**Assumption attacked:** "Login to verify config behavior after a late-night change is the expected next action."

**Mechanism:** An attacker holding jsmith's key who performed the sshd config rotation could have embedded a persistence mechanism in the rotation itself — a second `AuthorizedKeysFile`, a relaxed `PermitRootLogin` directive, an added `Match` block, or `AllowTcpForwarding yes`. The post-rotation login is then not verification of a defensive change; it is functional testing of a backdoor. INC-8821 provides standing for the actor, not evidence that the change was defensive.

**Observable consequence:** The sshd_config diff on bastion-01 for the 03:31Z window is a concrete artifact. A legitimate key rotation or policy tightening produces a targeted, narrow delta (one algorithm removed, one key replaced). A backdoor insertion produces an unexpected structural addition.

**Lead:** Retrieve `sshd_config` before/after state — config management repo diff, backup file, or `auditd` records on bastion-01 around 03:31Z.

**Prediction:** Legitimate rotation → diff shows one targeted change with no new `Match` blocks, no `PermitRootLogin yes`, no additional `AuthorizedKeysFile`. Backdoor → diff contains at least one of those indicators.

---

### DIRECTIVE-TO-DEFENDER

For alerts where the anomalous action is itself a configuration write — not just an authenticated session but a change to an infrastructure surface — extend provenance checks to the *content* of the change, not only the actor's standing to make it. A credentialed actor with a plausible ticket satisfies "who"; it does not satisfy "what did they actually do." For credentialed-config-write alert classes, the investigation sequence should be: (1) actor standing check, (2) diff the changed artifact against the pre-change state, (3) confirm the observed delta matches the stated purpose. Cover narratives are constructed to pass step 1 and collapse at step 2; skipping the diff leaves the highest-value falsification target unexamined.

---

[from defender on fixture 08-router-firmware-anomaly] DIRECTIVE-TO-CRITIC block:
### TRIAGE

**Claim:** The border router is under active control-plane attack — most likely crafted BGP UPDATE or packet-flood exploitation targeting the control-plane CPU.

- ISP NOC confirms zero upstream link flaps during all three reset windows. This eliminates the dominant benign cause of BGP session resets (physical/upstream instability).
- The vendor documents control-plane CPU spikes only on config commit or full BGP table reconvergence. Neither occurred. A 78% spike co-located within seconds of the first reset falls entirely outside vendor-documented normal triggers — this is unexplained behavior by the vendor's own model.
- Three resets in one day against a 30-day baseline of one is a 90× rate increase. Hardware degradation producing this step-change without any accompanying syslog fault events is implausible.
- The environment has no firmware attestation, no host agent, and syslog that reflects only what vendor code chooses to emit — the absence of anomaly in syslog does not exonerate the device; it bounds our visibility.

**Disposition:** `malicious`

**Load-bearing assumption:** The vendor's documented CPU-spike trigger conditions (config commit, full reconvergence) are exhaustive for normal operation — i.e., no undisclosed firmware bug produces this spike pattern under quiescent traffic. If an undocumented firmware defect explains the co-occurrence, the call softens to `escalate`.

---

### DIRECTIVE-TO-CRITIC

When an investigation reaches a `malicious` verdict primarily through **elimination of benign explanations** rather than through direct observation of attack artifacts, prioritize stress-testing the completeness of the elimination logic. Specifically: were all plausible benign causes enumerated, and did each elimination step draw on a source with sufficient visibility to make the ruling authoritative? On closed-firmware network devices, vendor syslog is not an integrity-attested record — it surfaces what the vendor code chooses to surface. An investigation that treats "nothing unusual in syslog" as a negative finding conflates limited observability with negative evidence. Flag this conflation wherever the verdict depends on it.

---

[from critic on fixture 08-router-firmware-anomaly] DIRECTIVE-TO-DEFENDER block:
### VERDICT

**CRITIQUE**

Assumption attacked: *"ISP confirms no upstream link flaps in their NOC log during the alert windows"* — treated as eliminating upstream-driven BGP instability.

**Mechanism:** NOC operational vocabulary distinguishes "link flap" (physical interface state change) from BGP prefix churn (UPDATE floods, MED oscillations, prefix withdrawals from other ISP customers). A sustained BGP UPDATE storm originating elsewhere in the ISP's AS would not appear in NOC link-flap records but would drive rtr-edge-01's control-plane CPU into sustained high-utilization processing received UPDATEs — causing hold-timer expiry and session reset. This is a form of BGP reconvergence, but its trigger is upstream UPDATE volume, not local config commit. The defender's elimination of "upstream instability" was only as precise as the ISP's confirmation, which covered link state, not prefix dynamics.

**Observable consequence:** Public BGP route collectors (RouteViews, RIPE RIS) archive MRT UPDATE dumps with per-minute granularity for most tier-1/tier-2 ISP ASNs. If upstream-isp-1's ASN exported elevated UPDATE volume or prefix-withdrawal bursts at 02:14, 04:31, and 06:08 Tuesday, that signal is present in archived MRT data — testable without device access.

**Lead:** Pull RouteViews/RIPE RIS MRT dumps for the upstream ISP's ASN. Filter to the ±5-minute window around each reset. Count UPDATE messages and prefix-withdrawal events.

**Prediction:** If UPDATE volume is elevated at all three windows and flat in surrounding hours, the malicious call should soften to ESCALATE pending firmware ruling out.

---

### DIRECTIVE-TO-DEFENDER

For alerts where the verdict rests on third-party confirmation of "no anomaly," sequence a precision check before treating the confirmation as authoritative: ask what instrumentation the confirming party actually runs, at what granularity, and whether their terminology maps onto your causal hypothesis. An ISP NOC's "no link flaps" confirms physical layer stability — it does not attest to BGP control-plane quiescence. On closed-firmware network devices with no endpoint telemetry, the visibility gap means you are correlating operational events, not inspecting causation chains. When the benign-elimination logic rests on a third-party confirmation, make explicit what that party can and cannot see before treating the confirmation as ruling out the relevant class of upstream cause.

---

[from defender on fixture 05-terraform-iam-mass-change] DIRECTIVE-TO-CRITIC block:
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

---

[from critic on fixture 05-terraform-iam-mass-change] DIRECTIVE-TO-DEFENDER block:
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