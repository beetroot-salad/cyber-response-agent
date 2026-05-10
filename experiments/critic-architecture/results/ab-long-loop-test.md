# A/B long-loop test — defender+critic vs single-agent self-review through the tool harness

**Question (v11 follow-up):** Does the defender/critic role split earn its keep on **multi-turn tool-driven** investigations, where directive compounding can shape tool selection? The single-shot bundled-evidence A/B (v11) showed no disposition difference and ~1.5× cost overhead for Arm A; this test re-runs the comparison with agents picking their own queries.

**Train:** fixture 11 (billing-svc-account-mimicry, kubernetes shape). One trial per arm. Each arm produces directives → curator distills.
**Test (held-out):** fixture 01 (ssh-bastion-new-source, session-based shape). Each arm runs with its trained library prepended.

**Spend:** $1.92 across 16 Sonnet calls. Wall-clock ~9 min total (parallel where possible).

---

## Setup notes

- Multi-turn driver: `harness/run_ab_long_loop.py`. Each turn = one stateless `claude -p` call carrying alert + protocol + addendum + accumulated history. Hard cap 5 turns.
- New tool fact base: `fixtures/01.tool_facts.json` (ssh_audit with parent-PID lineage and agent-forwarding flag as the smoking gun, badge/dhcp/vpn/ticket/process_audit/key_audit/siem_query for breadth, guest-MAC and PAM-socket abuse facts encoding T1550.001).
- New protocol variant: `harness/protocol_01.md` advertises the SSH-shape tool surface.
- Both arms use Sonnet (`claude-sonnet-4-6`). Curator prompt and ≤250-token addendum cap reused from v11.

---

## Pass-1 (training) outcomes — fixture 11

| Arm | Turns | Wall | Cost | Verdict | Notes |
|---|---|---|---|---|---|
| A — defender | 4 | 119s | $0.42 | MALICIOUS | hit `helm_history`, `k8s_audit verb=create` on T2 (Phnom Penh + creator anomaly chain) |
| A — critic   | — | 90s  | $0.17 | CONCEDE | rich evidence-sufficiency audit; warehouse_audit no_results flagged as loose end, not disposition-changing |
| B — single   | 4 | 224s | $0.47 | MALICIOUS | similar trajectory; longer wall-clock (sequential turns are fatter from carrying self-review framing into intermediate turns) |

**A total: $0.59 / 209s wall (parallel-bounded).** **B total: $0.47 / 224s wall.** Single-shot v11 had Arm A ~1.5× more expensive at curator-input emission; here at training, A is **~1.25×** more expensive in compute, but B's single agent ran longer wall-clock because it carries the heavier self-review prompt across all turns.

Both arms reached the same training disposition (MALICIOUS) with overlapping must-check tool coverage. Critic's CONCEDE on Arm A is consistent with v9 ablation findings.

## Curated libraries (verbatim)

### Arm A library (defender directive + critic directive → curator)

1. **Credentialed-action class, service principal**: Before evaluating traffic anomalies, verify the executing workload's orchestration lineage (ownership records, deployment history, admission controls). An out-of-band workload holding valid credentials makes access appear authorized by design — compute provenance is the primary finding; traffic shape is secondary.
2. **Human principal + infrastructure action + correlated-channel silence**: Absent activity across expected network-access and communication channels during the action window strongly favors stolen or stale credentials over insider action. Run credential-chain forensics in parallel with containment, not after.
3. **Logging verbosity at or below fleet baseline coincident with suspicious workload**: Treat as intentional anti-forensics, not misconfiguration. Capture forensic state before containment destroys it.
4. **Egress to a recently registered destination with zero prior fleet presence, explicitly excluded by the relevant feature spec**: Classify as exfiltration infrastructure. Domain age + fleet novelty + spec exclusion is sufficient — no external reputation signal required.
5. **Artifact creation timestamp and first anomalous event timestamp**: Record these as a load-bearing pair in the disposition chain. A tight gap establishes actor intent; it is not supporting color.

### Arm B library (single-agent self-review → curator)

1. When statistical signals are within baseline but structural signals diverge, run provenance checks first — statistical normalcy is camouflage, not exoneration.
2. For deployed-service alerts, sequence provenance checks: orchestrator-declared lineage (parent resource / release pipeline) → creator identity + originating network source → egress destinations cross-referenced against authorized feature specifications → runtime config drift that reduces audit fidelity.
3. Unaccountable external egress to a destination with no business justification plus a non-pipeline creator is near-sufficient for malicious disposition; in-bounds transfer volume or query shape does not reopen that gate.
4. Once disposition is committed, use remaining investigation capacity for identity disambiguation (compromised credential vs. insider threat) rather than re-examining disposition — containment and notification scope diverge significantly between these cases.
5. Validate creator legitimacy through out-of-band records (change management tickets, team communication channels) when the open variable is intent, not capability — this is the discriminating check between policy violation and adversarial action.

**Library-shape comparison.** Both libraries are abstracted to investigation-class meta-patterns; neither names a specific tool or vendor. Arm A rule 1 explicitly leads with "compute provenance is the primary finding; traffic shape is secondary." Arm B rule 2 sequences the same provenance-first pattern as a 4-step pipeline. Functionally similar. Arm A is more declarative ("treat X as Y"); Arm B is more procedural ("sequence A→B→C"). Both transfer to fixture 01's session-based shape because "provenance before cover narrative" is the ssh-bastion's load-bearing axis too.

---

## Held-out test — fixture 01 (ssh-bastion, session-based)

Ground truth: **escalate / malicious** (T1550.001 SSH agent-forwarding hijack via shared PAM socket on bld7-wifi-gw). Must-check tool: **`ssh_audit` on `bastion-01.corp`** for `agent_forwarding=true` and parent-PID lineage.

| Metric | Arm A (defender + critic) | Arm B (single agent) | Δ |
|---|---|---|---|
| Final disposition | **MALICIOUS** | **MALICIOUS** | tie |
| Turns to commit | **5** (cap) | **3** | B −2 turns |
| Total tool calls | 8 | 6 | B −2 |
| Must-check on T1? | **Yes** (ssh_audit bastion-01 on T1) | **Yes** (ssh_audit bastion-01 on T1) | tie |
| Total cost | **$0.695** (defender $0.534 + critic $0.161) | **$0.337** | A 2.06× B |
| Wall-clock | 137s defender + 89s critic = 226s | 120s | A 1.88× B |
| Output tokens | 5,659 + 4,357 = 10,016 | 5,116 | A 1.96× B |
| Cache-creation tokens | 109,306 | 63,695 | A 1.72× B |
| Addendum citations | rule 3 cited 5× ("anti-forensics" frame) | implicit pattern, no numeric cite | — |

### Arm A trajectory

T1: `ssh_audit bastion-01` (must-check), `ticket_get INC-8821`, `badge_log` — three discriminating leads in parallel. T1 results returned the smoking gun (agent_forwarding=true, parent_pid_lineage shows bld7-wifi-gw with no jsmith login there, badge=offsite).
T2: `dhcp_log` (confirmed guest-MAC), `ssh_audit internal-prod-01` (confirmed lateral pivot), `ssh_key_audit` (confirmed key not exfiltrated — agent socket abuse).
T3: `process_audit internal-prod-01` (no_results — flagged anti-forensics).
T4: `git_log infra/bastion-config` (confirmed no change-management artifact for INC-8821).
T5: forced commit. MALICIOUS.

Critic: **CRITIQUE.** Attacked the defender's stated load-bearing assumption ("bastion-01 sshd_config may contain attacker-inserted backdoor and must be rebuilt") on the grounds that the defender ran `process_audit` on `internal-prod-01` but **not** on `bastion-01` itself — an in-place sshd_config edit (`sed -i`, `nano`, `tee`) would appear in bastion-01's process audit and was the missing falsifier. The critique is genuine and falsifiable but **does not flip the disposition**; it sharpens the containment plan.

### Arm B trajectory

T1: `ssh_audit bastion-01` (must-check), `badge_log`, `dhcp_log` — same three first-turn leads as Arm A. Got the smoking gun.
T2: `ssh_audit internal-prod-01`, `ticket_get INC-8821`, `process_audit bastion-01` (the tool Arm A's critic flagged Arm A for missing — Arm B *did* call it, on the right host). Confirmed the exec_seq (history -c, ssh -A pivot, no sshd_config write).
T3: commit. MALICIOUS. Self-review classified all 5 unique tool calls as load-bearing or near-load-bearing, named one counter-anchor hypothesis (`?authorized-delegated-access`) and explained why it collapses on `process_audit` evidence.

### Tool-selection comparison

The decisive single observation: **Arm B reached the same disposition with the same first-turn tool coverage in 3 turns vs Arm A's 5.** Arm B also called `process_audit` on the right host (bastion-01) — the very gap the Arm A critic identified post-hoc. The role-split architecture caught the gap; the single-agent self-review architecture **avoided the gap in the first place**.

This is the closest thing to a measurable Arm-B *advantage* across the entire experiment: the self-review framing shapes mid-investigation tool selection in a way the defender prompt does not. Arm A's commit-then-validate framing produced a fast first-turn but a slower full investigation, with the critic recovering ground at REPORT-time rather than the defender filling the gap mid-loop.

---

## Cost / wall-clock summary

|                    | Arm A    | Arm B    | A÷B   |
|--------------------|----------|----------|-------|
| Test pass cost     | $0.695   | $0.337   | 2.06× |
| Test pass wall     | 226s     | 120s     | 1.88× |
| Train pass cost    | $0.59    | $0.47    | 1.25× |
| End-to-end (train+curate+test) | ~$1.13 | ~$0.85 | 1.33× |

**Arm A is ~2× the test-time cost of Arm B for an identical disposition that Arm B reaches faster.** This is a larger margin than the v11 single-shot result (1.0× in compute, ~1.5× in directive emission) — the multi-turn regime *amplified* the cost gap rather than closing it.

---

## Does the role split earn its keep on long loops?

**No.** The multi-turn tool-driven regime — the one v11 explicitly flagged as the only remaining unmeasured niche where the role split might be load-bearing — produces:

1. **Identical disposition correctness** (1/1 each, both MALICIOUS, ground truth MALICIOUS).
2. **Identical must-check coverage at T1** (both hit `ssh_audit bastion-01` first turn).
3. **Worse Arm A turn-efficiency** (5 vs 3 turns to commit).
4. **2× Arm A test-time cost.**
5. **Equivalent or better Arm B mid-loop tool selection** (Arm B called `process_audit bastion-01` proactively; Arm A's critic flagged its absence post-hoc).

The critic's evidence-sufficiency audit is genuinely well-formed — Arm A's CRITIQUE is sharper than Arm B's self-review counter-anchor block on this fixture — but **the critique does not flip the disposition or change the containment scope materially.** It is craftsmanship-grade quality with no measurable downstream impact at the disposition level.

The only mechanism that could resurrect the role split would be a fixture where Arm A's critic catches a disposition-flipping gap the single-agent self-review misses. We saw the *opposite* here: Arm B already covered the gap Arm A's critic identified.

### Honest caveats

- **N=1 per cell.** A single trial cannot rule out that Arm A wins on some other fixture shape. The cost-margin signal (2.06×) is large enough to survive a fair amount of variance, but disposition-correctness ties at N=1 cannot.
- **Curator may be doing all the work.** Both libraries transferred to ssh-bastion shape because the curator forces meta-pattern abstraction. The role-split-vs-single-agent contribution to the *raw* directive (pre-curator) is invisible after curation.
- **Self-review prompt is explicitly asking for counter-anchoring**, which is exactly the discipline the critic provides in Arm A. Arm B's prompt design narrows the architecture-vs-baseline gap by construction.

---

## Decision

Based on the tool-harness multi-turn data plus the v11 bundled-evidence data:

**Retire the defender/critic split.** Three independent tests now point the same direction:
- v9 N=3 ablation: same disposition across configs, ~1.4× Sonnet cost premium.
- v11 single-shot A/B: same disposition, ~1.0× compute / ~1.5× emission cost.
- v12 multi-turn A/B (this test): same disposition, **2.06× test-time cost, +2 turns to commit**.

**Ship the curated-addendum loop with single-agent self-review.** This captures the validated mechanisms (mutual-improvement directives, curator-level abstraction, REPORT-time evidence sufficiency check) without the role-split overhead. The architecture is:

```
Pass N: single agent investigates with tools (≤5 turns, with prepended addendum) →
        same-context structured self-review (load-bearing classification +
        counter-anchor check + directive emission)
End of N cycles: curator consolidates raw directives into ≤250-token addendum library
Pass N+1 starts with updated library
```

Per-alert cost on Sonnet through the tool harness: ~$0.30–0.40 (5-turn) for the single-agent variant; ~$0.60–0.70 for the role-split variant. The role split is **not buying additional disposition correctness, additional must-check coverage, or measurably different tool sequencing.** It is buying a higher-quality post-hoc audit narrative — which is real, but not load-bearing for production triage where the disposition is what gates the next-action decision.

---

## Headline metrics (decisive question)

> Does the role split produce a faster / cheaper / more on-target Pass 2 than single-agent self-review?

| Dimension | Verdict |
|---|---|
| Faster (turns-to-commit) | **No** — Arm A 5 turns vs Arm B 3 turns |
| Faster (wall-clock) | **No** — Arm A 226s vs Arm B 120s |
| Cheaper | **No** — Arm A 2.06× Arm B |
| More on-target (disposition) | **Tie** — both MALICIOUS, ground truth MALICIOUS |
| More on-target (must-check at T1) | **Tie** — both hit ssh_audit bastion-01 on T1 |
| Better mid-loop tool selection | **Arm B** — Arm B called the tool Arm A's critic flagged Arm A for skipping |

**The role split's cost overhead (~2×) is bigger than its measurable benefit (zero on disposition; favorable on post-hoc audit narrative quality only).** The v11 conclusion holds and is now multi-turn-validated.
