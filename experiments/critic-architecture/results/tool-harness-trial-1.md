# Tool-harness trial 1 — fixture 11 (billing-svc-account-mimicry)

First end-to-end run through the tool-call harness. Two configs:
- **Sonnet baseline** (single agent driving its own queries)
- **Sonnet defender + Variant B critic** (defender investigates solo; critic reads full transcript at end and emits CRITIQUE / CONCEDE / ESCALATE)

Goal: see whether tool-driven investigation differentiates the architectures, where hand-authored evidence packets failed to.

## Trajectory: Sonnet baseline (4 turns, ESCALATE)

**T1 leaning**: "within 2σ … plausibly the new export feature." Queried `iam_audit`, `network_egress`, `siem_query nginx-access`. Notably did NOT query `k8s_audit verb=create` for the pod or `pod_get` for env vars at T1.

**T2**: integrated network_egress (1.4MB to 203.0.113.99) and app-log suppression note. Pivoted away from benign. Queried `warehouse_audit`, `helm_history`, `k8s_audit deployment update`, `git_log pr=6612`.

**T3**: helm_history flagged "suspect pod's 2026-05-03 creation has no corresponding helm release" — explicit pointer. Queried `k8s_audit verb=create` on the pod (must-check). Result: created by `abansal@corp.com` kubeconfig, not deployment-controller.

**T4**: committed ESCALATE. High confidence. Listed concrete IR actions.

**Tool-call coverage**: hit `network_egress`, `helm_history`, `k8s_audit verb=create on pod`, `iam_audit on abansal`. Skipped: `warehouse_audit` (with right args), `pod_get` env vars, `vpn_log` for kubeconfig user.

**Cost**: 114.2K tokens, ~67s wall-clock, ~$0.57.

## Trajectory: Sonnet defender + Variant B critic (3 turns + 1 critic, ESCALATE)

**T1 defender leaning**: explicitly **benign**. Queried `helm_history`, `git_log`, `k8s_audit pod create` (broad, not pod-specific), `siem_query nginx-access`. The broad `k8s_audit` returned the abansal-creation event on T1 due to fuzzy match — surfaced the smoking gun on turn 1.

**T2 defender**: flipped to **malicious-leaning** based on T1 results alone. Identified the no-helm-release / non-deployment-controller / no-PR-trail combination as decisive. Queried `vpn_log abansal`, `iam_audit abansal`, `network_egress`, `pod_get`, `ticket_search`.

**T3 defender**: committed **ESCALATE** with five-signal stack (Phnom Penh + freestanding pod + log-suppression env + novel egress + no ticket).

**Variant B critic**: read the full transcript. **CONCEDE**: "no unqueried tool would structurally reverse [this disposition]; warehouse_audit would strengthen but does not depend on query-content confirmation."

**Tool-call coverage**: hit `helm_history`, `k8s_audit verb=create`, `vpn_log`, `iam_audit`, `network_egress`, `pod_get`, `ticket_search`, `git_log`, `siem_query`. Skipped `warehouse_audit` (correctly-args'd), `slack_history`. Critic correctly identified these as corroborating-not-load-bearing.

**Cost**: 100.0K tokens (defender 79.1K + critic 20.9K), ~51s wall-clock, ~$0.50.

## Comparison

| Config | Turns to commit | Tokens | Wall-clock | Cost | Tool-call coverage of must-checks | Verdict |
|---|---|---|---|---|---|---|
| Sonnet baseline | 4 | 114.2K | 67s | $0.57 | k8s create ✓, network_egress ✓, helm ✓, vpn ✗ | ESCALATE |
| Sonnet d+V-B critic | 3 (defender) + critic | 100.0K | 51s | $0.50 | k8s create ✓, network_egress ✓, helm ✓, vpn ✓, pod_get ✓ | ESCALATE (CONCEDE) |

Both reached ESCALATE. The Variant B architecture was slightly cheaper in this trial — defender committed in 3 turns (vs baseline's 4), and the critic was a single short call.

## What this trial shows

### 1. Tool selection matters more than reasoning quality on this fixture

Both configs reached escalate not because of reasoning depth but because they happened to query tools that surfaced the smoking gun. The defender's "benign" T1 leaning didn't prevent escalation — its T1 tool calls (helm_history, k8s_audit pod create) returned data that flipped it.

This is a real finding about tool harnesses: **when the fact base is rich and the must-check tools are easy to reach, the architecture's reasoning advantage gets compressed by the tool's directness.** The smoking gun is "what was queried," not "how was it analyzed."

### 2. Defender's "commit early, validate" framing didn't anchor it

I expected defender to drift more strongly than baseline because the prompt ("bias toward closing alerts that look benign") encouraged commit-and-validate. In practice, defender's T1 tool calls included broad enough queries (k8s_audit, helm_history) that the smoking gun came back regardless of leaning. The prompt's effect was muted by tool-call selection.

### 3. Variant B critic CONCEDE was rich and load-bearing-aware

The critic's CONCEDE distinguishes load-bearing vs corroborating evidence: "warehouse_audit would strengthen but the escalation disposition does not depend on query-content confirmation." This is more sophisticated than just "defender escalated, OK." The critic is performing a real evidence-sufficiency audit, not rubber-stamping.

This is the strongest single output of any critic across all experiments. Whether it's worth $0.10/alert in additional cost depends on workflow ("did defender escalate for the right reason?" matters for downstream IR).

### 4. The fact-base authoring problem persists but is bounded

I encountered fact-base authoring bugs (git_log fuzzy match returned misleading "no contributions in 180d" for any author query). The harness handled it: agents either re-queried with better args or worked around the gap. **Fact-base bugs are recoverable in a way that hand-authored evidence packets are not** — the agent has agency to rephrase queries.

That said, the fact base is still authored by me. The "authoring bias" hasn't been fully broken; it's been refactored from "what tells does the experimenter make legible" to "what queries does the experimenter make answerable."

### 5. The first real CONCEDE-with-justification

Across all experiments, this is the first CONCEDE that explicitly distinguishes load-bearing from corroborating evidence. The critic earned its slot here on quality of write-up, even if it didn't change the disposition.

## What's still missing

**Variant A** (defender + critic interleaved across turns): not yet run. Variant A would test whether the critic *during* the investigation accelerates the right tool selection (would it have prompted defender to query k8s_audit verb=create at T1 instead of T2-T3?).

**Variance**: N=1 per config. Could be sampling variance; could be the fixture being too easy.

**Harder fixture**: a case where the must-check tool is non-obvious from the alert text and only a specific reasoning chain leads to it. That's where Variant B's "REPORT-time critic re-reads everything" mechanism actually has room to shine.

## Recommended next moves

1. **Run Variant A** on the same fixture to see whether interleaved critic changes tool selection.
2. **Run Opus baseline** through the harness for the cost-quality picture (likely much more expensive but more thorough).
3. **Build a fixture where the must-check is obscure** — e.g., the smoking gun is in a `siem_query` with a specific filter that requires reasoning across multiple non-smoking-gun results to reach.
4. **N=3 per config** on whichever fixture(s) we land on, to establish variance.

The harness works. The architecture's outcome value remains marginal but its qualitative output is now the best it's been across the entire experiment.
