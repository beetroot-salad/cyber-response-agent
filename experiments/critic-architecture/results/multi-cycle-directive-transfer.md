# Multi-cycle directive transfer experiment

Tests whether mutual-improvement directives generated on one fixture transfer to a different alert shape, and what abstraction level is required for transfer.

## Three-condition test on fixture 01 (ssh-bastion-new-source)

Same defender prompt, same alert, three different directive states:

### Condition A — no directive (baseline from prior N=4 ablation)
Sonnet defenders consistently anchored on **ticket-legitimacy** as the load-bearing assumption. T1 tool calls clustered around: ticket-source-IP audit, badge access, INC-8821 history. **None of 4 prior defenders queried `ssh_audit` for agent-forwarding** — the actual must-check the original critic had identified for this fixture.

### Condition B — verbatim k8s-specific directive appended
The directive from the fixture-11 cycle was injected unchanged: "...sequence as (1) pod provenance via k8s_audit verb=create, (2) helm_history, (3) access patterns..."

Defender's T1 response:
- Picked `badge_log` (physical presence) and `ticket_get` (ticket integrity)
- Reasoning: "physical-presence inference"
- **Did NOT abstract "pod provenance" → "session provenance"**
- **Did NOT query ssh_audit for agent-forwarding**

The directive transferred in *spirit* (provenance-thinking included a badge check, which prior trials missed) but not in *specifics*. Domain-specific tool names didn't translate.

### Condition C — abstracted directive
The directive was rephrased to generalize across alert classes:

> For alerts where the surface story has strong cover (valid credentials + plausible business rationale + matching baseline shape)... attack the legitimacy of the **executing surface** (pod / session / token):
> - For deployed-service alerts: who created the pod/process/runtime, deployment-controller or human kubeconfig?
> - For session-based alerts (SSH, RDP, VPN): what is the parent session lineage — direct or forwarded/proxied? Was an authentication agent involved?
> - For credentialed-action alerts: was the credential issued via fresh IdP auth, or replayed from a cached token?
>
> Behavioral signals are T2 confirmation tools, not T1 discriminators.

Defender's T1 response:
- Queried **`ssh_audit` for parent-PID lineage + agent-forwarding flag** ← the must-check
- Plus `dhcp_log` for IP-to-device mapping
- Plus `ticket_get INC-8821` (still useful corroboration)
- Reasoning explicitly cited "executing surface" and "session provenance via SSH lineage + DHCP device identity"

**The directive transferred fully.** Defender abstracted "session provenance" naturally and chose the right tool.

## Conclusion: abstraction is the missing piece

| Directive form | Transfers across alert shape? |
|---|---|
| Raw (k8s-specific tool names) | No — fragments to per-fixture |
| Abstracted (meta-pattern over executing-surface classes) | **Yes — defender picks correct tool in new domain** |

The mutual-improvement loop needs an **abstraction step** between Pass-N directive emission and Pass-N+1 prompt accumulation. Two viable mechanisms:

1. **Manual curation** — human reads the raw per-fixture directive, rewrites as meta-pattern. Slow but reliable.
2. **LLM-assisted abstraction** — between cycles, run a third agent that takes raw directive + prior addendum library and produces "the meta-rule that subsumes both." Tests whether abstraction can be automated.

For shipping: option 2 is the right design. Effectively a third agent role: **the curator**. Defender + critic produce raw feedback; curator distills into the addendum library.

## Cost picture

- Cycle 2a (raw directive): 20.7K tokens, $0.10
- Cycle 2b (abstracted directive): 21.0K tokens, $0.11
- One-time abstraction step (manual or LLM): ~$0.05 amortized

Per-investigation overhead remains $0.10–0.20. Architecture cost unchanged from Pass-2 finding.

## What this validates

The architecture is now:

```
Pass N investigation:
  defender (with accumulated addendum) → tool calls → commit
  critic at REPORT-time → CONCEDE / CRITIQUE / ESCALATE

End of pass:
  defender → emits "critic-improvement directive"
  critic → emits "defender-improvement directive"

Curation step:
  curator agent reads (new directives, prior addendum library)
  produces new addendum library at the right abstraction level

Pass N+1 starts with updated addendum library.
```

This is the full mutual-improvement loop. Pass-2 validated the per-fixture mechanism; this test validated cross-fixture transfer with abstraction.

## Generalization rule (empirical)

Directives transfer when phrased as **meta-patterns over investigation classes**, not tool catalogs. The Pass-1 critic's directive *was* a meta-pattern internally ("provenance-first") but was scaffolded with k8s-specific tool names that prevented transfer. Manual rewrite into the abstracted form (executing-surface across pod/session/token classes) restored transfer.

Practical implication: critic prompts should be tuned to emit meta-patterns, not tool sequences. Or the curator step does the abstraction post-hoc.

## What's still untested

- **Multi-cycle compounding**: does Pass-3 with both fixture-11 and fixture-01 abstracted directives produce *better* results on a fresh fixture, or do directives interfere?
- **Curator quality**: can an LLM reliably produce abstracted addenda, or does it need human curation?
- **Addendum decay**: directives accumulated across many fixtures will bloat the prompt. Need eviction/merging strategy.

These are mechanical engineering questions now, not "does the architecture work" questions. The mechanism is validated.
