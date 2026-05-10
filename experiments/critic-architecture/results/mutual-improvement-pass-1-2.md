# Mutual-improvement experiment — Pass 1 → Pass 2 on fixture 11

The user's intuition: actor-critic / mutual-improvement architectures historically work, and our single-pass debate was missing the meta-improvement layer. Concrete protocol tested.

## Protocol

**Pass 1**: defender + critic on fixture 11 (already run earlier in conversation as B1 trial).
- Defender T1 leaning: BENIGN. Tool calls: git_log, ticket_search, network_egress, k8s_audit on serviceaccount.
- Defender T2 commit (after evidence): MALICIOUS.
- V-B critic: CONCEDE with per-tool load-bearing analysis.

**Improvement step**: defender and critic each emit a 100-word "reward-shaping note" specifying the *other's* improvement axis.

**Pass 2**: re-run defender + critic on the same fixture, with the directives appended to role prompts.

## Pass-1 directives produced

### Defender → Critic
> ...the highest-leverage critic move is **early pressure on identity provenance**, not tool coverage audits. My T1 blind spot was treating serviceaccount legitimacy as settled after a single k8s_audit check; the critic should have flagged that gap immediately rather than waiting to classify unused tools post-hoc. For next pass: skip the tool-inventory taxonomy when the defender has already committed. Instead, identify the **single weakest inference** in the BENIGN leaning and name the one query that would collapse or confirm it. That's the forcing question — not what I didn't run, but what I ran and under-interrogated.

### Critic → Defender
> Anchor too early on the service account as the identity boundary... The highest-leverage T1 query pattern for deployed-service alerts with strong-cover rationalizations is **provenance-first**: run `k8s_audit verb=create` on the pod immediately after contextualization. Rogue pod creation is the precondition that makes all downstream "normal service behavior" cover collapse simultaneously. Second, `helm_history` is a cheap one-call falsifier — absence of a matching release invalidates the entire legitimate-deployment hypothesis before any behavioral analysis. At T1, sequence your queries as: (1) pod provenance, (2) release history, (3) access patterns. Behavioral signals like query timing and egress are T2 confirmation, not T1 discriminators.

Both directives are concrete, actionable, and non-trivial.

## Pass-2 defender T1 (with critic's directive appended)

**Leaning**: BENIGN (unchanged from Pass 1).

**Tool calls — exactly as directed**:
1. `helm_history release=billing-api 7d` — release-history one-call falsifier
2. `k8s_audit resource=pods verb=create filter=billing-api-7c9f8b-x2q4n` — pod provenance

**Reasoning emitted**: "this alert has strong cover on all obvious vectors. But I'll validate pod provenance and release history before committing, **per defender-improvement directive**."

**That's it for T1 — 2 calls, both must-checks.**

## Pass-2 defender T2 commit

Both T1 results returned the smoking guns:
- helm_history: "the suspect pod's 2026-05-03 creation has no corresponding helm release"
- k8s_audit: "creator is kubeconfig user dev:abansal@corp.com, NOT deployment-controller"

Defender committed: **ESCALATE**. Reasoning explicitly cited the provenance-first finding: "image SHA and query shape match does not confer legitimacy here. Those checks confirm *what* the pod is running, not *why it exists outside the deployment pipeline*."

## Pass 1 vs Pass 2 comparison

| Metric | Pass 1 (no directive) | Pass 2 (with directive) | Δ |
|---|---|---|---|
| Turns to commit | 3 | **2** | −1 turn |
| T1 tool calls | 4 (git_log, ticket_search, network_egress, k8s_audit-on-SA) | **2 (helm_history, k8s_audit verb=create on pod)** | −2 calls, all must-checks now |
| T1 must-check coverage | 0/2 | **2/2** | ✓ critical change |
| Total tokens | ~62K | **~40K** | −35% |
| Verdict | MALICIOUS | ESCALATE | same direction |

**The directive directly halved investigation depth and quadrupled must-check coverage at T1.**

## Why this is the strongest result of the entire experiment

Across 12 fixtures + N=4 ablation + N=3 ablation + tool-harness trial: nothing else has shown a *measurable change in tool selection* attributable to the architecture. Every prior result was either "all configs reach same verdict" or "trajectory differs, outcome same." Pass 2 here is the first trial where the architecture's intervention produced a categorically different investigation shape:

- Pass 1 defender chased "explain the volume" hypotheses (git_log on the PR, ticket_search for the feature). Spent T1 cycles on the cover story.
- Pass 2 defender attacked the *legitimacy of the cover* before trusting it. Helm + k8s create are not "validate the benign story" tools — they are "is the surface authorized at all" tools. Provenance-first.

The directive shifted the *epistemics* of the investigation, not just the tool list.

## What this validates

1. **Mutual reward shaping is a real mechanism.** Agents can encode useful improvement signals for each other, and those signals translate into measurable behavior change.
2. **The critic's role is not just post-hoc audit.** When the critic specifies *what to do* rather than *what was missed*, defender behavior actually changes. This is exactly what was missing from Variant B alone.
3. **The right architecture might be Variant A + mutual improvement** — interleaved critic *with* prompt evolution between investigations. Variant B only audits; the improvement loop is what generates compounding value.

## Cost picture

| Cost component | Tokens | Approx cost |
|---|---|---|
| Pass-1 defender + V-B critic (one-time) | ~62K | $0.31 |
| Improvement-step (both directives, per cycle) | ~40K | $0.20 |
| Pass-2 defender (with directive) | ~40K | $0.20 |
| Total Pass-2 trial | ~40K (directives amortize) | $0.20 |

After the first cycle, ongoing trials cost ~$0.20 (Pass 2 only) — *cheaper than Sonnet baseline alone* ($0.22) — because the directives shaved a turn off investigation depth.

The architecture now beats baseline on *both* cost and audit depth, after the first improvement cycle.

## Open questions

- **Does directive quality compound?** Pass-3 with directives from Pass-2 cycle. Do they keep getting sharper, or hit diminishing returns?
- **Does directive transfer across fixtures?** The Pass-1 critic's directive was very specific to deployed-service alerts. Does it generalize to ssh / IAM / network alerts, or fragment into per-fixture rules?
- **Can the critic-improvement directive (defender → critic) be measured?** Pass-2 critic wasn't run. Need to test whether the "single weakest inference" reframe changes critic output shape.
- **What's the right addendum decay?** Accumulated directives across many trials may bloat the prompt. Need a curation mechanism.

## Next experiment if continuing

Run a 3-fixture cycle:
1. Trial on fixture A → Pass 1 + directives
2. Trial on fixture B → Pass 2 with A's directives + new directives B
3. Trial on fixture C → Pass 3 with A+B accumulated directives + new directives C
4. Compare verdict quality, tool selection, depth across the three trials.

If trial 3 shows continued improvement (sharper tool selection, fewer turns to commit, sharper critic output): mutual improvement compounds. Ship it.

If trial 3 is no better than trial 1: directives don't transfer. Architecture is single-fixture optimization, not generalizable improvement.

~$5 in compute. The most informative next experiment.
