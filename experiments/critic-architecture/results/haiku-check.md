# Haiku check — fixture 11 force-commit

User's question: does the architecture's value scale differently at lower model capability?

## Setup

Two Haiku trials on fixture 11, both given full pre-fetched evidence (smoking-gun-rich tool results bundled inline). Force-commit. Tests whether Haiku can synthesize a verdict from rich evidence.

## Results

### Haiku baseline
- **Disposition: ESCALATE.**
- Reasoning: walked through three hypotheses (benign feature expansion, suspicious unauthorized access, refutation of benign), correctly identified that "feature approval doesn't authorize manual pod creation by non-owners" and that "sequential query walk... suggests deliberate enumeration, not application use."
- Output structure: surprisingly comparable to Sonnet — explicit hypothesis assessment with refutation logic.
- Tokens: ~31K. **Cost: ~$0.05.**

### Haiku defender (commit-then-validate prompt, but force-committed at first turn given evidence)
- **Disposition: ESCALATE.**
- Reasoning: structured as "load-bearing evidence chain" with sub-headings for pod creation anomaly, query behavior, network egress. Identified the "assumption that flips disposition" cleanly: "if abansal's kubeconfig was intentionally shared with a billing-api team member for legitimate pod debugging... requires explicit corroboration."
- Output is *more structured* than Haiku baseline.
- Tokens: ~31K. **Cost: ~$0.05.**

## What this shows

1. **Haiku given clear evidence reaches the right verdict.** Both configs hit ESCALATE with rich reasoning. The capability gap I expected doesn't show up at the synthesis step.

2. **Haiku is genuinely cheap.** $0.05 per trial vs Sonnet's $0.22 baseline vs Opus's $2.57. **52× cheaper than Opus** at equivalent verdict on bundled evidence.

3. **The interesting Haiku test is multi-turn tool selection** — not the synthesis test we ran here. We didn't run Haiku through the full tool harness loop. The hypothesis: Haiku may pick *worse* tools at T1 (similar to Sonnet's miss-rate on helm_history) and need more turns to converge. Architecture's mutual-improvement directive could close that gap by directly instructing Haiku to query provenance-first.

## Open question — the genuinely interesting Haiku architecture

If Haiku is the cheapest model and the mutual-improvement directive is what enables provenance-first sequencing, the interesting deployment shape is:

**Haiku defender + Haiku critic + accumulated directives**

Cost per investigation: ~$0.05 × 2 + directive overhead ~$0.05 = **~$0.15 per alert**, with the architecture providing the must-check sequencing that Haiku alone wouldn't volunteer.

This is potentially the most cost-effective configuration in the entire experiment. Worth testing: full Haiku tool-harness loop, with Pass-1 directives transferred from the Sonnet experiment, on fixture 11.

If Haiku-with-directive matches Sonnet-without-directive at a fraction of the cost, the architecture's pitch shifts again — from "audit at small overhead" to "compensate for cheaper model with mutual-improvement priors."

## Caveat

Both Haiku tests were synthesis-only, not multi-turn investigation. The harder test (Haiku driving its own queries through 4-5 turns of tool calls) is unrun. The capability question for *that* setup is still open.
