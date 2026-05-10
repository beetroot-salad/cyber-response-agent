# Stress cases — when would a critic genuinely beat single-agent?

Question: under what conditions does a separate critic agent produce hypotheses or leads a single-agent baseline systematically misses?

The N=4 ablation showed the *current* architecture (defender → critic) systematically *under-explores* compared to baseline because the defender prompt anchors hard on one load-bearing assumption and the critic follows. So "where the critic helps" is not "everywhere the defender commits." It's the narrower set of cases where:

1. The defender has a systematic blind spot a fresh-eyes agent doesn't share, AND
2. The architecture can be designed to exploit (1) without paying the breadth-loss cost we just measured.

## Candidate stress cases, ranked by where I'd place a bet

### 1. End-of-long-investigation review (highest leverage)

The cleanest case. After a 5–10 loop investigation produces an `investigation.md` with accumulated leads, evidence, and intermediate state, the defender's reasoning compounds — each loop's noise builds on the prior loop's noise. A critic given only the final state and disposition reads with fresh eyes and isn't trapped in the accumulated rationalization.

Why this is the strongest case:
- The compounding-error mechanism is real and measurable
- The architecture cost is amortized over many loops (one critic call vs. dozens of investigation calls)
- The critic sees the conclusion only, so it can't share the path-dependent reasoning

Stress fixture shape: a synthetic 5-loop `investigation.md` where loops 1-4 build a benign narrative based on an early misread of evidence; loop 5 reaches benign disposition. Critic should catch the loop-1 misread when re-reading the final state.

This is the experiment I'd run next if continuing. Single-shot triage isn't where this architecture lives — it's loop-end review.

### 2. Domain-expertise asymmetry via differential prompting

Defender given the alert. Critic given the alert PLUS a domain-specific attacker-tradecraft catalog (e.g., for SSH alerts: agent forwarding, ProxyJump abuse, cert-based auth tricks, ssh-agent socket hijack; for cloud IAM: confused-deputy, cross-account assume-role chains, OIDC trust-policy abuse). The critic isn't smarter — it's *informed differently*.

Why this might work: an LLM's general training spreads thin across domains. A focused tradecraft prompt biases the critic toward domain-specific attack vectors the general defender wouldn't volunteer. This is closer to "expert second opinion" than "second analyst."

Risk: might just be re-discovering the value of better prompting. If we beat baseline by giving the critic a tradecraft prompt, the right move is to put that prompt in baseline.

### 3. Hostile-context alerts (adversarial framing)

Some alerts have *deliberately misleading* context — narratives crafted by an attacker with prior compromise (forged tickets, planted log entries, manipulated ticket histories). The defender, trained to use context, gets misled. The critic, trained to attack assumptions, asks "is this context itself trustworthy?"

The bait fixture #10 was supposed to test this. It failed because the bait wasn't subtle enough. A real test would need a fixture where attacker-controlled context provides 80% of the seemingly-benign signals. Hard to design, high payoff if successful.

### 4. Multi-source alerts where attention is selective

Alerts pulling from many systems (Wazuh + EDR + cloud audit + identity + ticketing) with 50+ context fields. Defender pattern-matches the headline and glosses over corner fields. Critic with same context but explicit "find the smallest detail that contradicts the leaning" might catch what defender skipped.

Testable today by extending fixture 01-09 with 30+ extra context fields, only 1 of which is the kill signal.

### 5. Persona asymmetry (low confidence)

"Defender = senior SOC analyst, Critic = red team operator" — does role prompting actually produce different reasoning, or is it cosmetic? The N=4 data is suggestive: critics consistently produced ticket-attack hypotheses, defenders consistently produced benign-narrative hypotheses. But that's anchor-following, not persona-driven divergence.

A clean test: keep prompts identical except the role, run N≥10, measure whether output distributions are statistically different.

### 6. Disagreement-as-signal architecture (different design)

Instead of defender-commits-critic-attacks, run two independent defenders with *different priors* and treat agreement as a green light, disagreement as a forced second-look. Doesn't have the breadth-loss problem of the current architecture because both agents enumerate hypotheses fully. The "critic" function emerges from the disagreement itself, not a separate role.

This is closer to ensemble methods than debate, and probably the cleanest engineering path if the goal is "find cases where one model would have been wrong."

## What we now know about *the existing* defender→critic architecture

The N=4 data shows:
- **Anchor convergence**: defender prompt forces all samples to identify the same load-bearing assumption (4/4 picked ticket-legitimacy on fix01).
- **Breadth loss**: critic produces 1 hypothesis vs. baseline's 5–6, missing the agent-forwarding angle entirely.
- **Depth gain**: when the critic does attack the seam, its lead is more concrete than baseline's average (specific ticketing-audit query vs. general "verify ticket scope").

So the architecture's mechanism is **focusing depth at the cost of breadth**. That tradeoff is only worth it when the seam the defender picks is *the* seam to attack — and we have no mechanism guaranteeing that.

## Recommended next experiment

If continuing this exploration: build the long-investigation fixture. That's the case where the architecture's *information-asymmetry* mechanism (critic reads only conclusion, defender lived through the loops) actually maps onto something a single agent can't simulate cheaply. Single-shot triage doesn't expose that mechanism, which is why our 10 fixtures didn't separate the architectures.

If pivoting: the disagreement-as-signal design (two independent defenders, escalate on disagreement) avoids the breadth-loss problem and is one prompt + one ensemble call away from being testable.

If retiring: fold the counter-anchor insight into a single-prompt PREDICT upgrade. "After committing to a leaning, generate one hypothesis that would flip your call, with a concrete observable check." That's the architecture's value at zero added latency.
