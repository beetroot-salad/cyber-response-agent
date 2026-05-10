# Model comparison: Sonnet+critic vs Opus baseline

The user's question: can a Sonnet defender+critic architecture beat an Opus baseline on quality, cost, AND time?

## Data from fixture 10 (the bait, where all configs caught the threat)

| Config | Tokens | Duration | Approx cost |
|---|---|---|---|
| Sonnet baseline | 20.9K | 19.4s | $0.10 |
| Sonnet+critic (D+C) | 41.1K | 21.6s | $0.21 |
| Opus baseline | 29.3K | 20.7s | $1.32 |
| Opus+critic (D+C) | 57.7K | 24.6s | $2.60 |

Pricing approximation: Sonnet ~$3/M input + $15/M output, Opus ~$15/M input + $75/M output (~5x). Mixed cost ~$0.005/K vs ~$0.045/K.

## Findings

### 1. Sonnet+critic vs Opus baseline — comparable quality, 6x cheaper, similar speed

Both reached escalate with concrete falsifiable leads. Sonnet+critic ran sequentially (defender then critic) so wall-clock is *additive*, but it still finished within 1s of Opus baseline because Sonnet calls are individually faster.

Cost: Sonnet+critic at $0.21 vs Opus baseline at $1.32 — ~6x cheaper.

**This is a genuinely interesting finding.** If it generalizes, the architecture-as-cost-reducer pitch is real even when novelty is marginal: pay 2x within Sonnet to maybe approach Opus quality, instead of paying 13x to use Opus directly.

### 2. But Sonnet baseline is the Pareto winner on this fixture

- 2x cheaper than Sonnet+critic
- Same time
- Same correct verdict
- Hypothesis breadth comparable (6 hypotheses including LD_PRELOAD and beacon-via-new-feature angles)

So the "Sonnet+critic beats Opus baseline" story is real, but the cleaner story is "Sonnet baseline beats everything on this fixture."

### 3. Critical caveat — sampling variance not measured

This is one trial per configuration. Sonnet baseline rerun on fixture 01 produced the agent-forwarding (T1550.001) hypothesis I previously attributed to the architecture as STRONG novelty. Same prompt, same model, different sample, different lead set. So:

- The "architecture novelty" measurements are unstable under sampling variance.
- The Sonnet+critic vs Sonnet baseline comparison may flip with a different sample.
- The Opus quality advantage may flip with a different sample.

**N=1 per cell isn't enough to distinguish the architecture's effect from sampling variance.** Before any architectural commitment, the right experiment is N=5–10 per cell on the same fixtures to estimate the baseline's lead-set distribution, then ask whether the architecture's distribution is meaningfully different.

### 4. Token cost of the architecture is fixed; quality benefit is variable

Defender + critic ≈ 2x baseline tokens by construction. Quality benefit varies fixture-to-fixture and trial-to-trial. So the architecture's expected ROI is `(P[critic catches what baseline missed] × value_of_catch) / (extra_cost)`. With baseline already producing strong lead sets including adversarial variants, P is small. The architecture would need a *consistent* edge to be worth 2x.

## Recommendations

If the user wants to keep pushing this:

**Don't add more fixtures.** The bottleneck is sampling variance, not coverage.

**Run N=5 per cell on 3 fixtures** (one ambiguous, one true-benign, one bait/true-malicious). Measure for each:
- Verdict-correct rate per config (how often does it land on the right disposition?)
- Lead-set Jaccard similarity within config (how consistent is the same config across samples?)
- Lead-set Jaccard similarity across configs (does the architecture produce a different distribution than baseline?)

If architecture's verdict-correct rate is +X% over baseline AND the lead sets diverge meaningfully, the architecture earns its slot. If not, the right move is a single-prompt PREDICT upgrade ("after committing, generate one hypothesis from the opposite leaning") rather than a two-agent debate.

The N=5×3 study costs ~$5 of compute for the most informative ablation in the experiment. Recommend doing this before any architectural commitment.

## Side note: the surprising winner

If the user's actual goal is "best SOC triage at minimum cost," the data so far suggests a **Sonnet baseline with explicit `?adversary-controlled-*` enumeration in the prompt** is the strongest single move. The architectural complexity of debate may be solving a problem that doesn't exist once the baseline is properly prompted.
