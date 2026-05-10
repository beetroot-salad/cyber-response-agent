# N=4 ablation on fixture 01 — Sonnet baseline vs Sonnet defender+critic vs Opus baseline

Goal: measure whether the architecture's apparent novelty over baseline (originally seen on fixture 01 as "agent-forwarding hypothesis the baseline missed") survives sampling variance.

## Lead-diversity raw data

For each trial, scored two things:
- **Hypothesis count** (single-agent only — defender+critic produces 1 critique)
- **Agent-forwarding hypothesis present** — the specific lead that originally drove the STRONG novelty claim

| Config | Trial | Hypotheses | Agent-forwarding hypothesis present | Disposition leaning |
|---|---|---|---|---|
| Sonnet baseline | 1 | 6 | NO | benign-leaning |
| Sonnet baseline | 2 | 5 | **YES** (`?credential-relay-or-agent-forward-abuse`) | benign-leaning |
| Sonnet baseline | 3 | 5 | NO | benign-leaning |
| Sonnet baseline | 4 | 5 | NO | benign-leaning |
| Opus baseline | 1 | 5 | **YES** (`?adversary-controlled-account` mentions ssh-agent forwarding abuse) | benign-leaning |
| Opus baseline | 2 | 6 | NO | benign-leaning |
| Opus baseline | 3 | 6 | NO | benign-leaning |
| Opus baseline | 4 | 5 | **YES** (`?building-7-wifi-shared-credential-misuse` includes "agent-forwarding leak") | benign-leaning |
| Sonnet defender+critic | 1 | 1 (critique only) | NO | benign committed; critic attacks ticket-legitimacy |
| Sonnet defender+critic | 2 | 1 | NO | benign committed; critic attacks ticket-legitimacy |
| Sonnet defender+critic | 3 | 1 | NO | benign committed; critic attacks ticket-legitimacy |
| Sonnet defender+critic | 4 | 1 | NO | benign committed; critic attacks ticket-legitimacy |

## Headline rates

| Config | Agent-forwarding hypothesis rate | Hypotheses per trial (mean) | Cost per trial | Total cost (N=4) |
|---|---|---|---|---|
| Sonnet baseline | **25% (1/4)** | 5.25 | $0.10 | $0.41 |
| Opus baseline | **50% (2/4)** | 5.50 | $1.26 | $5.04 |
| Sonnet defender+critic | **0% (0/4)** | 1.0 | $0.20 | $0.81 |

## Key finding: the defender prompt creates anchor convergence

All 4 Sonnet defenders identified the **same** load-bearing assumption — variations on "INC-8821 ticket is legitimately authored/closed by jsmith." All 4 critics then attacked ticket-legitimacy with variants of "query ticketing audit log for closure source IP."

**The architecture's hypothesis space on this fixture is concentrated on one seam (ticket-legitimacy), missing the agent-forwarding angle entirely.**

## What this means

The architecture is not a hypothesis-generator that beats baseline. It's a **focused assumption-attacker** that goes deep on the seam the defender self-identifies. On fixture 01, the defender consistently picks ticket-legitimacy as the seam, so the architecture consistently attacks that — and consistently misses agent-forwarding, which baseline produces 25-50% of the time.

| | Sonnet baseline | Opus baseline | Sonnet defender+critic |
|---|---|---|---|
| **Hypothesis breadth** (per trial) | 5–6 | 5–6 | 1 |
| **Hypothesis diversity** (across trials) | high (varied 5–6 sets) | high | low (all 4 attack same seam) |
| **Lead specificity** (depth of single check) | medium | medium-high | high |
| **Cost** (per trial) | $0.10 | $1.26 | $0.20 |
| **Agent-forwarding hit rate** | 25% | 50% | 0% |

## Implication

At N=4 on this fixture, the architecture is strictly dominated:
- Opus baseline beats it on quality (50% > 0% agent-forwarding rate, broader hypothesis enumeration)
- Sonnet baseline beats it on cost ($0.10 vs $0.20) at acceptable quality (still 25% agent-forwarding rate, broader enumeration)

The original STRONG-novelty finding on fixture 01 was sampling variance plus an unfair baseline (single sample, default model — possibly without explicit `?adversary-controlled-*` prompt). At N=4 with proper prompting, baseline produces what the architecture missed, not the other way around.

## Where the architecture might still pay off

The critic's depth on the seam it does attack is real. The trial 1 critic's lead (query ticketing audit for INC-8821 closure source IP + bastion syslog for config artifacts in 03:31-03:47Z window + cross-check against jsmith's normal ticket-IP baseline) is more concrete than baseline's general "verify ticket scope."

So the architecture might be valuable as a **selective deepening tool applied after baseline produces a hypothesis** — not as a hypothesis-generator. Different architecture entirely:

```
baseline (broad hypothesis enumeration, single agent)
  ↓
pick the most uncertain hypothesis
  ↓
critic-style depth pass on that one hypothesis
  ↓
report
```

Rather than:

```
defender (commits) → critic (attacks committed assumption)
```

The user's #2 question (where would a critic actually help?) is exactly the right next question.
