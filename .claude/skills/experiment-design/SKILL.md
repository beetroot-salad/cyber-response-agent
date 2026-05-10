---
name: experiment-design
description: "Draft an experiment plan for a prompt, skill, or engineering change before any trials run. Forces a clear question, regression-preserving variants, shape-current fixtures, batched mid-run analysis, and scratchpad placement. Use when comparing prompt variants, validating a skill change, or running any multi-trial investigation."
---

# Experiment Design

Produce a written plan answering each section below, then wait for confirmation before launching trials.

## 1. Question

State what the experiment is meant to answer. Either:
- a **product question** ("what experience do we want?" — settle edit surface, failure mode, file co-maintenance shape before quality comparison), or
- an **engineering question** ("what pattern should we converge on?" — e.g. does mechanism X reduce token use, does ordering Y stabilize tool calls).

Most experiments are engineering, not product. Pick the lens that fits — don't force product framing onto an engineering question.

## 2. Variants

- One variable changes between variants. Quote the diff inline (≤30 lines). If other edits are bundled, split them out.
- **Always include the current prompt/config as a variant** — it's the regression validator. A two-arm experiment is `current` vs `proposed`, not `proposed-A` vs `proposed-B` with current dropped.

## 3. Fixtures

Past investigations/alerts or synthetic examples both work. Requirements:
- **Shape-current** — schemas, structures, flows match the version under test. Stale fixtures invalidate results.
- **Load-bearing** — the variable plausibly changes outcomes on this fixture.
- For multi-fixture runs, list each one and what it's meant to exercise.

## 4. Trial count & batching

- Validation pass: 1 trial per variant per fixture, confirm the experiment is well-formed.
- Scale-up: only after validation passes. State N up front.
- For runs ≥10 trials per arm:
  - **(a) Write the analysis script before launching.** Define the metrics, the aggregation, the comparison. If you can't write the script, you can't interpret the run.
  - **(b) Mid-run analysis at 25–30% completion.** Pause, run the analysis script, decide whether to continue, abort, or adjust. Avoid one giant dump at the end.

## 5. Decision criteria

State up front what would make the proposed variant win — and what would make the current variant retained. If you can't articulate criteria before running, the experiment isn't ready.

## 6. Layout

All experiment artifacts live under `experiments/<experiment-name>/`:

```
experiments/<experiment-name>/
  plan.md           # this plan
  variants/         # prompt files or config diffs
  fixtures/         # or pointers to canonical fixtures
  runs/             # per-trial outputs
  analyze.py        # written before scale-up
  results/          # mid-run + final analysis
```

## 7. Ranking (when aggregating)

Rank by per-occurrence mean with `n` shown as support — not by `log1p(count) × mean` or other count-weighted scores.

## Output format

```
## Question
<engineering | product> — <one sentence>

## Variants
### current (regression)
<diff or quoted text>
### proposed
<diff or quoted text>

## Fixtures
- <path> — <what it exercises>

## Trials
Validation: 1 per variant per fixture.
Scale-up: N=<…>. Mid-run analysis at <25–30%>. Analysis script: experiments/<name>/analyze.py.

## Decision criteria
- proposed wins if <criterion>
- current retained if <criterion>

## Layout
experiments/<name>/
```
