---
title: Evaluation plan: build screening test corpus and scoring pipeline
status: backlog
groups: evaluation
---

Screening is the right starting point for evaluation (most common sub-flow, cheapest to evaluate, clear pass/fail).

Sub-tasks:
- Build test corpus: ~10-20 alerts per signature covering pattern space (clear matches, near-misses, true negatives)
- Define ground truth: expected screen_result, matched_pattern, and disposition per alert
- Run screening subagent against corpus, collect structured output
- Score: accuracy, false match rate, false no-match rate, output format compliance
- Identify failure modes: which patterns break, which indicators are ambiguous, which prompts need tuning
- After screening is solid: extend to ticket-context subagent, then full investigation loop
