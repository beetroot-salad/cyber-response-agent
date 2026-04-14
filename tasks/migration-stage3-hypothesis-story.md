---
title: Migration Stage 3: Sonnet writes hypothesis stories, Opus makes predictions
status: backlog
groups: sonnet, cost
---

HYPOTHESIZE-phase work splits into two cognitive modes:
- Stories: narrative descriptions of what a hypothesis means (descriptive, cheap output, Sonnet-friendly)
- Predictions: testable implications that drive lead selection (hard reasoning, Opus-worthy)

Sub-tasks:
- New subagent hypothesis-story pinned to Sonnet. Given CONTEXTUALIZE narrative + playbook seed list, produces a structured story per hypothesis: background, what it explains, what it doesn't, how analyst would describe it. Output: story.md per hypothesis in the run dir.
- Main agent (still Opus) reads stories and generates testable predictions — the discriminating evidence list (required_anchors / predictions shape). Then picks leads to confirm/refute based on predictions.
- Guard: cap stories at 4-6 per run (playbook seed count is natural limit). If Sonnet drafter tries to generate hypotheses outside playbook seeds, reject and retry — novel hypotheses must come from main agent's evidence-driven reasoning.
- Measure: HYPOTHESIZE phase output-token cost reduction vs run #9.
