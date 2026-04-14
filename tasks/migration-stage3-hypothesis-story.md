---
title: Migration Stage 3 (deferred): Sonnet writes hypothesis stories, Opus makes predictions
status: deferred
groups: sonnet-migration, cost
---

**Deferred — superseded by the direct main-agent flip.** Phase-by-phase partial migration is no longer the plan. The decision doc (2026-04-13 session) concluded that the "Sonnet main + phase-specific splits" approach is over-engineered; the active plan is to flip the whole main agent to Sonnet once signature scaffolding matures (migration-stage4-flip-main). Kept as reference in case a partial fallback is needed if the direct flip regresses.

Original design — HYPOTHESIZE-phase work splits into two cognitive modes:

- Stories: narrative descriptions of what a hypothesis means (descriptive, cheap output, Sonnet-friendly)
- Predictions: testable implications that drive lead selection (hard reasoning, Opus-worthy)

Sub-tasks:

- New subagent hypothesis-story pinned to Sonnet. Given CONTEXTUALIZE narrative + playbook seed list, produces a structured story per hypothesis: background, what it explains, what it doesn't, how analyst would describe it. Output: story.md per hypothesis in the run dir.
- Main agent (still Opus) reads stories and generates testable predictions — the discriminating evidence list (required_anchors / predictions shape). Then picks leads to confirm/refute based on predictions.
- Guard: cap stories at 4-6 per run (playbook seed count is natural limit). If Sonnet drafter tries to generate hypotheses outside playbook seeds, reject and retry — novel hypotheses must come from main agent's evidence-driven reasoning.
- Measure: HYPOTHESIZE phase output-token cost reduction vs run #9.
