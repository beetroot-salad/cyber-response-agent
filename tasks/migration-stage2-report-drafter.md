---
title: Migration Stage 2 (deferred): Sonnet drafts report.md, Opus reviews and edits
status: backlog
groups: sonnet-migration, cost
---

**Deferred — superseded by the direct main-agent flip.** Phase-by-phase partial migration is no longer the plan. The decision doc (2026-04-13 session) concluded that the "Sonnet main + phase-specific splits" approach is over-engineered; the active plan is to flip the whole main agent to Sonnet once signature scaffolding matures (migration-stage4-flip-main). Kept as reference in case a partial fallback is needed if the direct flip regresses.

Original design: splits the CONCLUDE-phase report write between a cheap draft and an expensive review.

Sub-tasks:
- New subagent report-drafter pinned to Sonnet; reads investigation.md + state.json + alert.json, produces first-draft report.md in correct frontmatter schema
- Main agent (still Opus) reads draft and edits via Edit rather than re-writing from scratch. Tier 1 + Tier 2 judge hooks fire on the Edit the same way they fire on a Write.
- Safety check: if report-drafter fails to produce valid frontmatter OR Tier 2 judge rejects the post-edit version twice, fall back to current path (main agent writes from scratch)
- Measure: report-write cost reduction vs run #9's CONCLUDE phase cost. Expect 30-50% savings on report-write specifically.
