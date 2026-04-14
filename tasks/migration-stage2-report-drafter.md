---
title: Migration Stage 2: Sonnet drafts report.md, Opus reviews and edits
status: backlog
groups: sonnet, cost
---

Splits the CONCLUDE-phase report write between a cheap draft and an expensive review.

Sub-tasks:
- New subagent report-drafter pinned to Sonnet; reads investigation.md + state.json + alert.json, produces first-draft report.md in correct frontmatter schema
- Main agent (still Opus) reads draft and edits via Edit rather than re-writing from scratch. Tier 1 + Tier 2 judge hooks fire on the Edit the same way they fire on a Write.
- Safety check: if report-drafter fails to produce valid frontmatter OR Tier 2 judge rejects the post-edit version twice, fall back to current path (main agent writes from scratch)
- Measure: report-write cost reduction vs run #9's CONCLUDE phase cost. Expect 30-50% savings on report-write specifically.
