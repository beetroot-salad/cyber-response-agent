---
title: Batch parallel reads in CONTEXTUALIZE section of SKILL.md
status: backlog
groups: performance
---

CONTEXTUALIZE currently consumes 18 turns in the full-loop run. Many are sequential Read calls for knowledge files (ip-ranges.md, identity-patterns.md, lead definitions) that could be issued as parallel tool calls in a single turn.

Add explicit batching instruction to SKILL.md CONTEXTUALIZE section: "When reading multiple knowledge or environment files, batch independent reads into a single turn using parallel tool calls. Do not issue sequential Reads for files that don't depend on each other."

Estimated savings: ~$0.15-0.25/run (3-5 fewer turns × ~$0.05/turn in cache reads).