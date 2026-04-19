---
title: Context window management: migrate detailed investigation reasoning to a subagent
status: done
groups: optional, context management
---

Main agent holds: investigation flow, phase state, key findings, hypothesis table.
Reasoning subagent handles: detailed evidence analysis, hypothesis weighting, narrative construction.

Prevents context exhaustion on complex multi-loop investigations. Implementation should be grounded in data