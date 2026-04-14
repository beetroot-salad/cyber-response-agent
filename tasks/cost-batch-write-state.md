---
title: Batch write_state with investigation.md writes at each phase transition
status: backlog
group: cost
---

Every phase transition currently takes two turns: one Bash call to write_state.py, then a separate Write/Edit to investigation.md. These are independent and can be batched into a single turn.

Add explicit batching instruction to SKILL.md phase transitions: "At each phase transition, issue the write_state.py Bash call and the investigation.md Edit as parallel tool calls in the same message."

Estimated savings: ~$0.25-0.30/run (5-6 fewer turns × ~$0.05/turn).
