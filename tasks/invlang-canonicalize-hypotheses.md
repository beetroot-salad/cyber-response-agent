---
title: Canonicalize hypothesis vocabulary per signature
status: backlog
groups: reliability, knowledge, invlang
---

Each signature's playbook should define a canonical seed-hypothesis name set; the agent can refine descriptions but must not rename the seeds.

Freeform novel hypotheses remain allowed but are flagged as "novel" so the cross-run matcher knows they aren't canonical.

Needed for cross-run pattern matching to work without fuzzy disambiguation (?compromise-followup vs ?session-compromise vs ?followup-success).
