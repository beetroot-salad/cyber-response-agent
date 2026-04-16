---
title: Canonicalize investigation vocabulary (hypotheses + lead names)
status: doing
groups: reliability, knowledge, invlang
---

**Hypotheses:** Each signature's playbook should define a canonical seed-hypothesis name set; the agent can refine descriptions but must not rename the seeds. Freeform novel hypotheses remain allowed but are flagged as "novel" so the cross-run matcher knows they aren't canonical. Needed for cross-run pattern matching to work without fuzzy disambiguation (?compromise-followup vs ?session-compromise vs ?followup-success).

**Lead names:** leads/ directory names are already the authoritative naming registry; enforce that investigation.md's "Selected lead:" field must match a directory entry exactly. A Layer 2 schema check (State Machine Transition Verification Criteria) can enforce this deterministically.