---
title: Make ticket-context / past-investigations re-invocation explicit down the line
status: todo
groups: knowledge, past-runs
---

`ticket-context` (and, once `past-runs-lead` lands, the past-investigations lead) is invoked once at CONTEXTUALIZE. Beyond that the workflow is implicit: the main agent may or may not remember to re-consult past cases at later decision points. In practice there are several moments where re-invocation is high-value but currently unprompted:

- At HYPOTHESIZE, after the lean hypothesis set is drafted — "have past cases with this alert shape refined at loop 1, and into what children?"
- At anchor-calibration time (when deciding `authority_for_question: full | partial` on a trust lead) — "how did past writers classify this anchor for this question shape?"
- At dead-end recognition — "is this lead known attribution-opaque for this vertex shape, based on prior dead-leads index entries?"
- At CONCLUDE severity-ceiling classification — "what termination category did past cases with the same multi-anchor evidence state pick?"

Current SKILL.md only documents the CONTEXTUALIZE invocation (§CONTEXTUALIZE step 3). Add explicit workflow guidance naming the decision points where re-invocation is expected, what to query for at each, and how to integrate the result (seeds, calibration, dead-end avoidance).

Related: `past-runs-lead` (backlog) is the lead-shaped surface the re-invocation would call. This task is the **main-agent workflow** side of the same capability — explicit prompts in SKILL.md telling the agent *when* to call it, not just *that* it exists.

Depends indirectly on the invlang pilot's query/distillation script: the thing the re-invocation actually queries against is the distillation projections computed from past investigation companions.
