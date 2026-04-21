---
title: State machine transition verification criteria (7 transitions)
status: done
groups: reliability, state
---

Add actionable verification gates to each transition so write_state.py can reject transitions where the agent hasn't done meaningful work. Currently enforces legal transitions but not quality of work within a phase.

Criteria to define per transition (gather eval data first, then enforce):

- CONTEXTUALIZE → SCREEN/HYPOTHESIZE: Did investigation.md get written? Contains alert observables, entity extraction, and resolution map?
- SCREEN → CONCLUDE: Does screen output contain screen_result: match, a named matched_pattern, and a valid matched_precedent file? Were required leads actually run?
- SCREEN → HYPOTHESIZE: Does screen output contain screen_result: no_match with a reason? Is evidence from screen leads carried forward?
- HYPOTHESIZE → GATHER: Does investigation.md contain at least one ?hypothesis with status active? Is there a selected lead with predictions?
- GATHER → ANALYZE: Was at least one tool call made? Does investigation.md contain raw observations (not just "no results")?
- ANALYZE → HYPOTHESIZE (loop): Does investigation.md contain assessment weights (++/+/-/--)? Is there a stated reason for another loop?
- ANALYZE → CONCLUDE: Is there exactly one ++ hypothesis? Are all adversarial hypotheses explicitly -- refuted with reasoning? Does investigation meet min-leads-by-severity?

Approach: instrument → identify failure modes → define thresholds → implement incrementally. Start with structural checks (file exists, field present), defer semantic checks.