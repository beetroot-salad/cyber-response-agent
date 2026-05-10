# ANALYZE Subagent Extraction Pilot

Empirical probe of extracting the ANALYZE phase of the investigation
loop into a dedicated subagent. Two open questions:

1. **What context is load-bearing?** ANALYZE has many state-bearing
   rules (prior grade history, named refutation checks, archetype
   anchors, adversarial status). The pilot sorts these into
   necessary / nice-to-have / ignored by varying context bundles
   across arms.
2. **Who owns routing?** Should the subagent decide
   HYPOTHESIZE|CONCLUDE, or only produce a weighted assessment and
   let the main agent route?

**Driver:** `.claude/skills/analyze-pilot/SKILL.md` — experimental
method, current state, how to continue.

## Quick tour

- `fixtures/` — truncated real past runs + held-out ground-truth
  ANALYZE blocks; see SKILL.md "Fixture shape".
- `rounds/` — per-round arm outputs and comparison writeups.
- `contract.md` — (appears after rounds complete) the locked
  contract: decision-owning vs assessment-only, plus the required
  context bundle.

Invoke via `/analyze-pilot [status|next|method|launch <round>]`.
