---
# Identity
subject: {kebab-referent}            # OPTIONAL — only for a fact about ONE referent (e.g. svc.monitoring).
                                     # The fold/equivalence key: two lessons with the same subject must be reconciled.

# Retrieval — classification-first, sharing invlang vertex vocabulary
# (`type` from `enum types`; `class` is the per-type slot string, e.g. identity = <kind>/<provenance>,
#  compute = <role>/<zone>/<kind>). Slot-wildcards allowed: `service-account/*`, `*/internal`.
entities:                            # CONJUNCTIVE: a case matches only if ALL selectors are satisfied
  - {type: <invlang-type>, class: <type/class slot>}   #   by some entity in the case prologue (AND across rows).
alert_rule_ids: []                   # secondary key — SIEM rule ids this lesson explains or bites

relevance_criteria: one-line predicate the actor scans during enumeration

# Mutability
mutable: true                        # true = deployment fact that can change; flip to stale when superseded
status: live                         # live | stale
# superseded_by: {name}              # only when status=stale

# Provenance
recorded_at: {batch-id}
source_observation_ids: []
---

{1–3 short paragraphs of observational advice/framing for the future actor, who reads this
without seeing the source case. State the standing deployment fact and what grounds it (the
system of record it is anchored in); add the baseline that makes the activity routine where
relevant. Write what is TRUE about this environment so the actor can reason WITH it — not
"do X" / "don't do Y". Lead with the claim; no preamble.}
