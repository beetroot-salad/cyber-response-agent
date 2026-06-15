---
# This is the actor TRADECRAFT corpus — pattern lessons only. Standing
# deployment facts live in defender/lessons-environment/ (issue #298), authored
# from both directions and retrieved by both actors. Do not author env-facts here.

# Identity (pattern lessons normally have no subject)
subject: {kebab-case-deployment-referent}     # OPTIONAL; only for a pattern bound to one specific referent. Equivalence key for folding.

# Retrieval keys (all optional; AND across keys, OR within a key)
techniques: []                                  # MITRE T-IDs; primary key for pattern lessons
alert_rule_ids: []                              # SIEM rule IDs the lesson bites or describes
defender_lead_tags: []                          # {system}.{kebab-name} lead families this lesson is relevant to

# Cross-links
applies_to: []                                  # subjects of environment-fact lessons (in lessons-environment/) this pattern depends on — human cross-reference

# Mutability
mutable: false                                  # pattern lessons are append-only; true only for the rare subject-bound pattern fact
status: live                                    # live | stale; only meaningful when mutable=true
# superseded_by: {name-of-newer-lesson}         # only when status=stale and a replacement was authored

# Provenance
recorded_at: {batch-id}
source_observation_ids: []

relevance_criteria: one-line predicate the actor scans during enumeration
---

{1–3 short paragraphs, attacker-framed prose for the future actor who will read this without seeing the source case. State the cover/bypass shape that succeeds or fails against this defender; do not preamble.}
