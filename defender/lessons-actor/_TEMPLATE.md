---
# Identity (subject is the filename for env-facts; pattern lessons have no subject)
subject: {kebab-case-deployment-referent}     # OPTIONAL; required for env-fact lessons. Equivalence key for folding.

# Retrieval keys (all optional; AND across keys, OR within a key)
techniques: []                                  # MITRE T-IDs; primary key for pattern lessons
alert_rule_ids: []                              # SIEM rule IDs the lesson bites or describes
defender_lead_tags: []                          # {system}.{kebab-name} lead families this lesson is relevant to

# Cross-links
applies_to: []                                  # subjects of env-fact lessons this pattern depends on

# Mutability
mutable: true                                   # true = world-fact that can change; false = append-only pattern
status: live                                    # live | stale; only meaningful when mutable=true
# superseded_by: {name-of-newer-lesson}         # only when status=stale and a replacement was authored

# Provenance
recorded_at: {batch-id}
source_observation_ids: []

relevance_criteria: one-line predicate the actor scans during enumeration
---

{1–3 short paragraphs, attacker-framed prose for the future actor who will read this without seeing the source case. State the deployment fact (env) or the cover/bypass shape (pattern); do not preamble.}
