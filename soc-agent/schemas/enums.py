"""Shared enums for investigation outcomes.

Single source of truth for status, disposition, confidence, and hypothesis
status values. Imported by report_frontmatter.py and precedent.py.
"""

# What action was taken on the alert
VALID_STATUSES = ("resolved", "escalated")

# The investigative conclusion about the mechanism / authorization axis.
# v2.11 collapses the four-way (benign / false_positive / true_positive /
# inconclusive) to the three-way (benign / true_positive / unclear) —
# false_positive collapses into benign (no threat + no impact) and
# inconclusive becomes unclear.
VALID_DISPOSITIONS = ("benign", "true_positive", "unclear")

# How confident the investigation is in its conclusion
VALID_CONFIDENCES = ("high", "medium", "low")

# Current state of a hypothesis during/after investigation
VALID_HYPOTHESIS_STATUSES = ("active", "confirmed", "refuted", "untested")

# Verdict returned by an authorization-class anchor consultation.
VALID_AUTHORIZATION_VERDICTS = ("authorized", "unauthorized", "indeterminate")

# Grounding kinds: which surface the consultation rests on. v2.11 splits
# the v2.10 `VALID_ANCHOR_KINDS` tuple into three surface-specific tuples —
# authorization resolutions, baseline/registry consultations, and impact
# resolutions have different admissible sets (schema rule #11).
VALID_AUTHZ_GROUNDING_KINDS = ("org-authority", "past-case")
VALID_CONSULTATION_GROUNDING_KINDS = ("org-authority", "telemetry-baseline")
VALID_IMPACT_GROUNDING_KINDS = (
    "telemetry-baseline",
    "business-owner-attestation",
    "dlp-policy",
)

# Anchor-consultation result vocabulary (baseline / registry lookups).
VALID_CONSULTATION_RESULTS = ("confirmed", "refuted", "partial", "no-data")

# Impact axis enums (rules #29–#31 + CONCLUDE two-axis block).
VALID_IMPACT_DIMENSIONS = ("confidentiality", "integrity", "availability", "scope")
VALID_IMPACT_VERDICTS = ("within", "exceeds", "indeterminate")
# CONCLUDE adds `none` (no impact predictions declared or all `within`).
VALID_CONCLUDE_IMPACT_VERDICTS = ("none", "within", "exceeds", "indeterminate")
VALID_IMPACT_SEVERITIES = (None, "low", "moderate", "high")
