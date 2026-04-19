"""Shared enums for investigation outcomes.

Single source of truth for status, disposition, confidence, and hypothesis
status values. Imported by report_frontmatter.py and precedent.py.
"""

# What action was taken on the alert
VALID_STATUSES = ("resolved", "escalated")

# The investigative conclusion about what happened
VALID_DISPOSITIONS = ("benign", "false_positive", "true_positive", "inconclusive")

# How confident the investigation is in its conclusion
VALID_CONFIDENCES = ("high", "medium", "low")

# Current state of a hypothesis during/after investigation
VALID_HYPOTHESIS_STATUSES = ("active", "confirmed", "refuted", "untested")

# Trust anchor citation kinds — distinguishes org authorities from
# telemetry-derived pragmatic anchors (e.g. image-baseline)
VALID_ANCHOR_KINDS = ("org-authority", "telemetry-baseline")

# Result of a trust anchor consultation
VALID_ANCHOR_RESULTS = ("confirmed", "refuted", "unavailable")

# What an authority consultation is asking about. Distinct from `result`:
#   asks: authorization  — "is this action sanctioned right now?"
#                          → emits a verdict (authorized/unauthorized/indeterminate)
#   asks: expectation    — "does this match our historical baseline / registry?"
#                          → no verdict; baselines don't authorize
VALID_ASKS = ("expectation", "authorization")

# Verdict returned by an authorization-class authority consultation.
# Required when trust_anchor_result.asks == "authorization"; forbidden
# when asks == "expectation" (telemetry baselines don't authorize).
VALID_LEGITIMACY_VERDICTS = ("authorized", "unauthorized", "indeterminate")
