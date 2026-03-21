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
