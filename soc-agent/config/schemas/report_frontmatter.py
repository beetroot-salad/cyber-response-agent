"""Report frontmatter schema and validation.

Validates the YAML frontmatter of investigation report.md files.
Used by hooks/scripts/validate_report.py to enforce structural safety.
"""

from dataclasses import dataclass
from typing import Optional


VALID_STATUSES = ("resolved", "escalate")
VALID_DISPOSITIONS = ("benign", "false_positive", "true_positive")
VALID_CONFIDENCES = ("high", "medium", "low")

# Minimum leads_pursued per severity level
MIN_LEADS_BY_SEVERITY = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


@dataclass
class ReportFrontmatter:
    """Structured representation of a report's YAML frontmatter."""

    ticket_id: str
    signature_id: str
    status: str  # resolved | escalate
    disposition: str  # benign | false_positive | true_positive
    confidence: str  # high | medium | low
    matched_precedent: Optional[str]  # precedent filename or null
    leads_pursued: int

    # Optional fields
    signature_description: Optional[str] = None
    trace: Optional[str] = None

    def validate(self) -> list[str]:
        """Validate all fields. Returns list of error messages (empty = valid)."""
        errors = []

        if not self.ticket_id:
            errors.append("ticket_id is required")
        if not self.signature_id:
            errors.append("signature_id is required")

        if self.status not in VALID_STATUSES:
            errors.append(
                f"status must be one of {VALID_STATUSES}, got '{self.status}'"
            )
        if self.disposition not in VALID_DISPOSITIONS:
            errors.append(
                f"disposition must be one of {VALID_DISPOSITIONS}, got '{self.disposition}'"
            )
        if self.confidence not in VALID_CONFIDENCES:
            errors.append(
                f"confidence must be one of {VALID_CONFIDENCES}, got '{self.confidence}'"
            )

        if not isinstance(self.leads_pursued, int) or self.leads_pursued < 0:
            errors.append(f"leads_pursued must be a non-negative integer, got '{self.leads_pursued}'")

        if self.status == "resolved" and not self.matched_precedent:
            errors.append(
                "status=resolved requires matched_precedent to be set"
            )

        return errors


def parse_frontmatter(fields: dict) -> tuple[Optional[ReportFrontmatter], list[str]]:
    """Parse a dict of frontmatter fields into a ReportFrontmatter.

    Returns (report, errors). If errors is non-empty, report may be partial.
    """
    errors = []
    required = ["ticket_id", "signature_id", "status", "disposition", "confidence", "leads_pursued"]
    for field_name in required:
        if field_name not in fields:
            errors.append(f"missing required field: {field_name}")

    if errors:
        return None, errors

    leads = fields.get("leads_pursued", 0)
    try:
        leads = int(leads)
    except (ValueError, TypeError):
        errors.append(f"leads_pursued must be an integer, got '{leads}'")
        leads = 0

    report = ReportFrontmatter(
        ticket_id=str(fields.get("ticket_id", "")),
        signature_id=str(fields.get("signature_id", "")),
        status=str(fields.get("status", "")),
        disposition=str(fields.get("disposition", "")),
        confidence=str(fields.get("confidence", "")),
        matched_precedent=fields.get("matched_precedent"),
        leads_pursued=leads,
        signature_description=fields.get("signature_description"),
        trace=fields.get("trace"),
    )

    validation_errors = report.validate()
    errors.extend(validation_errors)

    return report, errors
