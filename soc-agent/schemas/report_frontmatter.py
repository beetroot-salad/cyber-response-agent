"""Report frontmatter schema and validation.

Validates the YAML frontmatter of investigation report.md files.
Used by hooks/scripts/validate_report.py to enforce structural safety.
"""

from dataclasses import dataclass, field

from schemas.enums import (
    VALID_AUTHORIZATION_VERDICTS,
    VALID_CONFIDENCES,
    VALID_CONSULTATION_GROUNDING_KINDS,
    VALID_CONSULTATION_RESULTS,
    VALID_DISPOSITIONS,
    VALID_STATUSES,
)

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
    status: str  # resolved | escalated
    disposition: str  # benign | true_positive | unclear
    confidence: str  # high | medium | low
    leads_pursued: int

    # Optional fields
    signature_description: str | None = None
    trace: str | None = None
    # Archetype + optional precedent ticket citation. matched_archetype names
    # a directory under knowledge/signatures/{sig}/archetypes/ containing
    # story.md (observable shape) and trust-anchors.md (required_anchors +
    # grounding contract). matched_ticket_id optionally names a precedent
    # snapshot — a JSON file inside that archetype directory — which grounds
    # the match in a specific past ticket.
    # trust_anchors_consulted records which anchors were consulted and what
    # they returned; each entry is a dict with keys: anchor, kind, result,
    # citation (citation is a free-form short description).
    matched_archetype: str | None = None
    matched_ticket_id: str | None = None
    trust_anchors_consulted: list = field(default_factory=list)

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

        if self.status == "resolved":
            if not self.matched_archetype:
                errors.append(
                    "status=resolved requires matched_archetype to be set"
                )
            if self.matched_ticket_id and not self.matched_archetype:
                errors.append(
                    "matched_ticket_id cannot be set without matched_archetype"
                )

        # Validate trust_anchors_consulted shape (when present). v2.11 retains
        # the rolled-up frontmatter shape for report-level consumption; the
        # kind/result vocabularies mirror the on-companion
        # `anchor_consultations[]` block.
        if self.trust_anchors_consulted:
            if not isinstance(self.trust_anchors_consulted, list):
                errors.append("trust_anchors_consulted must be a list")
            else:
                for i, entry in enumerate(self.trust_anchors_consulted):
                    if not isinstance(entry, dict):
                        errors.append(
                            f"trust_anchors_consulted[{i}] must be a dict"
                        )
                        continue
                    for required_key in ("anchor", "kind", "result"):
                        if not entry.get(required_key):
                            errors.append(
                                f"trust_anchors_consulted[{i}] missing '{required_key}'"
                            )
                    kind = entry.get("kind")
                    if kind and kind not in VALID_CONSULTATION_GROUNDING_KINDS:
                        errors.append(
                            f"trust_anchors_consulted[{i}] kind must be one of "
                            f"{VALID_CONSULTATION_GROUNDING_KINDS}, got '{kind}'"
                        )
                    result = entry.get("result")
                    if result and result not in VALID_CONSULTATION_RESULTS:
                        errors.append(
                            f"trust_anchors_consulted[{i}] result must be one of "
                            f"{VALID_CONSULTATION_RESULTS}, got '{result}'"
                        )
                    # `verdict` is optional at the report-frontmatter layer.
                    # It's populated when a rolled-up authorization_resolutions
                    # entry is surfaced; must match the authz verdict vocab
                    # when present.
                    verdict = entry.get("verdict")
                    if verdict is not None and verdict not in VALID_AUTHORIZATION_VERDICTS:
                        errors.append(
                            f"trust_anchors_consulted[{i}] verdict must be one of "
                            f"{VALID_AUTHORIZATION_VERDICTS}, got '{verdict}'"
                        )

        return errors


def parse_frontmatter(fields: dict) -> tuple[ReportFrontmatter | None, list[str]]:
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
        leads_pursued=leads,
        signature_description=fields.get("signature_description"),
        trace=fields.get("trace"),
        matched_archetype=fields.get("matched_archetype"),
        matched_ticket_id=fields.get("matched_ticket_id"),
        trust_anchors_consulted=fields.get("trust_anchors_consulted") or [],
    )

    validation_errors = report.validate()
    errors.extend(validation_errors)

    return report, errors
