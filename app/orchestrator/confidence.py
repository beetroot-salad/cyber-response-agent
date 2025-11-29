"""
Decision matrix for routing alerts.

Maps discrete factors to routing decisions using a lookup table with hierarchical fallback:
- Asset/Identity criticality (from alert or asset inventory)
- Signature severity / Alert priority (from SIEM)
- Precedent exists (matched past ticket)
- Agent confidence (self-reported: high/medium/low)

The matrix produces a Decision, not a numeric score.
"""

from typing import Optional

from .models import Decision


# Decision matrix: (criticality, severity, has_precedent, agent_confidence) -> Decision
# Only key combinations are defined; others fall back hierarchically
DECISION_MATRIX: dict[tuple[str, str, bool, str], Decision] = {
    # Critical assets - always escalate unless reproduction confirmed
    ("critical", "critical", True, "high"): Decision.ESCALATE,
    ("critical", "critical", True, "medium"): Decision.ESCALATE,
    ("critical", "critical", True, "low"): Decision.ESCALATE,
    ("critical", "high", True, "high"): Decision.ESCALATE,
    ("critical", "medium", True, "high"): Decision.REPRODUCE,
    ("critical", "low", True, "high"): Decision.REPRODUCE,

    # Elevated assets - require high confidence for auto-close
    ("elevated", "critical", True, "high"): Decision.ESCALATE,
    ("elevated", "high", True, "high"): Decision.REPRODUCE,
    ("elevated", "medium", True, "high"): Decision.AUTO_CLOSE,
    ("elevated", "medium", True, "medium"): Decision.REPRODUCE,
    ("elevated", "low", True, "high"): Decision.AUTO_CLOSE,
    ("elevated", "low", True, "medium"): Decision.REPRODUCE,

    # Standard assets - most permissive
    ("standard", "critical", True, "high"): Decision.REPRODUCE,
    ("standard", "high", True, "high"): Decision.REPRODUCE,
    ("standard", "high", True, "medium"): Decision.ESCALATE,
    ("standard", "medium", True, "high"): Decision.AUTO_CLOSE,
    ("standard", "medium", True, "medium"): Decision.REPRODUCE,
    ("standard", "low", True, "high"): Decision.AUTO_CLOSE,
    ("standard", "low", True, "medium"): Decision.AUTO_CLOSE,
}


def _normalize_input(value: Optional[str], default: str, valid: set[str]) -> str:
    """Normalize input to lowercase, use default if missing or invalid."""
    if value is None:
        return default
    normalized = value.lower().strip()
    return normalized if normalized in valid else default


def get_decision(
    agent_confidence: Optional[str] = None,
    has_precedent: bool = False,
    asset_criticality: Optional[str] = None,
    signature_severity: Optional[str] = None,
    reproduction_result: Optional[str] = None,
) -> Decision:
    """
    Determine routing decision based on discrete factors.

    Uses a decision matrix with hierarchical fallback:
    1. Exact match in matrix -> use that decision
    2. No match -> try with lower severity
    3. Still no match -> try with lower criticality
    4. Final fallback -> ESCALATE

    Special rules applied before matrix lookup:
    - No precedent -> ESCALATE (novel alert)
    - Reproduction refuted -> ESCALATE
    - Reproduction confirmed + medium+ confidence -> AUTO_CLOSE

    Args:
        agent_confidence: "high", "medium", or "low" (default: "low")
        has_precedent: Whether a matching past ticket was found
        asset_criticality: "standard", "elevated", or "critical" (default: "standard")
        signature_severity: "low", "medium", "high", or "critical" (default: "medium")
        reproduction_result: "confirmed", "refuted", or None

    Returns:
        Decision enum value (AUTO_CLOSE, REPRODUCE, or ESCALATE)
    """
    # Normalize inputs with defaults
    confidence = _normalize_input(
        agent_confidence, "low", {"high", "medium", "low"}
    )
    criticality = _normalize_input(
        asset_criticality, "standard", {"standard", "elevated", "critical"}
    )
    severity = _normalize_input(
        signature_severity, "medium", {"low", "medium", "high", "critical"}
    )

    # Pre-matrix rules
    if not has_precedent:
        return Decision.ESCALATE

    if reproduction_result == "refuted":
        return Decision.ESCALATE

    if reproduction_result == "confirmed" and confidence in ("high", "medium"):
        return Decision.AUTO_CLOSE

    # Matrix lookup with hierarchical fallback
    return _lookup_with_fallback(criticality, severity, confidence)


def _lookup_with_fallback(
    criticality: str, severity: str, confidence: str
) -> Decision:
    """
    Look up decision in matrix with hierarchical fallback.

    Fallback order:
    1. Exact match
    2. Lower severity (critical -> high -> medium -> low)
    3. Lower criticality (critical -> elevated -> standard)
    4. Default to ESCALATE
    """
    severity_order = ["critical", "high", "medium", "low"]
    criticality_order = ["critical", "elevated", "standard"]

    # Get indices for fallback iteration
    sev_idx = severity_order.index(severity) if severity in severity_order else 2
    crit_idx = criticality_order.index(criticality) if criticality in criticality_order else 2

    # Try exact match first, then fall back through severity, then criticality
    for c in criticality_order[crit_idx:]:
        for s in severity_order[sev_idx:]:
            key = (c, s, True, confidence)
            if key in DECISION_MATRIX:
                return DECISION_MATRIX[key]
        # Reset severity for next criticality level
        sev_idx = 0

    # Final fallback: ESCALATE (conservative)
    return Decision.ESCALATE


def calculate_confidence(
    agent_confidence: Optional[str] = None,
    matched_tier: Optional[str] = None,
    reproduction_result: Optional[str] = None,
    asset_criticality: Optional[str] = None,
) -> float:
    """
    Calculate a numeric confidence score for audit logging.

    This is an approximation for logging/display purposes.
    The actual routing decision is made by get_decision().

    Returns:
        Approximate confidence score between 0.0 and 1.0
    """
    confidence = _normalize_input(
        agent_confidence, "low", {"high", "medium", "low"}
    )
    criticality = _normalize_input(
        asset_criticality, "standard", {"standard", "elevated", "critical"}
    )

    # Base from agent confidence
    confidence_scores = {"high": 0.85, "medium": 0.60, "low": 0.30}
    base = confidence_scores.get(confidence, 0.30)

    # Modifier from precedent tier
    tier_modifiers = {"gold": 0.10, "silver": 0.05, "bronze": 0.0}
    tier_mod = tier_modifiers.get(matched_tier, -0.15)

    # Modifier from reproduction
    repro_modifiers = {"confirmed": 0.15, "refuted": -0.30}
    repro_mod = repro_modifiers.get(reproduction_result, 0.0)

    # Penalty from asset criticality
    criticality_penalties = {"standard": 0.0, "elevated": -0.05, "critical": -0.15}
    crit_penalty = criticality_penalties.get(criticality, 0.0)

    total = base + tier_mod + repro_mod + crit_penalty
    return max(0.0, min(1.0, total))
