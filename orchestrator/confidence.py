"""
Confidence scoring formula.

Deterministic calculation based on:
- Precedent tier (base score)
- Conditions met ratio
- Evidence availability
- Reproduction result (if any)
- Asset criticality
"""

from typing import Optional

from .models import Decision, PrecedentTier


# Base scores by precedent tier
TIER_SCORES: dict[Optional[str], float] = {
    PrecedentTier.GOLD.value: 0.70,
    PrecedentTier.SILVER.value: 0.50,
    PrecedentTier.BRONZE.value: 0.30,
    "gold": 0.70,
    "silver": 0.50,
    "bronze": 0.30,
    None: 0.0,
}

# Reproduction result modifiers
REPRODUCTION_MODIFIERS: dict[Optional[str], float] = {
    "confirmed": 0.15,
    "refuted": -0.30,
    None: 0.0,
}

# Asset criticality penalties
CRITICALITY_PENALTIES: dict[str, float] = {
    "standard": 0.0,
    "elevated": -0.10,
    "critical": -0.25,
}


def calculate_confidence(
    matched_tier: Optional[str],
    conditions_met: int,
    conditions_total: int,
    evidence_available: bool,
    reproduction_result: Optional[str] = None,
    asset_criticality: str = "standard",
) -> float:
    """
    Calculate confidence score for auto-close decision.

    Args:
        matched_tier: "gold", "silver", "bronze", or None (from matched past ticket)
        conditions_met: Number of conditions satisfied
        conditions_total: Total number of conditions to check
        evidence_available: Whether sufficient evidence was gathered
        reproduction_result: "confirmed", "refuted", or None
        asset_criticality: "standard", "elevated", or "critical"

    Returns:
        Confidence score between 0.0 and 1.0
    """
    # Input validation
    if conditions_met < 0:
        raise ValueError("conditions_met cannot be negative")
    if conditions_total < 0:
        raise ValueError("conditions_total cannot be negative")
    if conditions_met > conditions_total and conditions_total > 0:
        raise ValueError("conditions_met cannot exceed conditions_total")
    if asset_criticality not in CRITICALITY_PENALTIES:
        raise ValueError(f"Invalid asset_criticality: {asset_criticality}")
    if reproduction_result is not None and reproduction_result not in REPRODUCTION_MODIFIERS:
        raise ValueError(f"Invalid reproduction_result: {reproduction_result}")

    # Base score from matched ticket tier
    base = TIER_SCORES.get(matched_tier, 0.0)

    # Condition satisfaction ratio (up to 0.20)
    if conditions_total > 0:
        condition_score = 0.20 * (conditions_met / conditions_total)
    else:
        condition_score = 0.0

    # Evidence availability bonus
    evidence_score = 0.10 if evidence_available else 0.0

    # Reproduction modifier
    repro_modifier = REPRODUCTION_MODIFIERS.get(reproduction_result, 0.0)

    # Asset criticality penalty
    asset_penalty = CRITICALITY_PENALTIES.get(asset_criticality, 0.0)

    # Calculate total and clamp to [0.0, 1.0]
    total = base + condition_score + evidence_score + repro_modifier + asset_penalty
    return max(0.0, min(1.0, total))


def get_decision(confidence: float, has_precedent: bool) -> Decision:
    """
    Determine routing decision based on confidence score.

    Args:
        confidence: Confidence score (0.0 to 1.0)
        has_precedent: Whether a precedent was matched

    Returns:
        Decision enum value
    """
    if not has_precedent:
        return Decision.ESCALATE

    if confidence >= 0.90:
        return Decision.AUTO_CLOSE
    elif confidence >= 0.70:
        return Decision.REPRODUCE
    else:
        return Decision.ESCALATE
