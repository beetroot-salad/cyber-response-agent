"""
Confidence scoring formula.

Simplified calculation based on:
- Matched ticket tier (base score from precedent quality)
- Reproduction result (if run)
- Asset criticality (penalty for critical assets)

The agent provides the recommendation; the orchestrator calculates confidence
to decide whether to trust it (auto-close), verify it (reproduce), or escalate.
"""

from typing import Optional

from .models import Decision


# Base scores by matched ticket tier
TIER_SCORES: dict[Optional[str], float] = {
    "gold": 0.90,    # High confidence - well-documented pattern
    "silver": 0.75,  # Medium confidence - known pattern, less documentation
    "bronze": 0.60,  # Low confidence - observed before but sparse data
    None: 0.0,       # No precedent - must escalate
}

# Reproduction result modifiers
REPRODUCTION_MODIFIERS: dict[Optional[str], float] = {
    "confirmed": 0.10,   # Reproduction confirmed agent's finding
    "refuted": -0.30,    # Reproduction contradicted agent's finding
    None: 0.0,
}

# Asset criticality penalties (more caution for critical assets)
CRITICALITY_PENALTIES: dict[str, float] = {
    "standard": 0.0,
    "elevated": -0.05,
    "critical": -0.15,
}


def calculate_confidence(
    matched_tier: Optional[str],
    reproduction_result: Optional[str] = None,
    asset_criticality: str = "standard",
) -> float:
    """
    Calculate confidence score for the agent's recommendation.

    Args:
        matched_tier: "gold", "silver", "bronze", or None (from matched past ticket)
        reproduction_result: "confirmed", "refuted", or None
        asset_criticality: "standard", "elevated", or "critical"

    Returns:
        Confidence score between 0.0 and 1.0
    """
    # Input validation
    if asset_criticality not in CRITICALITY_PENALTIES:
        raise ValueError(f"Invalid asset_criticality: {asset_criticality}")
    if reproduction_result is not None and reproduction_result not in REPRODUCTION_MODIFIERS:
        raise ValueError(f"Invalid reproduction_result: {reproduction_result}")

    # Base score from matched ticket tier
    base = TIER_SCORES.get(matched_tier, 0.0)

    # Reproduction modifier
    repro_modifier = REPRODUCTION_MODIFIERS.get(reproduction_result, 0.0)

    # Asset criticality penalty
    asset_penalty = CRITICALITY_PENALTIES.get(asset_criticality, 0.0)

    # Calculate total and clamp to [0.0, 1.0]
    total = base + repro_modifier + asset_penalty
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
