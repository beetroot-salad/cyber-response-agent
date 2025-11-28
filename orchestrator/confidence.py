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


# Base scores by precedent tier
TIER_SCORES = {
    "gold": 0.70,
    "silver": 0.50,
    "bronze": 0.30,
    None: 0.0,
}

# Reproduction result modifiers
REPRODUCTION_MODIFIERS = {
    "confirmed": 0.15,
    "refuted": -0.30,
    None: 0.0,
}

# Asset criticality penalties
CRITICALITY_PENALTIES = {
    "standard": 0.0,
    "elevated": -0.10,
    "critical": -0.25,
}


def calculate_confidence(
    precedent_tier: Optional[str],
    conditions_met: int,
    conditions_total: int,
    evidence_available: bool,
    reproduction_result: Optional[str] = None,
    asset_criticality: str = "standard",
) -> float:
    """
    Calculate confidence score for auto-close decision.

    Args:
        precedent_tier: "gold", "silver", "bronze", or None
        conditions_met: Number of conditions satisfied
        conditions_total: Total number of conditions to check
        evidence_available: Whether sufficient evidence was gathered
        reproduction_result: "confirmed", "refuted", or None
        asset_criticality: "standard", "elevated", or "critical"

    Returns:
        Confidence score between 0.0 and 1.0
    """
    # Base score from precedent tier
    base = TIER_SCORES.get(precedent_tier, 0.0)

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


def get_decision(confidence: float, has_precedent: bool) -> str:
    """
    Determine routing decision based on confidence score.

    Args:
        confidence: Confidence score (0.0 to 1.0)
        has_precedent: Whether a precedent was matched

    Returns:
        Decision: "auto_close", "reproduce", or "escalate"
    """
    if not has_precedent:
        return "escalate"

    if confidence >= 0.90:
        return "auto_close"
    elif confidence >= 0.70:
        return "reproduce"
    else:
        return "escalate"


# Self-test when run directly
if __name__ == "__main__":
    print("Testing confidence scoring...\n")

    test_cases = [
        # (tier, met, total, evidence, repro, criticality, expected_approx)
        ("gold", 4, 4, True, None, "standard", 1.0),  # Perfect match
        ("gold", 2, 4, True, None, "standard", 0.90),  # Half conditions
        ("gold", 1, 4, True, None, "standard", 0.85),  # Quarter conditions
        ("gold", 4, 4, True, "confirmed", "standard", 1.0),  # With repro confirm (clamped)
        ("gold", 4, 4, True, None, "critical", 0.75),  # Critical asset
        (None, 0, 0, False, None, "standard", 0.0),  # No precedent
        ("gold", 4, 4, True, "refuted", "standard", 0.70),  # Repro refuted
        ("silver", 3, 4, True, None, "standard", 0.75),  # Silver tier
        ("bronze", 4, 4, True, None, "standard", 0.60),  # Bronze tier
    ]

    passed = 0
    failed = 0

    for i, (tier, met, total, evidence, repro, crit, expected) in enumerate(test_cases):
        result = calculate_confidence(tier, met, total, evidence, repro, crit)
        decision = get_decision(result, tier is not None)

        status = "PASS" if abs(result - expected) < 0.01 else "FAIL"
        if status == "PASS":
            passed += 1
        else:
            failed += 1

        print(f"Test {i + 1}: {status}")
        print(f"  Input: tier={tier}, met={met}/{total}, evidence={evidence}, repro={repro}, crit={crit}")
        print(f"  Expected: {expected:.2f}, Got: {result:.2f}, Decision: {decision}")
        print()

    print(f"Results: {passed} passed, {failed} failed")
