"""
Tests for confidence scoring formula.
"""

import pytest
from orchestrator.confidence import calculate_confidence, get_decision
from orchestrator.models import Decision


class TestCalculateConfidence:
    """Tests for calculate_confidence function."""

    def test_gold_tier_all_conditions_met(self):
        """Gold tier with all conditions met should give 1.0."""
        result = calculate_confidence(
            matched_tier="gold",
            conditions_met=4,
            conditions_total=4,
            evidence_available=True,
        )
        assert result == pytest.approx(1.0)

    def test_gold_tier_half_conditions(self):
        """Gold tier with half conditions should give 0.90."""
        result = calculate_confidence(
            matched_tier="gold",
            conditions_met=2,
            conditions_total=4,
            evidence_available=True,
        )
        assert result == pytest.approx(0.90)

    def test_gold_tier_quarter_conditions(self):
        """Gold tier with quarter conditions should give 0.85."""
        result = calculate_confidence(
            matched_tier="gold",
            conditions_met=1,
            conditions_total=4,
            evidence_available=True,
        )
        assert result == pytest.approx(0.85)

    def test_gold_tier_with_reproduction_confirmed(self):
        """Reproduction confirmed should add 0.15 (clamped to 1.0)."""
        result = calculate_confidence(
            matched_tier="gold",
            conditions_met=4,
            conditions_total=4,
            evidence_available=True,
            reproduction_result="confirmed",
        )
        assert result == pytest.approx(1.0)

    def test_gold_tier_critical_asset(self):
        """Critical asset should subtract 0.25."""
        result = calculate_confidence(
            matched_tier="gold",
            conditions_met=4,
            conditions_total=4,
            evidence_available=True,
            asset_criticality="critical",
        )
        assert result == pytest.approx(0.75)

    def test_no_precedent(self):
        """No precedent should give 0.0."""
        result = calculate_confidence(
            matched_tier=None,
            conditions_met=0,
            conditions_total=0,
            evidence_available=False,
        )
        assert result == pytest.approx(0.0)

    def test_reproduction_refuted(self):
        """Reproduction refuted should subtract 0.30."""
        result = calculate_confidence(
            matched_tier="gold",
            conditions_met=4,
            conditions_total=4,
            evidence_available=True,
            reproduction_result="refuted",
        )
        assert result == pytest.approx(0.70)

    def test_silver_tier(self):
        """Silver tier base score is 0.50."""
        result = calculate_confidence(
            matched_tier="silver",
            conditions_met=3,
            conditions_total=4,
            evidence_available=True,
        )
        assert result == pytest.approx(0.75)

    def test_bronze_tier(self):
        """Bronze tier base score is 0.30."""
        result = calculate_confidence(
            matched_tier="bronze",
            conditions_met=4,
            conditions_total=4,
            evidence_available=True,
        )
        assert result == pytest.approx(0.60)

    def test_no_evidence(self):
        """No evidence should not add 0.10 bonus."""
        result = calculate_confidence(
            matched_tier="gold",
            conditions_met=4,
            conditions_total=4,
            evidence_available=False,
        )
        assert result == pytest.approx(0.90)

    def test_elevated_asset(self):
        """Elevated asset should subtract 0.10."""
        result = calculate_confidence(
            matched_tier="gold",
            conditions_met=4,
            conditions_total=4,
            evidence_available=True,
            asset_criticality="elevated",
        )
        assert result == pytest.approx(0.90)

    def test_zero_conditions_total(self):
        """Zero total conditions should not cause division error."""
        result = calculate_confidence(
            matched_tier="gold",
            conditions_met=0,
            conditions_total=0,
            evidence_available=True,
        )
        assert result == pytest.approx(0.80)  # gold (0.70) + evidence (0.10)

    def test_invalid_negative_conditions_met(self):
        """Negative conditions_met should raise ValueError."""
        with pytest.raises(ValueError, match="conditions_met cannot be negative"):
            calculate_confidence(
                matched_tier="gold",
                conditions_met=-1,
                conditions_total=4,
                evidence_available=True,
            )

    def test_invalid_conditions_exceed_total(self):
        """conditions_met > conditions_total should raise ValueError."""
        with pytest.raises(ValueError, match="conditions_met cannot exceed"):
            calculate_confidence(
                matched_tier="gold",
                conditions_met=5,
                conditions_total=4,
                evidence_available=True,
            )

    def test_invalid_asset_criticality(self):
        """Invalid asset_criticality should raise ValueError."""
        with pytest.raises(ValueError, match="Invalid asset_criticality"):
            calculate_confidence(
                matched_tier="gold",
                conditions_met=4,
                conditions_total=4,
                evidence_available=True,
                asset_criticality="invalid",
            )

    def test_invalid_reproduction_result(self):
        """Invalid reproduction_result should raise ValueError."""
        with pytest.raises(ValueError, match="Invalid reproduction_result"):
            calculate_confidence(
                matched_tier="gold",
                conditions_met=4,
                conditions_total=4,
                evidence_available=True,
                reproduction_result="invalid",
            )


class TestGetDecision:
    """Tests for get_decision function."""

    def test_high_confidence_auto_close(self):
        """Confidence >= 0.90 should return AUTO_CLOSE."""
        assert get_decision(0.90, has_precedent=True) == Decision.AUTO_CLOSE
        assert get_decision(1.0, has_precedent=True) == Decision.AUTO_CLOSE

    def test_medium_confidence_reproduce(self):
        """Confidence 0.70-0.89 should return REPRODUCE."""
        assert get_decision(0.70, has_precedent=True) == Decision.REPRODUCE
        assert get_decision(0.85, has_precedent=True) == Decision.REPRODUCE
        assert get_decision(0.89, has_precedent=True) == Decision.REPRODUCE

    def test_low_confidence_escalate(self):
        """Confidence < 0.70 should return ESCALATE."""
        assert get_decision(0.69, has_precedent=True) == Decision.ESCALATE
        assert get_decision(0.50, has_precedent=True) == Decision.ESCALATE
        assert get_decision(0.0, has_precedent=True) == Decision.ESCALATE

    def test_no_precedent_always_escalate(self):
        """No precedent should always return ESCALATE regardless of confidence."""
        assert get_decision(1.0, has_precedent=False) == Decision.ESCALATE
        assert get_decision(0.90, has_precedent=False) == Decision.ESCALATE
        assert get_decision(0.0, has_precedent=False) == Decision.ESCALATE
