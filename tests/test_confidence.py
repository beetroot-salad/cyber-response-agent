"""
Tests for confidence scoring formula.
"""

import pytest
from orchestrator.confidence import calculate_confidence, get_decision
from orchestrator.models import Decision


class TestCalculateConfidence:
    """Tests for calculate_confidence function."""

    def test_gold_tier(self):
        """Gold tier should give 0.90 base score."""
        result = calculate_confidence(matched_tier="gold")
        assert result == pytest.approx(0.90)

    def test_silver_tier(self):
        """Silver tier should give 0.75 base score."""
        result = calculate_confidence(matched_tier="silver")
        assert result == pytest.approx(0.75)

    def test_bronze_tier(self):
        """Bronze tier should give 0.60 base score."""
        result = calculate_confidence(matched_tier="bronze")
        assert result == pytest.approx(0.60)

    def test_no_match(self):
        """No matched tier should give 0.0."""
        result = calculate_confidence(matched_tier=None)
        assert result == pytest.approx(0.0)

    def test_gold_with_reproduction_confirmed(self):
        """Reproduction confirmed adds 0.10 (clamped to 1.0)."""
        result = calculate_confidence(
            matched_tier="gold",
            reproduction_result="confirmed",
        )
        assert result == pytest.approx(1.0)

    def test_gold_with_reproduction_refuted(self):
        """Reproduction refuted subtracts 0.30."""
        result = calculate_confidence(
            matched_tier="gold",
            reproduction_result="refuted",
        )
        assert result == pytest.approx(0.60)

    def test_silver_with_reproduction_confirmed(self):
        """Silver + confirmed = 0.85."""
        result = calculate_confidence(
            matched_tier="silver",
            reproduction_result="confirmed",
        )
        assert result == pytest.approx(0.85)

    def test_gold_critical_asset(self):
        """Critical asset subtracts 0.15."""
        result = calculate_confidence(
            matched_tier="gold",
            asset_criticality="critical",
        )
        assert result == pytest.approx(0.75)

    def test_gold_elevated_asset(self):
        """Elevated asset subtracts 0.05."""
        result = calculate_confidence(
            matched_tier="gold",
            asset_criticality="elevated",
        )
        assert result == pytest.approx(0.85)

    def test_silver_critical_asset(self):
        """Silver + critical = 0.60."""
        result = calculate_confidence(
            matched_tier="silver",
            asset_criticality="critical",
        )
        assert result == pytest.approx(0.60)

    def test_bronze_confirmed_critical(self):
        """Bronze + confirmed + critical = 0.55."""
        result = calculate_confidence(
            matched_tier="bronze",
            reproduction_result="confirmed",
            asset_criticality="critical",
        )
        assert result == pytest.approx(0.55)

    def test_invalid_asset_criticality(self):
        """Invalid asset_criticality should raise ValueError."""
        with pytest.raises(ValueError, match="Invalid asset_criticality"):
            calculate_confidence(
                matched_tier="gold",
                asset_criticality="invalid",
            )

    def test_invalid_reproduction_result(self):
        """Invalid reproduction_result should raise ValueError."""
        with pytest.raises(ValueError, match="Invalid reproduction_result"):
            calculate_confidence(
                matched_tier="gold",
                reproduction_result="invalid",
            )

    def test_clamp_to_zero(self):
        """Score should not go below 0.0."""
        result = calculate_confidence(
            matched_tier="bronze",
            reproduction_result="refuted",
            asset_criticality="critical",
        )
        # 0.60 - 0.30 - 0.15 = 0.15
        assert result == pytest.approx(0.15)

    def test_no_tier_refuted(self):
        """No tier + refuted should be 0.0 (clamped)."""
        result = calculate_confidence(
            matched_tier=None,
            reproduction_result="refuted",
        )
        assert result == pytest.approx(0.0)


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
