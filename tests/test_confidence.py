"""
Tests for confidence scoring and decision matrix.
"""

import pytest
from app.orchestrator.confidence import calculate_confidence, get_decision
from app.orchestrator.models import Decision


class TestCalculateConfidence:
    """Tests for calculate_confidence function (audit logging)."""

    def test_high_agent_confidence(self):
        """High agent confidence should give base 0.85."""
        result = calculate_confidence(agent_confidence="high")
        # 0.85 - 0.15 (no tier) = 0.70
        assert result == pytest.approx(0.70)

    def test_medium_agent_confidence(self):
        """Medium agent confidence should give base 0.60."""
        result = calculate_confidence(agent_confidence="medium")
        # 0.60 - 0.15 (no tier) = 0.45
        assert result == pytest.approx(0.45)

    def test_low_agent_confidence(self):
        """Low agent confidence should give base 0.30."""
        result = calculate_confidence(agent_confidence="low")
        # 0.30 - 0.15 (no tier) = 0.15
        assert result == pytest.approx(0.15)

    def test_high_confidence_gold_tier(self):
        """High confidence + gold tier = 0.95."""
        result = calculate_confidence(agent_confidence="high", matched_tier="gold")
        # 0.85 + 0.10 = 0.95
        assert result == pytest.approx(0.95)

    def test_medium_confidence_silver_tier(self):
        """Medium confidence + silver tier = 0.65."""
        result = calculate_confidence(agent_confidence="medium", matched_tier="silver")
        # 0.60 + 0.05 = 0.65
        assert result == pytest.approx(0.65)

    def test_reproduction_confirmed(self):
        """Reproduction confirmed adds 0.15."""
        result = calculate_confidence(
            agent_confidence="medium",
            matched_tier="silver",
            reproduction_result="confirmed",
        )
        # 0.60 + 0.05 + 0.15 = 0.80
        assert result == pytest.approx(0.80)

    def test_reproduction_refuted(self):
        """Reproduction refuted subtracts 0.30."""
        result = calculate_confidence(
            agent_confidence="high",
            matched_tier="gold",
            reproduction_result="refuted",
        )
        # 0.85 + 0.10 - 0.30 = 0.65
        assert result == pytest.approx(0.65)

    def test_critical_asset_penalty(self):
        """Critical asset subtracts 0.15."""
        result = calculate_confidence(
            agent_confidence="high",
            matched_tier="gold",
            asset_criticality="critical",
        )
        # 0.85 + 0.10 - 0.15 = 0.80
        assert result == pytest.approx(0.80)

    def test_clamp_to_bounds(self):
        """Score should be clamped to [0.0, 1.0]."""
        # High everything should clamp to 1.0
        result = calculate_confidence(
            agent_confidence="high",
            matched_tier="gold",
            reproduction_result="confirmed",
        )
        assert result == pytest.approx(1.0)

        # Low everything should be >= 0.0
        result = calculate_confidence(
            agent_confidence="low",
            matched_tier=None,
            reproduction_result="refuted",
            asset_criticality="critical",
        )
        assert result >= 0.0

    def test_defaults(self):
        """Default values should work."""
        result = calculate_confidence()
        # low confidence (0.30) + no tier (-0.15) = 0.15
        assert result == pytest.approx(0.15)

    def test_invalid_confidence_defaults_to_low(self):
        """Invalid agent confidence should default to low."""
        result = calculate_confidence(agent_confidence="invalid")
        assert result == pytest.approx(0.15)


class TestGetDecision:
    """Tests for get_decision function (decision matrix)."""

    def test_no_precedent_always_escalate(self):
        """No precedent should always return ESCALATE."""
        assert get_decision(agent_confidence="high", has_precedent=False) == Decision.ESCALATE
        assert get_decision(agent_confidence="medium", has_precedent=False) == Decision.ESCALATE
        assert get_decision(agent_confidence="low", has_precedent=False) == Decision.ESCALATE

    def test_reproduction_refuted_escalates(self):
        """Reproduction refuted should always escalate."""
        assert get_decision(
            agent_confidence="high",
            has_precedent=True,
            reproduction_result="refuted",
        ) == Decision.ESCALATE

    def test_reproduction_confirmed_auto_closes(self):
        """Reproduction confirmed + medium+ confidence should auto-close."""
        assert get_decision(
            agent_confidence="high",
            has_precedent=True,
            reproduction_result="confirmed",
        ) == Decision.AUTO_CLOSE
        assert get_decision(
            agent_confidence="medium",
            has_precedent=True,
            reproduction_result="confirmed",
        ) == Decision.AUTO_CLOSE

    def test_standard_asset_high_confidence(self):
        """Standard asset + high confidence + precedent should auto-close."""
        assert get_decision(
            agent_confidence="high",
            has_precedent=True,
            asset_criticality="standard",
            signature_severity="medium",
        ) == Decision.AUTO_CLOSE

    def test_standard_asset_medium_confidence(self):
        """Standard asset + medium confidence should reproduce."""
        assert get_decision(
            agent_confidence="medium",
            has_precedent=True,
            asset_criticality="standard",
            signature_severity="medium",
        ) == Decision.REPRODUCE

    def test_standard_asset_low_confidence(self):
        """Standard asset + low confidence should escalate."""
        assert get_decision(
            agent_confidence="low",
            has_precedent=True,
            asset_criticality="standard",
            signature_severity="medium",
        ) == Decision.ESCALATE

    def test_critical_asset_escalates(self):
        """Critical asset should escalate even with high confidence."""
        assert get_decision(
            agent_confidence="high",
            has_precedent=True,
            asset_criticality="critical",
            signature_severity="high",
        ) == Decision.ESCALATE

    def test_critical_severity_needs_high_confidence(self):
        """Critical severity with medium confidence should escalate."""
        assert get_decision(
            agent_confidence="medium",
            has_precedent=True,
            asset_criticality="standard",
            signature_severity="critical",
        ) == Decision.ESCALATE

    def test_defaults_to_medium_severity(self):
        """Missing severity should default to medium."""
        result = get_decision(
            agent_confidence="high",
            has_precedent=True,
            asset_criticality="standard",
            signature_severity=None,
        )
        assert result == Decision.AUTO_CLOSE

    def test_defaults_to_standard_criticality(self):
        """Missing criticality should default to standard."""
        result = get_decision(
            agent_confidence="high",
            has_precedent=True,
            asset_criticality=None,
            signature_severity="medium",
        )
        assert result == Decision.AUTO_CLOSE

    def test_low_severity_medium_confidence_auto_closes(self):
        """Low severity + medium confidence on standard asset should auto-close."""
        result = get_decision(
            agent_confidence="medium",
            has_precedent=True,
            asset_criticality="standard",
            signature_severity="low",
        )
        assert result == Decision.AUTO_CLOSE
