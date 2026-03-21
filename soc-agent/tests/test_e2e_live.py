"""End-to-end integration tests with live Wazuh SIEM.

Requires the playground Wazuh stack to be running.
Run with: pytest -m "llm and live"

These tests are never run in CI — manual execution only.
"""

import pytest


pytestmark = [pytest.mark.llm, pytest.mark.live]


class TestLiveWazuhIntegration:
    """Tests against real Wazuh SIEM. Requires playground stack."""

    def test_placeholder(self):
        """Placeholder — requires playground Wazuh stack and agent runner."""
        pytest.skip(
            "Live Wazuh integration tests require playground stack. "
            "Start with: cd .devcontainer && docker compose up -d"
        )
