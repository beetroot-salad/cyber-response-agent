"""Tests for SIEM mapping configuration.

Validates the structure of siem-mapping.json.
"""

import json
import sys
from pathlib import Path

import pytest

SOC_AGENT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SOC_AGENT_ROOT))

SIEM_MAPPING_PATH = SOC_AGENT_ROOT / "config" / "siem-mapping.json"


class TestSiemMapping:
    @pytest.fixture(autouse=True)
    def load_mapping(self):
        self.mapping = json.loads(SIEM_MAPPING_PATH.read_text())

    def test_file_exists(self):
        assert SIEM_MAPPING_PATH.exists()

    def test_has_siem_name(self):
        assert "siem_name" in self.mapping
        assert isinstance(self.mapping["siem_name"], str)

    def test_has_operations(self):
        assert "operations" in self.mapping
        assert isinstance(self.mapping["operations"], dict)

    def test_required_operations_present(self):
        required = ["search_events", "get_agent_info", "count_events", "list_alerts"]
        for op in required:
            assert op in self.mapping["operations"], f"Missing operation: {op}"

    def test_operation_structure(self):
        for name, op in self.mapping["operations"].items():
            assert "tool" in op, f"Operation '{name}' missing 'tool'"
            assert "description" in op, f"Operation '{name}' missing 'description'"
            assert "param_mapping" in op, f"Operation '{name}' missing 'param_mapping'"
            assert "response_mapping" in op, f"Operation '{name}' missing 'response_mapping'"

    def test_tool_names_are_mcp_prefixed(self):
        for name, op in self.mapping["operations"].items():
            assert op["tool"].startswith("mcp__"), (
                f"Operation '{name}' tool '{op['tool']}' should be MCP-prefixed"
            )

    def test_search_events_has_query_param(self):
        search = self.mapping["operations"]["search_events"]
        assert "query" in search["param_mapping"]

    def test_list_alerts_has_time_params(self):
        alerts = self.mapping["operations"]["list_alerts"]
        assert "time_range_start" in alerts["param_mapping"]
        assert "time_range_end" in alerts["param_mapping"]
