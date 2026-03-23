"""Tests for the YAML frontmatter parser.

Tests are organized by what the parser is actually used for in this project,
plus edge cases that could silently corrupt hook validation if mishandled.
"""

import sys
from pathlib import Path

import pytest

SOC_AGENT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SOC_AGENT_ROOT))

from hooks.scripts.frontmatter import (
    _parse_inline_list,
    _parse_scalar,
    parse_yaml_frontmatter,
)

SIGNATURES_DIR = SOC_AGENT_ROOT / "knowledge" / "signatures"
FIXTURES_DIR = SOC_AGENT_ROOT / "tests" / "fixtures" / "reports"


# ---------------------------------------------------------------------------
# _parse_scalar — the lowest-level unit. Gets every value in the frontmatter.
# ---------------------------------------------------------------------------


class TestParseScalar:
    """Scalar coercion rules — these affect every field the hooks read."""

    def test_null_variants(self):
        assert _parse_scalar("null") is None
        assert _parse_scalar("Null") is None
        assert _parse_scalar("NULL") is None
        assert _parse_scalar("~") is None
        assert _parse_scalar("") is None

    def test_integers(self):
        assert _parse_scalar("0") == 0
        assert _parse_scalar("3") == 3
        assert _parse_scalar("42") == 42

    def test_negative_numbers_stay_string(self):
        # isdigit() returns False for negative numbers — they stay as strings.
        # This is a known limitation. Document it rather than hide it.
        assert _parse_scalar("-1") == "-1"

    def test_floats_stay_string(self):
        # No float coercion — stays as string.
        assert _parse_scalar("3.14") == "3.14"
        assert _parse_scalar("0.92") == "0.92"

    def test_double_quoted(self):
        assert _parse_scalar('"hello world"') == "hello world"

    def test_single_quoted(self):
        assert _parse_scalar("'hello world'") == "hello world"

    def test_unquoted_string(self):
        assert _parse_scalar("medium") == "medium"
        assert _parse_scalar("wazuh-rule-5710") == "wazuh-rule-5710"

    def test_value_with_colon_preserved(self):
        # Values like timestamps or descriptions might contain colons.
        # _parse_scalar receives the value AFTER the first partition on ":".
        # This tests that colons in the value portion don't cause issues.
        assert _parse_scalar("10:30:00") == "10:30:00"

    def test_single_char_quotes_not_stripped(self):
        # A single quote char alone is not a quoted string.
        assert _parse_scalar("'") == "'"
        assert _parse_scalar('"') == '"'

    def test_boolean_strings_stay_string(self):
        # YAML spec treats true/false as bools, but our parser doesn't.
        # This is intentional — hook fields are strings or ints.
        assert _parse_scalar("true") == "true"
        assert _parse_scalar("false") == "false"


# ---------------------------------------------------------------------------
# _parse_inline_list
# ---------------------------------------------------------------------------


class TestParseInlineList:
    def test_empty(self):
        assert _parse_inline_list("[]") == []

    def test_single_item(self):
        assert _parse_inline_list("[one]") == ["one"]

    def test_multiple_items(self):
        assert _parse_inline_list("[a, b, c]") == ["a", "b", "c"]

    def test_items_with_integers(self):
        assert _parse_inline_list("[1, 2, 3]") == [1, 2, 3]

    def test_items_trimmed(self):
        assert _parse_inline_list("[  a ,  b  ]") == ["a", "b"]

    def test_null_in_list(self):
        assert _parse_inline_list("[a, null, b]") == ["a", None, "b"]


# ---------------------------------------------------------------------------
# parse_yaml_frontmatter — integration tests against real project frontmatter
# ---------------------------------------------------------------------------


class TestRealFrontmatter:
    """Parse actual frontmatter files from the project. If these break,
    hooks and tests will fail on real investigation data."""

    def test_report_resolved(self):
        """The report format that validate_report.py parses on every Stop hook."""
        text = (FIXTURES_DIR / "valid_resolved.md").read_text()
        fm = parse_yaml_frontmatter(text)
        assert fm["ticket_id"] == "SEC-2024-001"
        assert fm["signature_id"] == "wazuh-rule-5710"
        assert fm["status"] == "resolved"
        assert fm["disposition"] == "benign"
        assert fm["confidence"] == "high"
        assert fm["matched_precedent"] == "monitoring-probe-001.json"
        assert fm["leads_pursued"] == 2
        # Trace contains colons and arrows — must survive partition on ":"
        assert "authentication-history" in fm["trace"]
        assert "benign" in fm["trace"]

    def test_report_escalated(self):
        text = (FIXTURES_DIR / "valid_escalate.md").read_text()
        fm = parse_yaml_frontmatter(text)
        assert fm["status"] == "escalated"
        assert fm["matched_precedent"] is None
        assert fm["leads_pursued"] == 3

    def test_signature_context(self):
        """The context.md format read by get_signature_severity() and KB tests."""
        text = (SIGNATURES_DIR / "wazuh-rule-5710" / "context.md").read_text()
        fm = parse_yaml_frontmatter(text)
        assert fm["signature_id"] == "wazuh-rule-5710"
        assert fm["severity"] == "medium"
        # Nested dict
        assert isinstance(fm["mitre"], dict)
        assert fm["mitre"]["tactics"] == "Initial Access"
        assert fm["mitre"]["techniques"] == "T1110"
        # Block list
        assert isinstance(fm["data_sources"], list)
        assert "sshd" in fm["data_sources"]
        assert len(fm["data_sources"]) == 3
        # Nested dict with nulls
        assert isinstance(fm["base_rate"], dict)
        assert fm["base_rate"]["benign_pct"] is None

    def test_signature_playbook(self):
        text = (SIGNATURES_DIR / "wazuh-rule-5710" / "playbook.md").read_text()
        fm = parse_yaml_frontmatter(text)
        assert fm["signature_id"] == "wazuh-rule-5710"
        assert fm["total_investigations"] == 0
        assert fm["resolution_rate"] is None


# ---------------------------------------------------------------------------
# parse_yaml_frontmatter — structural edge cases
# ---------------------------------------------------------------------------


class TestFrontmatterEdgeCases:
    """Edge cases that, if mishandled, would silently corrupt hook validation."""

    def test_no_frontmatter(self):
        assert parse_yaml_frontmatter("# Just a heading") == {}

    def test_empty_string(self):
        assert parse_yaml_frontmatter("") == {}

    def test_only_opening_delimiter(self):
        """Missing closing --- — should still parse what's there."""
        text = "---\nkey: value\n"
        fm = parse_yaml_frontmatter(text)
        assert fm["key"] == "value"

    def test_body_not_included(self):
        """Content after closing --- must not leak into frontmatter."""
        text = """---
real_key: real_value
---
fake_key: fake_value"""
        fm = parse_yaml_frontmatter(text)
        assert "real_key" in fm
        assert "fake_key" not in fm

    def test_value_containing_colon(self):
        """Colons in values — partition on FIRST colon only."""
        text = """---
trace: "auth-history(fail:3) -> escalated"
url: https://example.com
time: 10:30:00
---"""
        fm = parse_yaml_frontmatter(text)
        assert fm["trace"] == "auth-history(fail:3) -> escalated"
        assert fm["url"] == "https://example.com"
        assert fm["time"] == "10:30:00"

    def test_blank_lines_in_frontmatter(self):
        """Blank lines between fields should be ignored."""
        text = """---
a: 1

b: 2
---"""
        fm = parse_yaml_frontmatter(text)
        assert fm["a"] == 1
        assert fm["b"] == 2

    def test_list_then_scalar(self):
        """A block list followed by a scalar — scalar must not append to the list."""
        text = """---
items:
  - one
  - two
name: test
---"""
        fm = parse_yaml_frontmatter(text)
        assert fm["items"] == ["one", "two"]
        assert fm["name"] == "test"

    def test_nested_dict_then_scalar(self):
        """A nested dict followed by a scalar — scalar must be top-level."""
        text = """---
mitre:
  tactics: Persistence
severity: high
---"""
        fm = parse_yaml_frontmatter(text)
        assert fm["mitre"] == {"tactics": "Persistence"}
        assert fm["severity"] == "high"

    def test_null_parent_then_list_items(self):
        """Parent key with null value, then indented list items.
        This is the pattern: key:\\n  - item"""
        text = """---
data_sources:
  - sshd
  - auth.log
---"""
        fm = parse_yaml_frontmatter(text)
        assert fm["data_sources"] == ["sshd", "auth.log"]

    def test_null_parent_then_nested_keys(self):
        """Parent key with no value, then indented key: value pairs."""
        text = """---
config:
  mode: strict
  timeout: 30
---"""
        fm = parse_yaml_frontmatter(text)
        assert fm["config"] == {"mode": "strict", "timeout": 30}

    def test_inline_list_with_spaces(self):
        text = """---
tags: [ Initial Access , Brute Force ]
---"""
        fm = parse_yaml_frontmatter(text)
        assert fm["tags"] == ["Initial Access", "Brute Force"]

    def test_empty_inline_list(self):
        text = """---
refs: []
---"""
        fm = parse_yaml_frontmatter(text)
        assert fm["refs"] == []

    def test_single_item_block_list(self):
        text = """---
related:
  - wazuh-rule-5712
---"""
        fm = parse_yaml_frontmatter(text)
        assert fm["related"] == ["wazuh-rule-5712"]

    def test_whitespace_only_body(self):
        text = "---\nkey: value\n---\n   \n\n"
        fm = parse_yaml_frontmatter(text)
        assert fm["key"] == "value"

    def test_tab_indented_content_ignored(self):
        """Tabs in indentation — treated as indent, should still work."""
        text = "---\nparent:\n\tchild: value\n---"
        fm = parse_yaml_frontmatter(text)
        assert fm["parent"] == {"child": "value"}

    def test_indented_line_without_parent_ignored(self):
        """Orphan indented line at the start — no current_key to attach to."""
        text = """---
  orphan: value
real: data
---"""
        fm = parse_yaml_frontmatter(text)
        # orphan has no parent — behavior depends on implementation,
        # but real: data must parse correctly regardless
        assert fm["real"] == "data"

    def test_integer_list_items(self):
        text = """---
ports:
  - 22
  - 443
  - 8080
---"""
        fm = parse_yaml_frontmatter(text)
        assert fm["ports"] == [22, 443, 8080]


# ---------------------------------------------------------------------------
# Known limitations — document what the parser does NOT handle.
# These tests verify the current behavior so we know what breaks if
# someone writes frontmatter that exceeds the parser's capabilities.
# ---------------------------------------------------------------------------


class TestKnownLimitations:
    """Things the parser deliberately does not support. If these start
    mattering, it's time to consider PyYAML."""

    def test_no_deep_nesting(self):
        """Only one level of nesting — deeper levels treated as nested keys."""
        text = """---
l1:
  l2:
    l3: deep
---"""
        fm = parse_yaml_frontmatter(text)
        # l2 becomes a key under l1, but l3 is parsed as a key under l2...
        # which isn't l1's child. The parser only tracks one parent level.
        # Just verify it doesn't crash.
        assert "l1" in fm

    def test_no_flow_mappings(self):
        """Inline dicts like {key: value} are not parsed as dicts."""
        text = """---
config: {mode: strict}
---"""
        fm = parse_yaml_frontmatter(text)
        # Stored as raw string, not a dict
        assert fm["config"] == "{mode: strict}"

    def test_no_multiline_strings(self):
        """Block scalars (| and >) are not supported."""
        text = """---
description: |
  This is a
  multiline value
---"""
        fm = parse_yaml_frontmatter(text)
        # The | is treated as the value
        assert fm["description"] == "|"

    def test_no_float_coercion(self):
        """Floats stay as strings."""
        text = """---
rate: 0.92
---"""
        fm = parse_yaml_frontmatter(text)
        assert fm["rate"] == "0.92"
        assert isinstance(fm["rate"], str)

    def test_no_boolean_coercion(self):
        """YAML bools (true/false) stay as strings."""
        text = """---
enabled: true
disabled: false
---"""
        fm = parse_yaml_frontmatter(text)
        assert fm["enabled"] == "true"
        assert fm["disabled"] == "false"

    def test_negative_int_stays_string(self):
        """Negative numbers are not coerced to int (isdigit limitation)."""
        text = """---
offset: -5
---"""
        fm = parse_yaml_frontmatter(text)
        assert fm["offset"] == "-5"
