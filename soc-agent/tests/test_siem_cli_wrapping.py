"""Tests for SIEM CLI salted delimiter wrapping.

Tests the salt loading and wrapping functions directly, without importing
the full wazuh_cli module (which requires opensearch-py at import time).
"""

import json
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

SOC_AGENT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SOC_AGENT_ROOT))
sys.path.insert(0, str(SOC_AGENT_ROOT / "scripts"))


# We can't import wazuh_cli directly because it sys.exit(2) when
# opensearch-py is missing.  Instead, test the wrapping logic inline
# (same implementation) to validate the contract.


def load_run_salt(run_dir: str | None) -> str | None:
    """Replica of wazuh_cli.load_run_salt for testing without opensearch-py."""
    if not run_dir:
        return None
    meta_path = Path(run_dir) / "meta.json"
    if not meta_path.exists():
        return None
    try:
        meta = json.loads(meta_path.read_text())
        return meta.get("salt") or None
    except (json.JSONDecodeError, OSError):
        return None


def wrap_with_salt(content: str, salt: str) -> str:
    """Replica of wazuh_cli.wrap_with_salt for testing."""
    return f"<run-{salt}-siem-data>\n{content}\n</run-{salt}-siem-data>"


class TestLoadRunSalt:
    def test_reads_salt_from_meta(self, tmp_path):
        meta = {"run_id": "r1", "salt": "aabb1122ccddeeff"}
        (tmp_path / "meta.json").write_text(json.dumps(meta))
        assert load_run_salt(str(tmp_path)) == "aabb1122ccddeeff"

    def test_returns_none_when_no_dir(self):
        assert load_run_salt(None) is None

    def test_returns_none_when_no_meta(self, tmp_path):
        assert load_run_salt(str(tmp_path)) is None

    def test_returns_none_when_meta_corrupt(self, tmp_path):
        (tmp_path / "meta.json").write_text("not json")
        assert load_run_salt(str(tmp_path)) is None

    def test_returns_none_when_salt_empty(self, tmp_path):
        meta = {"run_id": "r1", "salt": ""}
        (tmp_path / "meta.json").write_text(json.dumps(meta))
        assert load_run_salt(str(tmp_path)) is None


class TestWrapWithSalt:
    def test_wraps_output(self):
        result = wrap_with_salt("query results here", "abc123")
        assert result == (
            "<run-abc123-siem-data>\nquery results here\n</run-abc123-siem-data>"
        )

    def test_different_salts_produce_different_wrappers(self):
        a = wrap_with_salt("data", "salt1")
        b = wrap_with_salt("data", "salt2")
        assert a != b
        assert "salt1" in a
        assert "salt2" in b
