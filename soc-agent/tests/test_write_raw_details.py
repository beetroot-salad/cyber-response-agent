"""Tests for `_write_raw_details` and `_resolve_siem_response_from_paths`
in scripts/handlers/gather.py — Phase C path-sourced raw materialization.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path

import yaml

SOC_AGENT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SOC_AGENT_ROOT))

from scripts.handlers.gather import (
    _resolve_siem_response_from_paths,
    _write_raw_details,
)


@dataclass
class _Ctx:
    run_dir: Path


# ---------------------------------------------------------------------------
# _resolve_siem_response_from_paths
# ---------------------------------------------------------------------------


class TestResolveFromPaths:
    def test_none_when_paths_empty(self):
        assert _resolve_siem_response_from_paths([]) is None
        assert _resolve_siem_response_from_paths(None) is None

    def test_none_when_paths_malformed(self):
        assert _resolve_siem_response_from_paths([{"schema": "x"}]) is None
        assert _resolve_siem_response_from_paths(["string-not-dict"]) is None

    def test_single_path_returns_verbatim(self, tmp_path):
        f = tmp_path / "raw.json"
        f.write_text('{"events":[1,2,3]}')
        result = _resolve_siem_response_from_paths([{"path": str(f)}])
        assert result == '{"events":[1,2,3]}'

    def test_multi_path_concatenates_with_markers(self, tmp_path):
        a = tmp_path / "a.json"
        b = tmp_path / "b.json"
        a.write_text("first-body")
        b.write_text("second-body")
        result = _resolve_siem_response_from_paths([
            {"path": str(a)},
            {"path": str(b)},
        ])
        assert "--- saved-output: a.json ---" in result
        assert "--- saved-output: b.json ---" in result
        assert "first-body" in result
        assert "second-body" in result

    def test_unreadable_path_skipped(self, tmp_path):
        good = tmp_path / "good.json"
        good.write_text("good")
        result = _resolve_siem_response_from_paths([
            {"path": str(tmp_path / "missing.json")},
            {"path": str(good)},
        ])
        # Multi-path with one missing → still uses delimiter marker for the readable one
        assert "good" in result

    def test_all_unreadable_returns_none(self, tmp_path):
        result = _resolve_siem_response_from_paths([
            {"path": str(tmp_path / "missing-a.json")},
            {"path": str(tmp_path / "missing-b.json")},
        ])
        assert result is None


# ---------------------------------------------------------------------------
# _write_raw_details — path source preferred, agent-authored fallback
# ---------------------------------------------------------------------------


class TestWriteRawDetails:
    def test_empty_raw_by_lead_returns_empty(self, tmp_path):
        ctx = _Ctx(run_dir=tmp_path)
        assert _write_raw_details(ctx, 1, {}) == []

    def test_writes_agent_authored_when_no_paths(self, tmp_path):
        ctx = _Ctx(run_dir=tmp_path)
        raw_by_lead = {
            "l-001": {"siem_response": "agent-authored-verbatim", "consultations": []},
        }
        paths = _write_raw_details(ctx, 1, raw_by_lead)
        assert len(paths) == 1
        contents = yaml.safe_load(Path(paths[0]).read_text())
        assert contents["siem_response"] == "agent-authored-verbatim"
        assert contents["consultations"] == []

    def test_path_overrides_agent_authored(self, tmp_path):
        # hook-saved file
        saved = tmp_path / "raw_query_outputs" / "1-abcd.json"
        saved.parent.mkdir(parents=True)
        saved.write_text("hook-saved-verbatim")

        ctx = _Ctx(run_dir=tmp_path)
        raw_by_lead = {
            "l-001": {
                "siem_response": "stale-agent-authored",
                "consultations": [{"system": "x"}],
                "paths": [{"path": str(saved), "schema": "wazuh_cli"}],
            },
        }
        out_paths = _write_raw_details(ctx, 1, raw_by_lead)
        contents = yaml.safe_load(Path(out_paths[0]).read_text())
        assert contents["siem_response"] == "hook-saved-verbatim"
        assert contents["consultations"] == [{"system": "x"}]
        # paths key stripped from persisted YAML
        assert "paths" not in contents

    def test_path_unreadable_falls_back_to_agent_authored(self, tmp_path):
        ctx = _Ctx(run_dir=tmp_path)
        raw_by_lead = {
            "l-001": {
                "siem_response": "fallback-content",
                "paths": [{"path": str(tmp_path / "does-not-exist.json")}],
            },
        }
        out_paths = _write_raw_details(ctx, 1, raw_by_lead)
        contents = yaml.safe_load(Path(out_paths[0]).read_text())
        assert contents["siem_response"] == "fallback-content"
        assert "paths" not in contents

    def test_writes_multiple_leads_sorted(self, tmp_path):
        saved_a = tmp_path / "raw_query_outputs" / "1-aaaa.json"
        saved_b = tmp_path / "raw_query_outputs" / "1-bbbb.json"
        saved_a.parent.mkdir(parents=True)
        saved_a.write_text("body-a")
        saved_b.write_text("body-b")

        ctx = _Ctx(run_dir=tmp_path)
        raw_by_lead = {
            "l-002": {"paths": [{"path": str(saved_b)}]},
            "l-001": {"paths": [{"path": str(saved_a)}]},
        }
        out_paths = _write_raw_details(ctx, 2, raw_by_lead)
        # Sorted by lead_id
        assert Path(out_paths[0]).stem == "l-001"
        assert Path(out_paths[1]).stem == "l-002"
        assert (ctx.run_dir / "raw_details" / "loop-2" / "l-001.yaml").exists()
        assert (ctx.run_dir / "raw_details" / "loop-2" / "l-002.yaml").exists()

    def test_multi_path_single_lead_concatenates(self, tmp_path):
        a = tmp_path / "raw_query_outputs" / "1-aaaa.json"
        b = tmp_path / "raw_query_outputs" / "1-bbbb.json"
        a.parent.mkdir(parents=True)
        a.write_text("first-body")
        b.write_text("second-body")

        ctx = _Ctx(run_dir=tmp_path)
        raw_by_lead = {
            "l-001": {
                "paths": [{"path": str(a)}, {"path": str(b)}],
            },
        }
        out_paths = _write_raw_details(ctx, 1, raw_by_lead)
        contents = yaml.safe_load(Path(out_paths[0]).read_text())
        assert "first-body" in contents["siem_response"]
        assert "second-body" in contents["siem_response"]
        assert "--- saved-output: 1-aaaa.json ---" in contents["siem_response"]
        assert "--- saved-output: 1-bbbb.json ---" in contents["siem_response"]
