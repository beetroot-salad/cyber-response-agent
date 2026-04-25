"""Tests for scripts/handlers/_raw_manifest.py — manifest consumption +
per-lead correlation for hook-saved raw outputs.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

SOC_AGENT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SOC_AGENT_ROOT))

from scripts.handlers._raw_manifest import (
    attach_paths_to_envelope,
    consume_new_entries,
    correlate_to_leads,
)


def _seed_manifest(run_dir: Path, entries: list[dict]) -> Path:
    out_dir = run_dir / "raw_query_outputs"
    out_dir.mkdir(parents=True, exist_ok=True)
    manifest = out_dir / "manifest.jsonl"
    with manifest.open("a") as f:
        for e in entries:
            f.write(json.dumps(e) + "\n")
    return manifest


# ---------------------------------------------------------------------------
# consume_new_entries — cursor semantics
# ---------------------------------------------------------------------------


class TestConsumeNewEntries:
    def test_empty_when_manifest_missing(self, tmp_path):
        assert consume_new_entries(tmp_path) == []

    def test_returns_all_then_empty(self, tmp_path):
        _seed_manifest(tmp_path, [
            {"path": "a.json", "command_summary": "wazuh_cli x"},
            {"path": "b.json", "command_summary": "wazuh_cli y"},
        ])
        first = consume_new_entries(tmp_path)
        assert len(first) == 2
        # Cursor advanced — second consume returns empty.
        second = consume_new_entries(tmp_path)
        assert second == []

    def test_returns_only_appended_since_last(self, tmp_path):
        _seed_manifest(tmp_path, [{"path": "a.json"}])
        consume_new_entries(tmp_path)
        _seed_manifest(tmp_path, [{"path": "b.json"}, {"path": "c.json"}])
        new = consume_new_entries(tmp_path)
        assert [e["path"] for e in new] == ["b.json", "c.json"]

    def test_skips_blank_lines(self, tmp_path):
        out_dir = tmp_path / "raw_query_outputs"
        out_dir.mkdir(parents=True)
        (out_dir / "manifest.jsonl").write_text(
            json.dumps({"path": "a.json"}) + "\n\n" + json.dumps({"path": "b.json"}) + "\n"
        )
        entries = consume_new_entries(tmp_path)
        assert len(entries) == 2

    def test_skips_unparseable_lines(self, tmp_path):
        out_dir = tmp_path / "raw_query_outputs"
        out_dir.mkdir(parents=True)
        (out_dir / "manifest.jsonl").write_text(
            json.dumps({"path": "a.json"}) + "\nnot-json\n" + json.dumps({"path": "b.json"}) + "\n"
        )
        entries = consume_new_entries(tmp_path)
        assert len(entries) == 2

    def test_corrupt_cursor_resets_to_zero(self, tmp_path):
        _seed_manifest(tmp_path, [{"path": "a.json"}])
        cursor = tmp_path / "raw_query_outputs" / "_consumed_offset"
        cursor.write_text("not-a-number")
        entries = consume_new_entries(tmp_path)
        assert len(entries) == 1


# ---------------------------------------------------------------------------
# correlate_to_leads — per-lead grouping
# ---------------------------------------------------------------------------


class TestCorrelateToLeads:
    def test_empty_leads_returns_empty(self):
        assert correlate_to_leads([{"command_summary": "x"}], []) == {}

    def test_single_lead_absorbs_all(self):
        leads = [{"id": "l-001", "query": {"query": "evt.type=execve"}}]
        entries = [
            {"command_summary": "wazuh_cli.py query --query evt.type=execve"},
            {"command_summary": "wazuh_cli.py query --query something-else"},
        ]
        grouped = correlate_to_leads(entries, leads)
        assert len(grouped["l-001"]) == 2

    def test_multi_lead_match_by_substring(self):
        leads = [
            {"id": "l-001", "query": {"query": "evt.type=execve"}},
            {"id": "l-002", "query": {"query": "fd.lport=22"}},
        ]
        entries = [
            {"command_summary": "wazuh_cli.py --query 'evt.type=execve and proc.name=ssh'"},
            {"command_summary": "wazuh_cli.py --query 'fd.lport=22 and direction=in'"},
            {"command_summary": "wazuh_cli.py --query 'evt.type=execve and pid=1234'"},
        ]
        grouped = correlate_to_leads(entries, leads)
        assert len(grouped["l-001"]) == 2
        assert len(grouped["l-002"]) == 1

    def test_unmatched_falls_through_to_first_lead(self):
        leads = [
            {"id": "l-001", "query": {"query": "evt.type=execve"}},
            {"id": "l-002", "query": {"query": "fd.lport=22"}},
        ]
        entries = [{"command_summary": "host_query.py process-list"}]
        grouped = correlate_to_leads(entries, leads)
        assert len(grouped["l-001"]) == 1
        assert grouped["l-002"] == []

    def test_lead_with_no_query_still_keyed(self):
        leads = [{"id": "l-001"}]
        entries = [{"command_summary": "anything"}]
        grouped = correlate_to_leads(entries, leads)
        assert grouped["l-001"] == [entries[0]]

    def test_string_query_supported(self):
        leads = [{"id": "l-001", "query": "evt.type=execve"}]
        entries = [{"command_summary": "wazuh_cli.py 'evt.type=execve'"}]
        grouped = correlate_to_leads(entries, leads)
        assert grouped["l-001"] == [entries[0]]

    def test_leads_without_id_are_dropped(self):
        leads = [{"id": "l-001"}, {"name": "no-id"}]
        entries = [{"command_summary": "x"}]
        grouped = correlate_to_leads(entries, leads)
        assert "l-001" in grouped
        assert len(grouped) == 1


# ---------------------------------------------------------------------------
# attach_paths_to_envelope — additive merge into raw_by_lead
# ---------------------------------------------------------------------------


class TestAttachPathsToEnvelope:
    def test_attaches_paths_when_grouped(self):
        raw_by_lead = {}
        grouped = {
            "l-001": [
                {"path": "/run/raw_query_outputs/1-abcd.json", "schema": "wazuh_cli", "bytes": 100, "ts": "t1"},
            ],
        }
        attach_paths_to_envelope(raw_by_lead, grouped)
        assert raw_by_lead["l-001"]["paths"][0]["path"].endswith("1-abcd.json")
        assert raw_by_lead["l-001"]["paths"][0]["schema"] == "wazuh_cli"

    def test_preserves_existing_keys(self):
        raw_by_lead = {"l-001": {"siem_response": "verbatim"}}
        grouped = {"l-001": [{"path": "/p.json"}]}
        attach_paths_to_envelope(raw_by_lead, grouped)
        assert raw_by_lead["l-001"]["siem_response"] == "verbatim"
        assert raw_by_lead["l-001"]["paths"][0]["path"] == "/p.json"

    def test_appends_to_existing_paths(self):
        raw_by_lead = {"l-001": {"paths": [{"path": "/old.json"}]}}
        grouped = {"l-001": [{"path": "/new.json"}]}
        attach_paths_to_envelope(raw_by_lead, grouped)
        paths = raw_by_lead["l-001"]["paths"]
        assert len(paths) == 2
        assert paths[0]["path"] == "/old.json"
        assert paths[1]["path"] == "/new.json"

    def test_skips_entries_without_path(self):
        raw_by_lead = {}
        grouped = {"l-001": [{"path": ""}, {"schema": "x"}]}
        attach_paths_to_envelope(raw_by_lead, grouped)
        assert "l-001" not in raw_by_lead or raw_by_lead.get("l-001") == {}

    def test_empty_groups_no_op(self):
        raw_by_lead = {"l-001": {"siem_response": "x"}}
        attach_paths_to_envelope(raw_by_lead, {"l-001": []})
        assert raw_by_lead == {"l-001": {"siem_response": "x"}}

    def test_creates_lead_slot_when_missing(self):
        raw_by_lead = {}
        grouped = {"l-002": [{"path": "/p.json", "schema": "host_query"}]}
        attach_paths_to_envelope(raw_by_lead, grouped)
        assert "l-002" in raw_by_lead
        assert raw_by_lead["l-002"]["paths"][0]["path"] == "/p.json"
