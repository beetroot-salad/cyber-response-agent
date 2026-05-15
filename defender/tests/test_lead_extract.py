"""ExecutedLead extraction — per-query emission + result_ref globbing."""
from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from defender.learning import lead_extract


def _seed_run(
    tmp_path: Path,
    *,
    entries: list[dict],
    raw_files: list[str],
) -> Path:
    """Write a minimal run dir with lead_sequence.yaml + gather_raw/ files."""
    run_dir = tmp_path / "run-X"
    run_dir.mkdir()
    (run_dir / "lead_sequence.yaml").write_text(
        yaml.safe_dump({"case_id": "run-X", "alert_ref": "alert.json", "entries": entries})
    )
    raw = run_dir / "gather_raw"
    raw.mkdir()
    for name in raw_files:
        (raw / name).write_text("{}")
    return run_dir


# ---------------------------------------------------------------------------
# Result-ref pattern matching
# ---------------------------------------------------------------------------


def test_canonical_position_file_matches(tmp_path: Path):
    run = _seed_run(
        tmp_path,
        entries=[
            {
                "position": 0,
                "lead_description": {"goal": "g", "what_to_characterize": []},
                "queries": [{"id": "wazuh.auth-events", "params": {}}],
                "result_ref": "gather_raw/0.json",
            }
        ],
        raw_files=["0.json"],
    )
    out = lead_extract.extract(run)
    assert len(out) == 1
    assert out[0].result_refs == (run / "gather_raw" / "0.json",)


def test_fan_out_variants_match(tmp_path: Path):
    run = _seed_run(
        tmp_path,
        entries=[
            {
                "position": 2,
                "lead_description": {"goal": "g", "what_to_characterize": []},
                "queries": [{"id": "wazuh.auth-events", "params": {}}],
                "result_ref": "gather_raw/2.json",
            }
        ],
        raw_files=["2.json", "2a.json", "2b.json"],
    )
    out = lead_extract.extract(run)
    assert len(out) == 1
    names = sorted(p.name for p in out[0].result_refs)
    assert names == ["2.json", "2a.json", "2b.json"]


def test_prefix_collision_rejected(tmp_path: Path):
    """position=1 must NOT pull in ``10.json`` or ``11.json``."""
    run = _seed_run(
        tmp_path,
        entries=[
            {
                "position": 1,
                "lead_description": {"goal": "g", "what_to_characterize": []},
                "queries": [{"id": "wazuh.auth-events", "params": {}}],
                "result_ref": "gather_raw/1.json",
            }
        ],
        raw_files=["1.json", "10.json", "11.json"],
    )
    out = lead_extract.extract(run)
    assert len(out) == 1
    names = sorted(p.name for p in out[0].result_refs)
    assert names == ["1.json"]


def test_lead_sidecar_excluded(tmp_path: Path):
    run = _seed_run(
        tmp_path,
        entries=[
            {
                "position": 0,
                "lead_description": {"goal": "g", "what_to_characterize": []},
                "queries": [{"id": "wazuh.auth-events", "params": {}}],
                "result_ref": "gather_raw/0.json",
            }
        ],
        raw_files=["0.json", "0.lead.json"],
    )
    out = lead_extract.extract(run)
    assert len(out) == 1
    names = [p.name for p in out[0].result_refs]
    assert "0.lead.json" not in names
    assert "0.json" in names


def test_multi_dot_filenames_excluded(tmp_path: Path):
    """``0.foo.bar.json`` must not match position=0."""
    run = _seed_run(
        tmp_path,
        entries=[
            {
                "position": 0,
                "lead_description": {"goal": "g", "what_to_characterize": []},
                "queries": [{"id": "wazuh.auth-events", "params": {}}],
                "result_ref": "gather_raw/0.json",
            }
        ],
        raw_files=["0.json", "0.foo.bar.json"],
    )
    out = lead_extract.extract(run)
    names = [p.name for p in out[0].result_refs]
    assert names == ["0.json"]


def test_entry_with_no_matching_payload_is_skipped(tmp_path: Path):
    run = _seed_run(
        tmp_path,
        entries=[
            {
                "position": 5,
                "lead_description": {"goal": "g", "what_to_characterize": []},
                "queries": [{"id": "wazuh.auth-events", "params": {}}],
                "result_ref": "gather_raw/5.json",
            }
        ],
        raw_files=["0.json"],  # nothing for position=5
    )
    out = lead_extract.extract(run)
    assert out == []


# ---------------------------------------------------------------------------
# Per-query emission
# ---------------------------------------------------------------------------


def test_two_queries_in_one_entry_emit_two_leads(tmp_path: Path):
    """Multi-query fan-out: one entry with 2 queries → 2 ExecutedLeads.

    Both leads share position, goal_text, what_to_characterize,
    result_refs but differ on query_id / params / query_index.
    """
    run = _seed_run(
        tmp_path,
        entries=[
            {
                "position": 0,
                "lead_description": {
                    "goal": "shared goal",
                    "what_to_characterize": ["dim-a"],
                },
                "queries": [
                    {"id": "wazuh.auth-events", "params": {"host": "h1"}},
                    {"id": "wazuh.sudo-commands", "params": {"host": "h1"}},
                ],
                "result_ref": "gather_raw/0.json",
            }
        ],
        raw_files=["0.json"],
    )
    out = lead_extract.extract(run)
    assert len(out) == 2
    # Shared fields.
    assert {ld.position for ld in out} == {0}
    assert all(ld.goal_text == "shared goal" for ld in out)
    assert all(ld.what_to_characterize == ("dim-a",) for ld in out)
    assert all(ld.result_refs == (run / "gather_raw" / "0.json",) for ld in out)
    # Distinct per-query fields.
    assert {ld.query_index for ld in out} == {0, 1}
    assert {ld.query_id for ld in out} == {"wazuh.auth-events", "wazuh.sudo-commands"}


def test_query_id_resolves_cli(tmp_path: Path):
    run = _seed_run(
        tmp_path,
        entries=[
            {
                "position": 0,
                "lead_description": {"goal": "g", "what_to_characterize": []},
                "queries": [{"id": "wazuh.auth-events", "params": {}}],
                "result_ref": "gather_raw/0.json",
            }
        ],
        raw_files=["0.json"],
    )
    out = lead_extract.extract(run)
    assert out[0].cli == "wazuh_cli.py"


def test_unknown_query_id_prefix_yields_none_cli(tmp_path: Path):
    run = _seed_run(
        tmp_path,
        entries=[
            {
                "position": 0,
                "lead_description": {"goal": "g", "what_to_characterize": []},
                "queries": [{"id": "elasticsearch.fake", "params": {}}],
                "result_ref": "gather_raw/0.json",
            }
        ],
        raw_files=["0.json"],
    )
    out = lead_extract.extract(run)
    assert out[0].cli is None


def test_ad_hoc_query_id_yields_none_cli(tmp_path: Path):
    """An ``ad-hoc`` query_id (no system prefix) maps to ``cli=None``."""
    run = _seed_run(
        tmp_path,
        entries=[
            {
                "position": 0,
                "lead_description": {"goal": "g", "what_to_characterize": []},
                "queries": [{"id": "ad-hoc", "params": {}}],
                "result_ref": "gather_raw/0.json",
            }
        ],
        raw_files=["0.json"],
    )
    out = lead_extract.extract(run)
    assert out[0].cli is None
    assert out[0].query_id == "ad-hoc"


# ---------------------------------------------------------------------------
# Error paths
# ---------------------------------------------------------------------------


def test_missing_lead_sequence_raises(tmp_path: Path):
    run = tmp_path / "empty-run"
    run.mkdir()
    with pytest.raises(FileNotFoundError):
        lead_extract.extract(run)


def test_top_level_non_mapping_raises(tmp_path: Path):
    run = tmp_path / "bad-run"
    run.mkdir()
    (run / "lead_sequence.yaml").write_text("- not\n- a mapping\n")
    with pytest.raises(ValueError):
        lead_extract.extract(run)


def test_is_valid_result_ref_classifier():
    assert lead_extract.is_valid_result_ref("0.json", 0)
    assert lead_extract.is_valid_result_ref("0a.json", 0)
    assert lead_extract.is_valid_result_ref("0z.json", 0)
    assert not lead_extract.is_valid_result_ref("10.json", 1)
    assert not lead_extract.is_valid_result_ref("0.lead.json", 0)
    assert not lead_extract.is_valid_result_ref("0aa.json", 0)
    assert not lead_extract.is_valid_result_ref("a.json", 0)
