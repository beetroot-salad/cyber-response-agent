"""Unit tests for the telemetry-oracle additions to loop.py.

Focus: the new ``validate_oracle_doc`` and ``assemble_exemplar_bundle``
helpers. The existing actor / judge / persistence paths are exercised
end-to-end via the smoke-run script; this file pins the bits we can
test cheaply without spawning ``claude -p``.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest
import yaml

# Load loop.py directly — there is no package __init__ chain to anchor
# `import defender.learning.loop`, and the loop is designed to run as a
# standalone script.
_LOOP_PATH = Path(__file__).resolve().parent / "loop.py"
_spec = importlib.util.spec_from_file_location("_defender_learning_loop", _LOOP_PATH)
loop = importlib.util.module_from_spec(_spec)
sys.modules["_defender_learning_loop"] = loop
_spec.loader.exec_module(loop)

LoopError = loop.LoopError
assemble_exemplar_bundle = loop.assemble_exemplar_bundle
redact_exemplar = loop.redact_exemplar
validate_oracle_doc = loop.validate_oracle_doc


# ---------------------------------------------------------------------------
# validate_oracle_doc
# ---------------------------------------------------------------------------


def _ok_doc(positions=(0, 1)):
    return {
        "projections": [
            {
                "position": p,
                "system": "wazuh",
                "template": "auth-events",
                "events": [{"data": {"srcip": "1.2.3.4"}}],
            }
            for p in positions
        ]
    }


def test_validate_oracle_doc_accepts_well_formed():
    doc = _ok_doc()
    out = validate_oracle_doc(doc, expected_positions=[0, 1])
    assert out is doc


def test_validate_oracle_doc_accepts_empty_events_list():
    doc = _ok_doc()
    doc["projections"][1]["events"] = []
    validate_oracle_doc(doc, expected_positions=[0, 1])


def test_validate_oracle_doc_rejects_non_mapping():
    with pytest.raises(LoopError, match="not parse to a mapping"):
        validate_oracle_doc(["projections"], expected_positions=[0])


def test_validate_oracle_doc_rejects_extra_top_level_keys():
    doc = _ok_doc(positions=(0,))
    doc["notes"] = "should not be here"
    with pytest.raises(LoopError, match="exactly one top-level key"):
        validate_oracle_doc(doc, expected_positions=[0])


def test_validate_oracle_doc_rejects_count_mismatch():
    doc = _ok_doc(positions=(0,))
    with pytest.raises(LoopError, match="projections count"):
        validate_oracle_doc(doc, expected_positions=[0, 1])


def test_validate_oracle_doc_rejects_position_mismatch():
    doc = _ok_doc(positions=(0, 2))
    with pytest.raises(LoopError, match=r"projection\[1\]\.position"):
        validate_oracle_doc(doc, expected_positions=[0, 1])


def test_validate_oracle_doc_rejects_missing_projection_keys():
    doc = _ok_doc(positions=(0,))
    del doc["projections"][0]["template"]
    with pytest.raises(LoopError, match="missing keys"):
        validate_oracle_doc(doc, expected_positions=[0])


def test_validate_oracle_doc_rejects_unexpected_projection_keys():
    doc = _ok_doc(positions=(0,))
    doc["projections"][0]["coverage"] = "covered"
    with pytest.raises(LoopError, match="unexpected keys"):
        validate_oracle_doc(doc, expected_positions=[0])


def test_validate_oracle_doc_rejects_non_mapping_event():
    doc = _ok_doc(positions=(0,))
    doc["projections"][0]["events"] = ["a string event"]
    with pytest.raises(LoopError, match=r"events\[0\] is not a mapping"):
        validate_oracle_doc(doc, expected_positions=[0])


def test_validate_oracle_doc_rejects_events_not_list():
    doc = _ok_doc(positions=(0,))
    doc["projections"][0]["events"] = {"event": "a"}
    with pytest.raises(LoopError, match="events is not a list"):
        validate_oracle_doc(doc, expected_positions=[0])


# ---------------------------------------------------------------------------
# assemble_exemplar_bundle
# ---------------------------------------------------------------------------


def _gather_raw_fixture(tag: str) -> str:
    """Mirrors the wazuh-CLI gather_raw layout: counts/aggregations on top,
    then a `### Raw Sample Events` block carrying the per-event schema."""
    return (
        "## Query Results\n"
        "### Summary\n"
        f"- **Matching events:** 999  # ACTUAL-RESULT-{tag}\n"
        "### Aggregations\n"
        f"  total_events: 999  # ACTUAL-RESULT-{tag}\n"
        "### Raw Sample Events (first 3, full _source)\n"
        "```json\n"
        f'[{{"data": {{"srcip": "1.2.3.4", "tag": "{tag}"}}}}]\n'
        "```\n"
    )


def test_assemble_exemplar_bundle_concatenates_per_position(tmp_path: Path):
    (tmp_path / "gather_raw").mkdir()
    (tmp_path / "gather_raw" / "0.json").write_text(_gather_raw_fixture("0"))
    (tmp_path / "gather_raw" / "1.json").write_text(_gather_raw_fixture("1"))
    lead_seq = yaml.safe_dump(
        {
            "case_id": "x",
            "alert_ref": "alert.json",
            "entries": [
                {
                    "position": 0,
                    "queries": [{"id": "wazuh.auth-events", "params": {}}],
                    "result_ref": "gather_raw/0.json",
                },
                {
                    "position": 1,
                    "queries": [{"id": "wazuh.dns-history", "params": {}}],
                    "result_ref": "gather_raw/1.json",
                },
            ],
        }
    )
    out = assemble_exemplar_bundle(tmp_path, lead_seq)
    assert "position 0 (wazuh.auth-events)" in out
    assert "position 1 (wazuh.dns-history)" in out
    # Per-event schema kept as a type/field skeleton — field names survive.
    assert "Raw Sample Events" in out
    assert "values scrubbed" in out
    assert '"srcip": "<srcip>"' in out
    # Concrete values from the source JSON do not survive.
    assert '"1.2.3.4"' not in out
    assert '"tag": "0"' not in out
    assert '"tag": "1"' not in out
    # Counts / aggregations (which leak the actual lead result) are dropped.
    assert "ACTUAL-RESULT" not in out
    assert "Matching events" not in out
    assert "Aggregations" not in out


def test_assemble_exemplar_bundle_marks_missing_files(tmp_path: Path):
    (tmp_path / "gather_raw").mkdir()
    # Position 0 file missing on purpose.
    lead_seq = yaml.safe_dump(
        {
            "case_id": "x",
            "alert_ref": "alert.json",
            "entries": [
                {
                    "position": 0,
                    "queries": [{"id": "wazuh.auth-events", "params": {}}],
                    "result_ref": "gather_raw/0.json",
                },
            ],
        }
    )
    out = assemble_exemplar_bundle(tmp_path, lead_seq)
    assert "no exemplars on disk" in out


def test_assemble_exemplar_bundle_rejects_malformed_lead_sequence(tmp_path: Path):
    with pytest.raises(LoopError, match="`entries` list"):
        assemble_exemplar_bundle(tmp_path, "not_a_mapping: true\n")


# ---------------------------------------------------------------------------
# redact_exemplar
# ---------------------------------------------------------------------------


def test_redact_exemplar_returns_type_field_skeleton():
    text = _gather_raw_fixture("0")
    out = redact_exemplar(text)
    assert out.startswith("### Raw Sample Events")
    assert "values scrubbed" in out
    # Field names + nesting preserved.
    assert '"srcip"' in out
    assert '"data"' in out
    # Field-name placeholders replace concrete strings.
    assert '"<srcip>"' in out
    assert '"<tag>"' in out
    # Concrete values from the source JSON are gone.
    assert '"1.2.3.4"' not in out
    assert '"0"' not in out  # the "tag" was "0"; must not survive
    # Sections outside Raw Sample Events stay dropped.
    assert "Matching events" not in out
    assert "Aggregations" not in out
    assert "ACTUAL-RESULT" not in out


def test_redact_exemplar_returns_placeholder_when_no_raw_sample_block():
    text = (
        "## Query Results\n"
        "### Summary\n"
        "- **Matching events:** 0\n"
    )
    out = redact_exemplar(text)
    assert "no schema sample available" in out
    # Crucially, the upstream summary text is not echoed back.
    assert "Matching events" not in out


# ---------------------------------------------------------------------------
# _outcome_keyword tolerance
# ---------------------------------------------------------------------------


def test_outcome_keyword_accepts_bare_enum():
    assert loop._outcome_keyword("survived") == "survived"


def test_outcome_keyword_tolerates_period_then_rationale():
    # Observed live: model fused outcome with rationale via "survived. The…"
    fused = "survived. The defender's investigation returned results consistent with the oracle."
    assert loop._outcome_keyword(fused) == "survived"


def test_outcome_keyword_tolerates_block_scalar_newline_form():
    # YAML `|` block scalars produce trailing newlines; strip + token-extract.
    assert loop._outcome_keyword("caught\nrationale follows…\n") == "caught"


def test_outcome_keyword_rejects_unknown_first_token():
    with pytest.raises(LoopError, match="not in"):
        loop._outcome_keyword("definitely-survived. lots of detail")


def test_outcome_keyword_rejects_non_string():
    with pytest.raises(LoopError, match="not a string"):
        loop._outcome_keyword({"survived": True})
