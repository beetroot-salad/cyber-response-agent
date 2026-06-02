"""Unit tests for the telemetry-oracle additions to loop.py.

Focus: the new ``validate_oracle_doc`` and ``assemble_exemplar_bundle``
helpers. The existing actor / judge / persistence paths are exercised
end-to-end via the smoke-run script; this file pins the bits we can
test cheaply without spawning ``claude -p``.
"""
from __future__ import annotations

import importlib.util
import json
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
LoopPaths = loop.LoopPaths
assemble_exemplar_bundle = loop.assemble_exemplar_bundle
redact_exemplar = loop.redact_exemplar
validate_oracle_doc = loop.validate_oracle_doc
append_actor_observations = loop.append_actor_observations


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
    assert '<exemplar position="0" query="wazuh.auth-events"' in out
    assert '<exemplar position="1" query="wazuh.dns-history"' in out
    assert "</exemplar>" in out
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


# ---------------------------------------------------------------------------
# validate_judge_doc — split outcome/outcome_rationale schema
# ---------------------------------------------------------------------------


def _full_judge_doc(**overrides):
    doc = {
        "outcome": "caught",
        "outcome_rationale": "Lead l-001 refuted the projection.",
        "encounter_analysis": "lead-by-lead walkthrough.",
        "defender_findings": [
            {
                "type": "detection-confirmed",
                "subject_anchor": "l-001",
                "subject_topic": "falco container scan",
                "finding": "lead caught the story.",
                "citations": [{"source": "investigation", "quote": "q"}],
            }
        ],
        "confidence": "high.",
    }
    doc.update(overrides)
    return doc


def test_validate_judge_doc_accepts_split_schema():
    loop.validate_judge_doc(_full_judge_doc())


def test_validate_judge_doc_omits_scaffolding_fields_is_accepted():
    # `outcome_rationale`, `encounter_analysis`, `confidence` are thinking
    # scaffolding the loop never parsed — they are no longer required output.
    doc = _full_judge_doc()
    for k in ("outcome_rationale", "encounter_analysis", "confidence"):
        doc.pop(k, None)
    loop.validate_judge_doc(doc)


def test_validate_judge_doc_skip_passthrough_omits_analysis_and_confidence():
    doc = {
        "outcome": "skip-passthrough",
        "defender_findings": [],
    }
    loop.validate_judge_doc(doc)


def test_validate_judge_doc_requires_subject_anchor_and_topic():
    for missing in ("subject_anchor", "subject_topic"):
        doc = _full_judge_doc()
        del doc["defender_findings"][0][missing]
        with pytest.raises(LoopError, match=missing):
            loop.validate_judge_doc(doc)


def test_validate_judge_doc_accepts_apostrophe_in_subject_topic():
    # Apostrophes in prose ("actor's framing") are valid plain YAML scalars
    # and must not be rejected — the YAML parser already accepts them.
    doc = _full_judge_doc()
    doc["defender_findings"][0]["subject_topic"] = "actor's framing assumption"
    loop.validate_judge_doc(doc)


def test_validate_judge_doc_omitted_actor_observations_is_accepted():
    # `actor_observations` is optional per judge.md — omitting the key is valid.
    doc = _full_judge_doc()
    assert "actor_observations" not in doc
    loop.validate_judge_doc(doc)


def test_validate_judge_doc_accepts_well_formed_actor_observations():
    doc = _full_judge_doc()
    doc["actor_observations"] = [
        {
            "type": "misprediction",
            "subject_anchor": "entry-vector",
            "subject_topic": "ssh credential reuse",
            "observation": "story underweighted reuse risk.",
        }
    ]
    loop.validate_judge_doc(doc)


def test_validate_judge_doc_rejects_non_list_actor_observations():
    doc = _full_judge_doc()
    doc["actor_observations"] = {"type": "misprediction"}
    with pytest.raises(LoopError, match="actor_observations.*is not a list"):
        loop.validate_judge_doc(doc)


def test_validate_judge_doc_rejects_non_mapping_observation():
    doc = _full_judge_doc()
    doc["actor_observations"] = ["a bare string"]
    with pytest.raises(LoopError, match=r"actor_observations\[0\] is not a mapping"):
        loop.validate_judge_doc(doc)


def test_validate_judge_doc_rejects_observation_missing_split_field():
    for missing in ("type", "subject_anchor", "subject_topic", "observation"):
        doc = _full_judge_doc()
        obs = {
            "type": "misprediction",
            "subject_anchor": "entry-vector",
            "subject_topic": "ssh credential reuse",
            "observation": "underweighted reuse risk.",
        }
        del obs[missing]
        doc["actor_observations"] = [obs]
        with pytest.raises(LoopError, match=missing):
            loop.validate_judge_doc(doc)


def test_validate_judge_doc_rejects_empty_observation_field():
    doc = _full_judge_doc()
    doc["actor_observations"] = [
        {
            "type": "misprediction",
            "subject_anchor": "entry-vector",
            "subject_topic": "   ",  # whitespace-only — not load-bearing
            "observation": "underweighted reuse risk.",
        }
    ]
    with pytest.raises(LoopError, match="subject_topic must be a non-empty string"):
        loop.validate_judge_doc(doc)


def test_validate_judge_doc_rejects_unknown_observation_type():
    doc = _full_judge_doc()
    doc["actor_observations"] = [
        {
            "type": "bogus-category",
            "subject_anchor": "entry-vector",
            "subject_topic": "ssh credential reuse",
            "observation": "underweighted reuse risk.",
        }
    ]
    with pytest.raises(LoopError, match="actor_observations\\[0\\].type="):
        loop.validate_judge_doc(doc)


# ---------------------------------------------------------------------------
# strip_yaml_fence — envelope tolerance
# ---------------------------------------------------------------------------


def test_strip_yaml_fence_passes_through_plain_yaml():
    assert loop.strip_yaml_fence("outcome: caught\nconfidence: high\n") == (
        "outcome: caught\nconfidence: high"
    )


def test_strip_yaml_fence_strips_yaml_code_fence():
    fenced = "```yaml\noutcome: caught\n```\n"
    assert loop.strip_yaml_fence(fenced) == "outcome: caught"


def test_strip_yaml_fence_strips_trailing_close_tag():
    # Observed live: model emitted a stray </content> after the YAML.
    text = "outcome: caught\nconfidence: high\n</content>\n"
    assert loop.strip_yaml_fence(text) == "outcome: caught\nconfidence: high"


def test_strip_yaml_fence_strips_full_xml_envelope():
    text = "<content>\noutcome: caught\nconfidence: high\n</content>\n"
    assert loop.strip_yaml_fence(text) == "outcome: caught\nconfidence: high"


def test_strip_yaml_fence_strips_dangling_close_fence():
    # Observed live: model emitted a trailing ``` with no opener.
    text = "outcome: caught\nconfidence: high\n```\n"
    assert loop.strip_yaml_fence(text) == "outcome: caught\nconfidence: high"


def test_strip_yaml_fence_strips_thinking_prelude():
    # Observed live: model emitted a reasoning trace + dangling </thinking>
    # before the actual answer.
    text = (
        "outcome: caught\n(reasoning trace…)\n</thinking>\n"
        "outcome: survived\nconfidence: high\n"
    )
    assert loop.strip_yaml_fence(text) == "outcome: survived\nconfidence: high"


def test_strip_yaml_fence_strips_system_thinking_variant():
    # Observed live: model used </system_thinking> instead of </thinking>.
    text = (
        "outcome: caught\n(reasoning trace…)\n</system_thinking>\n"
        "outcome: survived\nconfidence: high\n"
    )
    assert loop.strip_yaml_fence(text) == "outcome: survived\nconfidence: high"


def test_strip_yaml_fence_passes_through_when_no_thinking_tag():
    text = "outcome: caught\nconfidence: high\n"
    assert loop.strip_yaml_fence(text) == "outcome: caught\nconfidence: high"


# ---------------------------------------------------------------------------
# append_actor_observations
# ---------------------------------------------------------------------------


def _judge_doc(outcome: str, observations: list[dict] | None) -> dict:
    doc: dict = {"outcome": outcome}
    if observations is not None:
        doc["actor_observations"] = observations
    return doc


def _obs(i: int) -> dict:
    return {
        "type": "misprediction",
        "subject_anchor": f"anchor-{i}",
        "subject_topic": f"topic phrase {i}",
        "observation": f"observation paragraph {i}\n",
    }


def _read_jsonl(path: Path) -> list[dict]:
    if not path.is_file():
        return []
    out = []
    for line in path.read_text().splitlines():
        s = line.strip()
        if s:
            out.append(json.loads(s))
    return out


def _isolate(tmp_path: Path) -> tuple[object, Path]:
    """Return (paths, learning_run_dir) rooted at tmp_path — no monkeypatching.

    The _pending dir is intentionally NOT pre-created: `_append_jsonl` mkdirs it on
    demand, so empty-case assertions verify the producer doesn't touch disk when
    there are zero rows. learning_run_dir resolves under paths.repo_root so the
    source_run_dir formatter's relative_to() works.
    """
    paths = LoopPaths(repo_root=tmp_path)
    learning_run_dir = paths.runs_dir / "case-x"
    learning_run_dir.mkdir(parents=True)
    return paths, learning_run_dir


def test_append_actor_observations_writes_one_row_per_observation(tmp_path: Path):
    paths, lrd = _isolate(tmp_path)
    doc = _judge_doc("caught", [_obs(0), _obs(1)])

    n = append_actor_observations(doc, "case-x", "rule-5710", lrd, paths=paths)

    assert n == 2
    rows = _read_jsonl(paths.actor_observations_file)
    assert [r["observation_id"] for r in rows] == ["case-x/0", "case-x/1"]
    assert [r["observation_index"] for r in rows] == [0, 1]
    assert all(r["run_id"] == "case-x" for r in rows)
    assert all(r["alert_rule_key"] == "rule-5710" for r in rows)
    assert all(r["judge_outcome"] == "caught" for r in rows)
    assert all(
        r["source_run_dir"] == "defender/learning/runs/case-x/" for r in rows
    )
    assert rows[0]["subject_anchor"] == "anchor-0"
    assert rows[1]["observation"] == "observation paragraph 1\n"


def test_append_actor_observations_dedupes_on_observation_id(tmp_path: Path):
    paths, lrd = _isolate(tmp_path)
    doc = _judge_doc("caught", [_obs(0), _obs(1)])

    assert append_actor_observations(doc, "case-x", "rule-5710", lrd, paths=paths) == 2
    # Replay — same case_id + same indices.
    assert append_actor_observations(doc, "case-x", "rule-5710", lrd, paths=paths) == 0
    assert len(_read_jsonl(paths.actor_observations_file)) == 2


def test_append_actor_observations_creates_lock_file(tmp_path: Path):
    paths, lrd = _isolate(tmp_path)
    doc = _judge_doc("caught", [_obs(0)])

    assert append_actor_observations(doc, "case-x", "rule-5710", lrd, paths=paths) == 1
    # The append serializes concurrent legs under an flock on this file.
    assert paths.actor_observations_lock_file.is_file()


def test_append_actor_observations_skips_passthrough_outcome(tmp_path: Path):
    paths, lrd = _isolate(tmp_path)
    doc = _judge_doc("skip-passthrough", [_obs(0)])

    assert append_actor_observations(doc, "case-x", "rule-5710", lrd, paths=paths) == 0
    assert _read_jsonl(paths.actor_observations_file) == []


def test_append_actor_observations_no_key_is_zero_rows(tmp_path: Path):
    paths, lrd = _isolate(tmp_path)
    doc = _judge_doc("caught", None)  # actor_observations omitted entirely

    assert append_actor_observations(doc, "case-x", "rule-5710", lrd, paths=paths) == 0
    assert not paths.actor_observations_file.exists()
    assert not paths.pending_dir.exists()


def test_append_actor_observations_empty_list_is_zero_rows(tmp_path: Path):
    paths, lrd = _isolate(tmp_path)
    doc = _judge_doc("caught", [])

    assert append_actor_observations(doc, "case-x", "rule-5710", lrd, paths=paths) == 0
    assert not paths.actor_observations_file.exists()
    assert not paths.pending_dir.exists()


def test_append_actor_observations_dedupes_against_consumed_history(tmp_path: Path):
    """After the author rotates an observation into the consumed file,
    re-running the persist stage on the same case must NOT replay it."""
    paths, lrd = _isolate(tmp_path)
    doc = _judge_doc("caught", [_obs(0), _obs(1)])

    assert append_actor_observations(doc, "case-x", "rule-5710", lrd, paths=paths) == 2
    # Simulate author rotation: move both rows into consumed and clear active.
    paths.actor_observations_consumed_file.write_text(
        paths.actor_observations_file.read_text()
    )
    paths.actor_observations_file.write_text("")

    # Replay — same case_id + same indices; producer must see consumed.
    assert append_actor_observations(doc, "case-x", "rule-5710", lrd, paths=paths) == 0
    assert _read_jsonl(paths.actor_observations_file) == []


def test_append_actor_observations_queues_survived_outcomes(tmp_path: Path):
    """Producer's only outcome filter is skip-passthrough; the author owns
    the caught/incoherent/survived policy."""
    paths, lrd = _isolate(tmp_path)
    doc = _judge_doc("survived", [_obs(0)])

    n = append_actor_observations(doc, "case-x", "rule-5710", lrd, paths=paths)

    assert n == 1
    rows = _read_jsonl(paths.actor_observations_file)
    assert rows[0]["judge_outcome"] == "survived"
