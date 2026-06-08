"""Unit tests for the telemetry-oracle additions to loop.py.

Focus: the new ``validate_oracle_doc``
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
validate_oracle_doc = loop.validate_oracle_doc
dump_oracle_doc = loop.dump_oracle_doc
append_actor_observations = loop.append_actor_observations

import _loop_oracle as oracle_mod  # type: ignore[import-not-found]  # noqa: E402
import lead_repository as lr  # type: ignore[import-not-found]  # noqa: E402


def _qr(query_id, params=None, *, seq=0, raw_ref=None, lead_id="l-001"):
    return lr.QueryRow(
        lead_id=lead_id, seq=seq, system="", verb="", query_id=query_id,
        params=params or {}, raw_command="", exit_code=0,
        payload_status="ok", payload_digest="", raw_ref=raw_ref,
    )


def _jl(lead_id="l-001", goal=None, wts=(), queries=()):
    return lr.JoinedLead(
        lead_id=lead_id, goal=goal, what_to_summarize=wts, queries=list(queries),
    )


# ---------------------------------------------------------------------------
# sanitize_wtc — relativize copyable absolute clock times
# ---------------------------------------------------------------------------


def test_sanitize_wtc_relativizes_iso_and_clock_times():
    assert oracle_mod.sanitize_wtc(
        "the login at 2026-06-02T17:08:19Z from host x"
    ) == "the login at <alert-time> from host x"
    assert oracle_mod.sanitize_wtc("a connection at 17:08:19Z") == (
        "a connection at <alert-time>"
    )
    assert oracle_mod.sanitize_wtc("the event at 14:08Z") == "the event at <alert-time>"


def test_sanitize_wtc_leaves_relative_spans_untouched():
    for item in ("within +/-5 minutes of the alert", "a few minutes later", "no times here"):
        assert oracle_mod.sanitize_wtc(item) == item


def test_sanitize_wtc_leaves_non_utc_clock_times_untouched():
    # Bare HH:MM:SS without a Z is ambiguous (a duration, or a local-time window half)
    # and must NOT be relativized — only ISO/Z-suffixed absolute times are.
    for item in (
        "session lasted 1:30:00",
        "window 2026-06-07 16:00:00 to 2026-06-07 18:00:00",
        "top 12:34:56 talkers",
    ):
        assert oracle_mod.sanitize_wtc(item) == item


# ---------------------------------------------------------------------------
# redact_exemplar — value-scrubbed shape skeleton (no defender values leak)
# ---------------------------------------------------------------------------


def test_redact_exemplar_scrubs_values_keeps_shape():
    payload = (
        "### Raw Sample Events (first 3)\n\n"
        "```json\n"
        '[{"host": "db-07", "port": 22, "ok": true, "nested": {"user": "alice"}}]\n'
        "```\n"
    )
    out = oracle_mod.redact_exemplar(payload)
    assert "db-07" not in out and "alice" not in out
    assert '"<host>"' in out and '"<user>"' in out
    assert '"port": 0' in out and '"ok": false' in out


def test_redact_exemplar_no_sample_block_is_placeholder():
    assert oracle_mod.redact_exemplar("## Query Results\n(no raw block)\n").startswith("(")


def test_redact_exemplar_empty_sample_block_is_placeholder():
    # A Raw Sample header over an empty `[]` block has no shape to show; redact returns a
    # leading-"(" placeholder so lead_sample_text falls through to sibling payloads.
    out = oracle_mod.redact_exemplar("### Raw Sample Events\n\n```json\n[]\n```\n")
    assert out.startswith("(")
    assert "is empty" in out


def test_lead_sample_text_reads_only_its_lead_subdir(tmp_path: Path):
    # Each lead's payloads live under gather_raw/{lead_id}/{seq}.json — the FK
    # subdir scopes them, so reading l-001 can never pick up l-010's payload
    # (the over-match the old flat {position}*.json glob risked is gone).
    gather = tmp_path / "gather_raw"
    (gather / "l-010").mkdir(parents=True)
    (gather / "l-010" / "0.json").write_text(
        '### Raw Sample Events\n\n```json\n[{"host": "wrong-lead"}]\n```\n'
    )
    (gather / "l-001").mkdir(parents=True)
    empty = gather / "l-001" / "0.json"
    empty.write_text("### Raw Sample Events\n\n```json\n[]\n```\n")
    lead = _jl("l-001", queries=[_qr("wazuh.x", seq=0, raw_ref=empty)])
    out = oracle_mod.lead_sample_text(lead)
    assert "wrong-lead" not in out
    assert out.startswith("(")  # l-001's only payload is empty -> placeholder


# ---------------------------------------------------------------------------
# parse_lead_events / assemble_oracle_doc — per-lead reply -> projections doc
# ---------------------------------------------------------------------------


def test_parse_lead_events_accepts_events_mappings_markers_and_empty():
    assert oracle_mod.parse_lead_events('events:\n  - {a: "b"}\n', 0) == [{"a": "b"}]
    assert oracle_mod.parse_lead_events("events: []\n", 1) == []
    assert oracle_mod.parse_lead_events(
        'events:\n  - "<standard environment noise>"\n', 2
    ) == ["<standard environment noise>"]
    assert oracle_mod.parse_lead_events(
        'events:\n  - "<suppressed: stopped auditd>"\n', 3
    ) == ["<suppressed: stopped auditd>"]


def test_parse_lead_events_rescues_unquoted_suppression_marker():
    # An unquoted `- <suppressed: reason>` is quoted by the pre-parse pass before
    # yaml.safe_load reads it, so it lands as a clean marker string.
    assert oracle_mod.parse_lead_events(
        "events:\n  - <suppressed: stopped auditd before the probe>\n", 0
    ) == ["<suppressed: stopped auditd before the probe>"]


def test_parse_lead_events_rescues_unquoted_marker_with_multiple_colons():
    # A reason carrying a second `: ` used to raise a ScannerError that aborted the whole
    # oracle direction; the pre-parse quoting handles any number of colons.
    assert oracle_mod.parse_lead_events(
        "events:\n  - <suppressed: ran cmd: systemctl stop auditd>\n", 0
    ) == ["<suppressed: ran cmd: systemctl stop auditd>"]
    assert oracle_mod.parse_lead_events(
        "events:\n  - <suppressed: cleared log: /var/log/auth>\n", 0
    ) == ["<suppressed: cleared log: /var/log/auth>"]


def test_parse_lead_events_keeps_single_field_placeholder_event():
    # A real one-field event whose key+value are angle-bracket placeholders must survive
    # as a mapping — the old _normalize_marker heuristic corrupted it into a marker string.
    assert oracle_mod.parse_lead_events(
        'events:\n  - {"<c2-domain>": "<resolved-ip>"}\n', 0
    ) == [{"<c2-domain>": "<resolved-ip>"}]


def test_parse_lead_events_embeds_raw_reply_on_failure():
    with pytest.raises(LoopError, match="UNPARSEABLE-MARKER"):
        oracle_mod.parse_lead_events("events:\n  not-a-list: UNPARSEABLE-MARKER\n", 0)


def test_parse_lead_events_strips_fence():
    assert oracle_mod.parse_lead_events("```yaml\nevents: []\n```\n", 0) == []


def test_parse_lead_events_rejects_missing_events_list():
    with pytest.raises(LoopError, match="no `events` list"):
        oracle_mod.parse_lead_events("projections: []\n", 0)


def test_assemble_oracle_doc_preserves_lead_order():
    doc = oracle_mod.assemble_oracle_doc(
        [("l-001", [{"a": 1}]), ("l-002", []), ("l-003", ["<x>"])]
    )
    assert [p["lead_id"] for p in doc["projections"]] == ["l-001", "l-002", "l-003"]
    assert doc["projections"][2]["events"] == ["<x>"]


def test_assembled_doc_round_trips_through_validate_and_dump():
    doc = oracle_mod.assemble_oracle_doc(
        [("l-001", [{"host": "h"}]), ("l-002", ["<standard environment noise>"])]
    )
    validate_oracle_doc(doc, ["l-001", "l-002"])
    text = dump_oracle_doc(doc)
    assert "projections:" in text and "<standard environment noise>" in text


# ---------------------------------------------------------------------------
# build_lead_user_prompt — no goal, sanitized characterization
# ---------------------------------------------------------------------------


def test_build_lead_user_prompt_drops_goal_and_sanitizes_wtc():
    lead = _jl(
        "l-001",
        goal="SECRET defender intent that must not leak",
        wts=["the login at 2026-06-02T17:08:19Z"],
        queries=[_qr("wazuh.auth-events", {"host": "h"})],
    )
    prompt = oracle_mod.build_lead_user_prompt(lead, "the story", "SAMPLE")
    assert "SECRET defender intent" not in prompt          # goal omitted
    assert "<alert-time>" in prompt and "17:08:19Z" not in prompt  # wtc sanitized
    assert "wazuh.auth-events" in prompt and "the story" in prompt and "SAMPLE" in prompt


def test_build_lead_user_prompt_handles_scalar_and_malformed_wtc():
    # A scalar what_to_summarize must not be iterated char-by-char, and None
    # params must not crash.
    scalar = oracle_mod.build_lead_user_prompt(
        _jl("l-001", wts="auth events by host", queries=[_qr("wazuh.x", None)]),
        "story", "SAMPLE",
    )
    assert "auth events by host" in scalar
    assert "\n- a\n- u\n- t" not in scalar           # not split into characters
    assert "params: {}" in scalar                     # None params rendered as {}
    # non-list wtc items (non-strings filtered out): no crash, no garbage
    oracle_mod.build_lead_user_prompt(_jl("l-002", wts=[42, {"x": 1}]), "story", "S")


def test_dump_oracle_doc_preserves_unicode():
    doc = oracle_mod.assemble_oracle_doc([("l-001", [{"user": "Bjørn"}])])
    text = dump_oracle_doc(doc)
    assert "Bjørn" in text and "\\xF8" not in text


# ---------------------------------------------------------------------------
# validate_oracle_doc
# ---------------------------------------------------------------------------


def _ok_doc(lead_ids=("l-001", "l-002")):
    return {
        "projections": [
            {"lead_id": lid, "events": [{"data_source": "logs-falco.alerts"}]}
            for lid in lead_ids
        ],
    }


def test_validate_oracle_doc_accepts_well_formed():
    doc = _ok_doc()
    out = validate_oracle_doc(doc, ["l-001", "l-002"])
    assert out is doc


def test_validate_oracle_doc_accepts_empty_events_list():
    doc = _ok_doc()
    doc["projections"][1]["events"] = []
    validate_oracle_doc(doc, ["l-001", "l-002"])


def test_validate_oracle_doc_accepts_marker_strings():
    doc = _ok_doc()
    doc["projections"][0]["events"] = ["<standard environment noise>"]
    doc["projections"][1]["events"] = ["<suppressed: cleared the auth log>"]
    validate_oracle_doc(doc, ["l-001", "l-002"])


def test_validate_oracle_doc_accepts_projections_only():
    validate_oracle_doc({"projections": []}, [])


def test_validate_oracle_doc_rejects_unrecognized_marker_string():
    doc = _ok_doc(lead_ids=("l-001",))
    doc["projections"][0]["events"] = ["this lead is silent"]
    with pytest.raises(LoopError, match="not a recognized baseline-diff marker"):
        validate_oracle_doc(doc, ["l-001"])


def test_validate_oracle_doc_rejects_empty_string_event():
    doc = _ok_doc(lead_ids=("l-001",))
    doc["projections"][0]["events"] = [""]
    with pytest.raises(LoopError, match="not a recognized baseline-diff marker"):
        validate_oracle_doc(doc, ["l-001"])


def test_validate_oracle_doc_rejects_marker_mixed_with_event_mapping():
    doc = _ok_doc(lead_ids=("l-001",))
    doc["projections"][0]["events"] = [{"host": "h"}, "<suppressed: cleared log>"]
    with pytest.raises(LoopError, match="must be the only event"):
        validate_oracle_doc(doc, ["l-001"])


def test_validate_oracle_doc_rejects_duplicate_markers():
    doc = _ok_doc(lead_ids=("l-001",))
    doc["projections"][0]["events"] = [
        "<standard environment noise>", "<standard environment noise>"
    ]
    with pytest.raises(LoopError, match="must be the only event"):
        validate_oracle_doc(doc, ["l-001"])


def test_validate_oracle_doc_rejects_non_mapping():
    with pytest.raises(LoopError, match="did not parse to a mapping"):
        validate_oracle_doc(["projections"], ["l-001"])


def test_validate_oracle_doc_rejects_extra_top_level_keys():
    # any non-`projections` top-level key is rejected.
    doc = _ok_doc(lead_ids=("l-001",))
    doc["uncovered"] = []
    with pytest.raises(LoopError, match="exactly one top-level key"):
        validate_oracle_doc(doc, ["l-001"])


def test_validate_oracle_doc_rejects_count_mismatch():
    doc = _ok_doc(lead_ids=("l-001",))
    with pytest.raises(LoopError, match="projections count"):
        validate_oracle_doc(doc, ["l-001", "l-002"])


def test_validate_oracle_doc_rejects_lead_id_mismatch():
    doc = _ok_doc(lead_ids=("l-001", "l-003"))
    with pytest.raises(LoopError, match=r"projection\[1\]\.lead_id"):
        validate_oracle_doc(doc, ["l-001", "l-002"])


def test_validate_oracle_doc_rejects_missing_projection_keys():
    doc = _ok_doc(lead_ids=("l-001",))
    del doc["projections"][0]["events"]
    with pytest.raises(LoopError, match="missing keys"):
        validate_oracle_doc(doc, ["l-001"])


def test_validate_oracle_doc_rejects_unexpected_projection_keys():
    doc = _ok_doc(lead_ids=("l-001",))
    doc["projections"][0]["coverage"] = "covered"
    with pytest.raises(LoopError, match="unexpected keys"):
        validate_oracle_doc(doc, ["l-001"])


def test_validate_oracle_doc_rejects_non_mapping_non_marker_event():
    # An event is a mapping or a marker string; an int (or any other scalar) is neither.
    doc = _ok_doc(lead_ids=("l-001",))
    doc["projections"][0]["events"] = [5]
    with pytest.raises(LoopError, match=r"events\[0\] is not a mapping or marker string"):
        validate_oracle_doc(doc, ["l-001"])


def test_validate_oracle_doc_rejects_events_not_list():
    doc = _ok_doc(lead_ids=("l-001",))
    doc["projections"][0]["events"] = {"event": "a"}
    with pytest.raises(LoopError, match="events is not a list"):
        validate_oracle_doc(doc, ["l-001"])


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
