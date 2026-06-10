"""Unit tests for the telemetry-oracle additions to loop.py.

Focus: the per-lead oracle parse/assemble/dump helpers and the judge schema.
The existing actor / judge / persistence paths are exercised end-to-end via the
smoke-run script; this file pins the bits we can test cheaply without spawning
``claude -p``.
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
dump_oracle_doc = loop.dump_oracle_doc
append_actor_observations = loop.append_actor_observations

import _loop_oracle as oracle_mod  # type: ignore[import-not-found]  # noqa: E402
import _loop_orchestrate as orch  # type: ignore[import-not-found]  # noqa: E402
import _loop_persist as persist  # type: ignore[import-not-found]  # noqa: E402
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


def test_assembled_doc_dumps_with_markers_inline():
    doc = oracle_mod.assemble_oracle_doc(
        [("l-001", [{"host": "h"}]), ("l-002", ["<standard environment noise>"])]
    )
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


# ---------------------------------------------------------------------------
# Phase-1 decoupling: out-of-repo queue safety, author-work marker, drainer
# ---------------------------------------------------------------------------


def test_rotate_queue_locked_preserves_concurrent_appends(tmp_path: Path):
    """A row appended after the author read its batch must survive the rewrite.

    The author processed r/0 (committed) and r/1 (held); meanwhile a producer
    appended r/2 the author never saw. Re-reading under the lock must keep r/2.
    """
    paths, _ = _isolate(tmp_path)
    pending = paths.pending_file
    pending.parent.mkdir(parents=True, exist_ok=True)
    rows = [
        {"finding_id": "r/0", "v": "f1"},
        {"finding_id": "r/1", "v": "f2"},
        {"finding_id": "r/2", "v": "f3-new-arrival"},
    ]
    pending.write_text("".join(json.dumps(r) + "\n" for r in rows))

    held = [{"finding_id": "r/1", "v": "f2", "held_reason": "no_ground_truth"}]
    consumed = [{"finding_id": "r/0", "v": "f1", "consumed_category": "consumed_committed"}]
    persist.rotate_queue_locked(
        pending_file=pending,
        consumed_file=paths.pending_dir / "consumed.jsonl",
        lock_file=paths.findings_lock_file,
        id_key="finding_id",
        held=held,
        consumed=consumed,
        commit_sha="abc123",
    )

    survivors = _read_jsonl(pending)
    assert {s["finding_id"] for s in survivors} == {"r/1", "r/2"}
    held_row = next(s for s in survivors if s["finding_id"] == "r/1")
    assert held_row["held_reason"] == "no_ground_truth"  # mutated held row kept
    consumed_rows = _read_jsonl(paths.pending_dir / "consumed.jsonl")
    assert consumed_rows[0]["consumed_commit"] == "abc123"
    assert "consumed_at" in consumed_rows[0]


def test_enqueue_for_authoring_writes_marker(tmp_path: Path):
    paths, _ = _isolate(tmp_path)
    run_dir = tmp_path / "tmprun" / "case-a"
    run_dir.mkdir(parents=True)
    orch._enqueue_for_authoring(run_dir, paths)
    spec = json.loads((paths.author_queue_dir / "case-a.json").read_text())
    assert spec == {"run_id": "case-a", "run_dir": str(run_dir.resolve())}


class _FakeBranch:
    """Stand-in for AuthorBranch — records the lifecycle, no real git/gh.

    ``pr_exists`` simulates the writer lease, ``dirty`` an uncommitted dev tree,
    ``commits`` whether the batch produced any commits to PR."""

    def __init__(self, *, pr_exists: bool = False, dirty: bool = False, commits: int = 1,
                 merge_ok: bool = True):
        self._pr_exists = pr_exists
        self._dirty = dirty
        self._commits = commits
        self._merge_ok = merge_ok
        self.events: list[str] = []
        self.merged: list[str] = []

    def open_lessons_pr_exists(self) -> bool:
        self.events.append("lease-check")
        return self._pr_exists

    def start_batch_branch(self, batch_id: str) -> str:
        if self._dirty:
            raise orch.BranchError("working tree is dirty")
        self.events.append("start")
        return "orig-ref"

    def finish_batch(self, batch_id: str):
        self.events.append("finish")
        return f"PR/{batch_id}" if self._commits else None

    def restore_ref(self, ref: str) -> None:
        self.events.append(f"restore:{ref}")

    def merge_pr(self, pr_ref: str, *, squash: bool = True) -> bool:
        self.merged.append(pr_ref)
        return self._merge_ok


def _green(passed: bool):
    """A stub green_bar_evaluate returning a result with the given verdict."""
    import green_bar as _gb  # type: ignore[import-not-found]
    return lambda paths: _gb.GreenBarResult(
        passed=passed, checks=[_gb.Check("stub", passed, "stub")], backlog={}
    )


def test_author_drain_runs_lead_author_then_clears_marker(tmp_path: Path):
    paths, _ = _isolate(tmp_path)
    run_dir = tmp_path / "tmprun" / "case-b"
    run_dir.mkdir(parents=True)
    orch._enqueue_for_authoring(run_dir, paths)
    seen: list[Path] = []
    branch = _FakeBranch()
    orch.author_drain(
        paths,
        run_lead_author=lambda rd: seen.append(rd),
        trigger_author=lambda *a: None,
        branch=branch,
    )
    assert seen == [run_dir.resolve()]
    assert not (paths.author_queue_dir / "case-b.json").exists()
    # full lifecycle: lease check → branch → author → PR → HEAD restored
    assert branch.events == ["lease-check", "start", "finish", "restore:orig-ref"]


def test_author_drain_marks_artifact_missing(tmp_path: Path):
    paths, _ = _isolate(tmp_path)
    run_dir = tmp_path / "tmprun" / "case-real"  # gives the drain work to do
    run_dir.mkdir(parents=True)
    orch._enqueue_for_authoring(run_dir, paths)
    gone = tmp_path / "tmprun" / "case-gone"  # never created
    orch._enqueue_for_authoring(gone, paths)
    seen: list[Path] = []
    orch.author_drain(
        paths,
        run_lead_author=lambda rd: seen.append(rd),
        trigger_author=lambda *a: None,
        branch=_FakeBranch(),
    )
    assert seen == [run_dir.resolve()]  # lead-author NOT called on the vanished one
    assert not (paths.author_queue_dir / "case-gone.json").exists()
    failed = paths.author_queue_dir / "failed" / "case-gone.json"
    assert json.loads(failed.read_text())["failed"] == "artifact-missing"


def test_author_drain_triggers_three_curators(tmp_path: Path):
    paths, _ = _isolate(tmp_path)
    run_dir = tmp_path / "tmprun" / "case-c"  # a marker gives the drain work
    run_dir.mkdir(parents=True)
    orch._enqueue_for_authoring(run_dir, paths)
    triggered: list[str] = []
    orch.author_drain(
        paths,
        run_lead_author=lambda rd: None,
        trigger_author=lambda pending_file, env, module, label: triggered.append(module),
        branch=_FakeBranch(),
    )
    assert triggered == ["author", "author_actor", "author_actor_benign"]


def test_author_drain_skips_when_lease_held(tmp_path: Path):
    """An open lessons PR holds the writer lease — the drain forms no second
    branch and leaves the queued work untouched for after the merge."""
    paths, _ = _isolate(tmp_path)
    run_dir = tmp_path / "tmprun" / "case-lease"
    run_dir.mkdir(parents=True)
    orch._enqueue_for_authoring(run_dir, paths)
    seen: list[Path] = []
    triggered: list[str] = []
    branch = _FakeBranch(pr_exists=True)
    rc = orch.author_drain(
        paths,
        run_lead_author=lambda rd: seen.append(rd),
        trigger_author=lambda *a: triggered.append(a),
        branch=branch,
    )
    assert rc == 0
    assert seen == [] and triggered == []
    assert "start" not in branch.events  # never branched
    assert (paths.author_queue_dir / "case-lease.json").exists()  # marker preserved


def test_author_drain_skips_when_no_work(tmp_path: Path):
    """Empty tick: no markers, no curator at threshold → git is never touched."""
    paths, _ = _isolate(tmp_path)
    triggered: list = []
    branch = _FakeBranch()
    rc = orch.author_drain(
        paths,
        run_lead_author=lambda rd: None,
        trigger_author=lambda *a: triggered.append(a),
        branch=branch,
    )
    assert rc == 0
    assert branch.events == []  # no lease-check, no branch checkout
    assert triggered == []


def test_author_drain_skips_dirty_working_tree(tmp_path: Path):
    """A dirty dev checkout blocks the batch branch — drain skips, queue intact."""
    paths, _ = _isolate(tmp_path)
    run_dir = tmp_path / "tmprun" / "case-dirty"
    run_dir.mkdir(parents=True)
    orch._enqueue_for_authoring(run_dir, paths)
    seen: list[Path] = []
    rc = orch.author_drain(
        paths,
        run_lead_author=lambda rd: seen.append(rd),
        trigger_author=lambda *a: None,
        branch=_FakeBranch(dirty=True),
    )
    assert rc == 0
    assert seen == []  # never authored
    assert (paths.author_queue_dir / "case-dirty.json").exists()  # marker preserved


def test_author_drain_no_commits_opens_no_pr_but_restores_head(tmp_path: Path):
    paths, _ = _isolate(tmp_path)
    run_dir = tmp_path / "tmprun" / "case-empty"
    run_dir.mkdir(parents=True)
    orch._enqueue_for_authoring(run_dir, paths)
    branch = _FakeBranch(commits=0)
    rc = orch.author_drain(
        paths,
        run_lead_author=lambda rd: None,
        trigger_author=lambda *a: None,
        branch=branch,
    )
    assert rc == 0
    assert "finish" in branch.events
    assert branch.events[-1] == "restore:orig-ref"  # HEAD restored even with no PR


def test_author_drain_singleton_lock_exits_without_work(tmp_path: Path):
    """A second drainer that can't grab the dedicated lock no-ops (rc 0)."""
    import fcntl

    paths, _ = _isolate(tmp_path)
    paths.author_drain_lock_file.parent.mkdir(parents=True, exist_ok=True)
    holder = paths.author_drain_lock_file.open("a+")
    fcntl.flock(holder.fileno(), fcntl.LOCK_EX)
    try:
        worked: list[str] = []
        rc = orch.author_drain(
            paths,
            run_lead_author=lambda rd: worked.append("lead"),
            trigger_author=lambda *a: worked.append("trigger"),
            branch=_FakeBranch(),
        )
        assert rc == 0
        assert worked == []
    finally:
        fcntl.flock(holder.fileno(), fcntl.LOCK_UN)
        holder.close()


def test_author_drain_quarantines_poison_run_dir(tmp_path: Path):
    """A lead-author that raises on one (present) run dir must NOT wedge the
    serial drain: the marker is quarantined to failed/ (so it can't re-poison
    every tick) and the threshold curators still fire."""
    paths, _ = _isolate(tmp_path)
    run_dir = tmp_path / "tmprun" / "case-poison"
    run_dir.mkdir(parents=True)
    orch._enqueue_for_authoring(run_dir, paths)
    triggered: list[str] = []

    def boom(_rd: Path) -> None:
        raise RuntimeError("lead-author blew up")

    orch.author_drain(
        paths,
        run_lead_author=boom,
        trigger_author=lambda pending_file, env, module, label: triggered.append(module),
        branch=_FakeBranch(),
    )
    assert not (paths.author_queue_dir / "case-poison.json").exists()
    failed = paths.author_queue_dir / "failed" / "case-poison.json"
    assert json.loads(failed.read_text())["failed"].startswith("lead-author-error")
    # the poison run dir didn't starve the accumulated findings/observation queues
    assert triggered == ["author", "author_actor", "author_actor_benign"]


# ---------------------------------------------------------------------------
# Off-process LEARN worker — learn-queue marker + learn_drain
# ---------------------------------------------------------------------------


def test_enqueue_for_learning_writes_marker(tmp_path: Path):
    paths, _ = _isolate(tmp_path)
    run_dir = tmp_path / "tmprun" / "case-a"
    run_dir.mkdir(parents=True)
    orch.enqueue_for_learning(run_dir, paths)
    spec = json.loads((paths.learn_queue_dir / "case-a.json").read_text())
    assert spec == {"run_id": "case-a", "run_dir": str(run_dir.resolve())}


def test_learn_drain_runs_run_one_renders_and_clears_marker(tmp_path: Path):
    paths, _ = _isolate(tmp_path)
    run_dir = tmp_path / "tmprun" / "case-b"
    run_dir.mkdir(parents=True)
    orch.enqueue_for_learning(run_dir, paths)
    # One ordered log so the assert proves render fires AFTER run_one, not just
    # that both ran (two independent lists couldn't catch a reorder).
    events: list[tuple[str, Path]] = []
    rc = orch.learn_drain(
        paths,
        run_one_fn=lambda rd: events.append(("run_one", rd)) or 0,
        render=lambda rd: events.append(("render", rd)),
    )
    assert rc == 0
    assert events == [("run_one", run_dir.resolve()), ("render", run_dir.resolve())]
    assert not (paths.learn_queue_dir / "case-b.json").exists()
    assert not (paths.learn_queue_dir / "inflight" / "case-b.json").exists()


def test_learn_drain_marks_artifact_missing(tmp_path: Path):
    paths, _ = _isolate(tmp_path)
    gone = tmp_path / "tmprun" / "case-gone"  # never created
    orch.enqueue_for_learning(gone, paths)
    learned: list[Path] = []
    orch.learn_drain(
        paths,
        run_one_fn=lambda rd: learned.append(rd) or 0,
        render=lambda rd: None,
    )
    assert learned == []  # run_one NOT called on a vanished artifact
    assert not (paths.learn_queue_dir / "case-gone.json").exists()
    # the claim is cleared out of inflight/, not left stuck there
    assert not (paths.learn_queue_dir / "inflight" / "case-gone.json").exists()
    failed = paths.learn_queue_dir / "failed" / "case-gone.json"
    assert json.loads(failed.read_text())["failed"] == "artifact-missing"


def test_learn_drain_quarantines_run_one_error(tmp_path: Path):
    """A run_one that raises on one (present) run dir must not wedge the worker:
    the marker is quarantined to learn-queue/failed/ and no render fires."""
    paths, _ = _isolate(tmp_path)
    run_dir = tmp_path / "tmprun" / "case-poison"
    run_dir.mkdir(parents=True)
    orch.enqueue_for_learning(run_dir, paths)

    def boom(_rd: Path) -> int:
        raise RuntimeError("run_one blew up")

    rendered: list[Path] = []
    orch.learn_drain(paths, run_one_fn=boom, render=lambda rd: rendered.append(rd))
    assert rendered == []
    assert not (paths.learn_queue_dir / "inflight" / "case-poison.json").exists()
    failed = paths.learn_queue_dir / "failed" / "case-poison.json"
    assert json.loads(failed.read_text())["failed"].startswith("run-one-error")


def test_learn_drain_skips_already_claimed_marker(tmp_path: Path):
    """The rename-claim is the cross-worker safety: a marker already moved into
    inflight/ (claimed by another worker) is not re-globbed, so run_one never
    runs twice on the same run dir."""
    paths, _ = _isolate(tmp_path)
    run_dir = tmp_path / "tmprun" / "case-claimed"
    run_dir.mkdir(parents=True)
    orch.enqueue_for_learning(run_dir, paths)
    inflight = paths.learn_queue_dir / "inflight"
    inflight.mkdir(parents=True)
    (paths.learn_queue_dir / "case-claimed.json").rename(inflight / "case-claimed.json")
    learned: list[Path] = []
    orch.learn_drain(
        paths,
        run_one_fn=lambda rd: learned.append(rd) or 0,
        render=lambda rd: None,
    )
    assert learned == []


def test_learn_drain_skips_marker_lost_to_claim_race(tmp_path: Path, monkeypatch):
    """The actual race branch: a marker present at glob time but already claimed by
    another worker before THIS worker's os.replace must be skipped — the loser gets
    FileNotFoundError and moves on, never processing the run."""
    paths, _ = _isolate(tmp_path)
    run_dir = tmp_path / "tmprun" / "case-race"
    run_dir.mkdir(parents=True)
    orch.enqueue_for_learning(run_dir, paths)

    def racing_replace(src, dst):  # another worker won the claim between glob+replace
        Path(src).unlink()
        raise FileNotFoundError(src)

    monkeypatch.setattr(orch.os, "replace", racing_replace)
    learned: list[Path] = []
    orch.learn_drain(
        paths,
        run_one_fn=lambda rd: learned.append(rd) or 0,
        render=lambda rd: None,
    )
    assert learned == []  # the loser does not run_one the contested run


def test_learn_drain_threads_paths_into_default_run_one(tmp_path: Path, monkeypatch):
    """With run_one_fn NOT injected, the default must call the real run_one with the
    drain's own `paths`, so the queue and the findings/runs it writes resolve to one
    state dir (not DEFAULT_PATHS)."""
    paths, _ = _isolate(tmp_path)
    run_dir = tmp_path / "tmprun" / "case-paths"
    run_dir.mkdir(parents=True)
    orch.enqueue_for_learning(run_dir, paths)
    seen: dict = {}

    def fake_run_one(rd, *, paths=None, agents=None):
        seen["rd"] = rd
        seen["paths"] = paths
        return 0

    monkeypatch.setattr(orch, "run_one", fake_run_one)
    orch.learn_drain(paths, render=lambda rd: None)  # run_one_fn left to default
    assert seen["rd"] == run_dir.resolve()
    assert seen["paths"] is paths


def test_learn_drain_each_queued_marker_processed_once(tmp_path: Path):
    paths, _ = _isolate(tmp_path)
    runs = []
    for name in ("case-1", "case-2", "case-3"):
        rd = tmp_path / "tmprun" / name
        rd.mkdir(parents=True)
        orch.enqueue_for_learning(rd, paths)
        runs.append(rd.resolve())
    learned: list[Path] = []
    orch.learn_drain(
        paths,
        run_one_fn=lambda rd: learned.append(rd) or 0,
        render=lambda rd: None,
    )
    assert sorted(learned) == sorted(runs)
    # a second drain finds an empty queue
    learned2: list[Path] = []
    orch.learn_drain(
        paths,
        run_one_fn=lambda rd: learned2.append(rd) or 0,
        render=lambda rd: None,
    )
    assert learned2 == []


# ---------------------------------------------------------------------------
# Out-of-repo state_dir (DEFENDER_LEARNING_STATE_DIR) — the concurrent-run config
# the seam exists for. Until now NO test exercised state_dir != None.
# ---------------------------------------------------------------------------


def test_source_run_dir_absolute_when_state_dir_out_of_repo(tmp_path: Path):
    """_source_run_dir must not crash when the run lives out-of-repo (it used to
    raise ValueError on relative_to) and must return an absolute path that the
    consumer contract (``repo_root / src``) resolves back to the real run dir."""
    repo = tmp_path / "repo"
    repo.mkdir()
    state = tmp_path / "state"  # out-of-repo, like /tmp/defender-state
    paths = LoopPaths(repo_root=repo, state_dir=state)
    assert paths.runs_dir == state / "runs"

    learning_run_dir = paths.runs_dir / "case-x"
    src = persist._source_run_dir(learning_run_dir, paths.repo_root)
    assert src == str(learning_run_dir) + "/"  # absolute, no crash
    assert paths.repo_root / src.rstrip("/") == learning_run_dir  # pathlib: abs RHS wins


def test_append_findings_survives_out_of_repo_state_dir(tmp_path: Path):
    """The headline concurrent path: append_findings must not crash with the run
    bundle out-of-repo, and the queue + its row land under state_dir, not the repo."""
    repo = tmp_path / "repo"
    repo.mkdir()
    state = tmp_path / "state"
    paths = LoopPaths(repo_root=repo, state_dir=state)
    learning_run_dir = paths.runs_dir / "case-y"
    learning_run_dir.mkdir(parents=True)

    judge_doc = {
        "outcome": "survived",
        "defender_findings": [
            {
                "type": "lead-set",
                "subject_anchor": "host-a",
                "subject_topic": "missed lateral move",
                "finding": "narrative",
                "citations": [{"source": "investigation", "quote": "..."}],
            }
        ],
    }
    n = persist.append_findings(
        judge_doc, "case-y", "rule-1", learning_run_dir,
        direction="adversarial", paths=paths,
    )
    assert n == 1
    rows = _read_jsonl(paths.pending_file)
    assert rows[0]["source_run_dir"] == str(learning_run_dir) + "/"
    assert paths.pending_file.is_relative_to(state)
    assert not paths.pending_file.is_relative_to(repo)


# ---------------------------------------------------------------------------
# author_branch — git/gh helpers for the in-place-branch + PR discipline
# (injected runners; no real git/gh is ever invoked)
# ---------------------------------------------------------------------------

import subprocess as _subprocess  # noqa: E402

import author_branch as ab  # type: ignore[import-not-found]  # noqa: E402


def _cp(stdout: str = "", returncode: int = 0, stderr: str = ""):
    return _subprocess.CompletedProcess([], returncode, stdout, stderr)


def _git_runner(*, dirty: bool = False, ref: str = "main", ahead: int = 1):
    def run(args):
        run.calls.append(list(args))
        a = list(args)
        if a[:1] == ["status"]:
            return _cp(stdout=" M file\n" if dirty else "")
        if a[:1] == ["symbolic-ref"]:
            return _cp(stdout=ref)
        if a[:2] == ["rev-list", "--count"]:
            return _cp(stdout=str(ahead))
        return _cp()  # fetch / checkout / push succeed silently

    run.calls = []
    return run


def _gh_runner(*, pr_list_json: str = "[]", create_out: str = "https://pr/1",
               create_rc: int = 0):
    def run(args):
        run.calls.append(list(args))
        a = list(args)
        if a[:2] == ["pr", "list"]:
            return _cp(stdout=pr_list_json)
        if a[:2] == ["pr", "create"]:
            return _cp(stdout=create_out, returncode=create_rc,
                       stderr="" if create_rc == 0 else "gh boom")
        return _cp()

    run.calls = []
    return run


def test_author_branch_lease_true_on_open_lessons_pr():
    gh = _gh_runner(pr_list_json='[{"number":1,"headRefName":"lessons/abc"}]')
    b = ab.AuthorBranch(git=_git_runner(), gh=gh)
    assert b.open_lessons_pr_exists() is True
    call = gh.calls[0]
    # prefix-search, NOT the exact --head glob (which would match nothing)
    assert "--search" in call and "head:lessons/" in call
    assert "--head" not in call


def test_author_branch_lease_false_when_no_lessons_pr():
    gh = _gh_runner(pr_list_json='[{"number":2,"headRefName":"feature/x"}]')
    b = ab.AuthorBranch(git=_git_runner(), gh=gh)
    assert b.open_lessons_pr_exists() is False


def test_author_branch_start_refuses_dirty_tree():
    b = ab.AuthorBranch(git=_git_runner(dirty=True), gh=_gh_runner())
    with pytest.raises(ab.BranchError):
        b.start_batch_branch("abc123")


def test_author_branch_start_fetches_and_branches_off_origin_main():
    git = _git_runner(ref="my-feature")
    b = ab.AuthorBranch(git=git, gh=_gh_runner())
    orig = b.start_batch_branch("abc123")
    assert orig == "my-feature"  # original ref captured for restore
    assert ["fetch", "origin"] in git.calls
    assert ["checkout", "-B", "lessons/abc123", "origin/main"] in git.calls


def test_author_branch_finish_no_commits_returns_none():
    git = _git_runner(ahead=0)
    gh = _gh_runner()
    b = ab.AuthorBranch(git=git, gh=gh)
    assert b.finish_batch("abc123") is None
    assert not any(c[:1] == ["push"] for c in git.calls)
    assert not any(c[:2] == ["pr", "create"] for c in gh.calls)


def test_author_branch_finish_pushes_and_opens_pr():
    git = _git_runner(ahead=2)
    gh = _gh_runner(create_out="https://github.com/o/r/pull/9")
    b = ab.AuthorBranch(git=git, gh=gh)
    pr = b.finish_batch("abc123")
    assert pr == "https://github.com/o/r/pull/9"
    assert ["push", "--set-upstream", "origin", "lessons/abc123"] in git.calls
    create = next(c for c in gh.calls if c[:2] == ["pr", "create"])
    assert "--base" in create and "main" in create
    assert "--head" in create and "lessons/abc123" in create


def test_author_branch_finish_raises_on_gh_failure():
    b = ab.AuthorBranch(git=_git_runner(ahead=1), gh=_gh_runner(create_rc=1))
    with pytest.raises(ab.BranchError):
        b.finish_batch("abc123")


def test_author_branch_restore_ref_checks_out():
    git = _git_runner()
    ab.AuthorBranch(git=git, gh=_gh_runner()).restore_ref("my-feature")
    assert ["checkout", "my-feature"] in git.calls


def test_author_branch_revert_lesson_pr_removes_and_opens_pr():
    git = _git_runner(ref="main")
    gh = _gh_runner(create_out="https://github.com/o/r/pull/42")
    b = ab.AuthorBranch(git=git, gh=gh)
    pr = b.revert_lesson_pr("defender/lessons/bad.md", "bad")
    assert pr == "https://github.com/o/r/pull/42"
    assert ["checkout", "-B", "lessons/revert-bad", "origin/main"] in git.calls
    assert ["rm", "defender/lessons/bad.md"] in git.calls
    assert ["commit", "-m", "revert lesson: bad"] in git.calls
    assert ["checkout", "main"] in git.calls  # HEAD restored
    create = next(c for c in gh.calls if c[:2] == ["pr", "create"])
    assert "revert lesson: bad" in create


def test_author_branch_revert_refuses_dirty_tree():
    b = ab.AuthorBranch(git=_git_runner(dirty=True), gh=_gh_runner())
    with pytest.raises(ab.BranchError):
        b.revert_lesson_pr("defender/lessons/bad.md", "bad")


# ---------------------------------------------------------------------------
# author_drain auto_on_green path (green bar gates the merge)
# ---------------------------------------------------------------------------


def _enqueue_one(paths, tmp_path, name):
    rd = tmp_path / "tmprun" / name
    rd.mkdir(parents=True)
    orch._enqueue_for_authoring(rd, paths)
    return rd


def test_author_drain_human_review_never_merges(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(orch, "MERGE_MODE", "human_review")
    paths, _ = _isolate(tmp_path)
    _enqueue_one(paths, tmp_path, "case-hr")
    branch = _FakeBranch()
    called = {"green": 0}
    orch.author_drain(
        paths, run_lead_author=lambda rd: None, trigger_author=lambda *a: None,
        branch=branch,
        green_bar_evaluate=lambda p: called.__setitem__("green", called["green"] + 1),
    )
    assert branch.merged == []  # PR opened, left for human review
    assert called["green"] == 0  # green bar not even consulted under human_review


def test_author_drain_auto_on_green_merges_when_green(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(orch, "MERGE_MODE", "auto_on_green")
    paths, _ = _isolate(tmp_path)
    _enqueue_one(paths, tmp_path, "case-green")
    branch = _FakeBranch(commits=1)
    orch.author_drain(
        paths, run_lead_author=lambda rd: None, trigger_author=lambda *a: None,
        branch=branch, green_bar_evaluate=_green(True),
    )
    assert len(branch.merged) == 1 and branch.merged[0].startswith("PR/")  # merge_pr called


def test_author_drain_auto_on_green_leaves_pr_when_not_green(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(orch, "MERGE_MODE", "auto_on_green")
    paths, _ = _isolate(tmp_path)
    _enqueue_one(paths, tmp_path, "case-red")
    branch = _FakeBranch(commits=1)
    orch.author_drain(
        paths, run_lead_author=lambda rd: None, trigger_author=lambda *a: None,
        branch=branch, green_bar_evaluate=_green(False),
    )
    assert branch.merged == []  # not green → no auto-merge


def test_author_drain_auto_on_green_no_pr_skips_green_bar(tmp_path: Path, monkeypatch):
    """No commits → no PR → the green bar isn't run and nothing merges."""
    monkeypatch.setattr(orch, "MERGE_MODE", "auto_on_green")
    paths, _ = _isolate(tmp_path)
    _enqueue_one(paths, tmp_path, "case-nopr")
    branch = _FakeBranch(commits=0)
    called = {"green": 0}
    orch.author_drain(
        paths, run_lead_author=lambda rd: None, trigger_author=lambda *a: None,
        branch=branch,
        green_bar_evaluate=lambda p: called.__setitem__("green", called["green"] + 1),
    )
    assert branch.merged == []
    assert called["green"] == 0


# ---------------------------------------------------------------------------
# green_bar — the no-regression gate (floors + fail-closed)
# ---------------------------------------------------------------------------

import green_bar as gb  # type: ignore[import-not-found]  # noqa: E402


def _mk_heldout_run(runs_dir: Path, name: str, *, true: str, pred: str | None):
    rd = runs_dir / name
    rd.mkdir(parents=True)
    (rd / "ground_truth.yaml").write_text(f"held_out: true\ndisposition: {true}\n")
    if pred is not None:
        (rd / "report.md").write_text(f"---\ndisposition: {pred}\n---\nbody\n")
    return rd


def test_eval_held_out_score_counts_failures_wrong(tmp_path: Path):
    import eval_held_out  # type: ignore[import-not-found]
    runs = tmp_path / "runs"
    runs.mkdir()
    _mk_heldout_run(runs, "a", true="benign", pred="benign")      # ok
    _mk_heldout_run(runs, "b", true="malicious", pred="benign")   # wrong
    _mk_heldout_run(runs, "c", true="benign", pred=None)          # no report → wrong
    correct, total, acc = eval_held_out.score(runs)
    assert (correct, total) == (1, 3)
    assert abs(acc - 1 / 3) < 1e-9


def test_green_bar_passes_when_both_floors_met():
    r = gb.evaluate(
        held_out_floor=0.8, secondary_floor=0.5,
        held_out_score=lambda p: (9, 10, 0.9),
        secondary_catch_rate=lambda: 0.6,
    )
    assert r.passed
    assert all(c.passed for c in r.checks)


def test_green_bar_fails_when_held_out_below_floor():
    r = gb.evaluate(
        held_out_floor=0.95, secondary_floor=0.5,
        held_out_score=lambda p: (9, 10, 0.9),
        secondary_catch_rate=lambda: 0.6,
    )
    assert not r.passed
    held = next(c for c in r.checks if c.name == "held_out")
    assert not held.passed


def test_green_bar_fails_closed_without_floors():
    r = gb.evaluate(
        held_out_score=lambda p: (10, 10, 1.0), secondary_catch_rate=lambda: 1.0,
    )
    assert not r.passed  # unset floors → not green


def test_green_bar_fails_closed_on_provider_error():
    def boom(_p):
        raise RuntimeError("no stack")

    r = gb.evaluate(
        held_out_floor=0.5, secondary_floor=0.5,
        held_out_score=boom, secondary_catch_rate=lambda: 0.9,
    )
    assert not r.passed
    held = next(c for c in r.checks if c.name == "held_out")
    assert not held.passed and "errored" in held.detail


def test_green_bar_fails_when_secondary_unavailable():
    r = gb.evaluate(
        held_out_floor=0.5, secondary_floor=0.5,
        held_out_score=lambda p: (10, 10, 1.0),
        secondary_catch_rate=lambda: None,  # 0 executed / replay-incompatible
    )
    assert not r.passed
    sec = next(c for c in r.checks if c.name == "secondary")
    assert not sec.passed
