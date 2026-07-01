"""Unit tests for the telemetry-oracle additions to loop.py.

Focus: the per-lead oracle parse/assemble/dump helpers and the judge schema.
The existing actor / judge / persistence paths are exercised end-to-end via the
smoke-run script; this file pins the bits we can test cheaply without spawning
``claude -p``.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from defender.learning import loop

RunUnprocessable = loop.RunUnprocessable
LoopPaths = loop.LoopPaths
dump_oracle_doc = loop.dump_oracle_doc
append_actor_observations = loop.append_actor_observations

from defender.learning.pipeline.judge import compare as comparison  # type: ignore[import-not-found]  # noqa: E402
from defender.learning.core import directions as directions  # type: ignore[import-not-found]  # noqa: E402
from defender.learning.pipeline.oracle import sample as oracle_mod  # type: ignore[import-not-found]  # noqa: E402
from defender.learning.core import orchestrate as orch  # type: ignore[import-not-found]  # noqa: E402
from defender.learning.core import persist as persist  # type: ignore[import-not-found]  # noqa: E402
from defender import _io as _io  # type: ignore[import-not-found]  # noqa: E402
from defender.learning.pipeline.judge import run as subagents  # type: ignore[import-not-found]  # noqa: E402
from defender.learning import lead_repository as lr  # type: ignore[import-not-found]  # noqa: E402


def _qr(query_id, params=None, *, seq=0, raw_ref=None, lead_id="l-001"):
    return lr.QueryRow(
        lead_id=lead_id, seq=seq, system="", verb="", query_id=query_id,
        params=params or {}, raw_command="", exit_code=0, error_class=None,
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
    assert "db-07" not in out
    assert "alice" not in out
    assert '"<host>"' in out
    assert '"<user>"' in out
    assert '"port": 0' in out
    assert '"ok": false' in out


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
    with pytest.raises(RunUnprocessable, match="UNPARSEABLE-MARKER"):
        oracle_mod.parse_lead_events("events:\n  not-a-list: UNPARSEABLE-MARKER\n", 0)


def test_parse_lead_events_strips_fence():
    assert oracle_mod.parse_lead_events("```yaml\nevents: []\n```\n", 0) == []


def test_parse_lead_events_rejects_missing_events_list():
    with pytest.raises(RunUnprocessable, match="no `events` list"):
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
    assert "projections:" in text
    assert "<standard environment noise>" in text


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
    assert "<alert-time>" in prompt
    assert "17:08:19Z" not in prompt
    assert "wazuh.auth-events" in prompt
    assert "the story" in prompt
    assert "SAMPLE" in prompt


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
    assert "Bjørn" in text
    assert "\\xF8" not in text


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
    with pytest.raises(RunUnprocessable, match="not in"):
        loop._outcome_keyword("definitely-survived. lots of detail")


def test_outcome_keyword_rejects_non_string():
    with pytest.raises(RunUnprocessable, match="not a string"):
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
        with pytest.raises(RunUnprocessable, match=missing):
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
    with pytest.raises(RunUnprocessable, match="actor_observations.*is not a list"):
        loop.validate_judge_doc(doc)


def test_validate_judge_doc_rejects_non_mapping_observation():
    doc = _full_judge_doc()
    doc["actor_observations"] = ["a bare string"]
    with pytest.raises(RunUnprocessable, match=r"actor_observations\[0\] is not a mapping"):
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
        with pytest.raises(RunUnprocessable, match=missing):
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
    with pytest.raises(RunUnprocessable, match="subject_topic must be a non-empty string"):
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
    with pytest.raises(RunUnprocessable, match="actor_observations\\[0\\].type="):
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
    return _io.read_jsonl_rows(path)


def _isolate(tmp_path: Path) -> tuple[object, Path]:
    """Return (paths, learning_run_dir) rooted at tmp_path — no monkeypatching.

    The _pending dir is intentionally NOT pre-created: `append_jsonl` mkdirs it on
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
    rows = _read_jsonl(paths.actor_observations.file)
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
    assert len(_read_jsonl(paths.actor_observations.file)) == 2


def test_append_actor_observations_creates_lock_file(tmp_path: Path):
    paths, lrd = _isolate(tmp_path)
    doc = _judge_doc("caught", [_obs(0)])

    assert append_actor_observations(doc, "case-x", "rule-5710", lrd, paths=paths) == 1
    # The append serializes concurrent legs under an flock on this file.
    assert paths.actor_observations.lock.is_file()


def test_append_actor_observations_skips_passthrough_outcome(tmp_path: Path):
    paths, lrd = _isolate(tmp_path)
    doc = _judge_doc("skip-passthrough", [_obs(0)])

    assert append_actor_observations(doc, "case-x", "rule-5710", lrd, paths=paths) == 0
    assert _read_jsonl(paths.actor_observations.file) == []


def test_append_actor_observations_no_key_is_zero_rows(tmp_path: Path):
    paths, lrd = _isolate(tmp_path)
    doc = _judge_doc("caught", None)  # actor_observations omitted entirely

    assert append_actor_observations(doc, "case-x", "rule-5710", lrd, paths=paths) == 0
    assert not paths.actor_observations.file.exists()
    assert not paths.pending_dir.exists()


def test_append_actor_observations_empty_list_is_zero_rows(tmp_path: Path):
    paths, lrd = _isolate(tmp_path)
    doc = _judge_doc("caught", [])

    assert append_actor_observations(doc, "case-x", "rule-5710", lrd, paths=paths) == 0
    assert not paths.actor_observations.file.exists()
    assert not paths.pending_dir.exists()


def test_append_actor_observations_dedupes_against_consumed_history(tmp_path: Path):
    """After the author rotates an observation into the consumed file,
    re-running the persist stage on the same case must NOT replay it."""
    paths, lrd = _isolate(tmp_path)
    doc = _judge_doc("caught", [_obs(0), _obs(1)])

    assert append_actor_observations(doc, "case-x", "rule-5710", lrd, paths=paths) == 2
    # Simulate author rotation: move both rows into consumed and clear active.
    paths.actor_observations.consumed.write_text(
        paths.actor_observations.file.read_text()
    )
    paths.actor_observations.file.write_text("")

    # Replay — same case_id + same indices; producer must see consumed.
    assert append_actor_observations(doc, "case-x", "rule-5710", lrd, paths=paths) == 0
    assert _read_jsonl(paths.actor_observations.file) == []


def test_append_actor_observations_queues_survived_outcomes(tmp_path: Path):
    """Producer's only outcome filter is skip-passthrough; the author owns
    the caught/incoherent/survived policy."""
    paths, lrd = _isolate(tmp_path)
    doc = _judge_doc("survived", [_obs(0)])

    n = append_actor_observations(doc, "case-x", "rule-5710", lrd, paths=paths)

    assert n == 1
    rows = _read_jsonl(paths.actor_observations.file)
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
    """Stand-in for AuthorBranch — records the worktree-batch lifecycle, no real git/gh.

    ``pr_exists`` simulates the per-prefix writer lease; ``commits`` whether the batch
    produced any commits to PR. ``branch_prefix`` mirrors the real field the drain logs."""

    def __init__(self, *, prefix: str = "lessons/", pr_exists: bool = False, commits: int = 1):
        self.branch_prefix = prefix
        self._pr_exists = pr_exists
        self._commits = commits
        self.events: list[str] = []

    def open_pr_exists(self) -> bool:
        self.events.append("lease-check")
        return self._pr_exists

    def start_batch(self, batch_id: str) -> Path:
        self.events.append("start")
        return Path(f"/tmp/wt-{batch_id}")

    def finish_batch(self, batch_id: str, wt: Path):
        self.events.append("finish")
        return f"PR/{batch_id}" if self._commits else None

    def cleanup(self, wt: Path) -> None:
        self.events.append("cleanup")


def _seed_curator_findings(paths, n: int = 5) -> None:
    """Write ``n`` rows to the findings queue so ``_has_curator_work`` is satisfied
    (default LEARNING_AUTHOR_THRESHOLD is 5)."""
    paths.pending_file.parent.mkdir(parents=True, exist_ok=True)
    with paths.pending_file.open("w") as fh:
        for i in range(n):
            fh.write(json.dumps({"finding_id": f"f{i}"}) + "\n")


# -- lessons author_drain (curators only; lead author is its own drain) ------


def test_author_drain_triggers_all_curators(tmp_path: Path):
    paths, _ = _isolate(tmp_path)
    _seed_curator_findings(paths)  # curator queue at threshold = the drain's work
    triggered: list[str] = []
    orch.author_drain(
        paths,
        trigger_author=lambda paths, pending_file, env, module, label: triggered.append(module),
        branch=_FakeBranch(),
    )
    # The current four-direction set: findings + actor + actor-env + actor-benign.
    assert triggered == [
        "author", "author_actor", "author_actor_env", "author_actor_benign",
    ]


def test_author_drain_skips_when_lease_held(tmp_path: Path):
    """An open lessons PR holds the writer lease — the drain forms no second branch
    and leaves the queued work untouched for after the merge."""
    paths, _ = _isolate(tmp_path)
    _seed_curator_findings(paths)
    triggered: list = []
    branch = _FakeBranch(pr_exists=True)
    rc = orch.author_drain(
        paths,
        trigger_author=lambda *a: triggered.append(a),
        branch=branch,
    )
    assert rc == 0
    assert triggered == []
    assert "start" not in branch.events  # never created a worktree


def test_author_drain_skips_when_no_work(tmp_path: Path):
    """Empty tick: no curator at threshold → git is never touched."""
    paths, _ = _isolate(tmp_path)
    triggered: list = []
    branch = _FakeBranch()
    rc = orch.author_drain(
        paths,
        trigger_author=lambda *a: triggered.append(a),
        branch=branch,
    )
    assert rc == 0
    assert branch.events == []  # no lease-check, no worktree
    assert triggered == []


def test_author_drain_no_commits_opens_no_pr_but_cleans_up(tmp_path: Path):
    paths, _ = _isolate(tmp_path)
    _seed_curator_findings(paths)
    branch = _FakeBranch(commits=0)
    rc = orch.author_drain(paths, trigger_author=lambda *a: None, branch=branch)
    assert rc == 0
    assert "finish" in branch.events
    assert branch.events[-1] == "cleanup"  # worktree removed even with no PR


def test_author_drain_singleton_lock_exits_without_work(tmp_path: Path):
    """A second drainer that can't grab the dedicated lock no-ops (rc 0)."""
    import fcntl

    paths, _ = _isolate(tmp_path)
    _seed_curator_findings(paths)
    paths.author_drain_lock_file.parent.mkdir(parents=True, exist_ok=True)
    holder = paths.author_drain_lock_file.open("a+")
    fcntl.flock(holder.fileno(), fcntl.LOCK_EX)
    try:
        worked: list[str] = []
        rc = orch.author_drain(
            paths,
            trigger_author=lambda *a: worked.append("trigger"),
            branch=_FakeBranch(),
        )
        assert rc == 0
        assert worked == []
    finally:
        fcntl.flock(holder.fileno(), fcntl.LOCK_UN)
        holder.close()


# -- lead_author_drain (its own marker queue, lock, worktree, and PR) --------


def test_lead_author_drain_runs_lead_author_then_clears_marker(tmp_path: Path):
    paths, _ = _isolate(tmp_path)
    run_dir = tmp_path / "tmprun" / "case-b"
    run_dir.mkdir(parents=True)
    orch._enqueue_for_authoring(run_dir, paths)
    seen: list[tuple[Path, Path]] = []
    branch = _FakeBranch(prefix="lead-author/")
    orch.lead_author_drain(
        paths,
        run_lead_author=lambda wt_paths, rd: seen.append((wt_paths.repo_root, rd)),
        branch=branch,
    )
    assert [rd for _, rd in seen] == [run_dir.resolve()]
    # the lead author runs rooted at the batch worktree, not the dev checkout
    assert str(seen[0][0]).startswith("/tmp/wt-")
    assert not (paths.author_queue_dir / "case-b.json").exists()
    assert branch.events == ["lease-check", "start", "finish", "cleanup"]


def test_lead_author_drain_runs_pitfalls_after_markers(tmp_path: Path):
    """The drain folds general-failure pitfalls into execution.md after the per-run
    catalog/skill markers, in the same worktree/PR."""
    paths, _ = _isolate(tmp_path)
    run_dir = tmp_path / "tmprun" / "case-p"
    run_dir.mkdir(parents=True)
    orch._enqueue_for_authoring(run_dir, paths)
    order: list[str] = []
    orch.lead_author_drain(
        paths,
        run_lead_author=lambda wt_paths, rd: order.append("marker"),
        run_pitfalls=lambda wt_paths: (order.append("pitfalls"), 0)[1],
        branch=_FakeBranch(prefix="lead-author/"),
    )
    assert order == ["marker", "pitfalls"]


def test_has_lead_author_work_fires_on_pitfalls_threshold(tmp_path: Path, monkeypatch):
    """Even with no run markers queued, the drain wakes once the cross-run pitfalls
    queue reaches its curation threshold."""
    from defender.learning.core import persist
    paths, _ = _isolate(tmp_path)
    assert orch._has_lead_author_work(paths) is False
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "2")
    persist.append_pitfalls(
        [{"pitfall_id": f"r:{i}", "system": "elastic"} for i in range(2)], paths=paths
    )
    assert orch._has_lead_author_work(paths) is True


def test_lead_author_drain_marks_artifact_missing(tmp_path: Path):
    paths, _ = _isolate(tmp_path)
    run_dir = tmp_path / "tmprun" / "case-real"
    run_dir.mkdir(parents=True)
    orch._enqueue_for_authoring(run_dir, paths)
    gone = tmp_path / "tmprun" / "case-gone"  # never created
    orch._enqueue_for_authoring(gone, paths)
    seen: list[Path] = []
    orch.lead_author_drain(
        paths,
        run_lead_author=lambda wt_paths, rd: seen.append(rd),
        branch=_FakeBranch(prefix="lead-author/"),
    )
    assert seen == [run_dir.resolve()]  # lead-author NOT called on the vanished one
    assert not (paths.author_queue_dir / "case-gone.json").exists()
    failed = paths.author_queue_dir / "failed" / "case-gone.json"
    assert json.loads(failed.read_text())["failed"] == "artifact-missing"


def test_lead_author_drain_skips_when_lease_held(tmp_path: Path):
    """An open lead-author PR holds the per-prefix lease — no second worktree."""
    paths, _ = _isolate(tmp_path)
    run_dir = tmp_path / "tmprun" / "case-lease"
    run_dir.mkdir(parents=True)
    orch._enqueue_for_authoring(run_dir, paths)
    seen: list = []
    branch = _FakeBranch(prefix="lead-author/", pr_exists=True)
    rc = orch.lead_author_drain(
        paths, run_lead_author=lambda wt_paths, rd: seen.append(rd), branch=branch
    )
    assert rc == 0
    assert seen == []
    assert "start" not in branch.events
    assert (paths.author_queue_dir / "case-lease.json").exists()  # marker preserved


def test_lead_author_drain_singleton_lock_distinct_from_lessons(tmp_path: Path):
    """The lead-author drain's lock is distinct from the lessons drain's, so holding
    the lessons drain lock does NOT block it (only its own lock does)."""
    import fcntl

    paths, _ = _isolate(tmp_path)
    run_dir = tmp_path / "tmprun" / "case-d"
    run_dir.mkdir(parents=True)
    orch._enqueue_for_authoring(run_dir, paths)
    # Hold the *lessons* drain lock — must not block the lead-author drain.
    paths.author_drain_lock_file.parent.mkdir(parents=True, exist_ok=True)
    holder = paths.author_drain_lock_file.open("a+")
    fcntl.flock(holder.fileno(), fcntl.LOCK_EX)
    try:
        seen: list = []
        rc = orch.lead_author_drain(
            paths,
            run_lead_author=lambda wt_paths, rd: seen.append(rd),
            branch=_FakeBranch(prefix="lead-author/"),
        )
        assert rc == 0
        assert seen == [run_dir.resolve()]  # ran despite the lessons lock being held
    finally:
        fcntl.flock(holder.fileno(), fcntl.LOCK_UN)
        holder.close()


def test_lead_author_drain_quarantines_poison_run_dir(tmp_path: Path):
    """A lead-author that raises on one run dir is quarantined to failed/ (so it can't
    re-poison every tick); a second good marker still processes."""
    paths, _ = _isolate(tmp_path)
    poison = tmp_path / "tmprun" / "case-poison"
    poison.mkdir(parents=True)
    good = tmp_path / "tmprun" / "case-good"
    good.mkdir(parents=True)
    orch._enqueue_for_authoring(poison, paths)
    orch._enqueue_for_authoring(good, paths)
    seen: list[Path] = []

    def maybe_boom(wt_paths, rd: Path) -> None:
        if rd.name == "case-poison":
            raise RuntimeError("lead-author blew up")
        seen.append(rd)

    orch.lead_author_drain(
        paths, run_lead_author=maybe_boom, branch=_FakeBranch(prefix="lead-author/")
    )
    assert seen == [good.resolve()]  # the good marker still processed
    assert not (paths.author_queue_dir / "case-poison.json").exists()
    failed = paths.author_queue_dir / "failed" / "case-poison.json"
    assert json.loads(failed.read_text())["failed"].startswith("lead-author-error")


def test_lead_author_drain_quarantines_on_nonzero_rc(tmp_path: Path, monkeypatch):
    """A lead-author run that exits non-zero (rc=2 — agent crash/timeout) is quarantined
    to failed/, not dropped (issue #426). Drives the real ``_invoke_lead_author`` (the
    default ``run_lead_author``) with the lead_author module's ``run`` stubbed to rc=2."""
    import defender.learning.leads.lead_author as la

    paths, _ = _isolate(tmp_path)
    run_dir = tmp_path / "tmprun" / "case-rc"
    run_dir.mkdir(parents=True)
    orch._enqueue_for_authoring(run_dir, paths)
    # lint-monkeypatch: ok — drives the real _invoke_lead_author; _run_curator_module
    # imports the curator via importlib, so its run has no DI seam (run_lead_author=
    # would bypass the very _invoke_lead_author rc→signal mapping under test).
    monkeypatch.setattr(la, "run", lambda rd, paths=None: 2)  # lint-monkeypatch: ok
    orch.lead_author_drain(paths, branch=_FakeBranch(prefix="lead-author/"))
    assert not (paths.author_queue_dir / "case-rc.json").exists()
    failed = paths.author_queue_dir / "failed" / "case-rc.json"
    assert json.loads(failed.read_text())["failed"].startswith("lead-author-error")


def test_lead_author_drain_bounded_retry_then_quarantine(tmp_path: Path, monkeypatch):
    """A *transient* lead-author failure (rc=None — a swallowed SubprocessError/OSError,
    the run did not complete) is left queued with a bumped attempt count and quarantined
    only after LEAD_AUTHOR_MAX_RETRIES attempts (issue #426 follow-up: a genuine blip
    retries instead of being silently dropped, but a persistent pseudo-transient still
    surfaces). Drives the real ``_invoke_lead_author``: ``la.run`` raising ``OSError`` is
    swallowed by ``_run_curator_module`` → rc=None → ``_LeadAuthorRetry``."""
    import defender.learning.leads.lead_author as la

    paths, _ = _isolate(tmp_path)
    run_dir = tmp_path / "tmprun" / "case-transient"
    run_dir.mkdir(parents=True)
    orch._enqueue_for_authoring(run_dir, paths)
    monkeypatch.setenv("LEAD_AUTHOR_MAX_RETRIES", "3")

    def boom(rd, paths=None):
        raise OSError("disk hiccup")

    # lint-monkeypatch: ok — same intentional seam as the rc=2 test above: drives the
    # real _invoke_lead_author (no DI seam for the importlib-loaded curator.run).
    monkeypatch.setattr(la, "run", boom)  # lint-monkeypatch: ok
    marker = paths.author_queue_dir / "case-transient.json"
    failed = paths.author_queue_dir / "failed" / "case-transient.json"

    # Attempts 1 and 2 stay under the cap: marker preserved, attempt count bumped, not
    # quarantined.
    for expected in (1, 2):
        orch.lead_author_drain(paths, branch=_FakeBranch(prefix="lead-author/"))
        assert marker.exists()
        assert json.loads(marker.read_text())["attempts"] == expected
        assert not failed.exists()

    # Attempt 3 hits the cap → quarantined, gone from the queue.
    orch.lead_author_drain(paths, branch=_FakeBranch(prefix="lead-author/"))
    assert not marker.exists()
    assert json.loads(failed.read_text())["failed"].startswith("transient-exhausted")


def test_lead_author_drain_opens_distinct_lead_author_pr(tmp_path: Path):
    """End-to-end with a real git worktree + a fake forge: the lead-author drain branches
    off ``lead-author/`` (NOT ``lessons/``) and opens its own PR."""
    paths, _ = _isolate(tmp_path)
    run_dir = tmp_path / "tmprun" / "case-pr"
    run_dir.mkdir(parents=True)
    orch._enqueue_for_authoring(run_dir, paths)
    _, work = _origin_work(tmp_path)
    forge = _FakeForge(create_ref="https://github.com/o/r/pull/77")
    branch = ab.AuthorBranch(
        forge=forge, repo_root=work, branch_prefix="lead-author/",
        pr_title=orch._lead_author_pr_title, pr_body=orch._lead_author_pr_body,
        worktree_base=tmp_path / "wt",
    )

    def _author(wt_paths, rd):
        # The loop is the sole committer in production; here the stub stands in, leaving a
        # committed edit on the worktree branch so finish_batch sees commits and opens a PR.
        f = wt_paths.repo_root / "defender" / "skills" / "note.md"
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text("edit\n")
        _real(wt_paths.repo_root, "add", "-A")
        _real(wt_paths.repo_root, "commit", "-q", "-m", "lead edit")

    rc = orch.lead_author_drain(paths, run_lead_author=_author, branch=branch)
    assert rc == 0
    assert forge.open_calls[0]["head"].startswith("lead-author/")
    assert not forge.open_calls[0]["head"].startswith("lessons/")
    # lease search was scoped to the lead-author prefix, not lessons
    assert forge.list_calls == ["lead-author/"]


def test_lead_author_drain_resets_worktree_between_markers(tmp_path: Path):
    """The batch worktree is shared across all markers, so a marker that fails the scope
    gate leaves uncommitted dirt that must NOT bleed into the next marker. The drain
    discards the worktree's uncommitted changes between markers, so the second marker sees
    a clean tree (and can neither inherit the first's leftover edit nor be falsely
    quarantined by it). Uses a real git repo as the worktree (the _FakeBranch path has no
    .git and short-circuits the reset)."""
    wt = tmp_path / "wt"
    catalog = wt / "defender" / "skills" / "gather" / "queries" / "wazuh"
    catalog.mkdir(parents=True)
    (catalog / "auth-events.md").write_text("---\nstatus: established\n---\n")
    _real(wt, "init", "-q", "-b", "main")
    _real(wt, "config", "user.email", "t@e.com")
    _real(wt, "config", "user.name", "T")
    _real(wt, "add", "-A")
    _real(wt, "commit", "-q", "-m", "seed")

    # repo_root=worktree, state_dir elsewhere — mirrors LoopPaths.with_repo_root, so the
    # queue/quarantine live outside the worktree the reset operates on.
    paths = LoopPaths(repo_root=wt, state_dir=tmp_path / "state")
    poison = tmp_path / "runs" / "case-a-poison"  # sorts before "case-b-good" → runs first
    good = tmp_path / "runs" / "case-b-good"
    poison.mkdir(parents=True)
    good.mkdir(parents=True)
    orch._enqueue_for_authoring(poison, paths)
    orch._enqueue_for_authoring(good, paths)

    clean_at_entry: dict[str, bool] = {}

    def run_lead_author(p, rd: Path) -> None:
        st = _subprocess.run(
            ["git", "-C", str(p.repo_root), "status", "--porcelain"],
            capture_output=True, text=True,
        )
        clean_at_entry[rd.name] = st.stdout.strip() == ""
        if rd.name == "case-a-poison":
            # delete an established template and raise: the marker is quarantined and its
            # uncommitted deletion is left behind in the shared worktree.
            (p.repo_root / "defender" / "skills" / "gather" / "queries"
             / "wazuh" / "auth-events.md").unlink()
            raise RuntimeError("scope-gate boom")

    orch._drain_lead_author_markers(paths, run_lead_author)

    assert clean_at_entry["case-a-poison"] is True   # first marker starts on a clean tree
    assert clean_at_entry["case-b-good"] is True      # reset wiped the poison's leftover
    # worktree ends clean — the poison's deletion was discarded, not left dangling
    end = _subprocess.run(["git", "-C", str(wt), "status", "--porcelain"],
                          capture_output=True, text=True)
    assert end.stdout.strip() == ""
    assert (paths.author_queue_dir / "failed" / "case-a-poison.json").exists()  # quarantined
    assert not (paths.author_queue_dir / "case-b-good.json").exists()           # consumed


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
    state = tmp_path / "state"  # out-of-repo
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
# author_branch — the per-batch git-worktree + PR discipline. Git runs for real
# against a tmp repo (repo_root injected); only the forge (gh) is faked.
# ---------------------------------------------------------------------------

import subprocess as _subprocess  # noqa: E402

from defender.learning.author import branch as ab  # type: ignore[import-not-found]  # noqa: E402
from defender.learning.author import forge as _forge  # type: ignore[import-not-found]  # noqa: E402


class _FakeForge:
    """In-memory forge for the branch tests — records list/open calls, never shells out
    to ``gh`` (the one injected seam). ``git`` is exercised for real against a tmp repo."""

    def __init__(self, *, pr_rows=None, create_ref="https://pr/1", raises=False):
        self.pr_rows = pr_rows or []
        self.create_ref = create_ref
        self.raises = raises
        self.list_calls: list[str] = []
        self.open_calls: list[dict] = []

    def list_open_prs(self, head_prefix: str) -> list[dict]:
        self.list_calls.append(head_prefix)
        return self.pr_rows

    def open_pr(self, *, base: str, head: str, title: str, body: str) -> str:
        self.open_calls.append({"base": base, "head": head, "title": title, "body": body})
        if self.raises:
            raise _forge.ForgeError("gh boom")
        return self.create_ref


def _real(cwd: Path, *args: str):
    return _subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, check=True)


def _origin_work(tmp_path: Path, *, lessons: dict[str, str] | None = None) -> tuple[Path, Path]:
    """A bare ``origin`` + a ``work`` clone with a seed commit pushed to ``origin/main``.
    ``lessons`` seeds repo-relative files (e.g. a lesson to later revert). Returns
    ``(origin, work)``; ``work`` is the repo root the AuthorBranch operates on."""
    origin = tmp_path / "origin.git"
    work = tmp_path / "work"
    _real(tmp_path, "init", "--bare", "-q", str(origin), "-b", "main")
    _real(tmp_path, "clone", "-q", str(origin), str(work))
    _real(work, "config", "user.email", "t@e.com")
    _real(work, "config", "user.name", "T")
    (work / "seed.md").write_text("seed\n")
    for rel, content in (lessons or {}).items():
        p = work / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
    _real(work, "add", "-A")
    _real(work, "commit", "-q", "-m", "seed")
    _real(work, "push", "-q", "origin", "main")
    return origin, work


def test_author_branch_lease_true_on_open_pr():
    forge = _FakeForge(pr_rows=[{"number": 1, "headRefName": "lessons/abc"}])
    assert ab.AuthorBranch(forge=forge).open_pr_exists() is True
    assert forge.list_calls == ["lessons/"]  # searched on the prefix


def test_author_branch_lease_false_when_no_matching_pr():
    forge = _FakeForge(pr_rows=[{"number": 2, "headRefName": "feature/x"}])
    assert ab.AuthorBranch(forge=forge).open_pr_exists() is False


def test_author_branch_lease_keyed_on_prefix():
    """A lessons PR does NOT hold the lead-author lease (per-prefix lease)."""
    forge = _FakeForge(pr_rows=[{"number": 3, "headRefName": "lessons/abc"}])
    b = ab.AuthorBranch(forge=forge, branch_prefix="lead-author/")
    assert b.open_pr_exists() is False
    assert forge.list_calls == ["lead-author/"]


def test_author_branch_start_adds_worktree_off_origin_main(tmp_path: Path):
    _, work = _origin_work(tmp_path)
    b = ab.AuthorBranch(forge=_FakeForge(), repo_root=work, worktree_base=tmp_path / "wt")
    wt = b.start_batch("abc123")
    assert wt == tmp_path / "wt" / "lessons-abc123"
    assert wt.is_dir()  # a real worktree checkout
    assert _real(wt, "rev-parse", "--abbrev-ref", "HEAD").stdout.strip() == "lessons/abc123"
    assert (_real(wt, "rev-parse", "HEAD").stdout.strip()
            == _real(work, "rev-parse", "origin/main").stdout.strip())  # off origin/main


def test_author_branch_start_cleans_up_partial_worktree_on_add_failure(tmp_path: Path):
    """If `worktree add` fails (its target is already occupied), start_batch re-raises as
    BranchError rather than leaving a half-created worktree registered."""
    _, work = _origin_work(tmp_path)
    wt_base = tmp_path / "wt"
    occupied = wt_base / "lessons-abc123"
    occupied.mkdir(parents=True)
    (occupied / "in_the_way.txt").write_text("x")  # non-empty → `git worktree add` refuses
    b = ab.AuthorBranch(forge=_FakeForge(), repo_root=work, worktree_base=wt_base)
    with pytest.raises(ab.BranchError):
        b.start_batch("abc123")
    assert "lessons-abc123" not in _real(work, "worktree", "list").stdout  # never registered


def test_author_branch_finish_no_commits_returns_none(tmp_path: Path):
    origin, work = _origin_work(tmp_path)
    forge = _FakeForge()
    b = ab.AuthorBranch(forge=forge, repo_root=work, worktree_base=tmp_path / "wt")
    wt = b.start_batch("abc123")  # no commit on the branch → nothing ahead of origin/main
    assert b.finish_batch("abc123", wt) is None
    assert forge.open_calls == []  # no PR opened
    assert not _real(work, "ls-remote", "--heads", "origin", "lessons/abc123").stdout.strip()


def test_author_branch_finish_pushes_and_opens_pr(tmp_path: Path):
    _, work = _origin_work(tmp_path)
    forge = _FakeForge(create_ref="https://github.com/o/r/pull/9")
    b = ab.AuthorBranch(forge=forge, repo_root=work, worktree_base=tmp_path / "wt")
    wt = b.start_batch("abc123")
    (wt / "added.md").write_text("from worktree\n")
    _real(wt, "add", "-A")
    _real(wt, "commit", "-q", "-m", "wt edit")
    assert b.finish_batch("abc123", wt) == "https://github.com/o/r/pull/9"
    assert forge.open_calls[0]["base"] == "main"
    assert forge.open_calls[0]["head"] == "lessons/abc123"
    # the branch reached origin
    assert _real(work, "ls-remote", "--heads", "origin", "lessons/abc123").stdout.strip()


def test_author_branch_finish_raises_on_gh_failure(tmp_path: Path):
    _, work = _origin_work(tmp_path)
    b = ab.AuthorBranch(forge=_FakeForge(raises=True), repo_root=work,
                        worktree_base=tmp_path / "wt")
    wt = b.start_batch("abc123")
    (wt / "added.md").write_text("x\n")
    _real(wt, "add", "-A")
    _real(wt, "commit", "-q", "-m", "edit")
    with pytest.raises(ab.BranchError):
        b.finish_batch("abc123", wt)


def test_author_branch_cleanup_removes_worktree(tmp_path: Path):
    _, work = _origin_work(tmp_path)
    b = ab.AuthorBranch(forge=_FakeForge(), repo_root=work, worktree_base=tmp_path / "wt")
    wt = b.start_batch("abc123")
    assert wt.is_dir()
    b.cleanup(wt)
    assert not wt.exists()  # worktree removed


def test_author_branch_worktree_lifecycle_real_git(tmp_path: Path):
    """The full lifecycle leaves the dev checkout's HEAD untouched (lead-author prefix)."""
    _, work = _origin_work(tmp_path)
    forge = _FakeForge(create_ref="https://pr/lead/1")
    b = ab.AuthorBranch(forge=forge, repo_root=work, branch_prefix="lead-author/",
                        worktree_base=tmp_path / "wt")
    head_before = _real(work, "rev-parse", "HEAD").stdout.strip()
    wt = b.start_batch("xyz789")
    (wt / "added.md").write_text("from worktree\n")
    _real(wt, "add", "-A")
    _real(wt, "commit", "-q", "-m", "wt edit")
    assert b.finish_batch("xyz789", wt) == "https://pr/lead/1"
    b.cleanup(wt)
    assert not wt.exists()
    assert _real(work, "rev-parse", "HEAD").stdout.strip() == head_before  # dev HEAD unmoved


# ---------------------------------------------------------------------------
# one-click revert (AuthorBranch.revert_lesson_pr + revert_lesson.revert)
# ---------------------------------------------------------------------------


def test_author_branch_revert_lesson_pr_removes_and_opens_pr(tmp_path: Path):
    _, work = _origin_work(tmp_path, lessons={"defender/lessons/bad.md": "bad lesson\n"})
    forge = _FakeForge(create_ref="https://github.com/o/r/pull/42")
    b = ab.AuthorBranch(forge=forge, repo_root=work, worktree_base=tmp_path / "wt")
    ref_before = _real(work, "rev-parse", "--abbrev-ref", "HEAD").stdout.strip()
    assert b.revert_lesson_pr("defender/lessons/bad.md", "bad") == "https://github.com/o/r/pull/42"
    assert forge.open_calls[0]["head"] == "lessons/revert-bad"
    assert forge.open_calls[0]["title"] == "revert lesson: bad"
    # the revert branch reached origin; the dev checkout's HEAD is never moved (worktree model)
    assert _real(work, "ls-remote", "--heads", "origin", "lessons/revert-bad").stdout.strip()
    assert _real(work, "rev-parse", "--abbrev-ref", "HEAD").stdout.strip() == ref_before
    assert not (tmp_path / "wt" / "lessons-revert-bad").exists()  # worktree removed after


def test_author_branch_revert_succeeds_with_dirty_dev_tree(tmp_path: Path):
    """The revert runs in its own worktree, so a dirty dev checkout no longer blocks it
    (the #477 HEAD-safety win) and the dev tree is left untouched."""
    _, work = _origin_work(tmp_path, lessons={"defender/lessons/bad.md": "bad\n"})
    (work / "dirty.txt").write_text("uncommitted\n")  # dev tree dirty — must not matter
    b = ab.AuthorBranch(forge=_FakeForge(create_ref="https://pr/1"),
                        repo_root=work, worktree_base=tmp_path / "wt")
    assert b.revert_lesson_pr("defender/lessons/bad.md", "bad") == "https://pr/1"
    assert (work / "dirty.txt").read_text() == "uncommitted\n"  # dev tree left alone


def test_author_branch_revert_refuses_missing_lesson_on_base(tmp_path: Path):
    """Existence is checked against origin/main, not the local tree — a lesson absent
    from the base raises before any branch churn (no stray local revert branch)."""
    _, work = _origin_work(tmp_path)  # no lesson seeded
    b = ab.AuthorBranch(forge=_FakeForge(), repo_root=work, worktree_base=tmp_path / "wt")
    head_before = _real(work, "rev-parse", "HEAD").stdout.strip()
    with pytest.raises(ab.BranchError):
        b.revert_lesson_pr("defender/lessons/ghost.md", "ghost")
    assert _real(work, "rev-parse", "HEAD").stdout.strip() == head_before  # HEAD unmoved
    assert not _real(work, "branch", "--list", "lessons/revert-ghost").stdout.strip()  # no churn


def test_revert_cli_holds_drain_lock_and_calls_through(tmp_path: Path):
    """revert() acquires the author-drain flock, then opens the revert PR."""
    from defender.learning.ops import revert_lesson as rl  # type: ignore[import-not-found]
    paths = LoopPaths(repo_root=tmp_path)
    _, work = _origin_work(tmp_path, lessons={"defender/lessons/bad.md": "bad\n"})
    forge = _FakeForge(create_ref="https://pr/7")
    b = ab.AuthorBranch(forge=forge, repo_root=work, worktree_base=tmp_path / "wt")
    assert rl.revert("bad", branch=b, paths=paths) == 0
    assert forge.open_calls[0]["head"] == "lessons/revert-bad"  # PR opened through the lock


def test_revert_cli_skips_when_drain_lock_held(tmp_path: Path):
    """A revert run while an author drain holds the lock fails fast (rc 3), without
    touching git — the flock still serializes the revert against the in-flight batch."""
    import fcntl as _fcntl

    from defender.learning.ops import revert_lesson as rl  # type: ignore[import-not-found]
    paths = LoopPaths(repo_root=tmp_path)
    lock = paths.author_drain_lock_file
    lock.parent.mkdir(parents=True, exist_ok=True)
    holder = lock.open("a+")
    _fcntl.flock(holder.fileno(), _fcntl.LOCK_EX | _fcntl.LOCK_NB)
    try:
        forge = _FakeForge()
        b = ab.AuthorBranch(forge=forge, repo_root=tmp_path)  # git/forge never reached
        assert rl.revert("bad", branch=b, paths=paths) == 3
        assert forge.open_calls == []  # never reached revert_lesson_pr
    finally:
        _fcntl.flock(holder.fileno(), _fcntl.LOCK_UN)
        holder.close()


# ---------------------------------------------------------------------------
# _loop_comparison — the grounding zipper (judge rework, #275)
# ---------------------------------------------------------------------------


def _make_run_dir(tmp_path: Path, *, disposition="benign", with_payload=True) -> Path:
    """A minimal defender run dir: alert + report + the two tables + one payload."""
    run = tmp_path / "run"
    (run / "gather_raw" / "l-001").mkdir(parents=True)
    (run / "alert.json").write_text(json.dumps({"rule": {"id": "r1"}}))
    (run / "report.md").write_text(f"---\ndisposition: {disposition}\n---\nbody\n")
    qrow = {
        "lead_id": "l-001", "seq": 0, "system": "elastic", "verb": "search",
        "query_id": "elastic.auth", "params": {"host": "h1"}, "raw_command": "x",
        "exit_code": 0, "payload_status": "ok", "payload_digest": "d",
        "payload_path": "gather_raw/l-001/0.json",
    }
    (run / "executed_queries.jsonl").write_text(json.dumps(qrow) + "\n")
    (run / "gather_raw" / "l-001.lead.json").write_text(
        json.dumps({"goal": "check auth", "what_to_summarize": ["accepted vs failed"]})
    )
    if with_payload:
        events = [{"user": "dev.dana", "outcome": "success"}]
        payload = (
            "### Summary\n3 events\n\n### Raw Sample Events\n\n"
            "```json\n" + json.dumps(events) + "\n```\n"
        )
        (run / "gather_raw" / "l-001" / "0.json").write_text(payload)
    return run


def _make_projection(tmp_path: Path, projections=None) -> Path:
    p = tmp_path / "projected_telemetry.yaml"
    if projections is None:
        projections = [{"lead_id": "l-001", "events": [{"user": "attacker", "outcome": "success"}]}]
    p.write_text(__import__("yaml").safe_dump({"projections": projections}))
    return p


_COMPANION = {
    "hypothesize": {"hypotheses": [{"id": "h-mal", "name": "malicious-cred-validation", "weight": "+"}]},
    "findings": [{
        "id": "l-001",
        "resolutions": [{
            "hypothesis": "h-mal", "before": "+", "after": "--",
            "reasoning": "2s cadence => conclusively scripted automation => benign",
        }],
        "outcome": {"authorization_resolutions": [
            {"resolved_by_lead": "l-001", "fulfills": "ac1", "verdict": "authorized"},
        ]},
    }],
    "conclude": {"disposition": "benign"},
}


def test_build_comparison_joins_projection_sample_and_invlang(tmp_path: Path):
    run = _make_run_dir(tmp_path)
    proj = _make_projection(tmp_path)
    comps = comparison.build_comparison(run, proj, companion=_COMPANION)
    assert len(comps) == 1
    c = comps[0]
    assert c.lead_id == "l-001"
    assert c.projected_events == [{"user": "attacker", "outcome": "success"}]
    assert "dev.dana" in c.real_sample  # column [2] is unredacted (the judge is the scorer)
    assert c.resolutions  # column [3] belief movement
    assert c.resolutions[0]["after"] == "--"
    assert c.authz
    assert c.authz[0]["verdict"] == "authorized"


def test_real_sample_text_keeps_values_where_lead_sample_text_scrubs(tmp_path: Path):
    run = _make_run_dir(tmp_path)
    lead = lr.joined(run)[0]
    real = oracle_mod.real_sample_text(lead)
    redacted = oracle_mod.lead_sample_text(lead)
    assert "dev.dana" in real
    assert "dev.dana" not in redacted
    assert "<user>" in redacted


def test_build_comparison_monitor_run_is_empty(tmp_path: Path):
    run = tmp_path / "run"
    run.mkdir()
    (run / "alert.json").write_text("{}")
    proj = _make_projection(tmp_path, projections=[])
    comps = comparison.build_comparison(run, proj)
    assert comps == []
    assert "monitor" in comparison.render_manifest(comps)


def test_build_comparison_missing_payload_degrades_sample(tmp_path: Path):
    run = _make_run_dir(tmp_path, with_payload=False)
    proj = _make_projection(tmp_path)
    comps = comparison.build_comparison(run, proj)
    assert comps[0].real_sample.startswith("(")  # placeholder, no crash


def test_build_comparison_lead_without_projection(tmp_path: Path):
    run = _make_run_dir(tmp_path)
    proj = _make_projection(tmp_path, projections=[])  # no projection for l-001
    comps = comparison.build_comparison(run, proj)
    assert comps[0].projected_events is None  # "(no projection emitted)" downstream


def test_build_comparison_orphan_projection_surfaced(tmp_path: Path):
    run = _make_run_dir(tmp_path)
    proj = _make_projection(tmp_path, projections=[
        {"lead_id": "l-001", "events": []},
        {"lead_id": "l-999", "events": [{"x": 1}]},  # projection for a lead not in the tables
    ])
    comps = comparison.build_comparison(run, proj)
    by_id = {c.lead_id: c for c in comps}
    assert "l-999" in by_id  # projection for a lead not in the tables — surfaced, not dropped
    assert by_id["l-999"].note  # anomaly annotated
    assert "anomaly" in comparison.render_manifest(comps)


def test_parse_investigation_companion_degrades_on_garbage(tmp_path: Path):
    run = tmp_path / "run"
    run.mkdir()
    (run / "investigation.md").write_text("just prose, no invlang fences")
    assert comparison.parse_investigation_companion(run) == {}
    # missing file → {} too
    assert comparison.parse_investigation_companion(tmp_path / "nope") == {}


def test_write_comparison_files_one_per_lead(tmp_path: Path):
    run = _make_run_dir(tmp_path)
    proj = _make_projection(tmp_path)
    comps = comparison.build_comparison(run, proj, companion=_COMPANION)
    out = tmp_path / "cmp"
    paths = comparison.write_comparison_files(comps, out, run / "gather_raw")
    assert [p.name for p in paths] == ["l-001.md"]
    txt = paths[0].read_text()
    assert "[1] Oracle projection" in txt
    assert "[3] What the defender" in txt
    assert "gather_raw/l-001/0.json" in txt  # jq hint with the absolute payload path
    assert "scripted automation" in txt  # the per-lead belief-movement reasoning


def test_render_synthesis_includes_reasoning_and_conclude():
    out = comparison.render_synthesis(_COMPANION)
    assert "h-mal" in out
    assert "scripted automation" in out  # the :T resolutions reasoning (the "why")
    assert "benign" in out  # the conclude block
    assert comparison.render_synthesis({}).startswith("(")  # empty → placeholder


def test_judge_settings_dict_is_readonly_and_unhooked(tmp_path: Path):
    s = comparison.judge_settings_dict(tmp_path / "gr", tmp_path / "cmp")
    assert "hooks" not in s  # the runtime block_main_loop_raw_access gate must NOT apply
    allow, deny = s["permissions"]["allow"], s["permissions"]["deny"]
    assert any(a.startswith("Bash(jq") for a in allow)
    assert any(str(tmp_path / "gr") in a for a in allow)
    for d in ("Task", "Agent", "Write(**)", "Edit(**)"):
        assert d in deny
    assert any("ground_truth" in d for d in deny)


def test_build_judge_invocation_assembles_grounded_call(tmp_path: Path):
    run = _make_run_dir(tmp_path)
    proj = _make_projection(tmp_path)
    story = tmp_path / "actor_story.md"
    story.write_text("Attack story\nGoal\nBypass\n")
    lrd = tmp_path / "lrd"
    lrd.mkdir()

    inv = subagents.build_judge_invocation(run, story, proj, lrd)

    assert (lrd / "comparison" / "l-001.md") in inv.comparison_paths
    assert inv.settings_path == lrd / "judge-settings.resolved.json"
    assert inv.settings_path.is_file()
    settings = json.loads(inv.settings_path.read_text())
    assert "hooks" not in settings
    assert set(inv.add_dirs) == {run / "gather_raw", lrd / "comparison"}
    # The user message is context + the comparison manifest, grounded on the actuals.
    assert str(run / "gather_raw") in inv.user_text
    assert "disposition: benign" in inv.user_text     # report.md — the claim being scored
    assert "scripted automation" not in inv.user_text  # per-lead "why" lives in the files, not inline
    assert "comparison" in inv.user_text.lower()


def test_invoke_judge_benign_is_grounded(tmp_path: Path):
    """The FP-direction judge is grounded on the actuals (#317): it writes per-lead
    comparison files + a read-only settings dict, add-dirs gather_raw + comparison, and
    shells out with the BENIGN prompt/model — the same zipper the adversarial judge uses,
    not the old narrative path. The FP direction fires on a malicious-disposed source."""
    run = _make_run_dir(tmp_path, disposition="malicious")
    proj = _make_projection(tmp_path)
    story = tmp_path / "actor_benign_story.md"
    story.write_text("1. Routine-activity story\n2. Benign grounding\n")
    lrd = tmp_path / "lrd"
    lrd.mkdir()

    captured: dict = {}

    def _fake_run_judge_claude(prompt_path, model, *args, **kwargs):
        # positional tail mirrors _run_judge_claude: effort, trace_name, label, user,
        # learning_run_dir; settings_path/add_dir/permission_mode arrive as kwargs.
        _effort, _trace, label, user, _lrd = args
        scope = kwargs["scope"]
        captured.update(
            prompt_path=prompt_path, model=model, label=label, user=user,
            settings_path=scope.settings_path, add_dir=scope.add_dir,
        )
        return "outcome: survived\ndefender_findings: []\n"

    out = subagents.invoke_judge(
        directions.BENIGN_WIRING, run, story, proj, lrd,
        judge_fn=_fake_run_judge_claude,
    )

    assert out.startswith("outcome:")
    # Grounded surface: per-lead comparison file + settings written; actuals add-dir'd.
    # Benign uses a per-direction comparison dir + settings name so a concurrent
    # adversarial leg (inconclusive case, shared learning_run_dir) can't clobber them.
    assert (lrd / "comparison_benign" / "l-001.md").is_file()
    assert captured["settings_path"] == lrd / "judge-benign-settings.resolved.json"
    assert set(captured["add_dir"]) == {run / "gather_raw", lrd / "comparison_benign"}
    # Benign prompt/model/label — not the adversarial ones; sourced from the wiring.
    assert captured["prompt_path"] == directions.BENIGN_WIRING.prompt_path
    assert captured["model"] == directions.BENIGN_WIRING.model
    assert captured["label"] == "judge-benign"
    # Scores the actuals, not the narrative — the old investigation / lead_sequence
    # sections are gone; report + the comparison manifest are in.
    assert "<investigation>" not in captured["user"]
    assert "<lead_sequence>" not in captured["user"]
    assert "disposition: malicious" in captured["user"]   # report.md, the claim scored
    assert "<comparison_files>" in captured["user"]
