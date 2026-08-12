from __future__ import annotations

import json
import re
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
from defender.learning.core import drains as drains  # type: ignore[import-not-found]  # noqa: E402
from defender.learning.core import markers as markers  # type: ignore[import-not-found]  # noqa: E402
from defender.learning.core import run_cycle as run_cycle  # type: ignore[import-not-found]  # noqa: E402
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
    for item in (
        "session lasted 1:30:00",
        "window 2026-06-07 16:00:00 to 2026-06-07 18:00:00",
        "top 12:34:56 talkers",
    ):
        assert oracle_mod.sanitize_wtc(item) == item




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


def _esql_sample(body: str) -> str:
    return f"### Raw Sample Events (first 3)\n\n```json\n{body}\n```\n"


def test_redact_exemplar_keeps_the_field_names_of_a_COLUMNAR_esql_payload():
    """The skeleton's whole job is "what fields does this lead's telemetry have".

    ES|QL states its field names once in `columns` and its rows as bare arrays (#834), so a
    pure type-walk scrubs the names as string VALUES and the oracle is handed a skeleton with
    no field names at all — where the pre-#834 per-row dicts kept them as keys. The names must
    survive; the ROW must not, because that is the data.
    """
    out = oracle_mod.redact_exemplar(_esql_sample(json.dumps({
        "query": "FROM logs-* | STATS failed = COUNT(*) BY host.name",
        "columns": [{"name": "host.name", "type": "keyword"},
                    {"name": "failed", "type": "long"},
                    {"name": "source.ip", "type": "ip"}],
        "row_count": 2,
        "values": [["web-01", 12, "10.1.1.5"], ["web-02", 3, "10.1.1.9"]],
    })))

    for name in ("host.name", "failed", "source.ip"):
        assert f'"{name}"' in out, f"the skeleton lost the field name {name!r}"
    for es_type in ("keyword", "long", "ip"):
        assert f'"{es_type}"' in out, f"the declared ES type {es_type!r} went with them"
    for leaked in ("web-01", "web-02", "10.1.1.5", "10.1.1.9"):
        assert leaked not in out, f"a ROW value survived the scrub: {leaked!r}"
    assert '"<query>"' in out, "the query text is data and is still scrubbed"


def test_the_columns_passthrough_does_not_unscrub_a_document_that_merely_has_that_key():
    """Passing `columns` through is licensed by it being ES|QL's SCHEMA block, not by its
    name. A document with a `columns` key that is not that block — no `values` list beside
    it, or entries that are not `{name, type}` descriptors — is data, and an attacker who
    could get a field named `columns` into an index would otherwise have bought themselves
    an unscrubbed region of the oracle's prompt."""
    not_an_envelope = oracle_mod.redact_exemplar(_esql_sample(json.dumps(
        {"columns": [{"name": "secret-host", "type": "keyword"}], "values": "not-a-list"})))
    assert "secret-host" not in not_an_envelope, "scrubbing was skipped without a `values` list"

    wrong_shape = oracle_mod.redact_exemplar(_esql_sample(json.dumps(
        {"columns": [{"label": "secret-host"}], "values": [[1]]})))
    assert "secret-host" not in wrong_shape, "scrubbing was skipped on a non-descriptor entry"

    nested_name = oracle_mod.redact_exemplar(_esql_sample(json.dumps(
        {"user": {"name": "alice"}, "host": {"name": "db-07"}})))
    for leaked in ("alice", "db-07"):
        assert leaked not in nested_name, f"a `name` VALUE survived the scrub: {leaked!r}"


def test_redact_exemplar_no_sample_block_is_placeholder():
    assert oracle_mod.redact_exemplar("## Query Results\n(no raw block)\n").startswith("(")


def test_redact_exemplar_empty_sample_block_is_placeholder():
    out = oracle_mod.redact_exemplar("### Raw Sample Events\n\n```json\n[]\n```\n")
    assert out.startswith("(")
    assert "is empty" in out


def test_lead_sample_text_reads_only_its_lead_subdir(tmp_path: Path):
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
    assert out.startswith("(")




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
    assert oracle_mod.parse_lead_events(
        "events:\n  - <suppressed: stopped auditd before the probe>\n", 0
    ) == ["<suppressed: stopped auditd before the probe>"]


def test_parse_lead_events_rescues_unquoted_marker_with_multiple_colons():
    assert oracle_mod.parse_lead_events(
        "events:\n  - <suppressed: ran cmd: systemctl stop auditd>\n", 0
    ) == ["<suppressed: ran cmd: systemctl stop auditd>"]
    assert oracle_mod.parse_lead_events(
        "events:\n  - <suppressed: cleared log: /var/log/auth>\n", 0
    ) == ["<suppressed: cleared log: /var/log/auth>"]


def test_parse_lead_events_keeps_single_field_placeholder_event():
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




def test_build_lead_user_prompt_drops_goal_and_sanitizes_wtc():
    lead = _jl(
        "l-001",
        goal="SECRET defender intent that must not leak",
        wts=["the login at 2026-06-02T17:08:19Z"],
        queries=[_qr("wazuh.auth-events", {"host": "h"})],
    )
    prompt = oracle_mod.build_lead_user_prompt(lead, "the story", "SAMPLE")
    assert "SECRET defender intent" not in prompt
    assert "<alert-time>" in prompt
    assert "17:08:19Z" not in prompt
    assert "wazuh.auth-events" in prompt
    assert "the story" in prompt
    assert "SAMPLE" in prompt


def test_build_lead_user_prompt_handles_scalar_and_malformed_wtc():
    scalar = oracle_mod.build_lead_user_prompt(
        _jl("l-001", wts="auth events by host", queries=[_qr("wazuh.x", None)]),
        "story", "SAMPLE",
    )
    assert "auth events by host" in scalar
    assert "\n- a\n- u\n- t" not in scalar
    assert "params: {}" in scalar
    oracle_mod.build_lead_user_prompt(_jl("l-002", wts=[42, {"x": 1}]), "story", "S")


def test_dump_oracle_doc_preserves_unicode():
    doc = oracle_mod.assemble_oracle_doc([("l-001", [{"user": "Bjørn"}])])
    text = dump_oracle_doc(doc)
    assert "Bjørn" in text
    assert "\\xF8" not in text




def test_outcome_keyword_accepts_bare_enum():
    assert loop._outcome_keyword("survived") == "survived"


def test_outcome_keyword_tolerates_period_then_rationale():
    fused = "survived. The defender's investigation returned results consistent with the oracle."
    assert loop._outcome_keyword(fused) == "survived"


def test_outcome_keyword_tolerates_block_scalar_newline_form():
    assert loop._outcome_keyword("caught\nrationale follows…\n") == "caught"


def test_outcome_keyword_rejects_unknown_first_token():
    with pytest.raises(RunUnprocessable, match="not in"):
        loop._outcome_keyword("definitely-survived. lots of detail")


def test_outcome_keyword_rejects_non_string():
    with pytest.raises(RunUnprocessable, match="not a string"):
        loop._outcome_keyword({"survived": True})




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
    doc = _full_judge_doc()
    doc["defender_findings"][0]["subject_topic"] = "actor's framing assumption"
    loop.validate_judge_doc(doc)


def test_validate_judge_doc_omitted_actor_observations_is_accepted():
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
            "subject_topic": "   ",
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




def test_strip_yaml_fence_passes_through_plain_yaml():
    assert loop.strip_yaml_fence("outcome: caught\nconfidence: high\n") == (
        "outcome: caught\nconfidence: high"
    )


def test_strip_yaml_fence_strips_yaml_code_fence():
    fenced = "```yaml\noutcome: caught\n```\n"
    assert loop.strip_yaml_fence(fenced) == "outcome: caught"


def test_strip_yaml_fence_strips_trailing_close_tag():
    text = "outcome: caught\nconfidence: high\n</content>\n"
    assert loop.strip_yaml_fence(text) == "outcome: caught\nconfidence: high"


def test_strip_yaml_fence_strips_full_xml_envelope():
    text = "<content>\noutcome: caught\nconfidence: high\n</content>\n"
    assert loop.strip_yaml_fence(text) == "outcome: caught\nconfidence: high"


def test_strip_yaml_fence_strips_dangling_close_fence():
    text = "outcome: caught\nconfidence: high\n```\n"
    assert loop.strip_yaml_fence(text) == "outcome: caught\nconfidence: high"


def test_strip_yaml_fence_strips_thinking_prelude():
    text = (
        "outcome: caught\n(reasoning trace…)\n</thinking>\n"
        "outcome: survived\nconfidence: high\n"
    )
    assert loop.strip_yaml_fence(text) == "outcome: survived\nconfidence: high"


def test_strip_yaml_fence_strips_system_thinking_variant():
    text = (
        "outcome: caught\n(reasoning trace…)\n</system_thinking>\n"
        "outcome: survived\nconfidence: high\n"
    )
    assert loop.strip_yaml_fence(text) == "outcome: survived\nconfidence: high"


def test_strip_yaml_fence_passes_through_when_no_thinking_tag():
    text = "outcome: caught\nconfidence: high\n"
    assert loop.strip_yaml_fence(text) == "outcome: caught\nconfidence: high"




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


def _noop_start_box(request, **_kw):
    """A no-op box lifecycle for drain tests predating #665's box wiring — these tests exercise
    the worktree/branch/queue mechanics, not the (separately spec'd) box lifecycle."""
    from types import SimpleNamespace

    return SimpleNamespace(name=request.name)


def _noop_stop_box(_box, **_kw):
    pass


def _noop_scrub(_path, **_kw):
    pass


def _isolate(tmp_path: Path) -> tuple[object, Path]:
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
    assert append_actor_observations(doc, "case-x", "rule-5710", lrd, paths=paths) == 0
    assert len(_read_jsonl(paths.actor_observations.file)) == 2


def test_append_actor_observations_creates_lock_file(tmp_path: Path):
    paths, lrd = _isolate(tmp_path)
    doc = _judge_doc("caught", [_obs(0)])

    assert append_actor_observations(doc, "case-x", "rule-5710", lrd, paths=paths) == 1
    assert paths.actor_observations.append_lock.is_file()


def test_append_actor_observations_skips_passthrough_outcome(tmp_path: Path):
    paths, lrd = _isolate(tmp_path)
    doc = _judge_doc("skip-passthrough", [_obs(0)])

    assert append_actor_observations(doc, "case-x", "rule-5710", lrd, paths=paths) == 0
    assert _read_jsonl(paths.actor_observations.file) == []


def test_append_actor_observations_no_key_is_zero_rows(tmp_path: Path):
    paths, lrd = _isolate(tmp_path)
    doc = _judge_doc("caught", None)

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
    paths, lrd = _isolate(tmp_path)
    doc = _judge_doc("caught", [_obs(0), _obs(1)])

    assert append_actor_observations(doc, "case-x", "rule-5710", lrd, paths=paths) == 2
    paths.actor_observations.consumed.write_text(
        paths.actor_observations.file.read_text()
    )
    paths.actor_observations.file.write_text("")

    assert append_actor_observations(doc, "case-x", "rule-5710", lrd, paths=paths) == 0
    assert _read_jsonl(paths.actor_observations.file) == []


def test_append_actor_observations_queues_survived_outcomes(tmp_path: Path):
    paths, lrd = _isolate(tmp_path)
    doc = _judge_doc("survived", [_obs(0)])

    n = append_actor_observations(doc, "case-x", "rule-5710", lrd, paths=paths)

    assert n == 1
    rows = _read_jsonl(paths.actor_observations.file)
    assert rows[0]["judge_outcome"] == "survived"




def test_rotate_queue_locked_preserves_concurrent_appends(tmp_path: Path):
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
    assert held_row["held_reason"] == "no_ground_truth"
    consumed_rows = _read_jsonl(paths.pending_dir / "consumed.jsonl")
    assert consumed_rows[0]["consumed_commit"] == "abc123"
    assert "consumed_at" in consumed_rows[0]


def test_enqueue_for_authoring_writes_marker(tmp_path: Path):
    paths, _ = _isolate(tmp_path)
    run_dir = tmp_path / "tmprun" / "case-a"
    run_dir.mkdir(parents=True)
    markers.enqueue_for_authoring(run_dir, paths)
    spec = json.loads((paths.author_queue_dir / "case-a.json").read_text())
    assert spec == {"run_id": "case-a", "run_dir": str(run_dir.resolve())}


class _FakeBranch:

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
    paths.pending_file.parent.mkdir(parents=True, exist_ok=True)
    with paths.pending_file.open("w") as fh:
        for i in range(n):
            fh.write(json.dumps({"finding_id": f"f{i}"}) + "\n")




def test_author_drain_triggers_all_curators(tmp_path: Path):
    paths, _ = _isolate(tmp_path)
    _seed_curator_findings(paths)
    triggered: list[str] = []
    drains.author_drain(
        paths,
        trigger_author=lambda paths, pending_file, env, module, label, **_kw: triggered.append(module),
        branch=_FakeBranch(),
        start_box=_noop_start_box, stop_box=_noop_stop_box, scrub=_noop_scrub,
    )
    assert triggered == [
        "author", "author_actor", "author_actor_env", "author_actor_benign",
    ]


def test_author_drain_skips_when_lease_held(tmp_path: Path):
    paths, _ = _isolate(tmp_path)
    _seed_curator_findings(paths)
    triggered: list = []
    branch = _FakeBranch(pr_exists=True)
    rc = drains.author_drain(
        paths,
        trigger_author=lambda *a, **_kw: triggered.append(a),
        branch=branch,
        start_box=_noop_start_box, stop_box=_noop_stop_box, scrub=_noop_scrub,
    )
    assert rc == 0
    assert triggered == []
    assert "start" not in branch.events


def test_author_drain_skips_when_no_work(tmp_path: Path):
    paths, _ = _isolate(tmp_path)
    triggered: list = []
    branch = _FakeBranch()
    rc = drains.author_drain(
        paths,
        trigger_author=lambda *a, **_kw: triggered.append(a),
        branch=branch,
        start_box=_noop_start_box, stop_box=_noop_stop_box, scrub=_noop_scrub,
    )
    assert rc == 0
    assert branch.events == []
    assert triggered == []


def test_author_drain_no_commits_opens_no_pr_but_cleans_up(tmp_path: Path):
    paths, _ = _isolate(tmp_path)
    _seed_curator_findings(paths)
    branch = _FakeBranch(commits=0)
    rc = drains.author_drain(paths, trigger_author=lambda *a, **_kw: None, branch=branch, start_box=_noop_start_box, stop_box=_noop_stop_box, scrub=_noop_scrub)
    assert rc == 0
    assert "finish" in branch.events
    assert branch.events[-1] == "cleanup"


def test_author_drain_singleton_lock_exits_without_work(tmp_path: Path):
    import fcntl

    paths, _ = _isolate(tmp_path)
    _seed_curator_findings(paths)
    paths.author_drain_lock_file.parent.mkdir(parents=True, exist_ok=True)
    holder = paths.author_drain_lock_file.open("a+")
    fcntl.flock(holder.fileno(), fcntl.LOCK_EX)
    try:
        worked: list[str] = []
        rc = drains.author_drain(
            paths,
            trigger_author=lambda *a, **_kw: worked.append("trigger"),
            branch=_FakeBranch(),
            start_box=_noop_start_box, stop_box=_noop_stop_box, scrub=_noop_scrub,
        )
        assert rc == 0
        assert worked == []
    finally:
        fcntl.flock(holder.fileno(), fcntl.LOCK_UN)
        holder.close()




def test_lead_author_drain_runs_lead_author_then_clears_marker(tmp_path: Path):
    paths, _ = _isolate(tmp_path)
    run_dir = tmp_path / "tmprun" / "case-b"
    run_dir.mkdir(parents=True)
    markers.enqueue_for_authoring(run_dir, paths)
    seen: list[tuple[Path, Path]] = []
    branch = _FakeBranch(prefix="lead-author/")
    drains.lead_author_drain(
        paths,
        run_lead_author=lambda wt_paths, rd, **_kw: seen.append((wt_paths.repo_root, rd)),
        branch=branch,
        start_box=_noop_start_box, stop_box=_noop_stop_box, scrub=_noop_scrub,
    )
    assert [rd for _, rd in seen] == [run_dir.resolve()]
    assert str(seen[0][0]).startswith("/tmp/wt-")
    assert not (paths.author_queue_dir / "case-b.json").exists()
    assert branch.events == ["lease-check", "start", "finish", "cleanup"]


def test_lead_author_drain_runs_pitfalls_after_markers(tmp_path: Path):
    paths, _ = _isolate(tmp_path)
    run_dir = tmp_path / "tmprun" / "case-p"
    run_dir.mkdir(parents=True)
    markers.enqueue_for_authoring(run_dir, paths)
    order: list[str] = []
    drains.lead_author_drain(
        paths,
        run_lead_author=lambda wt_paths, rd, **_kw: order.append("marker"),
        run_pitfalls=lambda wt_paths, **_kw: (order.append("pitfalls"), 0)[1],
        branch=_FakeBranch(prefix="lead-author/"),
        start_box=_noop_start_box, stop_box=_noop_stop_box, scrub=_noop_scrub,
    )
    assert order == ["marker", "pitfalls"]


def test_has_lead_author_work_fires_on_pitfalls_threshold(tmp_path: Path, monkeypatch):
    from defender.learning.core import persist
    paths, _ = _isolate(tmp_path)
    assert drains._has_lead_author_work(paths) is False
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "2")
    # Digest-less rows stay two distinct MISTAKES post-#840: an absent diagnosis is not a
    # shared one, so `pitfall_key` keys each such row to itself rather than folding them.
    persist.append_pitfalls(
        [{"pitfall_id": f"r:{i}", "system": "elastic"} for i in range(2)], paths=paths
    )
    assert drains._has_lead_author_work(paths) is True


def test_lead_author_drain_marks_artifact_missing(tmp_path: Path):
    paths, _ = _isolate(tmp_path)
    run_dir = tmp_path / "tmprun" / "case-real"
    run_dir.mkdir(parents=True)
    markers.enqueue_for_authoring(run_dir, paths)
    gone = tmp_path / "tmprun" / "case-gone"
    markers.enqueue_for_authoring(gone, paths)
    seen: list[Path] = []
    drains.lead_author_drain(
        paths,
        run_lead_author=lambda wt_paths, rd, **_kw: seen.append(rd),
        branch=_FakeBranch(prefix="lead-author/"),
        start_box=_noop_start_box, stop_box=_noop_stop_box, scrub=_noop_scrub,
    )
    assert seen == [run_dir.resolve()]
    assert not (paths.author_queue_dir / "case-gone.json").exists()
    failed = paths.author_queue_dir / "failed" / "case-gone.json"
    assert json.loads(failed.read_text())["failed"] == "artifact-missing"


@pytest.mark.parametrize(
    "body",
    [
        "{not valid json",
        "null",
        '["case-broken"]',
        '{"run_id": "case-broken", "run_dir": null}',
        '{"run_id": "case-broken", "run_dir": 7}',
        '{"run_id": "case-broken"}',
    ],
    ids=["torn", "null", "list", "run_dir-null", "run_dir-number", "run_dir-absent"],
)
def test_lead_author_drain_dead_letters_an_unservable_marker(tmp_path: Path, body: str):
    """A marker this pass cannot READ is dead-lettered, never left in the queue.

    Four shapes are unservable. Bytes that do not parse, and bytes that parse to something
    that is not a mapping (`null`, a list) — the second still answers `spec.get("run_dir")`
    with an AttributeError that unwinds the whole drain. Then the two #852 F-18 halves, a
    mapping whose `run_dir` is not a path: a non-string value raised a TypeError out of the
    claim generator — past every dead-letter path below it, so the drain stayed wedged on the
    file until a human removed it — and an ABSENT `run_dir` (the shape this module's own
    `unreadable` dead letter writes) coerced to `Path("")`, i.e. the process CWD, and was
    SERVED against whatever directory the drain happened to be started from.

    Either way, leaving the marker where it was means the reclaim hands it straight back next
    tick, it fails again, and `_has_lead_author_work` stays true on its presence forever, so
    the drain wakes every tick to re-fail on the same file. The healthy sibling in the same
    pass must still be served."""
    paths, _ = _isolate(tmp_path)
    run_dir = tmp_path / "tmprun" / "case-real"
    run_dir.mkdir(parents=True)
    markers.enqueue_for_authoring(run_dir, paths)
    paths.author_queue_dir.mkdir(parents=True, exist_ok=True)
    (paths.author_queue_dir / "case-broken.json").write_text(body, encoding="utf-8")

    seen: list[Path] = []
    drains.lead_author_drain(
        paths,
        run_lead_author=lambda wt_paths, rd, **_kw: seen.append(rd),
        branch=_FakeBranch(prefix="lead-author/"),
        start_box=_noop_start_box, stop_box=_noop_stop_box, scrub=_noop_scrub,
    )

    assert seen == [run_dir.resolve()], "the healthy request in the same pass was not served"
    assert not (paths.author_queue_dir / "case-broken.json").exists()
    assert not (paths.author_queue_dir / "inflight" / "case-broken.json").exists(), \
        "the unservable marker was left claimed — the next tick reclaims and re-fails on it"
    failed = paths.author_queue_dir / "failed" / "case-broken.json"
    assert json.loads(failed.read_text())["failed"].startswith("unreadable")
    assert drains._has_lead_author_work(paths) is False, \
        "the queue still reports work on a request nothing can ever serve"


def test_lead_author_drain_skips_when_lease_held(tmp_path: Path):
    paths, _ = _isolate(tmp_path)
    run_dir = tmp_path / "tmprun" / "case-lease"
    run_dir.mkdir(parents=True)
    markers.enqueue_for_authoring(run_dir, paths)
    seen: list = []
    branch = _FakeBranch(prefix="lead-author/", pr_exists=True)
    rc = drains.lead_author_drain(
        paths, run_lead_author=lambda wt_paths, rd, **_kw: seen.append(rd),
        branch=branch, start_box=_noop_start_box, stop_box=_noop_stop_box, scrub=_noop_scrub,
    )
    assert rc == 0
    assert seen == []
    assert "start" not in branch.events
    assert (paths.author_queue_dir / "case-lease.json").exists()


def test_lead_author_drain_singleton_lock_distinct_from_lessons(tmp_path: Path):
    import fcntl

    paths, _ = _isolate(tmp_path)
    run_dir = tmp_path / "tmprun" / "case-d"
    run_dir.mkdir(parents=True)
    markers.enqueue_for_authoring(run_dir, paths)
    paths.author_drain_lock_file.parent.mkdir(parents=True, exist_ok=True)
    holder = paths.author_drain_lock_file.open("a+")
    fcntl.flock(holder.fileno(), fcntl.LOCK_EX)
    try:
        seen: list = []
        rc = drains.lead_author_drain(
            paths,
            run_lead_author=lambda wt_paths, rd, **_kw: seen.append(rd),
            branch=_FakeBranch(prefix="lead-author/"),
            start_box=_noop_start_box, stop_box=_noop_stop_box, scrub=_noop_scrub,
        )
        assert rc == 0
        assert seen == [run_dir.resolve()]
    finally:
        fcntl.flock(holder.fileno(), fcntl.LOCK_UN)
        holder.close()


def test_lead_author_drain_quarantines_poison_run_dir(tmp_path: Path):
    paths, _ = _isolate(tmp_path)
    poison = tmp_path / "tmprun" / "case-poison"
    poison.mkdir(parents=True)
    good = tmp_path / "tmprun" / "case-good"
    good.mkdir(parents=True)
    markers.enqueue_for_authoring(poison, paths)
    markers.enqueue_for_authoring(good, paths)
    seen: list[Path] = []

    def maybe_boom(wt_paths, rd: Path, *, box=None) -> None:
        if rd.name == "case-poison":
            raise RuntimeError("lead-author blew up")
        seen.append(rd)

    drains.lead_author_drain(
        paths, run_lead_author=maybe_boom, branch=_FakeBranch(prefix="lead-author/"),
        start_box=_noop_start_box, stop_box=_noop_stop_box, scrub=_noop_scrub,
    )
    assert seen == [good.resolve()]
    assert not (paths.author_queue_dir / "case-poison.json").exists()
    failed = paths.author_queue_dir / "failed" / "case-poison.json"
    assert json.loads(failed.read_text())["failed"].startswith("lead-author-error")


def test_lead_author_drain_quarantines_on_nonzero_rc(tmp_path: Path, monkeypatch):
    import defender.learning.leads.lead_author as la

    paths, _ = _isolate(tmp_path)
    run_dir = tmp_path / "tmprun" / "case-rc"
    run_dir.mkdir(parents=True)
    markers.enqueue_for_authoring(run_dir, paths)
    # lint-monkeypatch: ok — drives the real _invoke_lead_author; _run_curator_module
    monkeypatch.setattr(la, "run", lambda rd, paths=None, box=None: 2)  # lint-monkeypatch: ok
    drains.lead_author_drain(paths, branch=_FakeBranch(prefix="lead-author/"), start_box=_noop_start_box, stop_box=_noop_stop_box, scrub=_noop_scrub)
    assert not (paths.author_queue_dir / "case-rc.json").exists()
    failed = paths.author_queue_dir / "failed" / "case-rc.json"
    assert json.loads(failed.read_text())["failed"].startswith("lead-author-error")


def test_lead_author_drain_bounded_retry_then_quarantine(tmp_path: Path, monkeypatch):
    import defender.learning.leads.lead_author as la

    paths, _ = _isolate(tmp_path)
    run_dir = tmp_path / "tmprun" / "case-transient"
    run_dir.mkdir(parents=True)
    markers.enqueue_for_authoring(run_dir, paths)
    monkeypatch.setenv("LEAD_AUTHOR_MAX_RETRIES", "3")

    def boom(rd, paths=None, box=None):
        raise OSError("disk hiccup")

    # lint-monkeypatch: ok — same intentional seam as the rc=2 test above: drives the
    monkeypatch.setattr(la, "run", boom)  # lint-monkeypatch: ok
    marker = paths.author_queue_dir / "case-transient.json"
    failed = paths.author_queue_dir / "failed" / "case-transient.json"

    for expected in (1, 2):
        drains.lead_author_drain(paths, branch=_FakeBranch(prefix="lead-author/"), start_box=_noop_start_box, stop_box=_noop_stop_box, scrub=_noop_scrub)
        assert marker.exists()
        assert json.loads(marker.read_text())["attempts"] == expected
        assert not failed.exists()

    drains.lead_author_drain(paths, branch=_FakeBranch(prefix="lead-author/"), start_box=_noop_start_box, stop_box=_noop_stop_box, scrub=_noop_scrub)
    assert not marker.exists()
    assert json.loads(failed.read_text())["failed"].startswith("transient-exhausted")


def test_lead_author_drain_opens_distinct_lead_author_pr(tmp_path: Path):
    paths, _ = _isolate(tmp_path)
    run_dir = tmp_path / "tmprun" / "case-pr"
    run_dir.mkdir(parents=True)
    markers.enqueue_for_authoring(run_dir, paths)
    _, work = _origin_work(tmp_path)
    forge = _FakeForge(create_ref="https://github.com/o/r/pull/77")
    branch = ab.AuthorBranch(
        forge=forge, repo_root=work, branch_prefix="lead-author/",
        pr_title=drains._lead_author_pr_title, pr_body=drains._lead_author_pr_body,
        worktree_base=tmp_path / "wt",
    )

    def _author(wt_paths, rd, *, box=None):
        f = wt_paths.repo_root / "defender" / "skills" / "note.md"
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text("edit\n")
        _real(wt_paths.repo_root, "add", "-A")
        _real(wt_paths.repo_root, "commit", "-q", "-m", "lead edit")

    rc = drains.lead_author_drain(paths, run_lead_author=_author, branch=branch, start_box=_noop_start_box, stop_box=_noop_stop_box, scrub=_noop_scrub)
    assert rc == 0
    assert forge.open_calls[0]["head"].startswith("lead-author/")
    assert not forge.open_calls[0]["head"].startswith("lessons/")
    assert forge.list_calls == ["lead-author/"]


def test_lead_author_drain_resets_worktree_between_markers(tmp_path: Path):
    wt = tmp_path / "wt"
    catalog = wt / "defender" / "skills" / "gather" / "queries" / "wazuh"
    catalog.mkdir(parents=True)
    (catalog / "auth-events.md").write_text("---\nstatus: established\n---\n")
    _real(wt, "init", "-q", "-b", "main")
    _real(wt, "config", "user.email", "t@e.com")
    _real(wt, "config", "user.name", "T")
    _real(wt, "add", "-A")
    _real(wt, "commit", "-q", "-m", "seed")

    paths = LoopPaths(repo_root=wt, state_dir=tmp_path / "state")
    poison = tmp_path / "runs" / "case-a-poison"
    good = tmp_path / "runs" / "case-b-good"
    poison.mkdir(parents=True)
    good.mkdir(parents=True)
    markers.enqueue_for_authoring(poison, paths)
    markers.enqueue_for_authoring(good, paths)

    clean_at_entry: dict[str, bool] = {}

    def run_lead_author(p, rd: Path, *, box=None) -> None:
        st = _subprocess.run(
            ["git", "-C", str(p.repo_root), "status", "--porcelain"],
            capture_output=True, text=True,
        )
        clean_at_entry[rd.name] = st.stdout.strip() == ""
        if rd.name == "case-a-poison":
            (p.repo_root / "defender" / "skills" / "gather" / "queries"
             / "wazuh" / "auth-events.md").unlink()
            raise RuntimeError("scope-gate boom")

    drains._drain_lead_author_markers(paths, run_lead_author)

    assert clean_at_entry["case-a-poison"] is True
    assert clean_at_entry["case-b-good"] is True
    end = _subprocess.run(["git", "-C", str(wt), "status", "--porcelain"],
                          capture_output=True, text=True)
    assert end.stdout.strip() == ""
    assert (paths.author_queue_dir / "failed" / "case-a-poison.json").exists()
    assert not (paths.author_queue_dir / "case-b-good.json").exists()




def test_enqueue_for_learning_writes_marker(tmp_path: Path):
    paths, _ = _isolate(tmp_path)
    run_dir = tmp_path / "tmprun" / "case-a"
    run_dir.mkdir(parents=True)
    markers.enqueue_for_learning(run_dir, paths)
    spec = json.loads((paths.learn_queue_dir / "case-a.json").read_text())
    assert spec == {"run_id": "case-a", "run_dir": str(run_dir.resolve())}


def test_learn_drain_runs_run_one_renders_and_clears_marker(tmp_path: Path):
    paths, _ = _isolate(tmp_path)
    run_dir = tmp_path / "tmprun" / "case-b"
    run_dir.mkdir(parents=True)
    markers.enqueue_for_learning(run_dir, paths)
    events: list[tuple[str, Path]] = []
    rc = run_cycle.learn_drain(
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
    gone = tmp_path / "tmprun" / "case-gone"
    markers.enqueue_for_learning(gone, paths)
    learned: list[Path] = []
    run_cycle.learn_drain(
        paths,
        run_one_fn=lambda rd: learned.append(rd) or 0,
        render=lambda rd: None,
    )
    assert learned == []
    assert not (paths.learn_queue_dir / "case-gone.json").exists()
    assert not (paths.learn_queue_dir / "inflight" / "case-gone.json").exists()
    failed = paths.learn_queue_dir / "failed" / "case-gone.json"
    assert json.loads(failed.read_text())["failed"] == "artifact-missing"


@pytest.mark.parametrize(
    "body",
    [
        "{not valid json",
        "null",
        '["case-broken"]',
        '{"run_id": "case-broken", "run_dir": null}',
        '{"run_id": "case-broken", "run_dir": 7}',
        '{"run_id": "case-broken"}',
    ],
    ids=["torn", "null", "list", "run_dir-null", "run_dir-number", "run_dir-absent"],
)
def test_learn_drain_dead_letters_an_unservable_marker(tmp_path: Path, body: str):
    """The learn queue dead-letters an unreadable marker, exactly as its sibling does.

    This is the LEARN half of a property that only the lead-author queue had a test for.
    Both queues run the same claim-and-serve protocol and both had the same forever-loop —
    a marker that cannot be read is already claimed, so skipping it leaves it in `inflight/`
    for the next tick's reclaim to hand back and fail on again — but the fix for it was
    hand-carried into two copies and only one of them grew a test. Now that
    `markers.claim_markers` owns the protocol, this pins the shared behaviour from the other
    caller, so a regression in either queue has two chances to be caught rather than one.

    Both unservable shapes: bytes that do not parse, and bytes that parse to something that
    is not a mapping (`null`, a list) — the second still answers `spec.get("run_dir")` with
    an AttributeError that unwinds the whole drain past every dead-letter path. The healthy
    sibling in the same pass must still be served.
    """
    paths, _ = _isolate(tmp_path)
    run_dir = tmp_path / "tmprun" / "case-real"
    run_dir.mkdir(parents=True)
    markers.enqueue_for_learning(run_dir, paths)
    paths.learn_queue_dir.mkdir(parents=True, exist_ok=True)
    (paths.learn_queue_dir / "case-broken.json").write_text(body, encoding="utf-8")

    learned: list[Path] = []
    rc = run_cycle.learn_drain(
        paths,
        run_one_fn=lambda rd: learned.append(rd) or 0,
        render=lambda rd: None,
    )

    assert rc == 0
    assert learned == [run_dir.resolve()], "the healthy request in the same pass was not served"
    assert not (paths.learn_queue_dir / "case-broken.json").exists()
    assert not (paths.learn_queue_dir / "inflight" / "case-broken.json").exists(), \
        "the unservable marker was left claimed — the next tick reclaims and re-fails on it"
    failed = paths.learn_queue_dir / "failed" / "case-broken.json"
    assert json.loads(failed.read_text())["failed"].startswith("unreadable")
    assert json.loads(failed.read_text())["run_id"] == "case-broken", \
        "the learn queue's dead letter must be keyed on run_id, not the curation queue's case_id"


def test_learn_drain_quarantines_run_one_error(tmp_path: Path):
    paths, _ = _isolate(tmp_path)
    run_dir = tmp_path / "tmprun" / "case-poison"
    run_dir.mkdir(parents=True)
    markers.enqueue_for_learning(run_dir, paths)

    def boom(_rd: Path) -> int:
        raise RuntimeError("run_one blew up")

    rendered: list[Path] = []
    run_cycle.learn_drain(paths, run_one_fn=boom, render=lambda rd: rendered.append(rd))
    assert rendered == []
    assert not (paths.learn_queue_dir / "inflight" / "case-poison.json").exists()
    failed = paths.learn_queue_dir / "failed" / "case-poison.json"
    assert json.loads(failed.read_text())["failed"].startswith("run-one-error")


def test_learn_drain_reclaims_a_marker_already_in_inflight(tmp_path: Path):
    """#791 P1: a marker sitting in `inflight/` is reclaimed rather than left forever — the
    prior behaviour (never touching it again) is exactly the orphaned-claim bug #791 closes,
    since nothing here distinguishes a crashed drain's leftover from one still being served
    (no lock, no age-out) and the queue's own count line must not read zero while it exists."""
    paths, _ = _isolate(tmp_path)
    run_dir = tmp_path / "tmprun" / "case-claimed"
    run_dir.mkdir(parents=True)
    markers.enqueue_for_learning(run_dir, paths)
    inflight = paths.learn_queue_dir / "inflight"
    inflight.mkdir(parents=True)
    (paths.learn_queue_dir / "case-claimed.json").rename(inflight / "case-claimed.json")
    learned: list[Path] = []
    run_cycle.learn_drain(
        paths,
        run_one_fn=lambda rd: learned.append(rd) or 0,
        render=lambda rd: None,
    )
    assert learned == [run_dir]
    assert not (inflight / "case-claimed.json").exists()


def test_learn_drain_skips_marker_lost_to_claim_race(tmp_path: Path, monkeypatch):
    paths, _ = _isolate(tmp_path)
    run_dir = tmp_path / "tmprun" / "case-race"
    run_dir.mkdir(parents=True)
    markers.enqueue_for_learning(run_dir, paths)

    def racing_replace(src, dst):
        Path(src).unlink()
        raise FileNotFoundError(src)

    # The claim itself moved into `markers.claim_markers` — both drains share it now — so
    # the race is injected where the `os.replace` actually happens.
    monkeypatch.setattr(markers.os, "replace", racing_replace)
    learned: list[Path] = []
    run_cycle.learn_drain(
        paths,
        run_one_fn=lambda rd: learned.append(rd) or 0,
        render=lambda rd: None,
    )
    assert learned == []


def test_learn_drain_threads_paths_into_default_run_one(tmp_path: Path, monkeypatch):
    paths, _ = _isolate(tmp_path)
    run_dir = tmp_path / "tmprun" / "case-paths"
    run_dir.mkdir(parents=True)
    markers.enqueue_for_learning(run_dir, paths)
    seen: dict = {}

    def fake_run_one(rd, *, paths=None, agents=None):
        seen["rd"] = rd
        seen["paths"] = paths
        return 0

    monkeypatch.setattr(run_cycle, "run_one", fake_run_one)
    run_cycle.learn_drain(paths, render=lambda rd: None)
    assert seen["rd"] == run_dir.resolve()
    assert seen["paths"] is paths


def test_learn_drain_each_queued_marker_processed_once(tmp_path: Path):
    paths, _ = _isolate(tmp_path)
    runs = []
    for name in ("case-1", "case-2", "case-3"):
        rd = tmp_path / "tmprun" / name
        rd.mkdir(parents=True)
        markers.enqueue_for_learning(rd, paths)
        runs.append(rd.resolve())
    learned: list[Path] = []
    run_cycle.learn_drain(
        paths,
        run_one_fn=lambda rd: learned.append(rd) or 0,
        render=lambda rd: None,
    )
    assert sorted(learned) == sorted(runs)
    learned2: list[Path] = []
    run_cycle.learn_drain(
        paths,
        run_one_fn=lambda rd: learned2.append(rd) or 0,
        render=lambda rd: None,
    )
    assert learned2 == []




def test_source_run_dir_absolute_when_state_dir_out_of_repo(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    state = tmp_path / "state"
    paths = LoopPaths(repo_root=repo, state_dir=state)
    assert paths.runs_dir == state / "runs"

    learning_run_dir = paths.runs_dir / "case-x"
    src = persist._source_run_dir(learning_run_dir, paths.repo_root)
    assert src == str(learning_run_dir) + "/"
    assert paths.repo_root / src.rstrip("/") == learning_run_dir


def test_append_findings_survives_out_of_repo_state_dir(tmp_path: Path):
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



import subprocess as _subprocess  # noqa: E402

from defender.learning.author import branch as ab  # type: ignore[import-not-found]  # noqa: E402
from defender.learning.author import forge as _forge  # type: ignore[import-not-found]  # noqa: E402


class _FakeForge:

    def __init__(self, *, pr_rows=None, create_ref="https://pr/1", raises=False,
                 list_raises=False):
        self.pr_rows = pr_rows or []
        self.create_ref = create_ref
        self.raises = raises
        self.list_raises = list_raises
        self.list_calls: list[str] = []
        self.head_calls: list[str] = []
        self.open_calls: list[dict] = []

    def list_open_prs(self, head_prefix: str) -> list[dict]:
        self.list_calls.append(head_prefix)
        if self.list_raises:
            raise _forge.ForgeError("gh boom")
        return self.pr_rows

    def list_prs_for_head(self, head: str) -> list[dict]:
        self.head_calls.append(head)
        if self.list_raises:
            raise _forge.ForgeError("gh boom")
        return [r for r in self.pr_rows if str(r.get("headRefName", "")) == head]

    def open_pr(self, *, base: str, head: str, title: str, body: str) -> str:
        self.open_calls.append({"base": base, "head": head, "title": title, "body": body})
        if self.raises:
            raise _forge.ForgeError("gh boom")
        return self.create_ref


def _real(cwd: Path, *args: str):
    return _subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, check=True)


def _origin_work(tmp_path: Path, *, lessons: dict[str, str] | None = None) -> tuple[Path, Path]:
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
    assert forge.list_calls == ["lessons/"]


def test_author_branch_lease_false_when_no_matching_pr():
    forge = _FakeForge(pr_rows=[{"number": 2, "headRefName": "feature/x"}])
    assert ab.AuthorBranch(forge=forge).open_pr_exists() is False


def test_author_branch_lease_keyed_on_prefix():
    forge = _FakeForge(pr_rows=[{"number": 3, "headRefName": "lessons/abc"}])
    b = ab.AuthorBranch(forge=forge, branch_prefix="lead-author/")
    assert b.open_pr_exists() is False
    assert forge.list_calls == ["lead-author/"]


def test_author_branch_start_adds_worktree_off_origin_main(tmp_path: Path):
    _, work = _origin_work(tmp_path)
    b = ab.AuthorBranch(forge=_FakeForge(), repo_root=work, worktree_base=tmp_path / "wt")
    wt = b.start_batch("abc123")
    assert wt == tmp_path / "wt" / "lessons-abc123"
    assert wt.is_dir()
    assert _real(wt, "rev-parse", "--abbrev-ref", "HEAD").stdout.strip() == "lessons/abc123"
    assert (_real(wt, "rev-parse", "HEAD").stdout.strip()
            == _real(work, "rev-parse", "origin/main").stdout.strip())


def test_author_branch_start_cleans_up_partial_worktree_on_add_failure(tmp_path: Path):
    _, work = _origin_work(tmp_path)
    wt_base = tmp_path / "wt"
    occupied = wt_base / "lessons-abc123"
    occupied.mkdir(parents=True)
    (occupied / "in_the_way.txt").write_text("x")
    b = ab.AuthorBranch(forge=_FakeForge(), repo_root=work, worktree_base=wt_base)
    with pytest.raises(ab.BranchError):
        b.start_batch("abc123")
    assert "lessons-abc123" not in _real(work, "worktree", "list").stdout


def test_author_branch_finish_no_commits_returns_none(tmp_path: Path):
    origin, work = _origin_work(tmp_path)
    forge = _FakeForge()
    b = ab.AuthorBranch(forge=forge, repo_root=work, worktree_base=tmp_path / "wt")
    wt = b.start_batch("abc123")
    assert b.finish_batch("abc123", wt) is None
    assert forge.open_calls == []
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
    assert not wt.exists()


def test_author_branch_worktree_lifecycle_real_git(tmp_path: Path):
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
    assert _real(work, "rev-parse", "HEAD").stdout.strip() == head_before




def test_author_branch_revert_lesson_pr_removes_and_opens_pr(tmp_path: Path):
    _, work = _origin_work(tmp_path, lessons={"defender/lessons/bad.md": "bad lesson\n"})
    forge = _FakeForge(create_ref="https://github.com/o/r/pull/42")
    b = ab.AuthorBranch(forge=forge, repo_root=work, worktree_base=tmp_path / "wt")
    ref_before = _real(work, "rev-parse", "--abbrev-ref", "HEAD").stdout.strip()
    assert b.revert_lesson_pr("defender/lessons/bad.md", "bad") == "https://github.com/o/r/pull/42"
    assert forge.open_calls[0]["head"] == "lessons/revert-bad"
    assert forge.open_calls[0]["title"] == "revert lesson: bad"
    assert _real(work, "ls-remote", "--heads", "origin", "lessons/revert-bad").stdout.strip()
    assert _real(work, "rev-parse", "--abbrev-ref", "HEAD").stdout.strip() == ref_before
    assert not (tmp_path / "wt" / "lessons-revert-bad").exists()


def test_author_branch_revert_succeeds_with_dirty_dev_tree(tmp_path: Path):
    _, work = _origin_work(tmp_path, lessons={"defender/lessons/bad.md": "bad\n"})
    (work / "dirty.txt").write_text("uncommitted\n")
    b = ab.AuthorBranch(forge=_FakeForge(create_ref="https://pr/1"),
                        repo_root=work, worktree_base=tmp_path / "wt")
    head_before = _real(work, "rev-parse", "HEAD").stdout.strip()
    assert b.revert_lesson_pr("defender/lessons/bad.md", "bad") == "https://pr/1"
    assert (work / "dirty.txt").read_text() == "uncommitted\n"
    assert _real(work, "rev-parse", "HEAD").stdout.strip() == head_before


def test_author_branch_revert_reclaims_leftover_nonworktree_dir(tmp_path: Path):
    _, work = _origin_work(tmp_path, lessons={"defender/lessons/bad.md": "bad\n"})
    wt_base = tmp_path / "wt"
    stale = wt_base / "lessons-revert-bad"
    stale.mkdir(parents=True)
    (stale / "leftover.txt").write_text("crashed-revert debris\n")
    b = ab.AuthorBranch(forge=_FakeForge(create_ref="https://pr/9"),
                        repo_root=work, worktree_base=wt_base)
    assert b.revert_lesson_pr("defender/lessons/bad.md", "bad") == "https://pr/9"
    assert _real(work, "ls-remote", "--heads", "origin", "lessons/revert-bad").stdout.strip()


def test_author_branch_revert_refuses_missing_lesson_on_base(tmp_path: Path):
    _, work = _origin_work(tmp_path)
    b = ab.AuthorBranch(forge=_FakeForge(), repo_root=work, worktree_base=tmp_path / "wt")
    head_before = _real(work, "rev-parse", "HEAD").stdout.strip()
    with pytest.raises(ab.BranchError):
        b.revert_lesson_pr("defender/lessons/ghost.md", "ghost")
    assert _real(work, "rev-parse", "HEAD").stdout.strip() == head_before
    assert not _real(work, "branch", "--list", "lessons/revert-ghost").stdout.strip()


def test_author_branch_revert_returns_existing_open_pr_idempotently(tmp_path: Path):
    _, work = _origin_work(tmp_path, lessons={"defender/lessons/bad.md": "bad\n"})
    forge = _FakeForge(
        pr_rows=[{"number": 3, "headRefName": "lessons/revert-bad", "url": "https://pr/existing"}],
        create_ref="https://pr/new",
    )
    b = ab.AuthorBranch(forge=forge, repo_root=work, worktree_base=tmp_path / "wt")
    assert b.revert_lesson_pr("defender/lessons/bad.md", "bad") == "https://pr/existing"
    assert forge.open_calls == []
    assert forge.head_calls == ["lessons/revert-bad"]
    assert forge.list_calls == []
    assert not _real(work, "ls-remote", "--heads", "origin", "lessons/revert-bad").stdout.strip()


def test_author_branch_revert_ignores_unrelated_open_lessons_pr(tmp_path: Path):
    _, work = _origin_work(tmp_path, lessons={"defender/lessons/bad.md": "bad\n"})
    forge = _FakeForge(
        pr_rows=[{"number": 5, "headRefName": "lessons/abc123batch", "url": "https://pr/batch"}],
        create_ref="https://pr/1",
    )
    b = ab.AuthorBranch(forge=forge, repo_root=work, worktree_base=tmp_path / "wt")
    assert b.revert_lesson_pr("defender/lessons/bad.md", "bad") == "https://pr/1"
    assert forge.open_calls[0]["head"] == "lessons/revert-bad"
    assert _real(work, "ls-remote", "--heads", "origin", "lessons/revert-bad").stdout.strip()


def test_author_branch_revert_fails_fast_on_stranded_remote_branch(tmp_path: Path):
    _, work = _origin_work(tmp_path, lessons={"defender/lessons/bad.md": "bad\n"})
    _real(work, "checkout", "-q", "-b", "tmp-div", "origin/main")
    (work / "divergent.txt").write_text("stranded prior revert\n")
    _real(work, "add", "-A")
    _real(work, "commit", "-q", "-m", "divergent")
    _real(work, "push", "-q", "origin", "tmp-div:lessons/revert-bad")
    _real(work, "checkout", "-q", "main")
    _real(work, "branch", "-q", "-D", "tmp-div")
    b = ab.AuthorBranch(forge=_FakeForge(pr_rows=[]), repo_root=work, worktree_base=tmp_path / "wt")
    with pytest.raises(ab.BranchError, match="stale revert branch"):
        b.revert_lesson_pr("defender/lessons/bad.md", "bad")


def test_author_branch_revert_wraps_forge_list_error_as_branch_error(tmp_path: Path):
    _, work = _origin_work(tmp_path, lessons={"defender/lessons/bad.md": "bad\n"})
    forge = _FakeForge(list_raises=True)
    b = ab.AuthorBranch(forge=forge, repo_root=work, worktree_base=tmp_path / "wt")
    with pytest.raises(ab.BranchError, match="gh boom"):
        b.revert_lesson_pr("defender/lessons/bad.md", "bad")
    assert forge.open_calls == []
    assert not _real(work, "ls-remote", "--heads", "origin", "lessons/revert-bad").stdout.strip()


def test_author_branch_revert_idempotent_return_falls_back_to_head_without_url(tmp_path: Path):
    _, work = _origin_work(tmp_path, lessons={"defender/lessons/bad.md": "bad\n"})
    forge = _FakeForge(pr_rows=[{"number": 8, "headRefName": "lessons/revert-bad"}])
    b = ab.AuthorBranch(forge=forge, repo_root=work, worktree_base=tmp_path / "wt")
    assert b.revert_lesson_pr("defender/lessons/bad.md", "bad") == "lessons/revert-bad"
    assert forge.open_calls == []
    assert not _real(work, "ls-remote", "--heads", "origin", "lessons/revert-bad").stdout.strip()


def test_revert_cli_holds_drain_lock_and_calls_through(tmp_path: Path):
    from defender.learning.ops import revert_lesson as rl  # type: ignore[import-not-found]
    paths = LoopPaths(repo_root=tmp_path)
    _, work = _origin_work(tmp_path, lessons={"defender/lessons/bad.md": "bad\n"})
    forge = _FakeForge(create_ref="https://pr/7")
    b = ab.AuthorBranch(forge=forge, repo_root=work, worktree_base=tmp_path / "wt")
    assert rl.revert("bad", branch=b, paths=paths) == 0
    assert forge.open_calls[0]["head"] == "lessons/revert-bad"


def test_revert_cli_skips_when_drain_lock_held(tmp_path: Path):
    import fcntl as _fcntl

    from defender.learning.ops import revert_lesson as rl  # type: ignore[import-not-found]
    paths = LoopPaths(repo_root=tmp_path)
    lock = paths.author_drain_lock_file
    lock.parent.mkdir(parents=True, exist_ok=True)
    holder = lock.open("a+")
    _fcntl.flock(holder.fileno(), _fcntl.LOCK_EX | _fcntl.LOCK_NB)
    try:
        forge = _FakeForge()
        b = ab.AuthorBranch(forge=forge, repo_root=tmp_path)
        assert rl.revert("bad", branch=b, paths=paths) == 3
        assert forge.open_calls == []
    finally:
        _fcntl.flock(holder.fileno(), _fcntl.LOCK_UN)
        holder.close()




def _make_run_dir(tmp_path: Path, *, disposition="benign", with_payload=True) -> Path:
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


def test_build_comparison_joins_sample_and_invlang(tmp_path: Path):
    run = _make_run_dir(tmp_path)
    comps = comparison.build_comparison(run, companion=_COMPANION)
    assert len(comps) == 1
    c = comps[0]
    assert c.lead_id == "l-001"
    assert not hasattr(c, "projected_events")
    assert "dev.dana" in c.real_sample
    assert c.resolutions
    assert c.resolutions[0]["after"] == "--"
    assert c.authz
    assert c.authz[0]["verdict"] == "authorized"


def test_real_sample_text_keeps_values_where_lead_sample_text_scrubs(tmp_path: Path):
    run = _make_run_dir(tmp_path)
    lead = lr.joined(run)[0]
    real = comparison.real_sample_text(lead)
    redacted = oracle_mod.lead_sample_text(lead)
    assert "dev.dana" in real
    assert "dev.dana" not in redacted
    assert "<user>" in redacted


def test_build_comparison_monitor_run_is_empty(tmp_path: Path):
    run = tmp_path / "run"
    run.mkdir()
    (run / "alert.json").write_text("{}")
    comps = comparison.build_comparison(run)
    assert comps == []
    assert "monitor" in comparison.render_manifest(comps)


def test_build_comparison_missing_payload_degrades_sample(tmp_path: Path):
    run = _make_run_dir(tmp_path, with_payload=False)
    comps = comparison.build_comparison(run)
    assert comps[0].real_sample.startswith("(")


def test_parse_investigation_companion_degrades_on_garbage(tmp_path: Path):
    run = tmp_path / "run"
    run.mkdir()
    (run / "investigation.md").write_text("just prose, no invlang fences")
    assert comparison.parse_investigation_companion(run) == {}
    assert comparison.parse_investigation_companion(tmp_path / "nope") == {}


def test_write_comparison_files_one_per_lead(tmp_path: Path):
    run = _make_run_dir(tmp_path)
    comps = comparison.build_comparison(run, companion=_COMPANION)
    out = tmp_path / "cmp"
    paths = comparison.write_comparison_files(comps, out, run / "gather_raw")
    assert [p.name for p in paths] == ["l-001.md"]
    txt = paths[0].read_text()
    assert "## Evidence" in txt
    assert "## Defender reasoning" in txt
    assert "gather_raw/l-001/0.json" in txt
    assert "scripted automation" in txt
    for line in txt.splitlines():
        assert not line.rstrip().endswith("\\"), f"line-continuation in a taught command: {line!r}"
    for line in txt.splitlines():
        if "cat " in line and "defender-sql" in line:
            operand = line.split("cat ", 1)[1].split(" |", 1)[0]
            assert operand.startswith("/"), f"relative operand in a taught command: {operand!r}"


def test_comparison_file_names_every_payload_seq(tmp_path: Path):
    run = _make_run_dir(tmp_path)
    rows = [json.loads(line) for line in (run / "executed_queries.jsonl").read_text().splitlines()]
    for seq in (1, 2):
        (run / "gather_raw" / "l-001" / f"{seq}.json").write_text("[]")
        rows.append({**rows[0], "seq": seq, "payload_path": f"gather_raw/l-001/{seq}.json"})
    (run / "executed_queries.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows))

    comps = comparison.build_comparison(run, companion=_COMPANION)
    txt = comparison.write_comparison_files(comps, tmp_path / "cmp", run / "gather_raw")[0].read_text()
    for seq in (0, 1, 2):
        assert str(run / "gather_raw" / "l-001" / f"{seq}.json") in txt, f"seq {seq} unnamed"


def test_render_synthesis_includes_reasoning_and_conclude():
    out = comparison.render_synthesis(_COMPANION)
    assert "h-mal" in out
    assert "scripted automation" in out
    assert "benign" in out
    assert comparison.render_synthesis({}).startswith("(")


def test_build_judge_invocation_assembles_grounded_call(tmp_path: Path):
    run = _make_run_dir(tmp_path)
    story = tmp_path / "actor_story.md"
    story.write_text("Attack story\nGoal\nBypass\n")
    lrd = tmp_path / "lrd"
    lrd.mkdir()

    inv = subagents.build_judge_invocation(run, story, lrd)

    assert (lrd / "comparison" / "l-001.md") in inv.comparison_paths
    assert set(inv.add_dirs) == {run / "gather_raw", lrd / "comparison"}
    assert re.search(r"<run-[0-9a-f]+-comparison_files>", inv.user_text)
    assert "l-001.md" in inv.user_text
    assert "disposition: benign" in inv.user_text
    assert "scripted automation" not in inv.user_text
    assert "comparison" in inv.user_text.lower()


def test_invoke_judge_benign_is_grounded(tmp_path: Path):
    run = _make_run_dir(tmp_path, disposition="malicious")
    story = tmp_path / "actor_benign_story.md"
    story.write_text("1. Routine-activity story\n2. Benign grounding\n")
    lrd = tmp_path / "lrd"
    lrd.mkdir()

    captured: dict = {}

    def _fake_judge_fn(wiring, *, user, scope, **kwargs):
        captured.update(
            prompt_path=wiring.prompt_path, model=wiring.model, label=wiring.label, user=user,
            add_dir=scope.add_dir, closed_ticket_read=scope.closed_ticket_read,
        )
        return "outcome: survived\ndefender_findings: []\n"

    out = subagents.invoke_judge(
        directions.BENIGN_WIRING, run, story, lrd,
        judge_fn=_fake_judge_fn, box=None,
    )

    assert out.startswith("outcome:")
    assert (lrd / "comparison_benign" / "l-001.md").is_file()
    assert set(captured["add_dir"]) == {run / "gather_raw", lrd / "comparison_benign"}
    assert captured["closed_ticket_read"] is True
    assert captured["prompt_path"] == directions.BENIGN_WIRING.prompt_path
    assert captured["model"] == directions.BENIGN_WIRING.model
    assert captured["label"] == "judge-benign"
    assert "<investigation>" not in captured["user"]
    assert "<lead_sequence>" not in captured["user"]
    assert "disposition: malicious" in captured["user"]
    assert re.search(r"<run-[0-9a-f]+-comparison_files>", captured["user"])
