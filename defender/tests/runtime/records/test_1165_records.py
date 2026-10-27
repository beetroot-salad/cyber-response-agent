"""#1165 O3–O5: store operations, strict source reads and rooted host mutations."""
from __future__ import annotations

import json
import os

import pytest

from defender import _io
from defender.records import _artifact_schema
from defender.investigation.branch import BranchError
from defender.tests.support.shared.contracts import _spec1077 as S
from defender.tests.support.runtime.records._1165_records import run_at, writes


@pytest.mark.parametrize(("group", "name"), [
    (group, name) for group, names in S.GROUP_MEMBERS.items() for name in names
])
def test_generic_records_expose_only_their_added_store_operations(tmp_path, group, name):
    """O3: generic read operations apply everywhere; new mutation verbs are per member."""
    record = S.member(run_at(tmp_path), group, name, *S.member_args(name))
    for reader in ("read", "read_result", "read_bytes", "read_rows"):
        assert callable(getattr(record, reader, None)), (name, reader)
    expected = {
        "payloads": {"ensure_parent"}, "gather_summaries": {"ensure_parent"},
        "alert_record": {"replace"}, "queries": {"seed"}, "investigation": {"seed"}, "ticket_write": {"delete"},
        "wire_log": {"append_text", "start_stream"},
        "policy_denials": {"append_text", "start_stream"},
        "review_trace": {"append_text"},
    }.get(name, set())
    added = {verb for verb in ("create", "seed", "delete", "append_text", "start_stream", "replace", "ensure_parent")
             if callable(getattr(record, verb, None))}
    assert added == expected
    if name == "wire_log":
        assert not hasattr(record, "logger_factory"), "the run sink must not construct path loggers"


@pytest.mark.parametrize("reader", ["read_result", "read_bytes", "read_rows"])
def test_reads_distinguish_absent_empty_and_refused_without_creating_files(tmp_path, reader):
    """O4: absent is not refused and empty is present; reading has no mutation side effect."""
    run = run_at(tmp_path)
    record = run.tables.queries
    before = S.snapshot(tmp_path)
    answer = getattr(record, reader)()
    if reader == "read_rows":
        rows, malformed, answer = answer
        assert (rows, malformed) == ([], 0)
    assert answer.absent
    assert answer.reason is None
    assert answer.refused_by is None
    assert S.snapshot(tmp_path) == before

    record.path.write_bytes(b"")
    answer = getattr(record, reader)()
    if reader == "read_rows":
        rows, malformed, answer = answer
        assert (rows, malformed) == ([], 0)
    assert not answer.absent
    assert answer.reason is None
    assert (answer.data if reader == "read_bytes" else answer.text) in (b"", "")

    record.path.unlink()
    record.path.mkdir()
    answer = getattr(record, reader)()
    if reader == "read_rows":
        rows, malformed, answer = answer
        assert (rows, malformed) == ([], 0)
    assert not answer.absent
    assert answer.reason
    assert answer.refused_by == _io.REFUSED_NOT_FILE


@pytest.mark.parametrize("reader", ["read_result", "read_bytes", "read_rows"])
@pytest.mark.parametrize("plant", ["outside", "inside", "cycle", "file-parent"])
def test_tree_and_address_resolution_oserrors_are_read_refusals(tmp_path, reader, plant):
    """O4: a planted composed parent is a refused result, including owner resolution errors."""
    run = run_at(tmp_path)
    record = run.tables.payloads("lead", 1)
    path = record.path
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "lead").mkdir()
    (outside / "lead" / path.name).write_bytes(b"outside secret")
    parent = run.run_dir / "gather_raw"
    if plant == "file-parent":
        parent.write_text("not a folder", encoding="utf-8")
    elif plant == "cycle":
        parent.symlink_to(parent)
    else:
        target = outside if plant == "outside" else run.run_dir / "real-raw"
        target.mkdir(exist_ok=True)
        (target / "lead").mkdir(exist_ok=True)
        (target / "lead" / path.name).write_bytes(b"must not follow")
        parent.symlink_to(target, target_is_directory=True)
    answer = getattr(record, reader)()
    if reader == "read_rows":
        rows, malformed, answer = answer
        assert (rows, malformed) == ([], 0)
    assert not answer.absent
    assert answer.reason
    assert answer.refused_by
    assert (answer.data if reader == "read_bytes" else answer.text) is None

    parent.unlink()
    path.parent.mkdir(parents=True)
    path.write_bytes(b'{"seq": 1}\n')
    answer = getattr(record, reader)()
    if reader == "read_rows":
        rows, malformed, answer = answer
        assert (rows, malformed) == ([{"seq": 1}], 0)
    assert not answer.absent
    assert answer.reason is None
    assert (answer.data if reader == "read_bytes" else answer.text) == (
        b'{"seq": 1}\n' if reader == "read_bytes" else '{"seq": 1}\n')


@pytest.mark.parametrize("reader", ["read_result", "read_bytes", "read_rows"])
@pytest.mark.parametrize("plant", ["symlink", "hardlink"])
def test_leaf_aliases_are_refused_without_exposing_the_target(tmp_path, reader, plant):
    """O4: generic reads retain the bound core's leaf-alias refusal and valid-file control."""
    record = run_at(tmp_path).tables.queries
    target = tmp_path / "leaf-target"
    target.write_bytes(b'{"secret":"must not follow"}\n')
    if plant == "symlink":
        record.path.symlink_to(target)
    else:
        os.link(target, record.path)
    answer = getattr(record, reader)()
    if reader == "read_rows":
        rows, malformed, answer = answer
        assert (rows, malformed) == ([], 0)
    assert not answer.absent
    assert answer.refused_by == _io.REFUSED_ALIAS
    assert (answer.data if reader == "read_bytes" else answer.text) is None
    assert record.read() is None
    record.path.unlink()
    record.path.write_bytes(b'{"seq":1}\n')
    answer = getattr(record, reader)()
    if reader == "read_rows":
        rows, malformed, answer = answer
        assert (rows, malformed) == ([{"seq": 1}], 0)
    assert answer.reason is None
    assert record.read() == '{"seq":1}\n'


def test_payload_write_preserves_opaque_bytes_through_the_real_handle(tmp_path):
    """O3/O4: a recognized payload can contain invalid UTF-8 without recoding or parsing."""
    io = S.RecordingIo()
    record = run_at(tmp_path, io=io).tables.payloads("lead", 1)
    raw = b"\xff\x00\r\nnot JSON\x80"
    record.write(raw)
    assert record.path.read_bytes() == raw
    assert writes(io, record.path)[-1]["text"] == raw
    assert record.read_bytes().data == raw


@pytest.mark.parametrize("reader", ["read_result", "read_bytes", "read_rows"])
def test_bad_address_values_propagate_instead_of_becoming_read_refusals(tmp_path, reader):
    """O4: an addressing bug is ValueError, unlike unreadable filesystem contents."""
    run = run_at(tmp_path)
    with pytest.raises(ValueError, match="lead_id"):
        getattr(run.tables.payloads("../escape", 1), reader)()
    with pytest.raises(ValueError, match="runs base"):
        getattr(S.Run().at(run.run_dir).facts.run_end, reader)()


def test_bytes_are_opaque_text_is_strict_and_jsonl_keeps_existing_tolerance(tmp_path):
    """O4: invalid UTF-8 survives byte reads; strict text and tolerant JSONL stay distinct."""
    record = run_at(tmp_path).tables.queries
    raw = b'{"seq": 1}\r\n\nnot json\n[]\n{"text": "\xff"}\n'
    record.path.write_bytes(raw)
    assert record.read_bytes().data == raw
    refused = record.read_result()
    assert not refused.absent
    assert refused.text is None
    assert refused.refused_by == _io.REFUSED_UNDECODABLE
    replaced = record.read_result(errors="replace")
    assert replaced.text == '{"seq": 1}\n\nnot json\n[]\n{"text": "\ufffd"}\n'
    rows, malformed, result = record.read_rows()
    assert rows == [{"seq": 1}, {"text": "\ufffd"}]
    assert malformed == 2
    assert result.reason is None
    assert result.text == replaced.text
    with pytest.raises(ValueError, match="errors"):
        record.read_result(errors="ignore")


@pytest.mark.parametrize("scaffold", ["absent", "empty"])
@pytest.mark.parametrize("rows", [[], [{"z": "café", "a": 2}, {"seq": 0, "params": {"tuple": [1, 2]}}]])
def test_query_seed_serializes_a_snapshot_then_normal_append_continues(tmp_path, scaffold, rows):
    """O2/O3: seed replaces absent/empty views, including a present empty snapshot."""
    io = S.RecordingIo()
    run = run_at(tmp_path, io=io)
    record = run.tables.queries
    if scaffold == "empty":
        record.path.write_bytes(b"")
    # The caller has already admitted the sibling and seeded its investigation.
    run.documents.investigation.path.write_text("# inherited investigation\n", encoding="utf-8")
    record.seed(rows)
    expected = "".join(json.dumps(row) + "\n" for row in rows).encode("utf-8")
    assert record.path.is_file()
    assert record.path.read_bytes() == expected
    calls = writes(io, record.path)
    assert len(calls) == 1
    assert calls[0]["mode"] == "replace"
    assert calls[0]["text"] == expected.decode("utf-8")
    assert not {"write_guarded", "append_jsonl", "rooted_delete"} & set(io.ops)

    row = {"later": "café", "seq": 3}
    record.append([row])
    assert record.path.read_bytes() == expected + (json.dumps(row) + "\n").encode("utf-8")
    assert [call["mode"] for call in writes(io, record.path)] == ["replace", "append"]


def test_query_seed_can_replace_a_prior_view_under_caller_owned_freshness(tmp_path):
    """O3/O4: generic seed has no extra content policy or whole-Run freshness check."""
    io = S.RecordingIo()
    run = run_at(tmp_path, io=io)
    record = run.tables.queries
    prior = b'{"old": "view"}\n'
    record.path.write_bytes(prior)
    run.documents.investigation.path.write_text("# already seeded\n", encoding="utf-8")
    record.seed([{"sparse": "snapshot", "first_key": 1}])
    assert record.path.read_bytes() == b'{"sparse": "snapshot", "first_key": 1}\n'
    record.seed([])
    assert record.path.is_file()
    assert record.path.read_bytes() == b""
    assert [call["mode"] for call in writes(io, record.path)] == ["replace", "replace"]


@pytest.mark.parametrize(("member", "args"), [("wire_log", ()), ("policy_denials", ())])
def test_stream_start_replaces_and_empty_append_recreates_without_reencoding(tmp_path, member, args):
    """O3: stream initialization truncates; even an empty append opens or recreates eagerly."""
    io = S.RecordingIo()
    run = run_at(tmp_path, io=io)
    group = "tables" if member == "policy_denials" else "observability"
    record = S.member(run, group, member, *args)
    record.path.parent.mkdir(parents=True, exist_ok=True)
    record.path.write_bytes(b"old content\n")
    encoded = '{"text": "caf\\u00e9 \\ud800"}\n'
    record.start_stream("")
    assert record.path.read_bytes() == b""
    record.append_text(encoded)
    assert record.path.read_bytes() == encoded.encode("ascii")
    record.path.unlink()
    record.append_text("")
    assert record.path.read_bytes() == b""
    assert [(call["mode"], call["text"]) for call in writes(io, record.path)] == [
        ("replace", ""), ("append", encoded), ("append", "")]


def test_run_end_replaces_instead_of_becoming_a_write_once_fact(tmp_path):
    """O3: repeated finalization replaces its record through the generic rooted writer."""
    io = S.RecordingIo()
    run = run_at(tmp_path, io=io)
    run.facts.run_end.write('{"exit_class":"failed"}\n')
    run.facts.run_end.write('{"exit_class":"success"}\n')
    assert run.facts.run_end.path.read_text() == '{"exit_class":"success"}\n'
    assert [call["mode"] for call in writes(io, run.facts.run_end.path)] == ["replace", "replace"]


def test_lead_claim_record_keeps_exclusive_create_semantics(tmp_path):
    """O3: the existing one-time lead record keeps its collision behavior."""
    io = S.RecordingIo()
    run = run_at(tmp_path, io=io)
    claim = run.tables.leads("lead")
    claim.write('{"goal":"first"}\n')
    with pytest.raises(FileExistsError):
        claim.write('{"goal":"stolen"}\n')
    assert claim.path.read_text() == '{"goal":"first"}\n'
    assert all(call["mode"] == "create" for call in writes(io, claim.path))


def test_investigation_seed_validates_against_itself_and_refuses_a_used_sibling(tmp_path):
    """O3/O4: inherited unfenced headers are a baseline, never a new schema violation."""
    record = run_at(tmp_path).documents.investigation
    inherited = ':H hypotheses\nlegacy prose\n'
    assert _artifact_schema.validate_artifact("investigation.md", inherited, inherited) is None
    assert _artifact_schema.validate_artifact("investigation.md", inherited, None) is not None
    record.seed(inherited)
    assert record.path.read_text() == inherited
    with pytest.raises((OSError, ValueError, BranchError)):
        record.seed("replacement\n")
    assert record.path.read_text() == inherited


@pytest.mark.parametrize("occupied", ["queries", "payloads", "gather_summaries"])
def test_investigation_seed_preserves_fresh_sibling_refusal_for_other_inherited_evidence(tmp_path, occupied):
    """O3/O4: a seed cannot interleave its document with evidence already in a sibling."""
    run = run_at(tmp_path)
    artifacts = {"queries": run.tables.queries,
                 "payloads": run.tables.payloads("lead", 1),
                 "gather_summaries": run.documents.gather_summaries("lead")}
    path = artifacts[occupied].path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"existing evidence\n")
    with pytest.raises((OSError, ValueError, BranchError)):
        run.documents.investigation.seed("# inherited prose\n")
    assert path.read_bytes() == b"existing evidence\n"
    assert not run.documents.investigation.path.exists()
    # Empty scaffolding carries no inherited evidence in the current fresh-sibling rule.
    path.unlink()
    if occupied == "payloads":
        path.parent.rmdir()
    run.documents.investigation.path.write_bytes(b"")
    run.documents.investigation.seed("# inherited prose\n")
    assert run.documents.investigation.path.read_text() == "# inherited prose\n"


@pytest.mark.parametrize("operation", ["write", "seed"])
def test_investigation_operations_keep_the_actual_schema_gate(tmp_path, operation):
    """O4: seeding does not become a caller-selectable schema bypass."""
    record = run_at(tmp_path).documents.investigation
    for invalid in ("x" * (_artifact_schema.INVESTIGATION_FILE_MAX + 1), "lone \ud800",
                    "```invlang\n:H hypotheses\n```\n"):
        with pytest.raises(ValueError, match="investigation"):
            getattr(record, operation)(invalid)
        assert not record.path.exists()
    getattr(record, operation)("# acceptable prose\n")
    assert record.path.read_text() == "# acceptable prose\n"


def test_ordinary_investigation_write_keeps_committed_history(tmp_path):
    """O4: ordinary writes still validate append-only content against existing contents."""
    record = run_at(tmp_path).documents.investigation
    committed = '```invlang\n:V prologue.vertices\n```\n'
    assert _artifact_schema.validate_artifact("investigation.md", committed, None) is None
    record.write(committed)
    with pytest.raises(ValueError, match="append-only"):
        record.write("# removed committed fence\n")
    assert record.path.read_text() == committed
    record.write(committed + "# new prose\n")
    assert record.path.read_text() == committed + "# new prose\n"


def test_report_schema_checks_proposed_text_without_reading_existing_baseline(tmp_path):
    """O4: report writes validate against None, so undecodable old content can be replaced."""
    io = S.RecordingIo()
    record = run_at(tmp_path, io=io).documents.report
    record.path.write_bytes(b"\xff")
    valid = S.report_text("reviewed conclusion\n")
    record.write(valid)
    assert record.path.read_text() == valid
    assert "rooted_read" not in io.ops, "report validation must not inspect its old document"
    with pytest.raises(ValueError, match="report"):
        record.write("no disposition frontmatter\n")
    assert record.path.read_text() == valid


def test_ticket_delete_succeeds_when_missing_and_unlinks_only_a_leaf_alias(tmp_path):
    """O3/O5: receipt cleanup has missing_ok semantics and safely removes a leaf symlink."""
    run = run_at(tmp_path)
    record = run.observability.ticket_write
    record.delete()
    record.write('{"ticket":"abc"}\n')
    record.delete()
    assert not record.path.exists()
    target = tmp_path / "external-receipt"
    target.write_bytes(b"untouched")
    record.path.symlink_to(target)
    record.delete()
    assert not record.path.is_symlink()
    assert target.read_bytes() == b"untouched"


@pytest.mark.parametrize("operation", ["write", "start_stream", "append_text"])
def test_mutations_refuse_parent_swapped_after_addressing_with_valid_folder_control(tmp_path, operation):
    """O5: a parent swapped after resolution still refuses at the actual rooted mutation."""
    io = S.RecordingIo()
    run = run_at(tmp_path, io=io)
    record = (run.tables.payloads("lead", 1) if operation == "write"
              else run.observability.wire_log)
    path = record.path
    parent = run.run_dir / ("gather_raw" if operation == "write" else "wire_logs")
    saved = run.run_dir / "saved-parent"
    outside = tmp_path / "outside"
    outside.mkdir()
    if operation == "write":
        (outside / "lead").mkdir()

    def plant(_path):
        parent.rename(saved)
        parent.symlink_to(outside, target_is_directory=True)

    io.fault = S.IoFault(before_write=plant)
    with pytest.raises(OSError):  # noqa: PT011 — exact OS errno/message is not the alias contract
        getattr(record, operation)("preserved\n")
    assert not (outside / path.relative_to(parent)).exists()
    assert not (saved / path.relative_to(parent)).exists()
    parent.unlink()
    saved.rename(parent)
    io.fault = S.IoFault()
    getattr(record, operation)("preserved\n")
    assert path.read_text() == "preserved\n"


def test_host_owned_root_alias_is_accepted_for_record_mutations(tmp_path):
    """O5 positive control: the root spelling may follow its host-owned alias."""
    directory = tmp_path / "actual"
    directory.mkdir()
    alias = tmp_path / "root-alias"
    alias.symlink_to(directory, target_is_directory=True)
    run = S.Run().at(alias)
    run.observability.wire_log.start_stream("first\n")
    run.observability.wire_log.append_text("second\n")
    assert (directory / "wire_logs" / "llm_requests.jsonl").read_bytes() == b"first\nsecond\n"
