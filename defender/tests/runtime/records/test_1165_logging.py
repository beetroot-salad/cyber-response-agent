"""#1165 O3/O4: Run-backed logger lifecycle and exact wire/review bytes."""
from __future__ import annotations

import json
import os

import pytest
from pydantic_ai.messages import ModelRequest, ModelResponse, TextPart, UserPromptPart

from defender.investigation import challenge_gate, observe
from defender.tests.support.shared.contracts import _spec1077 as S
from defender.tests.support.runtime.records._1165_records import run_at, writes


def _log(logger, text="reply"):
    logger.log(request_messages=[ModelRequest(parts=[UserPromptPart(content="question")])],
               response=ModelResponse(parts=[TextPart(content=text)]), agent_id="main")


def _deny(logger):
    return logger.log_policy_denial(role="gather", system="elastic", verb="query",
                                   call_id="call-1", params={"secret": "not raw params"})


def test_from_record_is_eager_truncates_first_open_and_routes_encoded_rows(tmp_path):
    """O3/O4: first construction creates an empty wire record then appends exact encoding."""
    io = S.RecordingIo()
    run = run_at(tmp_path, io=io)
    record = run.observability.wire_log
    record.path.parent.mkdir()
    record.path.write_bytes(b"old process contents\n")
    logger = observe.RequestLogger.from_record(record)
    try:
        assert record.path.read_bytes() == b""
        assert [(call["mode"], call["text"]) for call in writes(io, record.path)] == [
            ("replace", "")]
        _log(logger, "caf\u00e9 \ud800")
        encoded = "".join(json.dumps(row, ensure_ascii=True) + "\n" for row in logger.messages)
        assert record.path.read_bytes() == encoded.encode("ascii")
        calls = writes(io, record.path)
        assert [call["mode"] for call in calls] == ["replace", "append", "append"]
        assert [call["text"] for call in calls[1:]] == encoded.splitlines(keepends=True)
        assert logger.n_requests == 1
        assert [row["seq"] for row in logger.messages] == [0, 1]
        assert logger.messages[-1]["message"]["parts"][0]["content"] == "caf\u00e9 \ud800"
    finally:
        logger.close()


def test_record_logger_writes_to_current_record_instead_of_a_held_open_stream(tmp_path):
    """O3: replacing the leaf between events cannot strand subsequent writes on an old fd."""
    record = run_at(tmp_path).observability.wire_log
    logger = observe.RequestLogger.from_record(record)
    old = record.path.with_name("previous.jsonl")
    try:
        _log(logger, "first")
        record.path.rename(old)
        record.path.write_bytes(b"current\n")
        _log(logger, "second")
        expected = b"current\n" + b"".join(
            (json.dumps(row, ensure_ascii=True) + "\n").encode("ascii")
            for row in logger.messages[2:])
        assert record.path.read_bytes() == expected
        assert b"second" not in old.read_bytes()
        assert b"first" in old.read_bytes()
    finally:
        logger.close()


def test_duplicate_active_identity_includes_a_host_owned_root_alias(tmp_path):
    """O4: two Run spellings of one sink cannot become simultaneous writers."""
    run = run_at(tmp_path)
    alias = tmp_path / "same-run"
    alias.symlink_to(run.run_dir, target_is_directory=True)
    same = S.Run().at(alias).observability.wire_log
    logger = observe.RequestLogger.from_record(run.observability.wire_log)
    try:
        with pytest.raises(FileExistsError):
            observe.RequestLogger.from_record(same)
        # Path-scoped legacy consumers participate in the same identity registry too.
        with pytest.raises(FileExistsError):
            observe.RequestLogger(run.observability.wire_log.path)
        _log(logger)
        assert len(run.observability.wire_log.path.read_text().splitlines()) == 2
    finally:
        logger.close()
    reopened = observe.RequestLogger.from_record(same)
    reopened.close()
    assert len(same.path.read_text().splitlines()) == 2


@pytest.mark.parametrize("missing", [False, True])
def test_closed_record_logger_reopens_with_an_eager_empty_append(tmp_path, missing):
    """O4: reopening appends, recreates absent files immediately, and never clobbers rows."""
    io = S.RecordingIo()
    record = run_at(tmp_path, io=io).observability.wire_log
    logger = observe.RequestLogger.from_record(record)
    _log(logger)
    original = record.path.read_bytes()
    logger.close()
    if missing:
        record.path.unlink()
    reopened = observe.RequestLogger.from_record(record)
    try:
        assert record.path.read_bytes() == (b"" if missing else original)
        assert writes(io, record.path)[-1]["mode"] == "append"
        assert writes(io, record.path)[-1]["text"] == ""
    finally:
        reopened.close()


@pytest.mark.parametrize("reopen", [False, True])
def test_alias_initialization_refuses_eagerly_and_retry_preserves_open_mode(tmp_path, reopen):
    """O4: planted first/reopen initialization refuses eagerly and preserves retry mode."""
    io = S.RecordingIo()
    record = run_at(tmp_path, io=io).observability.wire_log
    path = record.path
    if reopen:
        logger = observe.RequestLogger.from_record(record)
        _log(logger)
        logger.close()
        path.unlink()
    else:
        path.parent.mkdir()
    target = path.with_name("external-target")
    target.write_bytes(b"target untouched\n")
    path.symlink_to(target)
    with pytest.raises(OSError):  # noqa: PT011 — leaf refusal is OS-dependent
        observe.RequestLogger.from_record(record)
    assert target.read_bytes() == b"target untouched\n"
    path.unlink()
    path.write_bytes(b"retry marker\n")
    logger = observe.RequestLogger.from_record(record)
    logger.close()
    assert path.read_bytes() == (b"retry marker\n" if reopen else b"")
    assert writes(io, path)[-1]["mode"] == ("append" if reopen else "replace")


@pytest.mark.parametrize("reopen", [False, True])
def test_initialization_fault_never_registers_an_active_or_new_ever_opened_identity(tmp_path, reopen):
    """O4: a same-identity failed open cannot consume first-open mode or block its retry."""
    io = S.RecordingIo()
    record = run_at(tmp_path, io=io).observability.wire_log
    record.path.parent.mkdir()
    if reopen:
        logger = observe.RequestLogger.from_record(record)
        logger.close()
    record.path.write_bytes(b"retry marker\n")
    io.fault = S.IoFault(fail_on=("rooted_write",), error=OSError("initialize failed"))
    with pytest.raises(OSError, match="initialize failed"):
        observe.RequestLogger.from_record(record)
    assert record.path.read_bytes() == b"retry marker\n"
    io.fault = S.IoFault()
    logger = observe.RequestLogger.from_record(record)
    logger.close()
    assert record.path.read_bytes() == (b"retry marker\n" if reopen else b"")
    assert writes(io, record.path)[-1]["mode"] == ("append" if reopen else "replace")


def test_record_write_failure_propagates_and_close_releases_identity(tmp_path):
    """O4: wire faults are loud; close forbids later writes and permits another writer."""
    io = S.RecordingIo()
    record = run_at(tmp_path, io=io).observability.wire_log
    logger = observe.RequestLogger.from_record(record)
    io.fault = S.IoFault(fail_on=("rooted_write",), error=OSError("disk fault"))
    with pytest.raises(OSError, match="disk fault"):
        _log(logger)
    assert record.path.read_bytes() == b""
    logger.close()
    with pytest.raises(ValueError, match="closed"):
        _deny(logger)
    logger.log_budget_refusal(tool_name="query")  # existing suppressor still applies
    io.fault = S.IoFault()
    reopened = observe.RequestLogger.from_record(record)
    try:
        _log(reopened)
        assert len(record.path.read_text().splitlines()) == 2
    finally:
        reopened.close()


def test_legacy_stream_close_failure_still_closes_logger_and_releases_identity(tmp_path):
    """O4: a real failed file close cannot leave an active logger identity behind."""
    path = tmp_path / "learning.jsonl"
    logger = observe.RequestLogger(path)
    # The existing path logger's held fd is a legacy seam; invalidate it immediately before
    # close so TextIOWrapper's close meets EBADF rather than a policy-bearing fake stream.
    os.close(logger._fh.fileno())
    logger.close()
    with pytest.raises(ValueError, match="closed"):
        _deny(logger)
    reopened = observe.RequestLogger(path)
    try:
        _log(reopened)
        assert len(path.read_text().splitlines()) == 2
    finally:
        reopened.close()


def test_denial_sink_is_lazy_shared_and_initial_fault_logs_once_with_cached_null(tmp_path, caplog):
    """O4: denial initialization failure caches a null sink; it does not alter denials."""
    io = S.RecordingIo()
    run = run_at(tmp_path, io=io)
    path = run.tables.policy_denials.path
    assert not path.exists()
    assert writes(io, path) == []
    io.fault = S.IoFault(fail_on=("rooted_write",), error=OSError("initial denial sink failure"))
    first = observe.denial_logger(run)
    try:
        first_row = _deny(first)
        assert first_row["event_type"] == observe.POLICY_DENIAL_EVENT_TYPE
        initial_calls = len(writes(io, path))
        assert initial_calls == 1
        second = observe.denial_logger(run)
        assert second is first
        _deny(second)
        assert len(writes(io, path)) == initial_calls
        assert len([record for record in caplog.records
                    if "could not be opened" in record.getMessage()]) == 1
        assert not path.exists()
    finally:
        first.close()


def test_denial_later_append_fault_propagates_instead_of_switching_to_null(tmp_path, caplog):
    """O4: lazy fallback applies to initialization only; a subsequent append fault is loud."""
    io = S.RecordingIo()
    run = run_at(tmp_path, io=io)
    logger = observe.denial_logger(run)
    try:
        row = _deny(logger)
        assert json.loads(run.tables.policy_denials.path.read_text()) == row
        io.fault = S.IoFault(fail_on=("rooted_write",), error=OSError("later append failure"))
        with pytest.raises(OSError, match="later append failure"):
            _deny(logger)
        assert not [record for record in caplog.records if "could not be opened" in record.getMessage()]
        assert observe.denial_logger(run) is logger
    finally:
        logger.close()


@pytest.mark.parametrize("reply", ["raw caf\u00e9\nsecond line", '{"verdict":"caf\\u00e9"}\n'])
def test_review_row_and_raw_reply_use_one_byte_faithful_record_append(tmp_path, reply):
    """O3/O4: review keeps its row-shaped reply predicate and atomic row/reply append."""
    io = S.RecordingIo()
    run = run_at(tmp_path, io=io)
    row = {"stage": "review", "text": "caf\u00e9 \ud800"}
    challenge_gate._write_trace_row(run, "support", 2, row, raw_reply=reply)
    path = run.observability.review_trace("support").path
    payload = {"round": 2, **row}
    if reply.startswith("{"):
        payload["raw_reply"] = reply
        expected = json.dumps(payload) + "\n"
    else:
        expected = json.dumps(payload) + "\n" + reply + "\n"
    assert path.read_bytes() == expected.encode("utf-8")
    calls = writes(io, path)
    assert len(calls) == 1
    assert calls[0]["mode"] == "append"
    assert calls[0]["text"] == expected


def test_review_append_fault_propagates_instead_of_observability_swallowing(tmp_path):
    """O4: review text append retains the existing effective write failure."""
    io = S.RecordingIo(S.IoFault(fail_on=("rooted_write",), error=OSError("review disk fault")))
    run = run_at(tmp_path, io=io)
    with pytest.raises(OSError, match="review disk fault"):
        challenge_gate._write_trace_row(run, "support", 1, {"stage": "review"})
    assert not run.observability.review_trace("support").path.exists()
    assert run.partial_failures == ()
