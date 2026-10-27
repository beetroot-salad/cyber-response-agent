"""#705 wire log: dumped verbatim (no delta encoding), the encoder fails loudly on a non-JSON-native value, concurrent constructions under one key do not clobber each other, the wire sha joins a store row to its log line, and the compaction dry-run reader still works on the verbatim log."""
from __future__ import annotations

import json

from defender.tests.support.shared.contracts._by_path import WORKTREE, load_module

import pytest

from defender.tests.support.runtime.state._1255_view import model_path

pytest.importorskip("pydantic_ai")

from pydantic_ai.messages import (  # noqa: E402
    ModelMessagesTypeAdapter,
)

from defender.investigation import observe
from defender.records import RunPaths
from defender.tests.support.storage._session_store_705 import (
    jsonl,
    sql,
    store_factory,
    store_mod,
    text_response,
    tool_call_response,
    tool_return_request,
    user_request,
)
from defender.tests.e2e._replay_harness import (
    GOLDEN,
    ReplayFn,
    Turn,
    drive,
    materialize,
)

REPO_ROOT = WORKTREE
SALT = "0011223344556677"


def _load_dryrun():
    """Import `tooling/testing/compaction_dryrun.py` by path.

    NOTE, carried from the demand: this script sits at the REPO ROOT, outside
    `specGraph.codeRoots`, so nothing mechanical checks the demands bound to it (G21/F13)."""
    return load_module(WORKTREE / "tooling" / "testing" / "compaction_dryrun.py",
                       name="compaction_dryrun_705")


# the encoding

def test_wire_log_dumps_the_request_list_verbatim_with_no_delta_encoding(tmp_path):
    log_path = tmp_path / "llm_requests.jsonl"
    logger = observe.RequestLogger(log_path)

    prefix = [user_request("orientation")]
    turn_lists = []
    for turn in range(4):
        # turn 2 is a fold (the list SHRINKS); turn 3 is a second fold
        if turn in (2, 3):
            request_list = [user_request("orientation"),
                            user_request(f"FRONTIER {turn}")]
        else:
            request_list = prefix + [tool_call_response(tool_call_id=f"t{turn}"),
                                     tool_return_request(tool_call_id=f"t{turn}")]
        turn_lists.append(request_list)
        logger.log(request_messages=request_list, response=text_response(f"r{turn}"),
                   run_step=turn, agent_id="main")
    logger.close()

    records = jsonl(log_path)
    per_turn: list[list[dict]] = []
    current: list[dict] = []
    for rec in records:
        if rec.get("kind") == "response":
            per_turn.append(current)
            current = []
        else:
            current.append(rec)

    assert len(per_turn) == 4, per_turn
    for turn, (logged, sent) in enumerate(zip(per_turn, turn_lists, strict=True)):
        expected = ModelMessagesTypeAdapter.dump_python(sent, mode="json")
        assert [r["message"] for r in logged] == expected, (
            f"turn {turn}: the log must hold the full list actually sent, verbatim")
    assert per_turn[3], "finding 2(b): the SECOND fold's request was omitted entirely"


def test_wire_log_encoder_fails_loudly_on_a_non_json_native_value(tmp_path):
    """A value the encoder cannot represent raises rather than being stringified into the
    record, so attacker-shaped content cannot enter the log as a silent `str()`."""
    class NotJson:
        pass

    with pytest.raises((TypeError, ValueError)):
        observe.encode_wire_record({"event_type": "message", "x": NotJson()})

    encoded = observe.encode_wire_record({"event_type": "message", "kind": "response",
                                          "message": {"parts": []}})
    assert json.loads(encoded) == {"event_type": "message", "kind": "response",
                                   "message": {"parts": []}}, (
        "positive control: an ordinary record still encodes")
    assert observe.WIRE_LOG_ENSURE_ASCII is True, (
        "the encoding must be stated: with ensure_ascii=False a lone surrogate raises "
        "UnicodeEncodeError, turning attacker text into a run-halting availability bug "
        "(adv:PO4)")
    assert "NotJson" not in encoded


def test_two_wire_log_constructions_under_one_key_do_not_silently_clobber_each_other(tmp_path):
    path = tmp_path / "llm_requests.jsonl"
    first = observe.RequestLogger(path)
    first.log(request_messages=[user_request("first construction")],
              response=text_response("one"), run_step=0, agent_id="main")
    first.close()
    before = jsonl(path)
    assert before, "the first construction wrote nothing — the fixture is broken"

    try:
        second = observe.RequestLogger(path)
    except FileExistsError:
        return  # failing loud on a second construction discharges the demand
    second.log(request_messages=[user_request("second construction")],
               response=text_response("two"), run_step=0, agent_id="main")
    second.close()

    after = jsonl(path)
    assert after[:len(before)] == before, (
        "the second construction silently truncated the first's lines")
    assert len(after) > len(before)


# the two-digest join — R7's restatement of O22

@pytest.mark.e2e
def test_wire_sha_joins_a_store_row_to_its_wire_log_line(tmp_path):
    ss = store_mod()
    run_dir = materialize(tmp_path, GOLDEN, run_id='join')
    opened: list = []
    replay = ReplayFn([
        Turn(tool_calls=[("read_file", {"path": model_path(run_dir / "alert.json", run_dir=run_dir)})]),
        Turn(text="done"),
    ])
    drive(run_dir, run_id="join", main=replay,
          store_factory=store_factory(tmp_path, sink=opened))

    store = opened[0]
    rows = sql(store, "SELECT session_id, run_step, wire_sha FROM message "
                      "WHERE kind = 'request' AND wire_sha IS NOT NULL ORDER BY run_step")
    assert rows, "no request row carries a renderer digest"

    lines = [r for r in jsonl(RunPaths(run_dir).wire_log) if r.get("kind") == "response"]
    by_key = {(r.get("session_id"), r.get("run_step")): r for r in lines}
    assert len(by_key) == len(lines), "the join key must be unique per wire line"

    for session_id, run_step, renderer_sha in rows:
        line = by_key.get((session_id, run_step))
        assert line is not None, (
            f"store row ({session_id}, {run_step}) has no wire line to join to")
        assert line.get("wire_sha"), (
            "the wire side must record its OWN digest — one digest cannot name a drift "
            "that happens after it is taken (auth:P1)")
        assert renderer_sha, "the renderer's stamp must survive (O4 forbids updating it)"

    assert ss.SCHEMA_VERSION is not None  # the join is a store contract, not a log one


# the consumers the census missed — survival

def test_compaction_dryrun_reader_survives_the_undelta_d_log(tmp_path):
    dryrun = _load_dryrun()
    log_path = tmp_path / "llm_requests.jsonl"
    logger = observe.RequestLogger(log_path)
    lists = []
    prefix = [user_request("orientation")]
    for turn in range(3):
        prefix = prefix + [tool_call_response(tool_call_id=f"t{turn}"),
                           tool_return_request(tool_call_id=f"t{turn}")]
        lists.append(list(prefix))
        logger.log(request_messages=prefix, response=text_response(f"r{turn}"),
                   run_step=turn, agent_id="main")
    logger.close()

    records = dryrun._load_main_records(log_path, "main")
    metrics = dryrun.dry_run(records)
    assert len(metrics) == 3, metrics

    growth = [m.full_chars for m in metrics]
    assert growth == sorted(growth), growth
    assert growth[-1] < sum(len(json.dumps(
        ModelMessagesTypeAdapter.dump_python(lst, mode="json"))) for lst in lists), (
        "the reader re-appended the whole prefix each turn — finding 2(a) reproduced by "
        "the fix (X4)")
