"""#705 — the wire log after `_seen` dies, and the consumers the census missed.

O24 deletes `RequestLogger._seen`'s delta encoding and O25 replaces
`json.dumps(..., default=str)` with an encoder that fails loudly. G1 REFUTED O26's census:
the wire log has THREE application consumers, not zero — `observe.write_trace` (in
process), `runtime.html` through the FILE in the visualizer subprocess, and
`_pydantic_stage.py:109/115` as CONTROL FLOW — and G3 (executed) refuted O24 as an
independent change: `build_transcript` has no dedup and no seen-set, so under a verbatim
dump one 6-request run's transcript went from 12 rows / 5 tool-results to 42 rows / 15,
against a ground truth of 5. O24 and O26 therefore ship together, which is why the
projection-move demands live beside these.

R13 settles `compaction_dryrun`'s migration: dedupe by WIRE POSITION and keep the reader on
`llm_requests.jsonl`. The invariant being preserved is the SAVINGS FIGURE — migrating to
the store would change both the ordering key the script sorts on and the usage arithmetic
it sums, making the survival demand's own sentence false by construction.
"""
from __future__ import annotations

import json

from defender.tests._by_path import WORKTREE, load_module

import pytest

pytest.importorskip("pydantic_ai")

from pydantic_ai.messages import (  # noqa: E402
    ModelMessagesTypeAdapter,
    ModelResponse,
    TextPart,
)

from defender.runtime import observe
from defender.tests._session_store_705 import (
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
    """Import `scripts/testing/compaction_dryrun.py` by path.

    NOTE, carried from the demand: this script sits at the REPO ROOT, outside
    `specGraph.codeRoots`, so nothing mechanical checks the demands bound to it (G21/F13)."""
    return load_module(WORKTREE / "scripts" / "testing" / "compaction_dryrun.py",
                       name="compaction_dryrun_705")


# ==========================================================================
# the encoding
# ==========================================================================

def test_wire_log_dumps_the_request_list_verbatim_with_no_delta_encoding(tmp_path):
    """Across a SECOND fold the wire log holds the full request list actually sent for
    that request, with no re-baselining and no request omitted because the history did not
    shrink below a cursor.

    The second fold is the case the demand names: finding 2(b) — a rewrite that does not
    shrink below `_seen` is never logged at all — is INVISIBLE on the first fold. A test
    that stopped at one fold would be green on the bug it exists to catch."""
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
    record, so attacker-shaped content cannot enter the log as a silent `str()`.

    `observe.py:72`'s `default=str` is what O25 replaces. The encoding is PINNED, not just
    the posture: adv:PO4 found the encoder's own behaviour is decided by an unstated
    `ensure_ascii` — with the default a lone surrogate survives end to end; with `False`
    the same content raises `UnicodeEncodeError` at the bind."""
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
    """Two `RequestLogger` constructions sharing a `(run_id, trace_name)` key do not
    silently clobber each other: the second either preserves the first's lines or fails
    loud, and nothing is lost without a signal.

    G24 (read) established the hazard as it stands: `RequestLogger.__init__` opens mode
    `'w'`, so EVERY construction truncates. G5 established three construction sites
    (`driver.py:391`, `_pydantic_stage.py:95`, `run_arms.py:129`). The boundary's own
    evidence note names this truncation as "the sharing hazard a store-backed rewrite must
    not inherit", and no demand pinned it before."""
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


# ==========================================================================
# the two-digest join — R7's restatement of O22
# ==========================================================================

@pytest.mark.e2e
def test_wire_sha_joins_a_store_row_to_its_wire_log_line(tmp_path):
    """Each request row in the store and its wire-log line are JOINABLE on
    `(session_id, run_step)`, each carries its own digest of what IT holds, and both
    digests are recorded — so a `_clean_message_history` merge that changes what went out
    is recorded rather than merely unrecorded.

    R7 restates O22 after `auth:P1` (executed) REFUTED the equality reading: THREE
    transforms sit between the processor returning and the bytes leaving —
    `fill_run_metadata` mutating `messages[-1]` in place, `_clean_message_history` merging
    the post-fold pair, and `model.prepare_messages` reshaping again — and digests differed
    in BOTH the fold and no-fold cases. A test asserting digest EQUALITY is red against
    every correct implementation, so equality is asserted nowhere here; the join and the
    two recorded digests are the contract."""
    ss = store_mod()
    run_dir = materialize(tmp_path, GOLDEN)
    opened: list = []
    replay = ReplayFn([
        Turn(tool_calls=[("read_file", {"path": str(run_dir / "alert.json")})]),
        Turn(text="done"),
    ])
    drive(run_dir, run_id="join", salt=SALT, main=replay,
          store_factory=store_factory(tmp_path, sink=opened))

    store = opened[0]
    rows = sql(store, "SELECT session_id, run_step, wire_sha FROM message "
                      "WHERE kind = 'request' AND wire_sha IS NOT NULL ORDER BY run_step")
    assert rows, "no request row carries a renderer digest"

    lines = [r for r in jsonl(run_dir / "llm_requests.jsonl") if r.get("kind") == "response"]
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


# ==========================================================================
# the consumers the census missed — survival
# ==========================================================================

def test_pydantic_stage_still_classifies_an_empty_final_response(tmp_path):
    """A learning stage's empty-final-response classification survives the delta encoding's
    removal unchanged: the same output produces the same verdict when the classifier reads
    a VERBATIM log as when it reads a delta-encoded one, for the empty string, for
    `U+00A0`, and for `U+200B` alike.

    `_pydantic_stage` is a NAMED exemption whose read survives as CONTROL FLOW (FK13/R17,
    3/3). adv:PO6 (executed) BREACHED the classifier in both directions —
    U+00A0/3000/2028/1680/0085/001C-1F read as EMPTY while U+200B/FEFF/NUL read as
    NON-EMPTY — and found the premise's own framing wrong: BOTH call sites raise
    `RunUnprocessable`, so a test asserting "it gates RunUnprocessable" is
    non-discriminating. The steerability is filed separately under R9; what this PR owes is
    that removing `_seen` changes NOTHING about the verdict."""
    from defender.learning.pipeline import _pydantic_stage

    outputs = {"empty": "", "nbsp": " ", "zwsp": "​", "text": "a real answer"}
    verdicts: dict[str, tuple[bool, bool]] = {}

    for label, content in outputs.items():
        response = ModelResponse(parts=[TextPart(content=content)])
        dumped = ModelMessagesTypeAdapter.dump_python([response], mode="json")[0]

        delta_records = [{"kind": "response", "agent_id": "stage", "message": dumped}]
        verbatim_records = [
            {"kind": "request", "agent_id": "stage",
             "message": ModelMessagesTypeAdapter.dump_python([user_request("go")],
                                                             mode="json")[0]},
            {"kind": "response", "agent_id": "stage", "message": dumped},
        ]
        verdicts[label] = (
            _pydantic_stage._last_response_is_empty_text(delta_records),
            _pydantic_stage._last_response_is_empty_text(verbatim_records),
        )

    for label, (delta, verbatim) in verdicts.items():
        assert delta == verbatim, (
            f"{label}: the verdict changed when the log stopped delta-encoding — the "
            f"control-flow read did not survive")
    assert verdicts["text"][0] is False, (
        "positive control: real text must not classify as empty, or every comparison "
        "above is trivially equal")
    assert verdicts["empty"][0] is True


def test_compaction_dryrun_reader_survives_the_undelta_d_log(tmp_path):
    """`compaction_dryrun` over a log written WITHOUT delta encoding reconstructs each
    request's history once rather than re-appending the whole prefix every turn: the
    per-step `full_chars` it computes matches the real history size at that step.

    X4 read the shape: `dry_run` does `history.append(msg)` for each `kind=='request'`
    record and calls `compact(history, …)` on the accumulated list, so under M6's verbatim
    dump it re-appends the whole prefix each turn — finding 2(a) reproduced BY THE FIX.
    R13's answer is a WIRE-POSITION dedupe, keeping the reader on `llm_requests.jsonl`."""
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


def test_compaction_dryrun_still_runs_end_to_end(tmp_path):
    """`scripts/testing/compaction_dryrun.py` runs to completion over a recorded run and
    reports the SAME mechanical savings figure it reports today — the savings figure is the
    invariant R13 preserves.

    G4 corrects O28's survival list: `payload_chars` is NOT a consumer (its only hit is the
    JSON output key `"history_payload_chars"` at :188); the real surface is `compact`,
    `FrozenState`, `CompactionStep`, `apply_writes` and `history_chars`. The script sits at
    the repo root, OUTSIDE `specGraph.codeRoots`, so nothing mechanical checks this demand.
    """
    dryrun = _load_dryrun()
    for symbol in ("compact", "FrozenState", "CompactionStep", "apply_writes",
                   "history_chars"):
        assert hasattr(dryrun.C, symbol), f"{symbol} retired out from under the dry run"
    source = (REPO_ROOT / "scripts" / "testing" / "compaction_dryrun.py").read_text()
    assert "C.payload_chars" not in source, (
        "G4: payload_chars is NOT a consumer — a survival demand written against it would "
        "pin a relationship that does not exist")

    log_path = tmp_path / "llm_requests.jsonl"
    logger = observe.RequestLogger(log_path)
    prefix = [user_request("orientation")]
    for turn in range(4):
        prefix = prefix + [tool_call_response(tool_call_id=f"t{turn}"),
                           tool_return_request(tool_call_id=f"t{turn}")]
        logger.log(request_messages=prefix, response=text_response(f"r{turn}"),
                   run_step=turn, agent_id="main")
    logger.close()

    records = dryrun._load_main_records(log_path, "main")
    metrics = dryrun.dry_run(records)
    savings = sum(m.full_chars - m.comp_chars for m in metrics)
    assert metrics, "the dry run produced no steps"
    assert savings >= 0, savings
    assert dryrun.dry_run(dryrun._load_main_records(log_path, "main")) == metrics, (
        "the savings figure must be a function of the log, not of read order")
