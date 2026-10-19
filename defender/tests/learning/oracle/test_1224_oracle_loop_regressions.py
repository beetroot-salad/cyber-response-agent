"""Regressions for the #1224 oracle loop found in PR #1232 review: turn/deadline handling, frozen
forged rows, accounting and pricing, pre-flight worlds, pre-branch calls, esql forging checks."""
from __future__ import annotations

from defender.tests.support.shared.contracts._spec1077 import fixture_run as _fixture_run_1165

from defender.tests.support.shared.contracts._spec1077 import fixture_run as _run_handle_1165

import os
import re
import shutil
import subprocess
import threading
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from defender.learning.branch.estate import oracle as oracle_mod
from defender.learning.branch.estate.checks import CheckStore, RealData, check_submission
from defender.runtime.verbs import CALL_DELIVERY, CallDelivery
from defender.box._oracle import OracleBox, stop_oracle_box
from defender.box._spec import BoxSpec, _DockerTransport
from defender.tests.learning.oracle.live_contracts import _spec1224 as S

ALICE = S.query_params("user:alice")
ALICE_ROWS = S.default_calls()[0].payload
BOB = S.query_params("user:bob")
BOB_ROWS = {"rows": [{"user": "bob", "event_id": "e-200", "action": "logon", "host": "web-2",
                      "ts": "2026-03-01T09:00:00Z"}]}
LOOKUP_ALICE = {"entity": "alice", "risk": "low", "record_id": "r-0001"}


class ProviderLikeModel:
    """A model double that refuses a conversation as a provider does (HTTP 400, "tool_use ids
    were found without tool_result blocks")."""

    def __init__(self, *replies: list[tuple[str, dict]],
                 name: str = S.double_model_name("provider-like")) -> None:
        self.replies = list(replies)
        self.name = name
        self.refused: list[str] = []
        self.requests = 0
        self._model: Any = None

    @property
    def model(self) -> Any:
        if self._model is None:
            from pydantic_ai.models.function import FunctionModel
            self._model = FunctionModel(self._answer, model_name=self.name)
        return self._model

    async def _answer(self, messages: list[Any], _info: Any) -> Any:
        from pydantic_ai.messages import (
            ModelResponse,
            RetryPromptPart,
            TextPart,
            ToolCallPart,
            ToolReturnPart,
        )

        self.requests += 1
        for i, message in enumerate(messages):
            if not isinstance(message, ModelResponse):
                continue
            asked = {p.tool_call_id for p in message.parts if isinstance(p, ToolCallPart)}
            after = messages[i + 1].parts if i + 1 < len(messages) else []
            answered = {p.tool_call_id for p in after
                        if isinstance(p, ToolReturnPart | RetryPromptPart)}
            if asked - answered:
                self.refused.append(f"request {self.requests}: {sorted(asked - answered)}")
                raise RuntimeError("tool_use ids were found without tool_result blocks")
        if not self.replies:
            return ModelResponse(parts=[TextPart(content="(script spent)")])
        return ModelResponse(parts=[
            ToolCallPart(tool_name=name, args=dict(args), tool_call_id=f"c{self.requests}-{n}")
            for n, (name, args) in enumerate(self.replies.pop(0))])


def _with_undeclared(rows: dict) -> dict:
    extra = {**rows["rows"][0], "event_id": "e-999"}
    return {**rows, "rows": [*rows["rows"], extra]}


_FORGE = ("forge", {"forged_id": "fg-1", "fact_id": "f1", "system": "idp",
                    "row": {"user": "alice", "event_id": "e-9001"}})


def test_a_tool_called_after_a_refused_submit_is_still_answered(tmp_path):
    est = S.estate(tmp_path)
    est.answer("idp", "query", ALICE, ALICE_ROWS)
    model = ProviderLikeModel(
        [("submit", {"served": _with_undeclared(ALICE_ROWS), "claim": S.EMPTY_CLAIM}), _FORGE],
        [("submit", {"served": ALICE_ROWS, "claim": S.EMPTY_CLAIM})])
    reg = S.world_registry(S.episode_v2(tmp_path), "b", est, oracle=model,
                           verifier=S.passing_verifier(), retry_cap=3)

    served = S.call(reg, "idp", "query", est.ctx(tmp_path / "inv"), q="user:alice")

    assert served == ALICE_ROWS
    assert model.refused == [], model.refused


def test_a_tool_called_after_submit_is_answered_but_not_run(tmp_path):
    """The attempt ends at its `submit`: a `run_query` the same reply calls after it gets an
    answer (the conversation stays valid) but reads nothing from the tenant."""
    est = S.estate(tmp_path)
    est.answer("idp", "query", ALICE, ALICE_ROWS)
    est.answer("idp", "lookup", {"entity": "alice"}, LOOKUP_ALICE)
    model = ProviderLikeModel(
        [("submit", {"served": _with_undeclared(ALICE_ROWS), "claim": S.EMPTY_CLAIM}),
         ("run_query", {"system": "idp", "verb": "lookup", "params": {"entity": "alice"}})],
        [("submit", {"served": ALICE_ROWS, "claim": S.EMPTY_CLAIM})])
    reg = S.world_registry(S.episode_v2(tmp_path), "b", est, oracle=model,
                           verifier=S.passing_verifier(), retry_cap=3)

    assert S.call(reg, "idp", "query", est.ctx(tmp_path / "inv"), q="user:alice") == ALICE_ROWS
    assert model.refused == [], model.refused
    assert est.calls("idp", "lookup") == [], "a query called after submit reached the tenant"


def test_a_tool_called_after_one_that_ended_the_attempt_is_still_answered(tmp_path):
    est = S.estate(tmp_path)
    est.answer("idp", "query", ALICE, ALICE_ROWS)

    def no_box() -> Any:
        raise RuntimeError("docker is not reachable")

    model = ProviderLikeModel([("python", {"code": "print(1)"}), _FORGE],
                              [("submit", {"served": ALICE_ROWS, "claim": S.EMPTY_CLAIM})])
    reg = S.world_registry(S.episode_v2(tmp_path), "b", est, oracle=model, box=no_box,
                           verifier=S.passing_verifier(), retry_cap=3)

    served = S.call(reg, "idp", "query", est.ctx(tmp_path / "inv"), q="user:alice")

    assert served == ALICE_ROWS
    assert model.refused == [], model.refused


def test_a_hung_verifier_is_cut_off_by_the_turn_deadline(tmp_path):
    est = S.estate(tmp_path)
    est.answer("idp", "query", ALICE, ALICE_ROWS)
    o = S.oracle(S.submit(ALICE_ROWS, S.EMPTY_CLAIM))
    hung = S.verifier(then=S.verdict(True), fault=S.Fault(delay=5.0))
    reg = S.world_registry(S.episode_v2(tmp_path), "b", est, oracle=o, verifier=hung,
                           retry_cap=1, turn_deadline=0.5)

    began = time.monotonic()
    with pytest.raises(oracle_mod.OracleUnservable) as stopped:
        S.call(reg, "idp", "query", est.ctx(tmp_path / "inv"), q="user:alice")

    assert time.monotonic() - began < 4.0, "the verifier ran to the end of its hang"
    assert "deadline" in stopped.value.detail, stopped.value.detail


def test_a_call_after_the_world_went_unservable_reports_the_failing_call(tmp_path):
    """CI race (test_conc_13)."""
    est = S.estate(tmp_path)
    est.answer("idp", "query", ALICE, ALICE_ROWS)
    est.answer("idp", "query", BOB, BOB_ROWS)
    reg = S.world_registry(S.episode_v2(tmp_path), "b", est, oracle=S.oracle(S.text_only("no.")),
                           verifier=S.passing_verifier(), retry_cap=1)
    ctx = est.ctx(tmp_path / "inv")
    with pytest.raises(oracle_mod.OracleUnservable) as first:
        S.call(reg, "idp", "query", ctx, q="user:alice")

    with pytest.raises(oracle_mod.OracleUnservable) as later:
        S.call(reg, "idp", "query", ctx, q="user:bob")

    assert later.value.call == first.value.call
    assert (later.value.reason, later.value.detail) == (first.value.reason, first.value.detail)


def test_the_advisory_check_resolves_the_base_handle_as_submit_does(tmp_path):
    est = S.estate(tmp_path)
    est.answer("idp", "query", ALICE, ALICE_ROWS)
    o = S.oracle(S.check(oracle_mod.BASE_HANDLE, S.EMPTY_CLAIM),
                 S.submit(oracle_mod.BASE_HANDLE, S.EMPTY_CLAIM))
    reg = S.world_registry(S.episode_v2(tmp_path), "b", est, oracle=o,
                           verifier=S.passing_verifier(), retry_cap=1)

    assert S.call(reg, "idp", "query", est.ctx(tmp_path / "inv"), q="user:alice") == ALICE_ROWS
    told = _tool_result(o.messages[1], "check")
    assert "passes the host checks" in told, told


def test_an_oracle_side_query_runs_in_the_context_of_the_call_whose_turn_it_is(tmp_path):
    est = S.estate(tmp_path)
    est.answer("idp", "query", ALICE, ALICE_ROWS)
    est.answer("idp", "query", BOB, BOB_ROWS)
    est.answer("idp", "lookup", {"entity": "alice"}, LOOKUP_ALICE)
    o = S.oracle(S.run_query("idp", "lookup", {"entity": "alice"}),
                 S.submit(ALICE_ROWS, S.EMPTY_CLAIM), S.submit(BOB_ROWS, S.EMPTY_CLAIM),
                 fault=S.Fault(delay=0.6))
    reg = S.world_registry(S.episode_v2(tmp_path), "b", est, oracle=o,
                           verifier=S.passing_verifier(), retry_cap=1)
    served: dict[str, Any] = {}

    def lead(name: str, q: str) -> None:
        served[name] = S.call(reg, "idp", "query", est.ctx(tmp_path / f"inv-{name}"), q=q)

    first = threading.Thread(target=lead, args=("a", "user:alice"))
    first.start()
    time.sleep(0.2)  # inside a's first oracle request
    second = threading.Thread(target=lead, args=("b", "user:bob"))
    second.start()
    first.join(timeout=30)
    second.join(timeout=30)

    assert served == {"a": ALICE_ROWS, "b": BOB_ROWS}, served
    side = est.calls("idp", "lookup")
    assert [Path(c["run_dir"]).name for c in side] == ["inv-a"], side


def test_stopping_an_oracle_box_removes_its_scratch_folder(tmp_path):
    removed: list[list[str]] = []

    def docker(argv: list[str], **_kw: Any) -> subprocess.CompletedProcess:
        removed.append(list(argv))
        return subprocess.CompletedProcess(argv, 0, "", "")

    scratch = tmp_path / "scratch"
    (scratch / "frame").mkdir(parents=True)
    stop_oracle_box(_box("defender-oracle-abc", docker, scratch))
    assert removed == [["docker", "rm", "-f", "defender-oracle-abc"]]
    assert not scratch.exists()

    def broken(argv: list[str], **_kw: Any) -> subprocess.CompletedProcess:
        return subprocess.CompletedProcess(argv, 1, "", "daemon gone")

    scratch.mkdir()
    with pytest.raises(Exception, match="daemon gone"):
        stop_oracle_box(_box("defender-oracle-abd", broken, scratch))
    assert not scratch.exists()


def _box(name: str, docker: Any, scratch: Path) -> OracleBox:
    """A sandboxed oracle box (its teardown goes through `docker`, never the real daemon)."""
    return OracleBox(transport=_DockerTransport(name=name, spec=BoxSpec()), name=name,
                     docker=docker, scratch=scratch)


def _tool_result(messages: list[Any], tool: str) -> str:
    """The text the host returned for `tool` in the last request of `messages`."""
    from pydantic_ai.messages import ModelRequest, ToolReturnPart

    last = [m for m in messages if isinstance(m, ModelRequest)][-1]
    return "\n".join(str(p.content) for p in last.parts
                     if isinstance(p, ToolReturnPart) and p.tool_name == tool)


# --- second round ---------------------------------------------------------------------------

_REAL_ROW = {"user": "alice", "event_id": "e-100", "action": "logon"}
_FROZEN = {"forged_id": "fg-1", "fact_id": "F", "system": "s",
           "row": {"user": "alice", "event_id": "e-9001", "action": "tgt"}}
_SEEN_SINCE = RealData(answers=[("s", {"rows": [{**_REAL_ROW, "src_ip": "10.0.0.1"}]})])


def _shape_failures(*, frozen: dict, staged: dict) -> list[str]:
    store = CheckStore(frozen=frozen, staged=staged, facts={}, rerun=lambda *_a: {})
    failures = check_submission(
        {"rows": [_REAL_ROW]}, {"rows": [_REAL_ROW, _FROZEN["row"]]},
        {"added": [{"forged_id": "fg-1", "fact_id": "F"}]},
        world=SimpleNamespace(facts=[SimpleNamespace(fact_id="F")]), store=store,
        real_data=_SEEN_SINCE)
    return [f for f in failures if f.startswith("check 2")]


def test_a_frozen_row_is_not_re_judged_against_real_data_seen_since_it_froze():
    assert _shape_failures(frozen={"fg-1": _FROZEN}, staged={}) == []
    assert _shape_failures(frozen={}, staged={"fg-1": _FROZEN}) != []


def test_re_forging_a_frozen_row_reuses_it_instead_of_staging_a_copy(tmp_path):
    est = S.estate(tmp_path)
    reg = S.world_registry(S.episode_v2(tmp_path), "b", est, oracle=S.oracle(),
                           verifier=S.passing_verifier())
    frozen = {**_FROZEN, "fact_id": "f1", "system": "idp"}
    reg.store.commit(forged=[frozen], facts=[], answer=None)
    attempt = oracle_mod._Attempt()

    told = reg.oracle._forge(dict(frozen), attempt, system="idp")

    assert attempt.forged == {}, "the frozen row was staged as a fresh copy"
    assert "already frozen" in told, told


def test_the_verifier_is_shown_a_large_unchanged_answer_once_and_capped(tmp_path):
    est = S.estate(tmp_path)
    big = {"rows": [{**_REAL_ROW, "event_id": f"e-{n:06d}", "note": "x" * 60}
                    for n in range(4000)]}
    est.answer("idp", "query", ALICE, big)
    v = S.passing_verifier()
    reg = S.world_registry(S.episode_v2(tmp_path), "b", est, verifier=v, retry_cap=1,
                           oracle=S.oracle(S.submit(oracle_mod.BASE_HANDLE, S.EMPTY_CLAIM)))

    assert S.call(reg, "idp", "query", est.ctx(tmp_path / "inv"), q="user:alice") == big
    shown = v.seen[0]
    assert len(shown) < oracle_mod._CONTEXT_CAP * 1.5, len(shown)
    assert "unchanged" in shown


def test_a_slow_tool_is_cut_off_by_the_attempt_deadline(tmp_path):
    est = S.estate(tmp_path)
    est.answer("idp", "query", ALICE, ALICE_ROWS)

    def slow_box() -> Any:
        def run_parsed(*_a: Any, **_kw: Any) -> Any:
            time.sleep(4.0)
            return SimpleNamespace(out=b"", err=b"", rc=0)
        return SimpleNamespace(sandboxed=True, name="slow-box", run_parsed=run_parsed)

    o = S.oracle(S.python("print('slow')"), S.submit(ALICE_ROWS, S.EMPTY_CLAIM))
    reg = S.world_registry(S.episode_v2(tmp_path), "b", est, oracle=o, box=slow_box,
                           verifier=S.passing_verifier(), retry_cap=2, turn_deadline=0.5)

    began = time.monotonic()
    served = S.call(reg, "idp", "query", est.ctx(tmp_path / "inv"), q="user:alice")

    assert served == ALICE_ROWS
    assert time.monotonic() - began < 3.0, "the attempt waited out the slow tool"


def test_an_unpriced_model_is_refused_before_any_request(tmp_path):
    est = S.estate(tmp_path)
    est.answer("idp", "query", ALICE, ALICE_ROWS)
    model = ProviderLikeModel([("submit", {"served": ALICE_ROWS, "claim": S.EMPTY_CLAIM})],
                              name="no-such-model")

    with pytest.raises(oracle_mod.OraclePricingError):
        _configure_and_ask(tmp_path, est, model, S.passing_verifier())
    assert model.requests == 0


def _configure_and_ask(tmp_path: Path, est: Any, oracle: Any, verifier: Any) -> Any:
    """Configure world b's registry over these models, then ask it one call: a refusal at
    either step is the same refusal before any request."""
    reg = S.world_registry(S.episode_v2(tmp_path), "b", est, oracle=oracle, verifier=verifier,
                           retry_cap=1)
    return S.call(reg, "idp", "query", est.ctx(tmp_path / "inv"), q="user:alice")


def test_an_undelivered_control_world_call_leaves_no_row(tmp_path):
    est = S.estate(tmp_path)
    est.answer("idp", "query", ALICE, ALICE_ROWS)
    ep = S.episode_v2(tmp_path)
    reg = S.sandboxed_registry(ep, "a", est, S.oracle(then=S.submit(ALICE_ROWS, S.EMPTY_CLAIM)),
                               S.passing_verifier())
    delivery = CallDelivery()
    delivery.abandoned = True
    token = CALL_DELIVERY.set(delivery)
    try:
        served = S.call(reg, "idp", "query", est.ctx(tmp_path / "inv"), q="user:alice")
    finally:
        CALL_DELIVERY.reset(token)

    assert served == ALICE_ROWS
    assert S.ledger_rows(ep, "a") == []


# --- fourth round: one row model ------------------------------------------------------------

_ESQL_COLUMNS = [{"name": "@timestamp", "type": "date"}, {"name": "user.name", "type": "keyword"},
                 {"name": "event_id", "type": "keyword"}, {"name": "host", "type": "keyword"}]
_ESQL_ROWS = [["2026-03-01T09:00:00Z", "alice", "e-100", "web-1"],
              ["2026-03-01T10:00:00Z", "alice", "e-101", "web-1"]]


def _esql(rows: list[list[Any]]) -> dict:
    """An ES|QL answer as the elastic adapter shapes it."""
    return {"query": "FROM logs-* | WHERE user.name == \"alice\"", "columns": _ESQL_COLUMNS,
            "row_count": len(rows), "values": rows}


def test_a_forged_row_can_be_added_to_an_esql_answer(tmp_path):
    """Fourth-round finding 2."""
    est = S.estate(tmp_path)
    base = est.answer("idp", "query", ALICE, _esql(_ESQL_ROWS))
    row = ["2026-03-01T11:00:00Z", "alice", "e-9f01", "db-1"]
    served = _esql([*_ESQL_ROWS, row])
    o = S.oracle(S.Move("forge", {"forged_id": "fg-1", "fact_id": "f1", "system": "idp",
                                  "row": row}),
                 S.submit(served, S.claim(added=[S.added("fg-1", "f1")],
                                          counts=[S.counted("*", base=2, added_=1, served=3)])))
    reg = S.world_registry(S.episode_v2(tmp_path), "b", est, oracle=o,
                           verifier=S.passing_verifier(), retry_cap=1)

    assert S.call(reg, "idp", "query", est.ctx(tmp_path / "inv"), q="user:alice") == served
    assert base["values"] == _ESQL_ROWS
    # Frozen as named cells, so a later query projecting other columns cannot misread it.
    assert reg.store.frozen["fg-1"]["row"] == dict(zip(
        [c["name"] for c in _ESQL_COLUMNS], row, strict=True))


def _checks(base: Any, served: Any, claim: dict, *, staged: dict | None = None,
            frozen: dict | None = None, rerun: Any = None, real: list | None = None) -> list[str]:
    store = CheckStore(frozen=frozen or {}, staged=staged or {}, facts={},
                       rerun=rerun or (lambda *_a: {}))
    return check_submission(base, served, claim,
                            world=SimpleNamespace(facts=[SimpleNamespace(fact_id="F")]),
                            store=store, real_data=RealData(answers=real or [("s", base)]))


def test_an_esql_side_query_selects_its_rows_not_its_columns():
    base = _esql(_ESQL_ROWS)
    served = _esql(_ESQL_ROWS[:1])
    side = {"system": "s", "verb": "esql", "params": {"query": "FROM logs-* | WHERE host == 1"}}
    claim = {"removed": [{"row": _ESQL_ROWS[1], "side_query": side, "count": 2}],
             "counts": [{"group": "*", "base": 2, "added": 0, "removed": 1, "served": 1}]}

    failures = _checks(base, served, claim, rerun=lambda *_a: _esql(_ESQL_ROWS))

    assert failures == [], failures


def test_esql_answers_projecting_other_columns_are_separate_tables_for_check_2():
    """Fourth-round finding 2, check 2."""
    other = {"columns": [{"name": "host", "type": "keyword"}, {"name": "risk", "type": "long"}],
             "values": [["web-1", 3]]}
    base = _esql(_ESQL_ROWS)

    def forged(row: list[Any]) -> list[str]:
        record = {"forged_id": "fg-1", "fact_id": "F", "system": "s", "row": row}
        claim = {"added": [{"forged_id": "fg-1", "fact_id": "F"}],
                 "counts": [{"group": "*", "base": 2, "added": 1, "removed": 0, "served": 3}]}
        return _checks(base, _esql([*_ESQL_ROWS, row]), claim, staged={"fg-1": record},
                       real=[("s", base), ("s", other)])

    assert forged(["2026-03-01T11:00:00Z", "alice", "e-9f01", "db-1"]) == []
    mistyped = forged(["2026-03-01T11:00:00Z", "alice", "e-9f01", 7])
    assert [f for f in mistyped if f.startswith("check 2")], mistyped


_PROCESS_ID = "c2f1a7e0-55d1-4b7e-9f0a-8d3e6b2a9c41"
_REAL_EVENT = {"@timestamp": "2026-03-01T09:00:00Z", "event": {"action": "exec"},
               "process": {"name": "bash", "entity_id": _PROCESS_ID}}


def test_a_nested_real_identifier_reused_by_a_forged_row_fails_check_3():
    base = {"hits": [_REAL_EVENT]}

    def forged(entity_id: str) -> list[str]:
        row = {"@timestamp": "2026-03-01T09:30:00Z", "event": {"action": "exec"},
               "process": {"name": "curl", "entity_id": entity_id}}
        record = {"forged_id": "fg-1", "fact_id": "F", "system": "s", "row": row}
        return _checks(base, {"hits": [_REAL_EVENT, row]},
                       {"added": [{"forged_id": "fg-1", "fact_id": "F"}]},
                       staged={"fg-1": record})

    reused = forged(_PROCESS_ID)
    assert any(f.startswith("check 3") and "process.entity_id" in f for f in reused), reused
    assert forged("0b9e4d2a-7c13-4f6e-a1d8-5e2f9b3c7a60") == []


def test_a_frozen_row_s_nested_id_collision_is_recorded():
    from defender.learning.branch.estate.checks import frozen_id_collisions, run_checks

    row = {"@timestamp": "2026-03-01T09:30:00Z", "event": {"action": "exec"},
           "process": {"name": "curl", "entity_id": _PROCESS_ID}}
    record = {"forged_id": "fg-1", "fact_id": "F", "system": "s", "row": row}
    store = CheckStore(frozen={"fg-1": record}, staged={}, facts={}, rerun=lambda *_a: {})
    real = RealData(answers=[("s", {"hits": [_REAL_EVENT]})])
    checked = run_checks({"hits": []}, {"hits": [row]},
                         {"added": [{"forged_id": "fg-1", "fact_id": "F"}]},
                         world=SimpleNamespace(facts=[SimpleNamespace(fact_id="F")]),
                         store=store, real_data=real)

    assert checked.failures == []
    found = frozen_id_collisions(checked, store=store, real_data=real)
    assert [(e["column"], e["value"]) for e in found] == [("process.entity_id", _PROCESS_ID)]
    # The real row carrying it, not the whole answer it came in.
    assert found[0]["real_rows"] == [{"@timestamp": "2026-03-01T09:00:00Z",
                                      "event.action": "exec", "process.name": "bash",
                                      "process.entity_id": _PROCESS_ID}]


# --- fourth round: state belongs to whoever created it; preconditions settle before spending ---


class _BoxLog:
    def __init__(self) -> None:
        self.names: list[str] = []
        self.scratch: list[Path] = []
        self.removed: list[str] = []
        self.frames = 0


def _python_box_factory(tmp_path: Path, *, slow_first: float = 0.0) -> tuple[Any, _BoxLog]:
    """A sandboxed oracle box factory whose boxes carry a recording docker and a real scratch
    folder, so a teardown shows as a `docker rm -f <name>` and a removed folder. The first frame
    any of its boxes runs takes `slow_first` seconds (a python frame outliving the deadline)."""
    from dataclasses import dataclass

    from defender.execution import box_codec as codec
    from defender.box import _spec

    log = _BoxLog()

    def docker(argv: list[str], **_kw: Any) -> subprocess.CompletedProcess:
        if argv[:3] == ["docker", "rm", "-f"]:
            log.removed.append(argv[3])
        return subprocess.CompletedProcess(argv, 0, "", "")

    @dataclass(frozen=True)
    class _Frames(_spec._DockerTransport):
        def __call__(self, frame: bytes, *, cwd: Path, timeout: float) -> Any:
            log.frames += 1
            if log.frames == 1 and slow_first:
                time.sleep(slow_first)
            return codec.RawExec(rc=0, stdout=codec.encode_response(
                codec.BoxResult(rc=0, out=b"ok\n", err=b"")), stderr=b"")

    def factory() -> Any:
        name = f"oracle-box-r4-{len(log.names) + 1}"
        scratch = tmp_path / "scratch" / name
        scratch.mkdir(parents=True)
        log.names.append(name)
        log.scratch.append(scratch)
        return OracleBox(spec=BoxSpec(), transport=_Frames(name=name, spec=BoxSpec()),
                         name=name, docker=docker, scratch=scratch)

    return factory, log


def test_the_python_box_is_stopped_when_the_attempt_that_used_it_ends(tmp_path):
    """Finding 9."""
    est = S.estate(tmp_path)
    est.answer("idp", "query", ALICE, ALICE_ROWS)
    box, log = _python_box_factory(tmp_path)
    o = S.oracle(S.python("print(1)"), S.submit(ALICE_ROWS, S.EMPTY_CLAIM))
    reg = S.world_registry(S.episode_v2(tmp_path), "b", est, oracle=o, box=box,
                           verifier=S.passing_verifier(), retry_cap=1)

    assert S.call(reg, "idp", "query", est.ctx(tmp_path / "inv"), q="user:alice") == ALICE_ROWS

    assert log.names == ["oracle-box-r4-1"], log.names
    assert log.removed == log.names, "the verified attempt's box outlived it"
    assert not any(p.exists() for p in log.scratch), "the attempt's scratch outlived it"


def test_a_deadline_abandoned_python_frame_does_not_share_the_next_attempts_box(tmp_path):
    est = S.estate(tmp_path)
    est.answer("idp", "query", ALICE, ALICE_ROWS)
    box, log = _python_box_factory(tmp_path, slow_first=1.5)
    o = S.oracle(S.python("import time; time.sleep(60)"), S.python("print(2)"),
                 S.submit(ALICE_ROWS, S.EMPTY_CLAIM))
    reg = S.world_registry(S.episode_v2(tmp_path), "b", est, oracle=o, box=box,
                           verifier=S.passing_verifier(), retry_cap=2, turn_deadline=0.4)

    assert S.call(reg, "idp", "query", est.ctx(tmp_path / "inv"), q="user:alice") == ALICE_ROWS

    assert len(log.names) == 2, f"the second attempt reused the abandoned box: {log.names}"
    assert log.removed == log.names, log.removed
    assert not any(p.exists() for p in log.scratch)


class _GatedLimiter:
    """A limiter double. The thread that acquired first (attempt 1's host check, abandoned
    mid-check) blocks on its next `acquire` until another thread's wait (the next attempt's
    own) releases it 0.2 s in; that wait then goes on for 1 s more."""

    def __init__(self) -> None:
        self.first: int | None = None
        self.next_attempt_waited = False
        self.abandoned_waiting = threading.Event()
        self.release_abandoned = threading.Event()

    def acquire(self) -> float:
        me = threading.get_ident()
        if self.first is None:
            self.first = me
            return 0.0
        if me == self.first:
            self.abandoned_waiting.set()
            self.release_abandoned.wait(10)
            return 0.0
        began = time.monotonic()
        self.abandoned_waiting.wait(10)
        time.sleep(0.2)
        self.release_abandoned.set()
        time.sleep(1.0)
        self.next_attempt_waited = True
        return time.monotonic() - began


def test_an_abandoned_attempts_limiter_wait_does_not_touch_the_next_attempts_clock(tmp_path):
    """Finding 10."""
    est = S.estate(tmp_path)
    est.answer("idp", "query", ALICE, ALICE_ROWS)
    est.answer("idp", "query", BOB, BOB_ROWS)
    est.answer("idp", "lookup", {"entity": "alice"}, LOOKUP_ALICE)
    side = [S.removed(row, system="idp", verb="query", params=params, count=1)
            for row, params in ((ALICE_ROWS["rows"][0], ALICE), (BOB_ROWS["rows"][0], BOB))]
    o = S.oracle(S.check(ALICE_ROWS, S.claim(removed=side)),
                 S.run_query("idp", "lookup", {"entity": "alice"}),
                 S.submit(ALICE_ROWS, S.EMPTY_CLAIM))
    limiter = _GatedLimiter()
    reg = S.world_registry(S.episode_v2(tmp_path), "b", est, oracle=o, limiter=limiter,
                           verifier=S.passing_verifier(), retry_cap=2, turn_deadline=0.5)
    door = reg.oracle.door
    real_context = door.context
    slowed: list[bool] = []

    def slow_once() -> Any:
        # The first side query's counted work outlives attempt 1's deadline; its thread is
        # abandoned and goes on into the second side query's limiter wait.
        if not slowed:
            slowed.append(True)
            time.sleep(0.9)
        return real_context()

    door.context = slow_once

    assert S.call(reg, "idp", "query", est.ctx(tmp_path / "inv"), q="user:alice") == ALICE_ROWS
    assert limiter.abandoned_waiting.is_set(), "attempt 1's thread never reached the limiter"
    assert limiter.next_attempt_waited, "the next attempt never waited on the limiter"


def test_an_oracle_turn_holds_the_clock_only_while_it_is_open(tmp_path):
    """Finding 7."""
    from defender.hooks import budget_enforcer as be

    state = S.run_state(tmp_path / "run", "r-1")
    assert be.oracle_held(state) == 0.0
    time.sleep(0.3)
    assert be.oracle_held(state) == 0.0, "a fresh run's clock is paused"

    be.oracle_turn_opened(state)
    try:
        opened = be.oracle_held(state)
        time.sleep(0.3)
        assert be.oracle_held(state) - opened >= 0.25, "a live turn no longer holds"
    finally:
        be.oracle_turn_closed(state)
    closed = be.oracle_held(state)
    assert closed >= 0.25, "the closed turn's held seconds were not credited"
    time.sleep(0.3)
    assert be.oracle_held(state) == closed, "a closed turn still holds the clock"


def test_a_failure_closing_the_oracle_mark_does_not_replace_the_unservable_abort(tmp_path,
                                                                               monkeypatch):
    from defender.learning.branch.estate import registry as registry_mod

    closed: list[Any] = []

    def broken(state: Any) -> None:
        closed.append(state)
        raise OSError("the oracle-held clock's close failed")

    # The close must fail mid-turn after the open succeeded; nothing but this seam does that
    # (the clock is the run's in-memory `RunState`, and a context with no state pauses none).
    monkeypatch.setattr(registry_mod, "oracle_turn_closed", broken)  # lint-monkeypatch: ok — only seam for a close that fails after its open
    est = S.estate(tmp_path)
    est.answer("idp", "query", ALICE, ALICE_ROWS)
    reg = S.world_registry(S.episode_v2(tmp_path), "b", est, oracle=S.oracle(S.text_only("no.")),
                           verifier=S.passing_verifier(), retry_cap=1)
    ctx = est.ctx(tmp_path / "inv", run_state=S.run_state(tmp_path / "inv"))

    with pytest.raises(oracle_mod.OracleUnservable):
        S.call(reg, "idp", "query", ctx, q="user:alice")
    assert closed, "the turn's close never ran, so its failure was not exercised"
    assert all(c is ctx.run_state for c in closed), "the close was not the run's own clock"


def test_an_unpriced_verifier_is_refused_before_the_oracles_first_request(tmp_path):
    est = S.estate(tmp_path)
    est.answer("idp", "query", ALICE, ALICE_ROWS)
    model = ProviderLikeModel([("submit", {"served": ALICE_ROWS, "claim": S.EMPTY_CLAIM})])
    unpriced = ProviderLikeModel([("verdict", {"passed": True, "reason": "ok"})],
                                 name="no-such-verifier-model")

    with pytest.raises(oracle_mod.OraclePricingError, match="verifier"):
        _configure_and_ask(tmp_path, est, model, unpriced)
    assert model.requests == 0, "the oracle paid for a request before the refusal"


def test_a_failing_trace_write_still_charges_and_is_not_a_model_failure(tmp_path):
    """Finding 8."""
    est = S.estate(tmp_path)
    est.answer("idp", "query", ALICE, ALICE_ROWS)
    o = S.oracle(S.submit(ALICE_ROWS, S.EMPTY_CLAIM))
    v = S.passing_verifier()
    reg = S.world_registry(S.episode_v2(tmp_path), "b", est, oracle=o, verifier=v, retry_cap=1)
    Path(reg.store.paths.trace).mkdir(parents=True)  # every append to the trace now fails

    assert S.call(reg, "idp", "query", est.ctx(tmp_path / "inv"), q="user:alice") == ALICE_ROWS
    assert reg.store.spent > 0, "the paid responses were not charged"
    assert (o.requests, v.requests) == (1, 1), (o.requests, v.requests)


# --- fifth round: the host fills in what it knows, and refuses malformed input at entry ------

_ALICE_ROW = ALICE_ROWS["rows"][0]
_HONEST = {"user": "alice", "event_id": "e-9f01", "action": "tgt", "host": "db-1",
           "ts": "2026-07-28T15:20:00Z"}


def _forge_and_serve(tmp_path: Path, row: Any, *, system: str = "Elastic") -> tuple[Any, Any]:
    est = S.estate(tmp_path)
    est.answer("idp", "query", ALICE, ALICE_ROWS)
    served = {"rows": [_ALICE_ROW, row]}
    o = S.oracle(S.Move("forge", {"forged_id": "fg-1", "fact_id": "f1", "system": system,
                                  "row": row}),
                 S.submit(served, S.claim(added=[S.added("fg-1", "f1")])))
    reg = S.world_registry(S.episode_v2(tmp_path), "b", est, oracle=o,
                           verifier=S.passing_verifier(), retry_cap=1)
    return reg, S.call(reg, "idp", "query", est.ctx(tmp_path / "inv"), q="user:alice")


def test_a_forged_row_belongs_to_the_calls_system_not_the_one_the_oracle_typed(tmp_path):
    """Fifth-round finding 3."""
    with pytest.raises(oracle_mod.OracleUnservable) as refused:
        _forge_and_serve(tmp_path / "a", {"ts": "2026-07-28T15:20:00Z", "totally": "different"})
    assert "check 2" in refused.value.detail, refused.value.detail

    reg, served = _forge_and_serve(tmp_path / "b", _HONEST)
    assert served == {"rows": [_ALICE_ROW, _HONEST]}
    assert reg.store.frozen["fg-1"]["system"] == "idp"


def test_an_esql_value_array_of_the_wrong_length_is_refused_at_forge(tmp_path):
    """Fifth-round finding 4."""
    est = S.estate(tmp_path)
    est.answer("idp", "query", ALICE, _esql(_ESQL_ROWS))
    short = ["2026-03-01T11:00:00Z", "alice", "e-9f01"]
    o = S.oracle(S.Move("forge", {"forged_id": "fg-1", "fact_id": "f1", "system": "idp",
                                  "row": short}),
                 S.submit(_esql([*_ESQL_ROWS, short]), S.claim(
                     added=[S.added("fg-1", "f1")],
                     counts=[S.counted("*", base=2, added_=1, served=3)])))
    reg = S.world_registry(S.episode_v2(tmp_path), "b", est, oracle=o,
                           verifier=S.passing_verifier(), retry_cap=1)

    with pytest.raises(oracle_mod.OracleUnservable) as refused:
        S.call(reg, "idp", "query", est.ctx(tmp_path / "inv"), q="user:alice")
    assert "fg-1" in refused.value.detail, refused.value.detail
    assert "check 1" in refused.value.detail, refused.value.detail
    assert "fg-1" not in reg.store.frozen

    told = reg.oracle._forge({"forged_id": "fg-2", "fact_id": "f1", "row": short},
                             oracle_mod._Attempt(), system="idp",
                             names=[c["name"] for c in _ESQL_COLUMNS])
    assert told.startswith("forge refused"), told
    assert "4 columns" in told, told


def test_a_nested_esql_value_array_that_does_not_zip_fails_check_2():
    """Fifth-round finding 4, the checks' side."""
    base = {"result": _esql(_ESQL_ROWS)}

    def forged(row: list[Any]) -> list[str]:
        record = {"forged_id": "fg-1", "fact_id": "F", "system": "s", "row": row}
        served = {"result": {**_esql([*_ESQL_ROWS, row]), "row_count": 2}}
        return _checks(base, served, {"added": [{"forged_id": "fg-1", "fact_id": "F"}]},
                       staged={"fg-1": record})

    short = forged(["2026-03-01T11:00:00Z", "alice", "e-9f01"])
    assert [f for f in short if f.startswith("check 2")], short
    assert forged(["2026-03-01T11:00:00Z", "alice", "e-9f01", "db-1"]) == []


def _two_fact_checks(claimed_fact: str, *, frozen: bool) -> list[str]:
    row = {"user": "alice", "event_id": "e-9f01", "action": "tgt"}
    record = {"x1": {"forged_id": "x1", "fact_id": "f1", "system": "s", "row": row}}
    store = CheckStore(frozen=record if frozen else {}, staged={} if frozen else record,
                       facts={}, rerun=lambda *_a: {})
    base = {"rows": [_REAL_ROW]}
    return check_submission(
        base, {"rows": [_REAL_ROW, row]}, {"added": [{"forged_id": "x1", "fact_id": claimed_fact}]},
        world=SimpleNamespace(facts=[SimpleNamespace(fact_id="f1"), SimpleNamespace(fact_id="f2")]),
        store=store, real_data=RealData(answers=[("s", base)]))


@pytest.mark.parametrize("frozen", [False, True], ids=["fresh", "frozen"])
def test_a_forged_row_is_claimed_under_the_fact_it_was_forged_for(frozen):
    """Fifth-round finding 7."""
    wrong = _two_fact_checks("f2", frozen=frozen)
    assert any(f.startswith("check 4") and "'f1', not 'f2'" in f for f in wrong), wrong
    assert _two_fact_checks("f1", frozen=frozen) == []


def test_a_star_count_does_not_cover_an_edit_to_a_real_rows_field():
    """Fifth-round finding 2."""
    base = {"total": 1, "hits": [{"user": "alice", "severity": 1, "risk": 1}]}
    forged_row = {"user": "bob", "severity": 1, "risk": 1}
    record = {"forged_id": "fg-1", "fact_id": "F", "system": "s", "row": forged_row}
    claim = {"added": [{"forged_id": "fg-1", "fact_id": "F"}],
             "counts": [{"group": "*", "base": 1, "added": 1, "removed": 0, "served": 2}]}

    edited = _checks(base, {"total": 2, "hits": [{"user": "alice", "severity": 2, "risk": 2},
                                                 forged_row]}, claim, staged={"fg-1": record})
    unclaimed = sorted(f.split("'")[1] for f in edited if "without a claimed change" in f)
    assert unclaimed == ["risk", "severity"], edited
    assert _checks(base, {"total": 2, "hits": [base["hits"][0], forged_row]}, claim,
                   staged={"fg-1": record}) == []


def test_one_count_entry_accounts_for_one_count_cell():
    base = {"hits": {"total": 1}, "aggregations": {"all": {"value": 1}}}
    served = {"hits": {"total": 2}, "aggregations": {"all": {"value": 2}}}
    star = {"group": "*", "base": 1, "added": 1, "removed": 0, "served": 2}

    one = _checks(base, served, {"counts": [star]})
    assert sum("without a claimed change" in f for f in one) == 1, one
    assert _checks(base, served, {"counts": [star, dict(star)]}) == []


class _NoScan(list):
    def __iter__(self):
        raise AssertionError("check 3 scanned every real row instead of the value index")


def test_a_declared_reference_is_found_by_value_not_by_scanning_every_real_row():
    real_row = {"user": "alice", "user_id": "u-4410", "event_id": "e-100"}
    real = RealData(answers=[("s", {"rows": [real_row]})])
    real.maps = _NoScan(real.maps)
    row = {"user": "alice", "user_id": "u-4410", "event_id": "e-9f01"}
    record = {"forged_id": "fg-1", "fact_id": "F", "system": "s", "row": row}
    claim = {"added": [{"forged_id": "fg-1", "fact_id": "F"}],
             "entity_refs": [{"forged_id": "fg-1", "column": "user_id", "entity": "alice"}]}
    store = CheckStore(frozen={}, staged={"fg-1": record}, facts={}, rerun=lambda *_a: {})

    assert check_submission({"rows": []}, {"rows": [row]}, claim,
                            world=SimpleNamespace(facts=[SimpleNamespace(fact_id="F")]),
                            store=store, real_data=real) == []


# --- fifth round: a turn's outcome is decided in one place, by one rule ---------------------


def test_a_result_that_returned_as_the_deadline_fired_is_completed():
    import anyio

    run = oracle_mod._Run(door=None, deadline=0.0)  # type: ignore[arg-type]

    async def work() -> str:
        return "submitted"  # returns before the watcher's cancel is delivered

    assert anyio.run(oracle_mod._within_deadline, run, work) == (True, "submitted")


_COLLIDING = {"forged_id": "fg-1", "fact_id": "f1", "system": "idp",
              "row": {"user": "alice", "event_id": "e-100", "action": "exec", "host": "web-1",
                      "ts": "2026-07-28T16:00:00Z"}}


def _serve_colliding(tmp_path: Path, *, answers_unwritable: bool) -> tuple[Any, Any]:
    est = S.estate(tmp_path)
    est.answer("idp", "query", ALICE, ALICE_ROWS)
    served = {"rows": [*ALICE_ROWS["rows"], _COLLIDING["row"]]}
    o = S.oracle(S.submit(served, S.claim(added=[S.added("fg-1", "f1")])))
    reg = S.world_registry(S.episode_v2(tmp_path), "b", est, oracle=o,
                           verifier=S.passing_verifier(), retry_cap=1)
    reg.store.commit(forged=[_COLLIDING], facts=[], answer=None)  # fg-1 frozen, id e-100
    if answers_unwritable:
        Path(reg.store.paths.answers).mkdir(parents=True)  # the answer's commit now fails
    return est, reg


def test_an_uncommitted_answer_leaves_no_collision_row(tmp_path):
    """Fifth-round finding 9, the side effect."""
    est, reg = _serve_colliding(tmp_path / "failed", answers_unwritable=True)
    with pytest.raises(oracle_mod.OracleUnservable):
        S.call(reg, "idp", "query", est.ctx(tmp_path / "inv"), q="user:alice")
    assert S.read_jsonl(Path(reg.store.paths.collisions)) == []

    est, reg = _serve_colliding(tmp_path / "served", answers_unwritable=False)
    S.call(reg, "idp", "query", est.ctx(tmp_path / "inv2"), q="user:alice")
    rows = S.read_jsonl(Path(reg.store.paths.collisions))
    assert [(r["forged_id"], r["value"]) for r in rows] == [("fg-1", "e-100")]


def test_a_failure_closing_the_clock_mark_leaves_no_row_for_the_answer_it_withheld(
        tmp_path, monkeypatch):
    """Fifth-round finding 6."""
    from defender.learning.branch.estate import registry as registry_mod

    real_close = registry_mod.oracle_turn_closed
    closes: list[Any] = []

    def fails_once(state: Any) -> None:
        closes.append(state)
        if len(closes) == 1:
            raise OSError("the oracle-held clock's close failed")
        real_close(state)

    # The close must fail after its open succeeded; no file fault does that (see the
    # round-four close test).
    monkeypatch.setattr(registry_mod, "oracle_turn_closed", fails_once)  # lint-monkeypatch: ok — only seam for a close that fails after its open
    est = S.estate(tmp_path)
    est.answer("idp", "query", ALICE, ALICE_ROWS)
    ep = S.episode_v2(tmp_path)
    o = S.oracle(S.submit(ALICE_ROWS, S.EMPTY_CLAIM))
    reg = S.world_registry(ep, "b", est, oracle=o, verifier=S.passing_verifier(), retry_cap=1)
    ctx = est.ctx(tmp_path / "inv", run_state=S.run_state(tmp_path / "inv"))

    with pytest.raises(OSError, match="close failed"):
        S.call(reg, "idp", "query", ctx, q="user:alice")
    assert closes, "the turn's close never ran, so its failure was not exercised"
    assert closes[0] is ctx.run_state, "the close was not the run's own clock"
    assert S.ledger_rows(ep, "b") == [], "a row records an answer the investigator never got"

    assert S.call(reg, "idp", "query", ctx, q="user:alice") == ALICE_ROWS
    assert len(S.ledger_rows(ep, "b")) == 1
    assert o.requests == 1, "the committed answer was not reused"


class _LimiterFailsOnce:
    """A rate limiter whose state read fails closed once (`LimiterStateError`), then admits."""

    def __init__(self) -> None:
        self.failed = False

    def acquire(self) -> float:
        from defender.learning.branch.estate.limiter import LimiterStateError

        if not self.failed:
            self.failed = True
            raise LimiterStateError("the rate limiter could not read its clock: EIO")
        return 0.0


def test_a_limiter_failing_closed_under_an_oracle_query_is_a_failed_attempt(tmp_path):
    """Fifth-round finding 10."""
    est = S.estate(tmp_path)
    est.answer("idp", "query", ALICE, ALICE_ROWS)
    est.answer("idp", "lookup", {"entity": "alice"}, LOOKUP_ALICE)
    o = S.oracle(S.run_query("idp", "lookup", {"entity": "alice"}),
                 S.submit(ALICE_ROWS, S.EMPTY_CLAIM))
    limiter = _LimiterFailsOnce()
    reg = S.world_registry(S.episode_v2(tmp_path), "b", est, oracle=o, limiter=limiter,
                           verifier=S.passing_verifier(), retry_cap=2)

    assert S.call(reg, "idp", "query", est.ctx(tmp_path / "inv"), q="user:alice") == ALICE_ROWS
    assert limiter.failed


def test_a_broken_serving_machine_makes_the_world_unservable_not_a_fault_row(tmp_path):
    est = S.estate(tmp_path)
    est.answer("idp", "query", ALICE, ALICE_ROWS)
    o = S.oracle(S.run_query("idp", "lookup", {"entity": "alice"}),
                 S.submit(ALICE_ROWS, S.EMPTY_CLAIM))
    reg = S.world_registry(S.episode_v2(tmp_path), "b", est, oracle=o,
                           verifier=S.passing_verifier(), retry_cap=3)

    def broken(_system: str) -> Any:
        raise TypeError("verbs() got an unexpected keyword")

    reg.oracle.door.real_verbs = broken

    with pytest.raises(oracle_mod.OracleUnservable) as raised:
        S.call(reg, "idp", "query", est.ctx(tmp_path / "inv"), q="user:alice")
    assert raised.value.reason == oracle_mod.REASON_FAULT
    assert isinstance(raised.value.__cause__, TypeError)


def test_a_trace_append_that_failed_part_way_is_counted_once_on_resume(tmp_path):
    from defender._io import write_guarded

    store = oracle_mod.OracleStore(tmp_path / "oracle")
    real_append = store._append
    trace_calls: list[int] = []

    def faulty(path: Path, rows: list[dict]) -> None:
        if path != store.paths.trace:
            return real_append(path, rows)
        trace_calls.append(len(rows))
        if len(trace_calls) == 1:
            raise OSError("ENOSPC")  # nothing lands
        if len(trace_calls) == 2:
            real_append(path, rows[:1])  # row 1 whole, row 2 torn, then the disk fills
            write_guarded(path, '{"id": "torn', mode="append")
            raise OSError("ENOSPC")
        return real_append(path, rows)

    store._append = faulty  # type: ignore[method-assign]
    usage = {"input_tokens": 1000, "output_tokens": 100}
    for _ in range(3):
        store.charge("oracle", "m", usage, priced_as=S.PRICED_MODEL)

    assert trace_calls == [1, 2, 3]
    assert oracle_mod.OracleStore(tmp_path / "oracle").spent == pytest.approx(store.spent)


def test_an_accounted_call_cannot_resurrect_a_closed_oracle_mark(tmp_path):
    """Fifth-round finding 5."""
    from defender.hooks import budget_enforcer as be

    def close(gate: threading.Barrier) -> None:
        gate.wait(timeout=10)
        be.oracle_turn_closed(state)

    state = S.run_state(tmp_path / "run", "r-1")
    held = 0.0
    for n in range(1, 31):
        be.oracle_turn_opened(state)
        time.sleep(0.002)
        gate = threading.Barrier(2)
        closer = threading.Thread(target=close, args=(gate,))
        closer.start()
        gate.wait(timeout=10)
        be.account_call(state, "bash", limits=be.DEFAULT_LIMITS, tier="core")
        closer.join(timeout=10)
        assert not closer.is_alive()

        budget = state.budget_snapshot()
        assert not {"oracle_open_since", "oracle_held_seconds"} & set(budget), (
            f"the budget state carries oracle clock state: {budget}")
        assert budget["tool_calls"] == n, budget
        now = be.oracle_held(state)
        assert now > held, f"round {n}: the closed turn's held seconds were lost"
        held = now
    time.sleep(0.2)
    assert be.oracle_held(state) == held, "a closed turn's open mark came back"


@pytest.mark.parametrize(("knob", "value", "named"), [
    (S.KNOB_RATE, "abc", "ORACLE_RATE"),
    ("ORACLE_RETRY_CAP", "0", "ORACLE_RETRY_CAP"),
    ("ORACLE_BUDGET", "-1", "ORACLE_BUDGET"),
    ("ORACLE_TURN_DEADLINE", "nan", "ORACLE_TURN_DEADLINE"),
    ("ORACLE_MODEL", "no-such-model", "oracle"),
    ("ORACLE_CHECK_MODEL", "no-such-verifier-model", "verifier"),
])
def test_a_bad_oracle_setting_is_refused_before_the_question_writer(tmp_path, monkeypatch, knob,
                                                                     value, named):
    """Fifth-round finding 8."""
    monkeypatch.setenv(S.T.EPISODES_BASE_ENV, str(tmp_path / "episodes-root"))
    S.T.isolate_learning_state(tmp_path, monkeypatch)
    monkeypatch.setenv(knob, value)
    est = S.estate(tmp_path)
    questioner = S.questioner_for()

    run = S.launch(tmp_path, est, questioner=questioner)

    assert run.rc != 0
    assert named in run.message, run.message
    assert questioner.calls == 0, "the question-writer was paid for before the refusal"


def test_the_oracle_box_binds_nothing_of_the_repository_and_no_env_file(tmp_path, monkeypatch):
    """Sixth-round finding 1."""
    from defender.box import _oracle as box_oracle
    from defender.tests.learning.oracle.live_contracts import test_1224_oracle_context_and_box as B

    shim_bin, argv_log = B._recording_docker(tmp_path / "recorder")
    env = {"PATH": f"{shim_bin}{os.pathsep}{os.environ.get('PATH', '')}",
           "DEFENDER_BOX_RUNTIME": "runc"}
    monkeypatch.setenv("PATH", env["PATH"])
    with pytest.raises(box_oracle.BoxStartRefused):
        box_oracle.start_oracle_box(env=env)
    creates = B._creates(B._docker_argvs(argv_log))
    assert creates, "the oracle box start never reached a container create"
    checkout = box_oracle.CHECKOUT
    secrets_file = checkout / ".env"
    binds = [bind for argv in creates for bind in B._binds(argv)]
    assert binds, f"the recorder read no bind from {creates}"
    for source, _read_only in binds:
        assert not B._overlaps(source, checkout), (
            f"the oracle box binds {source}, which overlaps the checkout {checkout}")
        assert not B._under(secrets_file, source), f"the oracle box binds {source}, over .env"
        assert not source.exists(), f"a refused start left its folder behind: {source}"

    # What the runner bind exposes, file for file: the transport's modules and nothing else.
    runner = box_oracle._make_runner()
    try:
        request = box_oracle.oracle_box_request(tmp_path / "scratch", runner, env=env)
        assert [(m.source, m.target, m.writable) for m in request.mounts] == [
            (runner, checkout, False), (tmp_path / "scratch", tmp_path / "scratch", True)]
        shipped = sorted(str(p.relative_to(runner)) for p in runner.rglob("*") if p.is_file())
        assert shipped == sorted(box_oracle.RUNNER_FILES), shipped
    finally:
        shutil.rmtree(runner, ignore_errors=True)


# -- sixth round --------------------------------------------------------------------------------

_SIX_MARK = "EXAMPLE6-HUGE"


def _big_rows(user: str, mark: str, n: int = 300) -> dict:
    return {"rows": [{"user": user, "event_id": f"e-{user}-{k:05d}", "action": "logon",
                      "note": f"{mark}-{k:05d}-" + "x" * 80} for k in range(n)]}


def test_oversized_family_example_answers_are_capped(tmp_path):
    """Sixth-round finding 9."""
    est = S.estate(tmp_path)
    est.answer("idp", "query", ALICE, ALICE_ROWS)
    o = S.oracle(S.submit(ALICE_ROWS, S.EMPTY_CLAIM))
    reg = S.world_registry(S.episode_v2(tmp_path), "b", est, oracle=o,
                           verifier=S.passing_verifier(), retry_cap=1)
    huge = {"hits": [{"_id": f"h-{k}", "msg": _SIX_MARK + "y" * 100} for k in range(6000)]}
    reg.oracle.family_examples = [("idp", "query", huge), ("edr", "query", huge)]

    assert S.call(reg, "idp", "query", est.ctx(tmp_path / "inv"), q="user:alice") == ALICE_ROWS
    first = o.seen[0]
    assert _SIX_MARK in first, "the examples were dropped rather than capped"
    assert len(first) < oracle_mod._CONTEXT_CAP, len(first)
    assert "past what one request carries" in first


def test_a_conversation_past_the_size_budget_restarts_and_keeps_the_frozen_rows(tmp_path,
                                                                               monkeypatch):
    """Sixth-round finding 5."""
    monkeypatch.setattr(
        # lint-monkeypatch: ok — the size budget is a module constant with no seam; a small one
        # keeps the scenario fast (the full-size one is ~400k characters a request).
        oracle_mod, "_PROMPT_BUDGET", 60_000, raising=False)
    est = S.estate(tmp_path)
    alice = _big_rows("alice", "CALL1MARK")
    bob = _big_rows("bob", "CALL2MARK")
    est.answer("idp", "query", ALICE, alice)
    est.answer("idp", "query", BOB, bob)
    row = {"user": "alice", "event_id": "e-9001", "action": "tgt", "note": "FORGED6"}
    served = {"rows": [*alice["rows"], row]}
    o = S.oracle(S.forge("fg-1", "f1", "idp", row),
                 S.submit(served, S.claim(added=[S.added("fg-1", "f1")])),
                 S.submit(oracle_mod.BASE_HANDLE, S.EMPTY_CLAIM))
    reg = S.world_registry(S.episode_v2(tmp_path), "b", est, oracle=o,
                           verifier=S.passing_verifier(), retry_cap=1)
    ctx = est.ctx(tmp_path / "inv")

    assert S.call(reg, "idp", "query", ctx, q="user:alice") == served
    second = o.requests
    assert S.call(reg, "idp", "query", ctx, q="user:bob") == bob

    restarted = o.seen[second]
    assert "CALL1MARK" not in restarted, "call 2 carried call 1's conversation past the budget"
    assert "Telemetry frozen in this world so far" in restarted
    assert "FORGED6" in restarted, "the restarted conversation lost the frozen row"
    assert reg.oracle._in_conversation == 1


def test_a_failed_worlds_detail_never_reaches_another_worlds_judge_prompt(tmp_path):
    """Sixth-round finding 7."""
    from defender.tests.support.learning.judge import _judge_921 as J

    ep = S.judged_episode(tmp_path / "judged", labels=("a", "c"))
    S.oracle_dir(ep, "c").mkdir(parents=True, exist_ok=True)
    S.world_record(ep, "b", call={"system": "idp", "verb": "query",
                                  "params": S.query_params("user:alice")},
                   detail='Submission refused: check 1: an unclaimed row was added '
                          '{"event_id": "e-FORGEDLEAK", "note": "FORGEDLEAK-6"}')

    judge = J.scripted_judge()
    J.grade(ep, judge=judge)

    world_c = [p for p, a in zip(judge.prompts, judge.agent_ids, strict=True) if a.startswith("judge:c:")]
    assert world_c, f"world c was never graded (agent ids: {judge.agent_ids})"
    assert all("world b" in p for p in world_c), "the failed world is not listed by its label"
    for agent, prompt in zip(judge.agent_ids, judge.prompts, strict=True):
        assert "FORGEDLEAK" not in prompt, f"{agent}: a failed world's detail reached the prompt"


# --- sixth round ---------------------------------------------------------------------------


def test_cached_tokens_are_billed_once(tmp_path):
    """Sixth-round finding 4."""
    from defender.configuration._pricing import usage_cost

    est = S.estate(tmp_path)
    reg = S.world_registry(S.episode_v2(tmp_path), "b", est, oracle=S.oracle(),
                           verifier=S.passing_verifier())
    usage = SimpleNamespace(input_tokens=1_000_000, output_tokens=0,
                            cache_read_tokens=900_000, cache_write_tokens=50_000)
    reg.oracle.charge("oracle", SimpleNamespace(model_name=None, usage=usage))

    row = S.read_jsonl(reg.store.paths.trace)[-1]
    once = usage_cost(row["model"], {"input_tokens": 50_000, "cache_read_input_tokens": 900_000,
                                     "cache_creation_input_tokens": 50_000})
    assert once > 0, "the double's price row bills nothing; the test would prove nothing"
    assert reg.store.spent == pytest.approx(once), (reg.store.spent, once)


def test_python_code_the_box_wire_cannot_carry_fails_that_call_only(tmp_path):
    """Sixth-round finding 6."""
    est = S.estate(tmp_path)
    est.answer("idp", "query", ALICE, ALICE_ROWS)
    box, log = _python_box_factory(tmp_path)
    o = S.oracle(S.python("print('a\x00b')"), S.submit(ALICE_ROWS, S.EMPTY_CLAIM))
    reg = S.world_registry(S.episode_v2(tmp_path), "b", est, oracle=o, box=box,
                           verifier=S.passing_verifier(), retry_cap=1)

    assert S.call(reg, "idp", "query", est.ctx(tmp_path / "inv"), q="user:alice") == ALICE_ROWS
    told = _tool_result(o.messages[1], "python")
    assert "python refused" in told, told
    assert "NUL" in told, told
    assert log.names == [], "a box was started for code that cannot reach it"


def test_a_star_count_cannot_claim_an_ordinary_field_of_a_document():
    """Sixth-round finding 12."""
    base = {"user": {"name": "alice", "failed_logins": 3}}
    served = {"user": {"name": "alice", "failed_logins": 10}}
    for group in ("*", "failed_logins"):
        claim = {"counts": [{"group": group, "base": 3, "added": 7, "removed": 0,
                             "served": 10}]}
        failures = _checks(base, served, claim)
        assert any(f.startswith("check 1") and "failed_logins" in f for f in failures), (
            group, failures)
    changed = {"changed": [{"entity": "alice", "field": "failed_logins", "old": 3, "new": 10}]}
    assert _checks(base, served, changed) == []
    # Still count cells: a count-named answer, and an ES total that carries its relation.
    count = {"counts": [{"group": "*", "base": 3, "added": 7, "removed": 0, "served": 10}]}
    assert _checks({"count": 3}, {"count": 10}, count) == []
    assert _checks({"hits": {"total": {"value": 3, "relation": "eq"}}},
                   {"hits": {"total": {"value": 10, "relation": "eq"}}}, count) == []


def test_an_unexpected_error_in_one_preflight_world_stops_the_others(tmp_path):
    """Sixth-round finding 13."""
    from defender.learning.branch import cli

    est = S.estate(tmp_path)
    calls = [S.default_calls()[0], S.Call("idp", "query", BOB, BOB_ROWS)]
    _base, src = S.source_run(tmp_path, est, calls=calls)
    ep = S.episode_v2(tmp_path, doc=S.family_v2(source_run_dir=str(src)),
                      base_rows=[S.captured("idp", "query", ALICE, ALICE_ROWS),
                                 S.captured("idp", "query", BOB, BOB_ROWS)])
    (ep / "oracle").mkdir(exist_ok=True)
    (ep / "oracle" / "b").write_text("not a folder", encoding="utf-8")
    o = S.oracle(S.submit(ALICE_ROWS, S.EMPTY_CLAIM), S.submit(BOB_ROWS, S.EMPTY_CLAIM),
                 fault=S.Fault(delay=1.5))

    with pytest.raises(OSError, match=re.escape(str(ep / "oracle" / "b"))):
        cli.preflight_replay(ep, source=S.T.open_source(src), roster=est.roster(),
                             tenant=est.run_tenant(), oracle=o.model,
                             verifier=S.passing_verifier().model, rate=1e6)

    # 0 when b failed before c's first turn began, 1 when that turn was already under way.
    assert o.requests <= 1, f"world c paid {o.requests} oracle turns after b's thread failed"
    assert not (ep / "outcome.yaml").exists()


#: A base answer whose columns a forged row can share (check 2), and that row (check 3: an id no
#: real answer holds) — the shape the serving suite forges onto.
_PB_BASE = {"rows": [{"action": "logon", "event_id": "e-100", "user": "alice"}]}
_PB_FORGED = {"action": "tgt-issued", "event_id": "e-9001", "user": "alice"}
_PB_CHANGED = {"rows": [*_PB_BASE["rows"], _PB_FORGED]}
_PB_CLAIM = S.claim(added=[S.added("fg-1", "f1")])
_PB_REFUSAL = "made before the branch point; serve its base answer unchanged"


def _pb_change() -> list:
    """One attempt that forges fact f1's row onto the alice answer and submits the change."""
    return [S.forge("fg-1", "f1", "idp", _PB_FORGED), S.submit(_PB_CHANGED, _PB_CLAIM)]


def _pb_registry(tmp_path: Path, o: Any, v: Any, *, prebranch: bool, retry_cap: int = 3) -> Any:
    """World b's registry over a tenant answering the alice call `_PB_BASE`; `prebranch` puts
    that call in the source run's pre-branch set, as `prebranch_calls` derives it.

    A pre-branch call is one the source RECEIVED an answer to, so the family's recording holds
    it: `prebranch=True` primes `_PB_BASE` as the source's captured answer — the state the real
    primer leaves for an answered call. #1255 D6 (owner decision, 2026-10-16): only a recorded
    pre-branch answer is fixed (served unchanged); a pre-fork call the source asked that has no
    recording because its call failed or its payload was unreadable (the primer's skip record)
    is reconstructed by the oracle at the fork time, and its change IS served
    (`test_1255_world_serving.test_1255_a_pre_fork_question_with_no_recording_is_reconstructed_at_the_fork_time`).
    A pre-branch key with neither a recording nor a skip record is a state production never
    produces, so this fixture no longer builds one."""
    from defender.learning.branch.ledger import request_key

    est = S.estate(tmp_path)
    est.answer("idp", "query", ALICE, _PB_BASE)
    keys = {request_key("idp", "query", ALICE)} if prebranch else set()
    recording = [S.captured("idp", "query", ALICE, _PB_BASE)] if prebranch else None
    reg = S.world_registry(S.episode_v2(tmp_path, base_rows=recording), "b", est, oracle=o,
                           verifier=v, retry_cap=retry_cap, prebranch=keys)
    return reg, est.ctx(tmp_path / "inv")


def test_a_sibling_s_changed_answer_to_a_pre_branch_call_is_refused_and_retried(tmp_path):
    """Seventh-round finding 5."""
    o = S.oracle(*_pb_change(), S.submit(_PB_BASE, S.EMPTY_CLAIM))
    v = S.passing_verifier()
    reg, ctx = _pb_registry(tmp_path, o, v, prebranch=True)

    assert S.call(reg, "idp", "query", ctx, **ALICE) == _PB_BASE
    assert o.submissions() == 2, "the changed answer was not refused and retried"
    assert v.requests == 1, "the verifier was paid for the refused change"
    assert _PB_REFUSAL in o.seen[-1], "the oracle was not told why its change was refused"
    rows = list(reg.store.answers.values())
    assert len(rows) == 1, rows
    assert rows[0]["decision"] == "passthrough", rows
    assert not reg.store.frozen, "the refused attempt's forged row was frozen"


def test_an_oracle_that_only_changes_a_pre_branch_call_makes_it_unservable(tmp_path):
    o = S.oracle(*_pb_change(), then=S.submit(_PB_CHANGED, _PB_CLAIM))
    v = S.passing_verifier()
    reg, ctx = _pb_registry(tmp_path, o, v, prebranch=True, retry_cap=2)

    with pytest.raises(S.unservable_cls()) as raised:
        S.call(reg, "idp", "query", ctx, **ALICE)
    assert raised.value.reason == "retries", raised.value.reason
    assert _PB_REFUSAL in raised.value.detail, raised.value.detail
    assert v.requests == 0
    assert not reg.store.answers


def test_a_post_branch_call_can_still_be_changed(tmp_path):
    """Seventh-round finding 5, the control: a call outside the pre-branch set is served the
    world's verified change, and its framing does not call it pre-branch."""
    o = S.oracle(*_pb_change())
    v = S.passing_verifier()
    reg, ctx = _pb_registry(tmp_path, o, v, prebranch=False)

    assert S.call(reg, "idp", "query", ctx, **ALICE) == _PB_CHANGED
    assert "BEFORE the branch point" not in o.seen[0]


def test_the_sibling_s_registry_gets_pre_flight_s_pre_branch_set(tmp_path):
    from defender import run
    from defender.learning.branch.estate.registry import prebranch_calls
    from defender.learning.branch.ledger import request_key

    est = S.estate(tmp_path)
    post = S.post_branch_call()
    _base, src = S.source_run(tmp_path, est, calls=[*S.default_calls(), post])
    expected = {request_key(c.system, c.verb, c.params) for c in S.default_calls()}
    assert prebranch_calls(_run_handle_1165(src), S.BRANCH_MESSAGE_ID) == expected

    ep = S.episode_v2(tmp_path, doc=S.family_v2(source_run_dir=str(src)))
    seen: dict = {}
    from defender.episodes._episode_handle import Episode
    run._drive_investigation(
        alert_path=src / "alert.json", run=_fixture_run_1165(tmp_path / 'sib'),
        defender_dir=est.defender_dir, model_name="m", model_override=None, box=None,
        tenant=est.run_tenant(), world=S.load_world(ep, "b"), episode=Episode.open(ep),
        serving=S.serving(), source=S.T.open_source(src),
        investigate=lambda **kw: seen.update(kw) or {})
    assert seen["verbs"].prebranch == expected


# --- seventh round (re-ruled M14/M12) -------------------------------------------------------

_ES_EVENT = {"@timestamp": "2026-03-01T09:00:00Z", "event": {"kind": "event"},
             "host": {"name": "web-1"}, "process": {"name": "bash"}}
_ES_ALERT = {"@timestamp": "2026-03-01T09:01:00Z", "event": {"kind": "alert"},
             "host": {"name": "web-1"}, "kibana.alert.rule.name": "odd shell",
             "kibana.alert.severity": "high"}


def _hits_check(row: dict) -> list[str]:
    base = {"hits": [_ES_EVENT, _ES_ALERT]}
    record = {"forged_id": "fg-1", "fact_id": "F", "system": "s", "row": row}
    failures = _checks(base, {"hits": [_ES_EVENT, _ES_ALERT, row]},
                       {"added": [{"forged_id": "fg-1", "fact_id": "F"}]},
                       staged={"fg-1": record})
    return [f for f in failures if f.startswith("check 2")]


def test_a_forged_row_in_an_answer_mixing_event_and_alert_documents_has_one_real_rows_shape():
    """Seventh round (re-ruled M14/M12)."""
    event = {"@timestamp": "2026-03-01T09:30:00Z", "event": {"kind": "event"},
             "host": {"name": "db-1"}, "process": {"name": "kinit"}}
    assert _hits_check(event) == []
    union = {**event, "kibana.alert.rule.name": "x", "kibana.alert.severity": "low"}
    assert _hits_check(union), "a union-shaped row matches no real row and must fail check 2"
    short = {k: v for k, v in event.items() if k != "process"}
    failures = _hits_check(short)
    assert failures, "a row short of the event's `process` must fail check 2"
    assert "missing ['process']" in failures[0], failures
    # Types are judged against the real rows sharing the forged row's columns.
    assert _hits_check({**event, "process": "kinit"}), "a retyped event column must fail"


def test_only_columns_named_as_ids_are_id_columns():
    """Seventh round (re-ruled M14/M12): any column whose name ended in `id` was id-like, so
    `valid`, `paid` and `android` were ids; `pid`, `userId` and `host_id` are, those are not."""
    from defender.learning.branch.estate.checks import id_column

    for name in ("id", "pid", "PPID", "userId", "hostID", "host_id", "agent-id", "user.id",
                 "process.pid", "file_hash", "file.hash", "hash", "session_uuid", "GUID"):
        assert id_column(name), name
    for name in ("valid", "paid", "android", "void", "squid", "liquid", "", "hashtag"):
        assert not id_column(name), name


def _ids_check(real_rows: list[dict], forged: dict) -> list[str]:
    base = {"rows": real_rows}
    record = {"forged_id": "fg-1", "fact_id": "F", "system": "s", "row": forged}
    failures = _checks(base, {"rows": [*real_rows, forged]},
                       {"added": [{"forged_id": "fg-1", "fact_id": "F"}]},
                       staged={"fg-1": record})
    return [f for f in failures if f.startswith("check 3")]


def test_a_forged_id_collides_only_with_a_real_identifier():
    real = [{"pid": 4242, "total": 1}]
    assert _ids_check(real, {"pid": 1, "total": 5}) == []
    reused = _ids_check(real, {"pid": 4242, "total": 5})
    assert reused, "a forged pid equal to a real pid must fail check 3"
    assert "'pid'" in reused[0], reused
    # Across columns: a real `host_id` value reused in a forged `userId` is a real identifier.
    real = [{"host_id": "h-77", "userId": "u-1"}]
    assert _ids_check(real, {"host_id": "h-78", "userId": "h-77"})
    # `valid` is not an id column, so a real `valid` value is not a real identifier.
    real = [{"valid": "v-500", "id": "r-1"}]
    assert _ids_check(real, {"valid": "x", "id": "v-500"}) == []


def test_a_frozen_row_records_only_collisions_with_real_identifiers():
    from defender.learning.branch.estate.checks import frozen_id_collisions, run_checks

    row = {"pid": 1, "user_id": "u-9", "total": 2}
    record = {"forged_id": "fg-1", "fact_id": "F", "system": "s", "row": row}
    store = CheckStore(frozen={"fg-1": record}, staged={}, facts={}, rerun=lambda *_a: {})
    real = RealData(answers=[("s", {"rows": [{"pid": 5, "user_id": "u-9", "total": 1}]})])
    checked = run_checks({"rows": []}, {"rows": [row]},
                         {"added": [{"forged_id": "fg-1", "fact_id": "F"}]},
                         world=SimpleNamespace(facts=[SimpleNamespace(fact_id="F")]),
                         store=store, real_data=real)
    found = frozen_id_collisions(checked, store=store, real_data=real)
    assert [(e["column"], e["value"]) for e in found] == [("user_id", "u-9")], found
