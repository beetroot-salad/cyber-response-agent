"""Regressions for PR #1232's review findings that structural changes dissolve (#1224).

First round: the oracle on the agent loop (no unanswered tool call, a bounded verifier, no
private import, one host checker), the turn-held context, the box-owned scratch folder.
Second round: a forged row is fresh or frozen, never both (a frozen row is not re-judged, and a
re-forged one is reused); one deadline over the whole attempt, tools included; one framing,
with its size cap, for every prompt; one recorder for every delivered row; a price settled
before any request. Each test is red on the code it replaces.
"""
from __future__ import annotations

import ast
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
from defender.runtime.box._oracle import OracleBox, stop_oracle_box
from defender.runtime.box._spec import BoxSpec, _DockerTransport
from defender.tests.live_oracle_1224 import _spec1224 as S

ALICE = S.query_params("user:alice")
ALICE_ROWS = S.default_calls()[0].payload
BOB = S.query_params("user:bob")
BOB_ROWS = {"rows": [{"user": "bob", "event_id": "e-200", "action": "logon", "host": "web-2",
                      "ts": "2026-03-01T09:00:00Z"}]}
LOOKUP_ALICE = {"entity": "alice", "risk": "low", "record_id": "r-0001"}


class ProviderLikeModel:
    """A model double that refuses a conversation as a provider does (HTTP 400, "tool_use ids
    were found without tool_result blocks"): every tool call of a reply must be answered in the
    request right after it. Its replies are raw `ModelResponse` parts, so one reply can carry
    several tool calls — what a real model does and `ScriptedModel` cannot."""

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
    """Finding 1: a reply of [submit, forge] whose submit is refused left forge unanswered, and
    the provider refused every later request of the conversation — the call went unservable.
    The agent loop answers every call of the reply, so the retry goes out and is served."""
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
    """Finding 1, the tool path: `python` with no sandboxed box ends the attempt; a forge in
    the same reply after it was never answered. It now is (as not run), and the next attempt
    is served."""
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
    """Finding 2: the verifier's requests ran with no deadline, while the investigator's clock
    was paused, so a hung provider stream hung the sibling. They now run under the same guard
    as the oracle's: the pass ends at the deadline and the attempt fails, naming why."""
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
    """CI race (test_conc_13): a call queued behind the failing one raised unservable for its
    own call. Both aborts surface together and the first one found writes the world's record,
    which then named a call the oracle never saw. Every later call raises the world's one
    failure."""
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


def test_the_oracle_imports_nothing_private_from_pydantic_ai():
    """Finding 4: `pydantic_ai._utils.abandon_threads_on_cancel` is absent from pydantic-ai
    2.19, which the declared floor allowed; every oracle turn then failed as a 'model request
    failure'. The oracle reaches pydantic-ai only through its public modules."""
    tree = ast.parse(Path(oracle_mod.__file__).read_text(encoding="utf-8"))
    private = [node.module for node in ast.walk(tree)
               if isinstance(node, ast.ImportFrom) and node.module
               and node.module.startswith("pydantic_ai")
               and any(part.startswith("_") for part in node.module.split("."))]
    assert private == []


def test_the_advisory_check_resolves_the_base_handle_as_submit_does(tmp_path):
    """Finding 6: `check(served="$BASE")` diffed the base against the literal string and
    reported a shape change, while the same submission passed at `submit`. Both run one host
    checker, which resolves the handle."""
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
    """Finding 7: a call entering the registry overwrote the shared context before it queued
    for the turn lock, so the turn already running issued its remaining oracle-side queries in
    the newcomer's context. The context now belongs to the turn, set under the lock."""
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
    """Finding 10: each box's host scratch folder was kept in a module-wide map that nothing
    cleared, and teardown removed only the container. The box now owns its folder, and
    stopping it removes both — the folder even when the container's removal fails."""
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
    """Second-round finding 1: real data seen after a row froze (a column it lacks) failed
    check 2 on every later call serving it, and a frozen row cannot be changed — the world went
    unservable. Check 2 judges fresh rows only; the same row fresh still fails (control)."""
    assert _shape_failures(frozen={"fg-1": _FROZEN}, staged={}) == []
    assert _shape_failures(frozen={}, staged={"fg-1": _FROZEN}) != []


def test_re_forging_a_frozen_row_reuses_it_instead_of_staging_a_copy(tmp_path):
    """Second-round finding 9: re-forging a frozen row with its exact content staged a copy,
    and a row both frozen and staged escaped check 3 (frozen) and the collision recorder
    (staged). A row is now fresh or frozen, never both."""
    est = S.estate(tmp_path)
    reg = S.world_registry(S.episode_v2(tmp_path), "b", est, oracle=S.oracle(),
                           verifier=S.passing_verifier())
    frozen = {**_FROZEN, "fact_id": "f1", "system": "idp"}
    reg.store.commit(forged=[frozen], facts=[], answer=None)
    attempt = oracle_mod._Attempt()

    told = reg.oracle._forge(dict(frozen), attempt)

    assert attempt.forged == {}, "the frozen row was staged as a fresh copy"
    assert "already frozen" in told, told


def test_the_verifier_is_shown_a_large_unchanged_answer_once_and_capped(tmp_path):
    """Second-round finding 2: the oracle saw a large base answer capped, but the verifier was
    handed it in full twice (base and served), past what a request carries. Every prompt frames
    answers through one capped renderer, and an unchanged answer is not sent a second time."""
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
    """Second-round finding 6: the deadline bounded model requests only, so a tool running
    long (a hung tenant read, a box run) held the turn — and the investigator's paused clock —
    past it. One deadline now covers the whole attempt, tools included."""
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
    """Second-round finding 5: a model with no pricing row was charged $0 per response, so the
    oracle's budget never bounded it. Its price is settled when its agent is built, and a model
    with none is refused before any request goes out."""
    est = S.estate(tmp_path)
    est.answer("idp", "query", ALICE, ALICE_ROWS)
    model = ProviderLikeModel([("submit", {"served": ALICE_ROWS, "claim": S.EMPTY_CLAIM})],
                              name="no-such-model")
    reg = S.world_registry(S.episode_v2(tmp_path), "b", est, oracle=model,
                           verifier=S.passing_verifier(), retry_cap=1)

    with pytest.raises(oracle_mod.OraclePricingError):
        S.call(reg, "idp", "query", est.ctx(tmp_path / "inv"), q="user:alice")
    assert model.requests == 0


def test_an_undelivered_control_world_call_leaves_no_row(tmp_path):
    """Second-round finding 7: the no-facts (control) world wrote its passthrough row itself,
    without the rule that an undelivered call leaves no row (N12). Every delivered row now goes
    through one recorder."""
    est = S.estate(tmp_path)
    est.answer("idp", "query", ALICE, ALICE_ROWS)
    ep = S.episode_v2(tmp_path)
    reg = S.world_registry(ep, "a", est)
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
    """Fourth-round finding 2: an ES|QL answer (`columns` + `values`) could never be changed:
    `forge` refused a value-array row and check 1 recognised only mapping rows, so every added
    row was unclaimed. A value array zips with the column names into one row model; a forged
    ES|QL row is staged, matched, shape-checked and served."""
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
    """Fourth-round finding 3: check 5 counted the first list in a side query's answer, which
    for ES|QL is `columns`: a removal selecting 2 rows over 4 columns read as 4. It counts the
    answer's rows, and finds the removed row among them."""
    base = _esql(_ESQL_ROWS)
    served = _esql(_ESQL_ROWS[:1])
    side = {"system": "s", "verb": "esql", "params": {"query": "FROM logs-* | WHERE host == 1"}}
    claim = {"removed": [{"row": _ESQL_ROWS[1], "side_query": side, "count": 2}],
             "counts": [{"group": "*", "base": 2, "added": 0, "removed": 1, "served": 1}]}

    failures = _checks(base, served, claim, rerun=lambda *_a: _esql(_ESQL_ROWS))

    assert failures == [], failures


def test_esql_answers_projecting_other_columns_are_separate_tables_for_check_2():
    """Fourth-round finding 2, check 2: every ES|QL answer of a system sat at one place
    (`values`), so the union of all projections ever seen was required of each forged row. An
    ES|QL table is its column set: an honest row of this projection passes, and a mistyped
    one still fails (control)."""
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
    """Fourth-round finding 4: check 3 judged only a forged row's top-level scalars, so a
    nested id (`process.entity_id`) copied from a real event passed. Rows are judged by their
    flat columns; the same row with a fresh id passes (control)."""
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
    """Fourth-round finding 4, the collision record: a frozen row serving a nested id that
    real data carries was never recorded for the judge. It is, with the column spelled flat,
    off the submission's own structural diff."""
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
