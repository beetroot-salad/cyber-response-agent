"""Regressions for PR #1232's review findings that structural changes dissolve (#1224).

First round: the oracle on the agent loop (no unanswered tool call, a bounded verifier, no
private import, one host checker), the turn-held context, the box-owned scratch folder.
Second round: a forged row is fresh or frozen, never both (a frozen row is not re-judged, and a
re-forged one is reused); one deadline over the whole attempt, tools included; one framing,
with its size cap, for every prompt; one recorder for every delivered row; a price settled
before any request. Fourth round: the python box and the limiter-wait record belong to one
attempt, the oracle-open clock mark to the process that wrote it; both price rows and the
charge settle outside the provider-failure path. Fifth round: the host stamps a forged row's
system and refuses a value array that is not one value per column; a claimed row backs the
fact it was forged for; a count entry accounts for one count cell; an entity reference is
found by value. A turn's outcome is decided in one place — a returned result wins over a late
cancel, collisions and the ledger row follow the commit and the turn's close, every other
error is a failed attempt or an unservable world, and a trace row counts once. Each test is
red on the code it replaces. Each pre-flight world runs on its own role models and in the
launcher's log context, budget.json has one locked writer, and every oracle setting is refused
before the question-writer. Sixth round: one size budget governs everything the oracle and the
verifier are sent — the family's example answers are capped, and a conversation past the
budget restarts from its prefix, the store's frozen rows carried in it; a failed world's
detail never reaches another world's judge prompt; the oracle and the verifier are told the
branch point (M27: told, and the verifier checks — no host rule); usage is priced by one rule (cached tokens once); a
bad argument to an oracle tool fails that call only; a count cell is the answer's own count,
never a document's field; a pre-flight thread's error stops the other worlds; a capped call
writes nothing; the family recording is parsed once per pre-flight.
"""
from __future__ import annotations

import ast
import json
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
from defender.run_repository import RunPaths
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

    told = reg.oracle._forge(dict(frozen), attempt, system="idp")

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
    oracle's budget never bounded it. Its price is settled when the oracle is configured, and
    a model with none is refused before any request goes out."""
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

    from defender.runtime import box_codec as codec
    from defender.runtime.box import _spec

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
    """Finding 9: the box outlived its attempt (kept for the sibling), and the reset after a
    deadline never ran, so the next attempt's python shared the abandoned frame's container and
    scratch. The box belongs to one attempt: started on its first python call, its container
    and scratch removed when the attempt ends, whatever the ending."""
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
    """Finding 9: by the time `_attempt` asked whether python was busy, the cancelled tool had
    cleared the flag, so the abandoned frame's box was kept and the next attempt ran in it. The
    attempt that the deadline ends stops its box (ending the frame); the next starts its own."""
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
    """Finding 10: one `waiting_since` slot served every thread on the door, so a thread of an
    abandoned attempt leaving `acquire` cleared the next attempt's wait in progress, and that
    attempt was cut off for limiter time the deadline excludes. Each attempt keeps its own
    wait record; a thread of another attempt cannot touch it."""
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


def test_an_oracle_open_mark_left_by_a_dead_process_does_not_stop_the_clock(tmp_path):
    """Finding 7: a sibling killed mid-turn left `oracle_open_since` in budget.json, and every
    later read counted `now - opened` as oracle-held, so a resume's elapsed time stood still and
    the wall-clock limit never tripped. (Sixth round: the open turn is no longer a file record
    at all, but this process's memory.) A turn a process that has since exited opened holds
    nothing here; a turn this live process holds still pauses the clock (control)."""
    import sys

    from defender.hooks import budget_enforcer as be

    run_dir = tmp_path / "run"
    run_dir.mkdir()
    be.open_budget(run_dir, "r-1")
    root = Path(be.__file__).resolve().parents[2]
    subprocess.run(
        [sys.executable, "-c", "import sys; from pathlib import Path; "
         "from defender.hooks.budget_enforcer import oracle_turn_opened; "
         "oracle_turn_opened(Path(sys.argv[1]))", str(run_dir)],
        check=True, env={**os.environ, "PYTHONPATH": str(root)})

    def elapsed() -> float | None:
        return be._elapsed({**be.read_budget(run_dir),
                            be.ENFORCEMENT_HELD_KEY: be.oracle_held(run_dir)})

    first = elapsed()
    time.sleep(0.3)
    later = elapsed()
    assert first is not None
    assert later is not None
    assert later - first >= 0.25, f"a dead writer's mark froze the clock ({first} -> {later})"

    be.oracle_turn_opened(run_dir)
    try:
        held = elapsed()
        time.sleep(0.3)
        assert elapsed() - held < 0.1, "a live turn no longer holds"
    finally:
        be.oracle_turn_closed(run_dir)


def test_a_failure_closing_the_oracle_mark_does_not_replace_the_unservable_abort(tmp_path,
                                                                               monkeypatch):
    """Finding 7, second half: `oracle_turn_closed` raising in the turn's `finally` replaced an
    in-flight `OracleUnservable`, which was then filed as a fault row instead of ending the
    sibling. The abort leaves the turn as itself."""
    from defender.learning.branch.estate import registry as registry_mod

    def broken(_run_dir: Path) -> None:
        raise OSError("budget.json lock timed out")

    # The close must fail mid-turn after the open succeeded; no file fault does that (a missing
    # or odd budget record makes both a no-op, and permissions do not bind root).
    monkeypatch.setattr(registry_mod, "oracle_turn_closed", broken)  # lint-monkeypatch: ok — only seam for a close that fails after its open
    est = S.estate(tmp_path)
    est.answer("idp", "query", ALICE, ALICE_ROWS)
    reg = S.world_registry(S.episode_v2(tmp_path), "b", est, oracle=S.oracle(S.text_only("no.")),
                           verifier=S.passing_verifier(), retry_cap=1)

    with pytest.raises(oracle_mod.OracleUnservable):
        S.call(reg, "idp", "query", est.ctx(tmp_path / "inv"), q="user:alice")


def test_an_unpriced_verifier_is_refused_before_the_oracles_first_request(tmp_path):
    """Finding 6: the verifier's price row was settled only when its agent was first built,
    after the oracle's paid attempt, so pre-flight paid and then aborted. Both roles' rows are
    settled when the oracle is configured, before any request."""
    est = S.estate(tmp_path)
    est.answer("idp", "query", ALICE, ALICE_ROWS)
    model = ProviderLikeModel([("submit", {"served": ALICE_ROWS, "claim": S.EMPTY_CLAIM})])
    unpriced = ProviderLikeModel([("verdict", {"passed": True, "reason": "ok"})],
                                 name="no-such-verifier-model")

    with pytest.raises(oracle_mod.OraclePricingError, match="verifier"):
        _configure_and_ask(tmp_path, est, model, unpriced)
    assert model.requests == 0, "the oracle paid for a request before the refusal"


def test_a_failing_trace_write_still_charges_and_is_not_a_model_failure(tmp_path):
    """Finding 8: the charge ran inside the provider-failure `try`, so a failed `trace.jsonl`
    append was reported as a failed model request, the paid response's cost never reached
    `spent`, and the verifier re-asked (paying again). Only the model call is guarded: the
    spend is counted whatever the trace write does, and the answer is served."""
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
    """Fifth-round finding 3: check 2 found its real rows under the `system` the oracle typed
    into `forge`, so a misspelt system ("Elastic" for idp) found none and passed a row of any
    shape (D2). The host stamps the call's system: the misshapen row fails check 2, and an
    honest row is frozen under the call's system (control)."""
    with pytest.raises(oracle_mod.OracleUnservable) as refused:
        _forge_and_serve(tmp_path / "a", {"ts": "2026-07-28T15:20:00Z", "totally": "different"})
    assert "check 2" in refused.value.detail, refused.value.detail

    reg, served = _forge_and_serve(tmp_path / "b", _HONEST)
    assert served == {"rows": [_ALICE_ROW, _HONEST]}
    assert reg.store.frozen["fg-1"]["system"] == "idp"


def test_an_esql_value_array_of_the_wrong_length_is_refused_at_forge(tmp_path):
    """Fifth-round finding 4: a value array whose length is not the ES|QL answer's column count
    was staged as a raw list; the diff left it unzipped and check 2 skipped it, so a 3-value
    row in a 4-column answer was served. `forge` refuses it with a legible reason, nothing is
    staged, and the submission naming it fails."""
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
    """Fifth-round finding 4, the checks' side: an ES|QL answer nested below the top level
    gives `forge` no column names, so a short value array reached the checks raw and check 2
    skipped every non-mapping row. A forged row in an ES|QL table that is not one value per
    column fails check 2; a full row passes (control)."""
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
    """Fifth-round finding 7: a claim's `added[].fact_id` was compared with the forge record's
    only for frozen rows, so a row forged this attempt for f1 could be claimed — and shown to
    the verifier — as backing f2, then frozen under f1. Fresh or frozen, the claimed fact must
    be the record's; the right fact passes (control)."""
    wrong = _two_fact_checks("f2", frozen=frozen)
    assert any(f.startswith("check 4") and "'f1', not 'f2'" in f for f in wrong), wrong
    assert _two_fact_checks("f1", frozen=frozen) == []


def test_a_star_count_does_not_cover_an_edit_to_a_real_rows_field():
    """Fifth-round finding 2: a `counts` entry whose base/served matched a changed value
    claimed it whatever the cell, and was never used up — one "*" entry (1 -> 2) covered the
    answer's total AND edits of a real row's severity and risk from 1 to 2. Each count entry
    accounts for one count cell, and a real row's ordinary field is none: the edits fail
    check 1; the total alone, counted, passes (control)."""
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
    """Fifth-round finding 2, consumption: one count entry covered every changed count cell
    with its base and served. Two totals moving 1 -> 2 need two entries; with two, the answer
    passes (control)."""
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
    """Fifth-round finding 15: an entity reference was confirmed by scanning every flat real
    row, though `RealData.by_value` indexes rows by value. It is looked up by value; the
    reference still exempts the reused id."""
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
    """Fifth-round finding 9: `_within_deadline` reported `(False, result)` whenever its scope
    caught the deadline's cancel, so a work() that had returned (a verified submission) as the
    cancel landed was thrown away as 'the turn deadline passed'. A returned result wins."""
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
    """Fifth-round finding 9, the side effect: a verified submission's frozen-row collisions
    were written to collisions.jsonl before its commit, so an answer whose commit failed (never
    served) left collision rows for the judge. They are recorded only once the answer commits
    (control: a committed one records its collision)."""
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
    """Fifth-round finding 6: the ledger row was written inside the turn, so a clock-mark close
    that raised on the turn's normal exit replaced the answer after the row recorded it as
    delivered (against N12). The row is written after the turn closes: a close failure leaves
    no row, and the committed answer is served, with its row, on the next ask."""
    from defender.learning.branch.estate import registry as registry_mod

    real_close = registry_mod.oracle_turn_closed
    closes: list[Path] = []

    def fails_once(run_dir: Path) -> None:
        closes.append(run_dir)
        if len(closes) == 1:
            raise OSError("budget.json lock timed out")
        real_close(run_dir)

    # The close must fail after its open succeeded; no file fault does that (see the
    # round-four close test).
    monkeypatch.setattr(registry_mod, "oracle_turn_closed", fails_once)  # lint-monkeypatch: ok — only seam for a close that fails after its open
    est = S.estate(tmp_path)
    est.answer("idp", "query", ALICE, ALICE_ROWS)
    ep = S.episode_v2(tmp_path)
    o = S.oracle(S.submit(ALICE_ROWS, S.EMPTY_CLAIM))
    reg = S.world_registry(ep, "b", est, oracle=o, verifier=S.passing_verifier(), retry_cap=1)
    ctx = est.ctx(tmp_path / "inv")

    with pytest.raises(OSError, match="lock timed out"):
        S.call(reg, "idp", "query", ctx, q="user:alice")
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
    """Fifth-round finding 10: `serve()` mapped only a spent budget; a `LimiterStateError`
    raised by the oracle's `run_query` escaped `serve_one` as an ordinary exception, filed as
    a fault row the investigator read. The oracle's own limiter failing is a failed attempt:
    the next attempt serves the call."""
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
    """Fifth-round finding 10, the other tier: any other error escaping an attempt (here the
    door's verb lookup breaking) reached the investigator as itself. It is logged and the call
    ends unservable (`fault`), a `ServingAbort` that never becomes a fault row."""
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
    """Fifth-round finding 12: after an append that landed its first row whole and tore the
    second, the next charge rewrote both, and a resumed store counted the first row twice.
    Each trace row carries an id and is counted once: the resumed `spent` is exact."""
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


def _calibration_seen(tmp_path: Path, monkeypatch: Any) -> list[dict]:
    """Run pre-flight over the default family (fact worlds b and c) with production's role
    models (`oracle=None`, `verifier=None`), each world's calibration replaced by a recorder of
    the registry it was handed and the log context it ran in. No model is ever built."""
    from defender import _log
    from defender.learning.branch import cli
    from defender.learning.branch.estate import registry as registry_mod

    seen: list[dict] = []
    lock = threading.Lock()

    def record(registry: Any, *_args: Any, **_kw: Any) -> None:
        with lock:
            seen.append({"world": registry.world.label,
                         "family_answers": registry._family_answers,
                         "oracle": registry.oracle.oracle_model,
                         "verifier": registry.oracle.verifier_model,
                         "context": dict(_log.current_context())})

    # The only seam inside a world's thread that runs before any model request.
    monkeypatch.setattr(registry_mod, "calibrate_one", record)  # lint-monkeypatch: ok — observes each world's registry from inside its pre-flight thread
    est = S.estate(tmp_path)
    _base, src = S.source_run(tmp_path, est, calls=[S.default_calls()[0]])
    ep = S.episode_v2(tmp_path, doc=S.family_v2(source_run_dir=str(src)),
                      base_rows=[S.captured("idp", "query", ALICE, ALICE_ROWS)])
    with _log.log_context(run_id="launch-run", tenant_id=S.FIXTURE_TENANT):
        record_ = cli.preflight_replay(ep, roster=est.roster(), tenant=est.run_tenant(),
                                       rate=1e6)
    assert record_["outcome"] == "accepted", record_
    return seen


def test_each_preflight_world_calibrates_on_its_own_role_models(tmp_path, monkeypatch):
    """Fifth-round finding 1: pre-flight built one oracle side for the pass, so every world —
    each on its own thread, each attempt on that thread's own event loop — shared one oracle
    and one verifier model, and so one provider and HTTP client across loops. Each world's
    oracle side is now built in its own thread: no two worlds hold the same model object."""
    seen = _calibration_seen(tmp_path, monkeypatch)

    assert sorted(s["world"] for s in seen) == ["b", "c"]
    assert len({id(s["oracle"]) for s in seen}) == 2, "two worlds share one oracle model"
    assert len({id(s["verifier"]) for s in seen}) == 2, "two worlds share one verifier model"


def test_a_preflight_world_thread_keeps_the_launch_s_log_context(tmp_path, monkeypatch):
    """Fifth-round finding 13: the pre-flight pool submitted each world's calibration without
    the launcher's context, so its log lines lost the run and tenant. Each world runs in a copy
    of it."""
    seen = _calibration_seen(tmp_path, monkeypatch)

    assert [s["context"] for s in seen] == [
        {"run_id": "launch-run", "tenant_id": S.FIXTURE_TENANT}] * 2


def test_an_accounted_call_cannot_resurrect_a_closed_oracle_mark(tmp_path, monkeypatch):
    """Fifth-round finding 5: `account_call` read budget.json, then wrote it back with
    `write_atomic` under a process-local lock, while the oracle-turn marks are written under the
    file lock. An `oracle_turn_closed` landing between its read and its write was overwritten:
    the open mark came back (the investigator's clock paused for good) and the held seconds were
    lost. (Sixth round: the oracle's clock state left budget.json for host state, so the count
    and the close no longer share a record.) A close landing mid-count still credits its
    seconds, and budget.json carries no oracle field either way.

    Driven in the problematic order, not raced: the close is started from inside the count, once
    it has read the state."""
    from defender.hooks import budget_enforcer as be

    run_dir = tmp_path / "run"
    run_dir.mkdir()
    be.open_budget(run_dir, "r-1")
    be.oracle_turn_opened(run_dir)
    closer = threading.Thread(target=be.oracle_turn_closed, args=(run_dir,))
    real_count = be._valid_count

    def count_then_close(value: object) -> int | None:
        if not closer.is_alive() and closer.ident is None:
            closer.start()
            closer.join(timeout=0.5)
        return real_count(value)

    # `_valid_count` is the one step every version of the count runs after reading the state.
    monkeypatch.setattr(be, "_valid_count", count_then_close)  # lint-monkeypatch: ok — the only point between the count's read and its write
    be.account_call(run_dir, "r-1", "bash", limits=be.DEFAULT_LIMITS, tier="core")
    closer.join(timeout=10)
    assert not closer.is_alive()

    state = be.read_budget(run_dir)
    assert not {"oracle_open_since", be.ORACLE_HELD_KEY} & set(state), (
        f"budget.json carries oracle clock state: {state}")
    assert state["tool_calls"] == 1, state
    sidecar = json.loads(RunPaths(run_dir).oracle_held(tmp_path).read_text(encoding="utf-8"))
    assert isinstance(sidecar.get(be.ORACLE_HELD_KEY), float), (
        "the closed turn's held seconds were lost")


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
    """Fifth-round finding 8: the oracle's knobs and both roles' pricing rows were first judged
    in pre-flight, after the question-writer was paid for, leaving an episode with a family and
    no outcome. They are judged in `preflight_episode`, the launch's one refusal block, by the
    rules pre-flight applies: the question-writer is never called."""
    monkeypatch.setenv(S.T.EPISODES_BASE_ENV, str(tmp_path / "episodes-root"))
    S.T.isolate_learning_state(tmp_path, monkeypatch)
    monkeypatch.setenv(knob, value)
    est = S.estate(tmp_path)
    questioner = S.questioner_for()

    run = S.launch(tmp_path, est, questioner=questioner)

    assert run.rc != 0
    assert named in run.message, run.message
    assert questioner.calls == 0, "the question-writer was paid for before the refusal"


# --------------------------------------------------------------------------------------
# Sixth round: the oracle box binds nothing of the repository; the oracle's clock state is
# host state the box cannot write.
# --------------------------------------------------------------------------------------


def test_the_oracle_box_binds_nothing_of_the_repository_and_no_env_file(tmp_path, monkeypatch):
    """Sixth-round finding 1: the oracle box bound the whole repository root read-only, its
    `.env` (live credentials) included, so one `python` turn fed injected telemetry could read
    the secrets and hand them to the oracle model. The box now binds a fresh runner folder
    holding only the modules its transport imports, at the checkout's path, and its scratch
    folder: no bind source lies under or over the checkout.

    Driven through the production start against a `docker` on PATH that records every argv
    and refuses the create (no daemon here shares this tree's path). The process PATH carries
    it, as `_start_oracle_box_recorded` does: the start's docker calls resolve `docker` there."""
    from defender.runtime.box import _oracle as box_oracle
    from defender.tests.live_oracle_1224 import test_1224_oracle_context_and_box as B

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


def _enforced_state(run_dir: Path, started_ago: float) -> dict:
    """The state the investigator's budget hooks judge, built the production way."""
    from defender.hooks.budget_enforcer import read_budget
    from defender.runtime.driver._budget import _budget_state_for_enforcement

    deps = SimpleNamespace(run_dir=run_dir, budget_started_monotonic=time.monotonic() - started_ago)
    return _budget_state_for_enforcement(read_budget(run_dir), deps)  # type: ignore[arg-type]


def _box_written_budget(run_dir: Path, **over: Any) -> None:
    """budget.json as the box (root on the run-dir mount) can rewrite it: the counters it had,
    plus whatever oracle fields the box plants."""
    from defender.hooks import budget_enforcer as be

    be.open_budget(run_dir, "r-1")
    state = be.read_budget(run_dir)
    state.update(over)
    (run_dir / "budget.json").write_text(json.dumps(state), encoding="utf-8")


#: Every oracle clock field the box could plant: a huge credited total, an open mark naming
#: pid 1 (always alive) with no start time, and the enforcement key itself.
_PLANTED = {"oracle_held_seconds": 1e12,
            "oracle_open_since": {"at": 0, "pid": 1, "started": None},
            "_host_oracle_held": 1e12}


def test_a_box_written_budget_record_cannot_stop_the_investigators_clock(tmp_path):
    """Sixth-round finding 2: the investigator's elapsed time subtracted `oracle_held_seconds`
    and `oracle_open_since` read from budget.json, which the box can write: a huge total, or an
    open mark naming pid 1 with no start time, drove elapsed hugely negative and no wall-clock
    limit ever tripped. Oracle-held time is host state now; nothing in budget.json moves it."""
    from defender.hooks import budget_enforcer as be

    run_dir = tmp_path / "run"
    run_dir.mkdir()
    _box_written_budget(run_dir, **_PLANTED)
    limits = {**be.DEFAULT_LIMITS, "wall_clock_timeout": 50, "grace_seconds": 10}

    state = _enforced_state(run_dir, started_ago=100)
    elapsed = be._elapsed(state)
    assert elapsed is not None
    assert elapsed >= 99, f"box-written oracle fields moved the investigator's clock: {elapsed}"
    assert be.should_refuse(state, "query", "core", limits)
    assert be.tail_exhausted(state, limits)


def test_an_unbranched_runs_clock_ignores_oracle_fields(tmp_path):
    """Sixth-round finding 2, second half: the subtraction ran for every run, branched or not,
    so the planted fields stopped even an unbranched run's clock — through every reader,
    lead-0's gate on the bare budget record included. A run no oracle served excludes
    nothing."""
    from datetime import UTC, datetime, timedelta

    from defender.hooks import budget_enforcer as be

    run_dir = tmp_path / "run"
    run_dir.mkdir()
    origin = (datetime.now(UTC) - timedelta(seconds=1000)).isoformat()
    _box_written_budget(run_dir, created_at=origin, started_at=origin, **_PLANTED)
    limits = {**be.DEFAULT_LIMITS, "wall_clock_timeout": 50, "grace_seconds": 10}

    bare = be.read_budget(run_dir)
    assert be._elapsed(bare) >= 999, "the bare budget record's oracle fields were subtracted"
    assert be.tail_exhausted(bare, limits)
    assert be.oracle_held(run_dir) == 0.0
    assert be._elapsed(_enforced_state(run_dir, started_ago=1)) >= 999


def test_a_link_planted_at_budget_json_does_not_fault_an_oracle_turn(tmp_path):
    """Sixth-round finding 11: opening and closing an oracle turn wrote budget.json through
    `update_json_locked`, which refuses a link — so a link the box planted at budget.json made
    every oracle turn raise before it ran, a fault charged to the circuit breaker that aborted
    the run. A turn writes nothing in the run dir now: it is served, and its row recorded."""
    est = S.estate(tmp_path)
    est.answer("idp", "query", ALICE, ALICE_ROWS)
    ep = S.episode_v2(tmp_path)
    reg = S.world_registry(ep, "b", est, oracle=S.oracle(S.submit(ALICE_ROWS, S.EMPTY_CLAIM)),
                           verifier=S.passing_verifier(), retry_cap=1)
    run_dir = tmp_path / "inv"
    ctx = est.ctx(run_dir)
    target = tmp_path / "elsewhere.json"
    target.write_text(json.dumps({"tool_calls": 0}), encoding="utf-8")
    (run_dir / "budget.json").symlink_to(target)

    assert S.call(reg, "idp", "query", ctx, q="user:alice") == ALICE_ROWS
    assert len(S.ledger_rows(ep, "b")) == 1
    assert (run_dir / "budget.json").is_symlink()


def test_a_link_or_garbage_at_the_held_record_neither_crashes_nor_pauses(tmp_path):
    """Sixth-round finding 11, at the new location: the host-only held record is beside the run
    dir, out of the box's reach, but a link or garbage there still reads as nothing credited
    (the clock runs; it never pauses) and a turn whose credit cannot be written still closes."""
    from defender.hooks import budget_enforcer as be

    run_dir = tmp_path / "run"
    run_dir.mkdir()
    be.open_budget(run_dir, "r-1")
    held = RunPaths(run_dir).oracle_held(tmp_path)

    held.write_text("not json {", encoding="utf-8")
    assert be.oracle_held(run_dir) == 0.0
    be.oracle_turn_opened(run_dir)
    be.oracle_turn_closed(run_dir)
    assert json.loads(held.read_text(encoding="utf-8"))[be.ORACLE_HELD_KEY] >= 0.0

    held.unlink()
    target = tmp_path / "planted.json"
    target.write_text(json.dumps({be.ORACLE_HELD_KEY: 1e12}), encoding="utf-8")
    held.symlink_to(target)
    assert be.oracle_held(run_dir) == 0.0, "a linked held record paused the clock"
    be.oracle_turn_opened(run_dir)
    be.oracle_turn_closed(run_dir)  # the refused write is logged, not raised
    assert be.oracle_held(run_dir) == 0.0
    assert json.loads(target.read_text(encoding="utf-8")) == {be.ORACLE_HELD_KEY: 1e12}


# -- sixth round --------------------------------------------------------------------------------

_SIX_MARK = "EXAMPLE6-HUGE"


def _big_rows(user: str, mark: str, n: int = 300) -> dict:
    return {"rows": [{"user": user, "event_id": f"e-{user}-{k:05d}", "action": "logon",
                      "note": f"{mark}-{k:05d}-" + "x" * 80} for k in range(n)]}


def test_oversized_family_example_answers_are_capped(tmp_path):
    """Sixth-round finding 9: `_prefix` framed the family's example answers whole, past the cap
    every other framed value goes through, so one large recorded answer put megabytes into
    every conversation. The family block now shares one fixed cap, its examples shown as their
    head, saying so."""
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
    """Sixth-round finding 5: the conversation was append-only across calls and restarted only
    after `restart_after` attempts, never by size, so a few large answers carried it past the
    model's window and every later request failed at the provider. A call that would take it
    past the budget now starts from the prefix; the rows frozen so far live in the store and
    are shown in the fresh prefix, so the later call still serves them. The budget is set
    small (each answer here is ~40k characters) so the test stays fast."""
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
    """Sixth-round finding 7: the family text put every failed world's `detail` into every
    judged world's prompt; that detail is the oracle's last refusal, quoting the rows it forged
    for that world's facts. A failed world now shows its label, reason word and failing call,
    never its detail."""
    from defender.learning.judge import render as render_mod

    ep = S.judged_episode(tmp_path / "judged", labels=("a", "c"))
    S.world_record(ep, "b", call={"system": "idp", "verb": "query",
                                  "params": S.query_params("user:alice")},
                   detail='Submission refused: check 1: an unclaimed row was added '
                          '{"event_id": "e-FORGEDLEAK", "note": "FORGEDLEAK-6"}')

    sections = render_mod.render(ep, "c").as_prompt_sections()

    family = sections["family"]
    assert "world b" in family, family
    assert "FORGEDLEAK" not in "\n".join(sections.values()), family


def test_the_oracle_and_the_verifier_are_told_the_branch_point(tmp_path):
    """Sixth-round finding 8 (M27: the oracle is told forged rows lie at or before `as_of`, the
    verifier checks; no host rule): neither model was told the branch-point time, so nothing
    kept a forged row from being dated after it. Both prompts now carry it."""
    est = S.estate(tmp_path)
    est.answer("idp", "query", ALICE, ALICE_ROWS)
    o = S.oracle(S.submit(ALICE_ROWS, S.EMPTY_CLAIM))
    v = S.passing_verifier()
    reg = S.world_registry(S.episode_v2(tmp_path), "b", est, oracle=o, verifier=v, retry_cap=1)

    assert S.call(reg, "idp", "query", est.ctx(tmp_path / "inv"), q="user:alice") == ALICE_ROWS
    point = S.AS_OF_DT.isoformat().replace("+00:00", "Z")
    for who, seen in (("oracle", o.seen[0]), ("verifier", v.seen[0])):
        assert f"branch point is {point}" in seen, f"the {who} was not told the branch point"
        assert "at or before" in seen, f"the {who} was not told rows lie at or before it"


# --- sixth round ---------------------------------------------------------------------------


def test_cached_tokens_are_billed_once(tmp_path):
    """Sixth-round finding 4: `Oracle.charge` passed pydantic-ai's `input_tokens`, which already
    includes the cache reads and writes, beside the cache counts, so every cached token was
    billed at the full input rate and again at its cache rate. Usage reaches `usage_cost`
    through the one rule (`billed_usage`) the wire log's pricing uses."""
    from defender._pricing import usage_cost

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
    """Sixth-round finding 6: code holding a NUL (or a lone surrogate) made the box codec raise
    `ValueError` outside the python tool's handling; the agent run, the attempt and `serve`
    took it for a fault and the world went unservable. A bad argument to an oracle tool is
    that call's feedback, answered in the tool wrapper: the oracle is told, no box starts, and
    the attempt goes on to serve."""
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
    """Sixth-round finding 12: a `*` counts entry claimed any whole number outside a table row,
    so a single-document answer's ordinary field (`failed_logins` 3 -> 10) passed check 1 on a
    count claim alone, and the verifier saw a count, not a changed field. A count cell is the
    answer's own count of its rows (a count-named cell, a total, an aggregation's value, a
    group-to-count map): the edit needs a claimed change (control), and a named group spelled
    as the field's key claims it no more than "*" does."""
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
    """Sixth-round finding 13: an exception other than a world's own failure in one world's
    calibration thread did not set `stop`, so the other worlds went on paying for every call
    before the launch aborted with no outcome record. Any error in a world's thread stops the
    rest before their next paid turn; the launch still raises it and writes no outcome.

    World b's oracle store cannot be created (a file squats `oracle/b`): its first call fails
    at once, while world c's first oracle answer takes 1.5 s (margin for a loaded runner to
    schedule b's thread), so c has a second paid turn to skip."""
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
        cli.preflight_replay(ep, roster=est.roster(), tenant=est.run_tenant(), oracle=o.model,
                             verifier=S.passing_verifier().model, rate=1e6)

    # 0 when b failed before c's first turn began, 1 when that turn was already under way.
    assert o.requests <= 1, f"world c paid {o.requests} oracle turns after b's thread failed"
    assert not (ep / "outcome.yaml").exists()


def test_a_call_at_the_cap_writes_nothing(tmp_path):
    """Sixth-round finding 14: `account_call` rewrote budget.json on every call, at the cap
    too, where nothing changes — so a write failure there climbed the accounting-failure kill
    circuit over a count never made. A capped call reads the state and writes nothing."""
    import json

    from defender.hooks import budget_enforcer as be
    from defender.run_repository import RunPaths

    run_dir = tmp_path / "run"
    run_dir.mkdir()
    limits = {**be.DEFAULT_LIMITS, "max_tool_calls": 2}
    budget = RunPaths(run_dir).budget
    capped = json.dumps({**be.make_budget_state("r-1"), "tool_calls": 2})
    budget.write_text(capped, encoding="utf-8")

    state = be.account_call(run_dir, "r-1", "bash", limits=limits, tier="core")

    assert state["tool_calls"] == 2
    assert budget.read_text(encoding="utf-8") == capped, "a capped call rewrote budget.json"


def test_preflight_parses_the_family_recording_once_for_every_world(tmp_path, monkeypatch):
    """Sixth-round finding 15: every world's registry re-read and re-parsed the whole family
    recording, so pre-flight parsed it once per world on top of each ledger's own read.
    Pre-flight parses it once and hands that one parse to every world's registry."""
    seen = _calibration_seen(tmp_path, monkeypatch)

    answers = [s["family_answers"] for s in seen]
    assert len(answers) == 2
    assert answers[0]
    assert answers[0] == answers[1]
    assert all(a is b for a, b in zip(answers[0], answers[1], strict=True)), (
        "each world parsed the family recording itself")
