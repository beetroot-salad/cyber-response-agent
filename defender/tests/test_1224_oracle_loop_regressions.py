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

from defender import run as run_mod
from defender._episode_handle import Episode
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
    """CI race (test_conc_13): a call queued behind the failing one raises unservable for its
    own call (s_p158). Both aborts surface together and the first one found writes the world's
    record, which then named a call the oracle never saw. A later call's abort now carries the
    world's first failure, and the record is written from it."""
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

    assert dict(later.value.call[2])["q"] == "user:bob"
    assert later.value.world is first.value
    with Episode.open(S.episode_v2(tmp_path / "rec")) as episode:
        run_mod._record_unservable_world(episode, SimpleNamespace(label="b"), later.value)
        assert S.read_world_record(episode.dir, "b")["call"]["params"]["q"] == "user:alice"


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
