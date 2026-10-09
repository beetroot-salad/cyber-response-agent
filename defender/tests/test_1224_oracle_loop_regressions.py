"""Regressions for PR #1232's review findings that the oracle's move onto the agent loop, the
turn-held context and the box-owned scratch folder dissolve (#1224).

Each test is red on the hand-rolled loop it replaces: a reply whose tool calls were left
unanswered, a verifier no deadline bounded, a `check` that read `$BASE` literally, an oracle-side
query run in whichever call entered last, a scratch folder no teardown removed.
"""
from __future__ import annotations

import ast
import subprocess
import threading
import time
from pathlib import Path
from typing import Any

import pytest

from defender.learning.branch.estate import oracle as oracle_mod
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

    def __init__(self, *replies: list[tuple[str, dict]]) -> None:
        self.replies = list(replies)
        self.refused: list[str] = []
        self.requests = 0
        self._model: Any = None

    @property
    def model(self) -> Any:
        if self._model is None:
            from pydantic_ai.models.function import FunctionModel
            self._model = FunctionModel(self._answer, model_name="provider-like")
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
