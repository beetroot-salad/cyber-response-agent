"""One world's oracle and verifier serve call after call through real model clients, each attempt on an event loop of
its own.

The oracle's and the verifier's models are built once per world and reused by every attempt, and each attempt runs on a fresh loop
(`oracle._run_coroutine`). A connection the client kept alive from an earlier, closed loop failed the next attempt's
request: with "Event loop is closed" on the OpenAI-compatible client (every second request of a branch oracle, so two
worlds of an episode lost all their retries), and on the Anthropic client as a "no response" the retrier hid behind a
wait. The fake provider keeps connections alive, as a real one does, so the client pools them.
"""
from __future__ import annotations

import dataclasses
import json
from pathlib import Path
from typing import Any

import pytest

from defender import providers
from defender.providers.openai_compat import OpenAICompatProvider
from defender.tests.learning.oracle.live_contracts import _spec1224 as S
from defender.tests.runtime.providers import _spec1243 as P

ALICE_ROWS = S.default_calls()[0].payload
BOB_ROWS = {"rows": [{"user": "bob", "event_id": "e-200", "action": "logon", "host": "web-2",
                      "ts": "2026-03-01T09:00:00Z"}]}
CALLS = [("user:alice", ALICE_ROWS), ("user:bob", BOB_ROWS)]


def _submit(rows: dict) -> tuple[str, dict]:
    return "submit", {"served": rows, "claim": S.EMPTY_CLAIM}


#: The verifier's tool call: it passes every submission.
VERDICT = (S.COINED["tool.verdict"], {"passed": True, "reason": "the fact's telemetry is present"})


def _openai_tool_call(tool: tuple[str, dict]) -> P.WireAnswer:
    name, args = tool
    return P.WireAnswer(200, {
        "id": "chatcmpl-loops", "object": "chat.completion", "created": 0, "model": S.PRICED_MODEL,
        "choices": [{"index": 0, "finish_reason": "tool_calls", "message": {
            "role": "assistant", "content": None,
            "tool_calls": [{"id": "call-1", "type": "function",
                            "function": {"name": name, "arguments": json.dumps(args)}}]}}],
        "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
    })


def _anthropic_tool_call(tool: tuple[str, dict]) -> P.WireAnswer:
    name, args = tool
    return P.WireAnswer(200, {
        "id": "msg-loops", "type": "message", "role": "assistant", "model": S.PRICED_MODEL,
        "content": [{"type": "tool_use", "id": "toolu-1", "name": name, "input": args}],
        "stop_reason": "tool_use", "stop_sequence": None, "usage": {"input_tokens": 1, "output_tokens": 1},
    })


def _openai_model(url: str, monkeypatch: pytest.MonkeyPatch) -> Any:
    monkeypatch.setenv("T_LOOPS_API_KEY", "k-loops")
    provider = OpenAICompatProvider(id="t-loops", base_url=f"{url}/v1", api_key_var="T_LOOPS_API_KEY",
                                    aliases={}, main_effort="low", gather_effort="none")
    return provider.build_model(S.PRICED_MODEL)


def _anthropic_model(url: str, monkeypatch: pytest.MonkeyPatch) -> Any:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "k-loops")
    monkeypatch.setenv("ANTHROPIC_BASE_URL", url)
    return providers.ANTHROPIC.build_model(S.PRICED_MODEL)


#: The attempt deadline on the real clock, generous enough for a loaded runner, and a hang past it.
DEADLINE, HANG = 3.0, 6.0


def _hung(answer: P.WireAnswer) -> P.WireAnswer:
    return dataclasses.replace(answer, delay=HANG)


@pytest.mark.parametrize("hung", [None, "oracle", "verifier"], ids=["no-hang", "oracle-hangs", "verifier-hangs"])
@pytest.mark.parametrize(("answer", "build"),
                         [(_openai_tool_call, _openai_model), (_anthropic_tool_call, _anthropic_model)],
                         ids=["openai-compatible", "anthropic"])
def test_one_world_s_oracle_serves_successive_calls_through_one_client(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch, answer: Any, build: Any, hung: str | None) -> None:
    """`hung`: that endpoint's first request hangs past the deadline, which cuts its attempt off; the world's next
    attempt and calls must still get through the same model's client."""
    from pydantic_ai.models import override_allow_model_requests

    for var in P._PROXY_VARS:   # a proxy in the environment would carry the requests to 127.0.0.1 elsewhere
        monkeypatch.delenv(var, raising=False)
    est = S.estate(tmp_path)
    for q, rows in CALLS:
        est.answer("idp", "query", S.query_params(q), rows)
    timeline = P.Timeline()

    def real(url: str) -> Any:
        return providers.BuiltModel(providers.with_retries(build(url, monkeypatch), timeline.policy()), None)

    submits = [answer(_submit(rows)) for _, rows in CALLS]
    verdict = answer(VERDICT)
    oracle_answers = {None: submits, "oracle": [_hung(submits[0]), *submits],
                      "verifier": [submits[0], *submits]}[hung]
    verifier_answers = [_hung(verdict), verdict] if hung == "verifier" else [verdict]
    with (P.FakeProvider(oracle_answers, keep_alive=True) as oracle_end,
          P.FakeProvider(verifier_answers, keep_alive=True) as verifier_end):
        reg = S.world_registry(S.episode_v2(tmp_path), "b", est, oracle=real(oracle_end.url),
                               verifier=real(verifier_end.url), retry_cap=2, turn_deadline=DEADLINE)
        with override_allow_model_requests(True):
            served = [S.call(reg, "idp", "query", est.ctx(tmp_path / "inv"), q=q) for q, _ in CALLS]

    assert served == [rows for _, rows in CALLS]
    assert timeline.waits == [], f"the retrier waited {timeline.waits}: a request failed before it was answered"
    verifications = len(CALLS) + (hung == "verifier")
    assert (len(oracle_end.hits), len(verifier_end.hits)) == (len(oracle_answers), verifications), (
        f"{len(oracle_end.hits)} oracle and {len(verifier_end.hits)} verifier requests; expected "
        f"{len(oracle_answers)} and {verifications}")
