"""The arrival stamp beside a reply is the reading of the row that records it (#1385 O7, A6).

One reading of the run clock is taken for each call's row; the stamp the model is shown is that
same reading, so the line and the row can never disagree, and each call's reading is its own, not another's.
"""
from __future__ import annotations

import datetime as dt
import re
from typing import Any

import pytest

pytest.importorskip("pydantic_ai")

from defender.tests.learning.oracle.live_contracts import _spec1224 as S  # noqa: E402
from defender.tests.support.runtime.state import _1255_clock as C  # noqa: E402

STAMP = re.compile(r"\[reply received ([^\]]+)\]")


class TickingClock(C.FakeClock):
    """A run clock source that moves on every read: any second reading of the clock for one call
    shows as a different instant."""

    def __call__(self) -> dt.datetime:
        with self._lock:
            self._now += dt.timedelta(seconds=1)
            return self._now


def _mark(n: int) -> str:
    return f"MARK-STAMP-{n:02d}"


def test_1385_each_call_is_shown_the_reading_of_its_own_row_when_calls_run_together(tmp_path):
    """Five calls asked in one turn, one of them twice, then two more asked later, one of those a
    repeat served from the world's store: each reply is shown a stamp equal to its own row's
    `received_at`, whatever order the calls ran in (T4, O7, A6)."""
    H = S.replay_harness()
    est = S.estate(tmp_path)
    asked = [S.query_params(f"user:stamp{n}") for n in range(5)]
    for n, params in enumerate(asked):
        est.answer("idp", "query", params, {"rows": [{"user": f"stamp{n}", "event_id": _mark(n)}]})
    ep = S.episode_v2(tmp_path, base_rows=[])
    oracle = S.oracle(then=S.submit("$BASE", S.EMPTY_CLAIM))
    reg = S.sandboxed_registry(ep, "b", est, oracle=oracle, verifier=S.passing_verifier())

    def together(*which: int) -> Any:
        return H.Turn(tool_calls=[("query", {"system": "idp", "verb": "query",
                                             "params": dict(asked[n])}) for n in which])

    clock = TickingClock(C.SOURCE_START)
    run_dir, gather, _state = S.drive_gather_run(
        tmp_path / "drive", verbs=reg, tenant=est.place(), clock=clock, gather_turns=[
            together(0, 1, 2, 3, 0), together(1, 4), S.done_turn()])

    rows = S.lead_rows(run_dir)
    assert len(rows) == 7, f"the lead made {len(rows)} call(s), not 7: {rows}"
    owned = sorted((_mark(int(r["params"]["q"].removeprefix("user:stamp"))), r["received_at"])
                   for r in rows)
    text = max(gather.seen, key=len)
    shown: list[tuple[str, str]] = []
    cursor = 0
    for stamp in STAMP.finditer(text):
        marks = re.findall(r"MARK-STAMP-\d\d", text[cursor:stamp.start()])
        cursor = stamp.end()
        if marks:
            shown.append((marks[-1], stamp.group(1)))
    assert sorted(shown) == owned, (
        f"the stamps shown beside the replies are not their rows' received_at:\n shown {sorted(shown)}"
        f"\n rows  {owned}")
    for mark in {m for m, _stamp in owned}:
        stamps = [stamp for m, stamp in owned if m == mark]
        assert len(set(stamps)) == len(stamps), (
            f"a repeat of {mark} was given the reading of its earlier ask: {owned}")


def test_1385_the_framework_still_closes_a_retry_prompt_with_the_tail_the_query_tool_strips():
    """A schema refusal is the framework's own wording less its closing line, then the stamp
    (`query_tool._validation_text`). If a pydantic-ai upgrade rewords that line, stripping it
    silently stops and the model is told to fix its errors twice: fail here instead."""
    from pydantic import BaseModel, ValidationError
    from pydantic_ai.messages import RetryPromptPart

    from defender.investigation import query_tool

    class _Args(BaseModel):
        system: str

    try:
        _Args.model_validate({})
    except ValidationError as refused:
        worded = RetryPromptPart.from_error(refused, tool_name="query").model_response()
        text = query_tool._validation_text(refused, "query")
    assert worded.endswith(query_tool._RETRY_TAIL), worded
    assert query_tool._RETRY_TAIL.strip() not in text, text
