"""Pins two ``ModelMessagesTypeAdapter.dump_python`` behaviors ``RequestLogger``
(``defender/runtime/observe.py``) relies on but never asserted (#724).

1. ``dump_python`` silently COERCES rather than raising: ``NaN``/``Infinity`` -> ``None``,
   ``set`` -> ``list``, ``bytes`` -> base64. No writer is at fault and nothing raises at
   any stage, so a "verbatim round-trip" claim over this path is false for these value
   shapes — pinned here so nobody asserts it without qualification.
2. A lone UTF-16 surrogate (reachable from a provider response body via a ``\\udXXX``
   JSON escape a model can be steered into emitting) survives ``dump_python`` and the
   on-disk ``json.dumps`` encode ONLY because ``ensure_ascii=True`` is pinned explicitly
   at both write sites in ``RequestLogger``. With ``ensure_ascii=False``, or a raw ``str``
   bound to a UTF-8 sink, the same content raises ``UnicodeEncodeError`` — a
   content-triggered availability halt gated entirely by that one argument.
"""
from __future__ import annotations

import json
import math
from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")

from pydantic_ai.messages import (  # noqa: E402
    ModelRequest,
    ModelResponse,
    TextPart,
    ToolReturnPart,
    UserPromptPart,
)
from pydantic_ai.messages import ModelMessagesTypeAdapter  # noqa: E402

from defender.runtime import observe  # noqa: E402

LONE_SURROGATE = "lead \ud800 x"


def _logged_disk_lines(tmp_path: Path, parts, tag: str) -> list[dict]:
    trace = tmp_path / f"{tag}.trace.jsonl"
    logger = observe.RequestLogger(trace)
    try:
        logger.log(
            request_messages=[ModelRequest(parts=[UserPromptPart(content="u")])],
            response=ModelResponse(parts=parts),
        )
    finally:
        logger.close()
    return [json.loads(line) for line in trace.read_text(encoding="utf-8").splitlines()]


def test_lone_surrogate_survives_the_disk_write_because_ensure_ascii_is_pinned(tmp_path):
    lines = _logged_disk_lines(tmp_path, [TextPart(content=LONE_SURROGATE)], "surrogate")
    response_line = next(r for r in lines if r["kind"] == "response")
    text_part = response_line["message"]["parts"][0]
    assert text_part["content"] == LONE_SURROGATE, (
        "the on-disk record must recover the exact lone surrogate — a raw utf-8 encode "
        "of this string raises UnicodeEncodeError, so recovery only works because the "
        "disk write escapes it (ensure_ascii=True)"
    )
    # The raw disk bytes never contain the literal surrogate: json.dumps(ensure_ascii=True)
    # escapes it as the ASCII sequence \ud800, which is what makes the utf-8 write safe.
    raw = (tmp_path / "surrogate.trace.jsonl").read_bytes()
    raw.decode("ascii")  # would raise if a raw surrogate leaked into the bytes on disk


def test_ensure_ascii_false_would_raise_on_the_same_content():
    """Negative control: proves the pin in observe.py is load-bearing, not incidental."""
    dumped = json.dumps({"content": LONE_SURROGATE}, ensure_ascii=False)
    with pytest.raises(UnicodeEncodeError):
        dumped.encode("utf-8")


def test_nan_and_infinity_tool_returns_are_silently_coerced_to_none():
    """dump_python never raises on these — it coerces, so a round-trip assertion must
    compare against the coerced value, not the original NaN/Infinity."""
    request = ModelRequest(
        parts=[ToolReturnPart(tool_name="t", tool_call_id="1", content=math.nan)]
    )
    dumped = ModelMessagesTypeAdapter.dump_python([request], mode="json")[0]
    assert dumped["parts"][0]["content"] is None, (
        "dump_python's NaN handling changed — either it now raises (tighten this test "
        "and drop the #724 caveat) or it coerces to something other than None (update "
        "the pinned value)"
    )


def test_bytes_and_set_tool_returns_are_silently_coerced_not_rejected():
    request = ModelRequest(
        parts=[
            ToolReturnPart(tool_name="t1", tool_call_id="1", content=b"\xe0gcmF"),
            ToolReturnPart(tool_name="t2", tool_call_id="2", content={1, 2, 3}),
        ]
    )
    dumped = ModelMessagesTypeAdapter.dump_python([request], mode="json")[0]
    bytes_content, set_content = (p["content"] for p in dumped["parts"])
    assert isinstance(bytes_content, str), "bytes silently became a base64 str, not a rejection"
    assert sorted(set_content) == [1, 2, 3], "set silently became a list, not a rejection"
