"""A lone UTF-16 surrogate in a provider response must survive RequestLogger's disk write (ensure_ascii pinned)."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")

from pydantic_ai.messages import (  # noqa: E402
    ModelRequest,
    ModelResponse,
    TextPart,
    UserPromptPart,
)

from defender.investigation import observe  # noqa: E402

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

