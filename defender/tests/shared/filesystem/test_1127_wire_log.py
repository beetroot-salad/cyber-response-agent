"""The wire log keeps a record for every response, however deep its tool call."""
from __future__ import annotations

import json

import pytest

pytest.importorskip("pydantic_ai")

from pydantic_ai.messages import ModelRequest, ModelResponse, ToolCallPart, UserPromptPart  # noqa: E402
from pydantic_ai.usage import RequestUsage  # noqa: E402

from defender._io import JSON_NESTING_LIMIT, json_nesting_depth, parse_jsonl_row  # noqa: E402
from defender.investigation import observe  # noqa: E402


def _chain(depth: int) -> dict:
    value: dict = {"leaf": "x"}
    for _ in range(depth - 1):
        value = {"k": value}
    return value


@pytest.mark.parametrize("depth", [150, 260], ids=["cut", "past-the-dump"])
def test_a_response_carrying_a_deep_call_is_logged_readable_with_its_usage(tmp_path, depth):
    path = tmp_path / "llm_requests.jsonl"
    logger = observe.RequestLogger(path)
    response = ModelResponse(
        parts=[ToolCallPart(tool_name="query", args={"params": _chain(depth)})],
        usage=RequestUsage(input_tokens=11, output_tokens=7))
    try:
        logger.log(request_messages=[ModelRequest(parts=[UserPromptPart(content="go")])],
                   response=response, agent_id="gather:l-001")
    finally:
        logger.close()

    lines = path.read_text(encoding="utf-8").splitlines()
    assert [json_nesting_depth(line) <= JSON_NESTING_LIMIT for line in lines] == [True, True]
    records = [parse_jsonl_row(line) for line in lines]
    assert [r["kind"] for r in records] == ["request", "response"]
    assert records[1]["usage"]["output_tokens"] == 7
    assert logger.n_requests == 1
    json.dumps(records)
