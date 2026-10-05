"""#1127 second review: a call that skips validation is held to the depth limit where it runs.

The query tool refuses a model's too-deep call at validation. Lead zero issues its host-built
calls through `wrap_tool_execute` directly, so validation never sees them. A too-deep one used
to reach the grant check, where the registry's own refusal (`LedgerError`) was taken for an
adapter that failed to load: an infra row was filed against the same deep params, charging the
circuit breaker, and the queries table then raised past every handler. Host-built params are
shallow by construction, so a deep one is a host bug: it is refused loudly, first, as
`ParamsTooDeep`, with nothing decided, charged or rowed.
"""
from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest

pytest.importorskip("pydantic_ai")

from defender.runtime.query_tool import QueryCapture  # noqa: E402
from defender._query_rules import PARAMS_NESTING_LIMIT, ParamsTooDeep


class _Registry:
    """A registry that records every question it is asked."""

    def __init__(self) -> None:
        self.asked: list[tuple[str, str]] = []

    def decide_call(self, system: str, verb: str, params: dict):  # noqa: ANN201
        self.asked.append((system, verb))
        raise AssertionError("the grant was decided for a call too deep to store")

    def systems(self) -> tuple[str, ...]:
        return ("elastic",)


def _chain(depth: int) -> dict:
    value: dict = {}
    for _ in range(depth - 1):
        value = {"k": value}
    return value


@pytest.mark.parametrize("arg", ["params", "query_id"])
def test_a_too_deep_call_that_skipped_validation_is_refused_before_anything_runs(tmp_path, arg):
    registry = _Registry()
    capture = QueryCapture(registry)
    ran: list[dict] = []

    async def handler(args: dict):  # noqa: ANN202
        ran.append(args)
        return "ran"

    deep = _chain(PARAMS_NESTING_LIMIT + 1)
    args = {"system": "elastic", "verb": "query", "params": {"q": "x"}, arg: deep}
    ctx = SimpleNamespace(deps=SimpleNamespace(run_dir=tmp_path, lead_id="l-000"))

    with pytest.raises(ParamsTooDeep):
        asyncio.run(capture.wrap_tool_execute(
            ctx, call=SimpleNamespace(tool_name="query"), args=args, handler=handler))

    assert registry.asked == [], "the grant was decided for the too-deep call"
    assert ran == [], "the verb ran"
    assert list(tmp_path.iterdir()) == [], "something was written for the too-deep call"
