from __future__ import annotations

from collections.abc import Callable
from typing import Any

from defender.tests.tooling.layout_contracts import _spec1080 as S


def _run(fn: Callable[..., Any], /, *args: Any, **kwargs: Any) -> tuple[Any, Exception | None]:
    try:
        return fn(*args, **kwargs), None
    except Exception as e:  # noqa: BLE001 — the exception IS the observed outcome
        return None, e


def test_moved_exception_type_raised_on_one_side_and_caught_on_the_other():
    """One definition, so a raise on one side cannot be missed by the catch on the other."""
    assert len(S.definitions("ParamsTooDeep")) == 1, (
        f"`ParamsTooDeep` has {len(S.definitions('ParamsTooDeep'))} definitions: "
        f"{list(S.definitions('ParamsTooDeep'))}")

    too_deep = S.moved("ParamsTooDeep")
    deep: Any = []
    for _ in range(40):
        deep = [deep]
    exc = _run(S.query_rule("_json_safe_params"), {"q": deep})[1]
    assert type(exc) is too_deep, f"the nesting refusal is {exc!r}"
