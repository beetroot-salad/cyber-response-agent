"""`_io.load_json_artifact` — ONE decoder for box-written JSON, with nesting judged by the bytes.

`json.loads` recurses once per nested container on the interpreter's shared stack budget, so
without a bound "is this text readable" was a fact about the CALLER: the same line decoded
from a deep call raised `RecursionError` where a shallow one returned a value. Every reader
of a run dir that tolerated the nested shape did so by catching that error — a safe direction
for a reader (skip it) and a wrong one for the writer side of the trace-row agreement
(`challenge_gate._is_row_shaped`, asked deep inside the gate: "not a row" there let a reply
stand as a raw line that every reader, asked from the top, then parsed as a row). The bound
makes both sides answer from the bytes, so they cannot disagree.

Pinned here: the depth scan is exact on valid JSON (brackets inside strings, escaped quotes);
the bound admits `JSON_NESTING_LIMIT` and refuses one past it; and the row predicate answers
the SAME from a stack that has almost no budget left as from the top — for a line the old
predicate answered two ways.
"""
from __future__ import annotations

import inspect
import json
import sys
from collections.abc import Callable
from typing import Any

import pytest

from defender._io import (
    JSON_NESTING_LIMIT,
    json_nesting_depth,
    load_json_artifact,
    parse_jsonl_row,
    read_jsonl_rows_report,
)

#: Stack frames left for the call under test once `from_a_deep_stack` has used the rest. Small
#: enough that `json.loads` of `_DEEP` containers cannot complete in it, large enough for the
#: predicate's own frames — the point of the bound is that the second fact no longer matters.
_HEADROOM = 150
#: Nested past the headroom and short of Python's default budget from the top: the depth the
#: OLD predicate decoded from the top and could not from the deep stack.
_DEEP = 500


def from_a_deep_stack(fn: Callable[[], Any]) -> Any:
    """`fn()` with `_HEADROOM` frames of recursion budget left."""
    def descend(n: int) -> Any:
        return fn() if n == 0 else descend(n - 1)
    return descend(sys.getrecursionlimit() - len(inspect.stack()) - _HEADROOM)


def _nested(depth: int) -> str:
    return '{"lead_id": "l-001", "params": ' + "[" * depth + "]" * depth + "}"


def test_the_depth_scan_is_exact_on_valid_json_and_blind_to_brackets_inside_strings():
    """A `[` or `{` in a string value is text, not a level; an escaped quote does not end the
    string early; a scalar has no depth at all. Each expected depth is what `json.loads` would
    recurse to, so the scan and the decoder agree on every valid input."""
    cases = {
        "3": 0,
        '"[[[{"': 0,
        "[]": 1,
        '{"a": [1, {"b": "[[[{"}], "c": "x\\"["}': 3,
        '{"a": "\\\\", "b": [[]]}': 3,
        json.dumps({"hits": [{"_source": {"proc": {"args": ["[", "{"]}}}]}): 6,
    }
    for text, depth in cases.items():
        assert json_nesting_depth(text) == depth, f"{text!r}: {json_nesting_depth(text)}"


def test_the_bound_admits_the_limit_and_refuses_one_past_it():
    at = "[" * JSON_NESTING_LIMIT + "]" * JSON_NESTING_LIMIT
    past = "[" * (JSON_NESTING_LIMIT + 1) + "]" * (JSON_NESTING_LIMIT + 1)
    value, reason = load_json_artifact(at)
    assert reason is None, "the limit itself is refused"
    assert isinstance(value, list)
    value, reason = load_json_artifact(past)
    assert value is None
    assert reason == f"nested deeper than {JSON_NESTING_LIMIT}", reason
    # `null` is a value, so success is the reason and not the value.
    assert load_json_artifact("null") == (None, None)
    value, reason = load_json_artifact("{not json")
    assert value is None
    assert reason, "a decode error is not reported"


@pytest.mark.parametrize(("depth", "is_row"), [(20, True), (_DEEP, False), (200_000, False)])
def test_the_row_predicate_answers_from_the_bytes_not_the_stack(depth, is_row):
    """The same line, asked from the top and from a stack with `_HEADROOM` frames left: one
    answer. `_DEEP` is the discriminating case — from the top the old predicate decoded it (a
    dict, a row); from the deep stack `json.loads` raised and the caught `RecursionError` read
    as "not a row". A writer that trusted the deep answer put the line out raw; the reader,
    from the top, counted it as a row.

    Observed failing by: a predicate that decodes first and catches `RecursionError` — the
    `_DEEP` line is a dict from the top and `None` from the deep stack."""
    line = _nested(depth)
    shallow = parse_jsonl_row(line)
    deep = from_a_deep_stack(lambda: parse_jsonl_row(line))
    assert (shallow is not None) is is_row, f"from the top: {type(shallow).__name__}"
    assert (deep is not None) is is_row, f"from the deep stack: {type(deep).__name__}"


def test_the_table_reader_counts_a_nested_row_as_unreadable(tmp_path):
    """The tolerance is not silence: the report's count names the row, so the capture primer
    states the size of what it could not read."""
    table = tmp_path / "t.jsonl"
    table.write_text(_nested(_DEEP) + "\n" + _nested(2) + "\n", encoding="utf-8")
    rows, unreadable = read_jsonl_rows_report(table)
    assert [r["lead_id"] for r in rows] == ["l-001"], rows
    assert unreadable == 1, "the nested row was not counted as unreadable"
