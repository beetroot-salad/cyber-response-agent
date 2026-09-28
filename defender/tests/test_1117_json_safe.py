"""#1117: the four places that make a value JSON-safe share one traversal and differ only in
the non-finite policy each one states.

Logs and the query record keep a non-finite float as text, spelled as the Protocol Buffers JSON
mapping and OpenTelemetry spell it (`"NaN"`, `"Infinity"`, `"-Infinity"`) — they are read to
diagnose, so "infinite" must not collapse into "missing". The lessons page and the SQL tool's
rows (pinned in `test_sql.py`) write `null`, the data convention: a field stays
number-or-empty. Everything else — keys, sequences, sets, other values — is decided once, so the
callers are compared with EACH OTHER over a swept domain rather than each against its own copy
of the rule.
"""
from __future__ import annotations

import datetime as dt
import json
import logging
from decimal import Decimal
from pathlib import Path

import pytest

from defender import _log
from defender.learning.frontend import serialize
from defender.scripts.gather_tools.record_query import _json_safe_params

NAN, INF = float("nan"), float("inf")

#: Everything but a non-finite float, nested no deeper than the log's cap.
_FINITE = [
    None, True, 0, -1, 1.5, "s", "",
    {"k": 1}, {1: "int key"}, {(1, 2): "tuple key"}, {None: "none key"},
    {dt.date(2026, 1, 1): "date key"},
    [1, [2, [3]]], (1, 2), {"b", "a", "c"}, frozenset({2, 1}),
    dt.date(2026, 1, 2), dt.datetime(2026, 1, 2, 3, 4, 5), dt.time(9, 30),
    Path("/p"), b"\xff", Decimal("1.10"),
    {"nest": [{"deep": ({"y", "x"},)}]},
]
_NON_FINITE = [NAN, INF, -INF, {"x": [NAN, (INF,)]}]


def _logged(value):
    return _log.record_fields(logging.makeLogRecord({"name": "defender.t", "msg": "m", "odd": value}))["odd"]


@pytest.mark.parametrize("value", _FINITE + _NON_FINITE, ids=lambda v: type(v).__name__)
def test_the_log_and_the_query_record_make_the_same_value(value):
    assert _json_safe_params(value) == _logged(value)
    json.dumps(_logged(value), allow_nan=False)


@pytest.mark.parametrize("value", _FINITE, ids=lambda v: type(v).__name__)
def test_the_lessons_page_agrees_with_the_log_on_every_finite_value(value):
    assert serialize._json_safe(value) == _logged(value)


def test_the_log_and_the_query_record_spell_non_finite_as_the_standard_text():
    assert _json_safe_params({"x": [NAN, (INF, -INF)]}) == {"x": ["NaN", ["Infinity", "-Infinity"]]}


def test_the_lessons_page_writes_non_finite_as_null():
    assert serialize._json_safe({"x": [NAN, (INF, -INF)]}) == {"x": [None, [None, None]]}


def _nested(levels: int, leaf):
    return leaf if levels == 0 else [_nested(levels - 1, leaf)]


def test_only_the_log_cuts_a_deep_value_and_it_cuts_below_six_levels():
    """The log takes any object through `extra=`, so it caps depth; the data callers never
    truncate what the model or a reader is shown."""
    assert _logged(_nested(6, "x")) == _nested(6, "x")
    assert _logged(_nested(7, "x")) == _nested(6, "['x']")
    assert _json_safe_params(_nested(9, "x")) == _nested(9, "x")
    assert serialize._json_safe(_nested(9, "x")) == _nested(9, "x")


def test_a_set_is_written_in_sorted_order():
    members = [f"m{i:02d}" for i in range(30)]
    assert _json_safe_params(set(members)) == members


def test_a_float_subclass_with_its_own_repr_is_still_spelled_and_never_raises():
    """numpy's `float64` is a `float` that prints as `np.float64(nan)`: the spelling is taken
    from the value, so a log line holding one is not lost."""
    class Tagged(float):
        def __repr__(self) -> str:
            return f"Tagged({float(self)!r})"

    assert _logged([Tagged("nan"), Tagged("inf"), Tagged("-inf")]) == ["NaN", "Infinity", "-Infinity"]
