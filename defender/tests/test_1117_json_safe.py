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
    deep_map: object = {"k": "x"}
    for _ in range(6):
        deep_map = {"k": deep_map}
    cut = _logged(deep_map)
    for _ in range(6):
        cut = cut["k"]
    assert cut == "{'k': 'x'}", "a nested map must count toward the cap like a nested list"
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


# --- The review of #1123: the helper touches only what the encoder cannot carry. ---

from defender._io import json_safe  # noqa: E402
from defender.tests._by_path import DEFENDER  # noqa: E402
from defender.tests._defender_sql import EXIT_OK, run_sql_py  # noqa: E402


def test_the_sql_tool_leaves_keys_json_already_writes_to_the_encoder():
    """A map with true/false keys reads `"true"`/`"false"`, as `json.dump` writes them — the
    helper must not re-spell a key the encoder already carries."""
    proc = run_sql_py("SELECT map([true, false], [1, 2]) AS m FROM data", stdin='{"x": 1}')
    assert proc.returncode == EXIT_OK, proc.stderr
    assert json.loads(proc.stdout) == [{"m": {"true": 1, "false": 2}}]


def test_every_output_writes_a_timestamp_in_the_one_standard_form():
    """ISO 8601 with `T`: the SQL tool's detected timestamp column, a lesson's `created_at`,
    and a log field all read the same way."""
    proc = run_sql_py("SELECT ts FROM data", stdin='{"ts": "2026-01-01T10:00:00Z"}\n')
    assert proc.returncode == EXIT_OK, proc.stderr
    assert json.loads(proc.stdout) == [{"ts": "2026-01-01T10:00:00"}]
    created = dt.datetime(2026, 6, 4, tzinfo=dt.UTC)
    assert serialize._json_safe({"created_at": created}) == {"created_at": "2026-06-04T00:00:00+00:00"}
    assert _logged(created) == "2026-06-04T00:00:00+00:00"


def test_a_non_finite_key_takes_the_standard_spelling_under_either_policy():
    """A key cannot be null, so both policies spell it."""
    for policy in ("text", "null"):
        assert json_safe({NAN: 1, INF: 2}, non_finite=policy) == {"NaN": 1, "Infinity": 2}


def test_a_set_whose_members_print_alike_comes_out_in_one_order_under_every_hash_seed():
    import os
    import subprocess
    import sys
    probe = ("import json; from defender._io import json_safe; "
             "print(json.dumps(json_safe({1, '1', 'a'}, non_finite='text')))")
    outs = {
        subprocess.run([sys.executable, "-c", probe], capture_output=True, text=True, check=True,
                       env={**os.environ, "PYTHONHASHSEED": str(seed),
                            "PYTHONPATH": str(DEFENDER.parent)}).stdout
        for seed in range(16)
    }
    assert len(outs) == 1, outs


def test_an_unknown_policy_is_refused():
    with pytest.raises(ValueError, match="non_finite"):
        json_safe(NAN, non_finite="none")  # type: ignore[arg-type]


# --- The denial fingerprint cleans parameters by the same rule. ---


from defender.runtime import observe  # noqa: E402
from defender.scripts.gather_tools.record_query import _request_key  # noqa: E402

_PARAMS = [
    {"threshold": NAN}, {"threshold": INF, "floor": -INF}, {"hosts": {"b", "a"}},
    {"since": dt.date(2026, 1, 1)}, {"pair": (1, [2, NAN])}, {"q": "FROM logs", "n": 3},
]


@pytest.mark.parametrize("params", _PARAMS, ids=lambda p: "-".join(p))
def test_a_denial_fingerprints_a_call_the_way_the_query_record_stores_it(params):
    """A blocked call and the same call as the query record writes it carry one fingerprint:
    the two surfaces identify a call by one rule, not two."""
    stored = _json_safe_params(params)
    assert observe._params_digest(params) == observe._params_digest(stored)


def test_mixed_key_types_neither_crash_the_fingerprint_nor_the_repeat_key():
    """Both sort their keys, and a sort over `1` and `"b"` raises — so every key reaches them
    as text, spelled as the encoder would write it."""
    params = {1: "a", "b": 2, False: "f", None: "n", 1.5: "x"}
    assert json_safe(params, non_finite="text") == {
        "1": "a", "b": 2, "false": "f", "null": "n", "1.5": "x"}
    observe._params_digest(params)
    _request_key("elastic", "probe", _json_safe_params(params))
