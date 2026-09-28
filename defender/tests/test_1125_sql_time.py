"""How `defender-sql` hands times to the gather lead (#1125, #1126).

The lead writes its next query from what the last one showed it, so a field's type and
spelling must not depend on which rows happened to arrive. The engine guesses a column's type
from its rows: `…00Z` alone became a converted TIMESTAMP, `…00Z` beside `…00.5Z` stayed text.
The contract now:

- A field loaded from the payload is TEXT, spelled exactly as the source spelled it — the same
  string the lead saw in the query tool's own output, and can bind back into the next query.
- A time the query computes (`::TIMESTAMPTZ`, `now()`, `to_timestamp`, `date_trunc`) is written
  in one form, UTC `2026-01-01T10:00:00.000000Z`, and the session's zone is UTC whatever the
  host's is.
- A duration is a number of seconds.
- An ES|QL row's positions are JSON whatever their values' types, so the one taught idiom
  `v[N]->>'$'` works on every row.
- An engine error while rows are fetched is a `query error:`, not a traceback.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys

from defender._io import read_text_utf8
from defender.tests._by_path import DEFENDER
from defender.tests._defender_sql import EXIT_OK, SQL_PY, assert_query_error, run_sql_py

_DOC = DEFENDER / "skills" / "gather" / "defender-sql.md"
_FIXED_UTC = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{6}Z$")
_HITS = "FROM (SELECT unnest(hits) h FROM data)"
_VALUES = "FROM (SELECT unnest(values) v FROM data)"


def _rows(payload: object, query: str, env: dict[str, str] | None = None) -> list[dict]:
    proc = run_sql_py(query, stdin=json.dumps(payload), env=env)
    assert proc.returncode == EXIT_OK, proc.stderr
    return json.loads(proc.stdout)


# --- A loaded field is the source's text. ---

def test_a_loaded_time_field_comes_back_spelled_as_the_source_whatever_the_rows():
    """Each of these was converted by the engine's guess before, or not, depending on the
    other rows — the lead could not know which form to expect."""
    alone = _rows({"ts": "2026-01-01T10:00:00Z"}, "SELECT ts, typeof(ts) AS t FROM data")
    assert alone == [{"ts": "2026-01-01T10:00:00Z", "t": "VARCHAR"}]

    offset = _rows({"ts": "2026-01-01T12:00:00+02:00"}, "SELECT ts, typeof(ts) AS t FROM data")
    assert offset == [{"ts": "2026-01-01T12:00:00+02:00", "t": "VARCHAR"}]

    hits = {"hits": [{"@timestamp": "2026-01-01T10:00:00.000Z"},
                     {"@timestamp": "2026-01-01T10:00:00.123Z"}]}
    rows = _rows(hits, f'SELECT h."@timestamp" AS ts, typeof(h."@timestamp") AS t {_HITS}')
    assert rows == [{"ts": "2026-01-01T10:00:00.000Z", "t": "VARCHAR"},
                    {"ts": "2026-01-01T10:00:00.123Z", "t": "VARCHAR"}]

    day = _rows({"d": "2026-01-01"}, "SELECT typeof(d) AS t FROM data")
    assert day == [{"t": "VARCHAR"}]


# --- A computed time has one form, in UTC. ---

def test_a_zoned_result_is_written_in_the_fixed_utc_form():
    """Any zoned value reaching Python used to end in an uncaught traceback (#1126) — an
    explicit cast, and also `now()` and `to_timestamp`, which return zoned values."""
    rows = _rows({"x": 1}, "SELECT '2026-01-01T12:00:00+02:00'::TIMESTAMPTZ AS tz, "
                           "to_timestamp(1767261600) AS epoch, now() AS n FROM data")
    assert rows[0]["tz"] == "2026-01-01T10:00:00.000000Z"
    assert rows[0]["epoch"] == "2026-01-01T10:00:00.000000Z"
    assert _FIXED_UTC.match(rows[0]["n"]), rows


def test_the_session_zone_is_utc_whatever_the_hosts_is():
    """The engine's zone follows the host's. Under Jerusalem time a day bucket would start at
    22:00 UTC the day before, silently."""
    env = {**os.environ, "TZ": "Asia/Jerusalem"}
    rows = _rows({"x": 1}, "SELECT date_trunc('day', '2026-01-01T01:00:00Z'::TIMESTAMPTZ) AS d, "
                           "('2026-01-01T12:00:00+02:00'::TIMESTAMPTZ)::VARCHAR AS v FROM data",
                 env=env)
    assert rows == [{"d": "2026-01-01T00:00:00.000000Z", "v": "2026-01-01 10:00:00+00"}]


def test_a_duration_is_a_number_of_seconds():
    """Not Python's `1 day, 2:00:00`: a number the lead can compare and divide."""
    rows = _rows({"x": 1}, "SELECT '2026-01-02 12:00:00'::TIMESTAMP - '2026-01-01 10:00:00'::TIMESTAMP "
                           "AS d, INTERVAL 500 MILLISECONDS AS half, -INTERVAL 1 HOUR AS back, "
                           "[INTERVAL 1 MINUTE] AS listed FROM data")
    assert rows == [{"d": 93600.0, "half": 0.5, "back": -3600.0, "listed": [60.0]}]


# --- An ES|QL row's positions are JSON whatever they hold. ---

def test_the_esql_idiom_works_on_a_row_of_any_one_type():
    """A row whose values all share a type was typed as that type, so `->>'$'` failed on an
    all-text row, and read a third time spelling off an all-timestamp one."""
    def payload(values: list) -> dict:
        return {"columns": [{"name": "a", "type": "keyword"}, {"name": "b", "type": "keyword"}],
                "values": values, "row_count": len(values)}

    text = payload([["bob", "h1"], ["al", None]])
    assert _rows(text, f"SELECT v[1]->>'$' AS a, v[2]->>'$' AS b {_VALUES}") == [
        {"a": "bob", "b": "h1"}, {"a": "al", "b": None}]

    numbers = payload([[412, 9]])
    assert _rows(numbers, f"SELECT (v[1]->>'$')::BIGINT + (v[2]->>'$')::BIGINT AS s {_VALUES}") \
        == [{"s": 421}]

    times = payload([["2026-01-01T10:00:00.000Z", "2026-01-01T11:00:00.000Z"]])
    assert _rows(times, f"SELECT v[1]->>'$' AS first_seen {_VALUES}") == [
        {"first_seen": "2026-01-01T10:00:00.000Z"}]



def test_only_an_esql_payload_with_rows_is_retyped():
    """An ES|QL result with no rows, and a payload carrying only one of the two ES|QL keys,
    load and read as before — a zero-row `STATS` is an ordinary answer."""
    empty = {"columns": [{"name": "a", "type": "keyword"}], "values": [], "row_count": 0}
    assert _rows(empty, "SELECT row_count FROM data") == [{"row_count": 0}]
    assert _rows({"columns": ["a"], "host": "web-1"}, "SELECT host FROM data") == [{"host": "web-1"}]
    assert _rows({"values": [[1, 2]]}, 'SELECT "values"[1][1] + 1 AS n FROM data') == [{"n": 2}]

# --- Every engine error is the tool's `query error:`. ---

def test_an_engine_error_while_rows_are_fetched_is_a_query_error():
    """The pytz import failure surfaced at fetch, outside the tool's error handling. Hiding
    pytz in the child reproduces a fetch-time engine error with the dependency installed."""
    hide_pytz = ("import runpy, sys; sys.modules['pytz'] = None; sys.argv = sys.argv[1:]; "
                 "runpy.run_path(sys.argv[0], run_name='__main__')")
    proc = subprocess.run(
        [sys.executable, "-c", hide_pytz, str(SQL_PY),
         "SELECT '2026-01-01T10:00:00Z'::TIMESTAMPTZ AS tz FROM data"],
        input='{"x": 1}', capture_output=True, text=True, encoding="utf-8", timeout=120,
    )
    assert "Traceback" not in proc.stderr, proc.stderr
    assert_query_error(proc, "a fetch-time engine error was not reported as a query error")


# --- The lead is taught the rule, and the rule runs. ---

def test_the_docs_time_recipe_is_literal_and_runs():
    """The doc's cast for time comparison, present as a literal and executed: over mixed
    spellings it finds the real earliest, where the text MIN is lexical (`.` sorts below `Z`)
    and `::TIMESTAMP` drops an offset instead of converting it."""
    doc = read_text_utf8(_DOC)
    recipe = f'SELECT min(h."@timestamp"::TIMESTAMPTZ) AS first {_HITS}'
    assert recipe in doc, "the doc's time recipe changed"
    assert "Never `::TIMESTAMP`" in doc, "the doc no longer warns off ::TIMESTAMP"
    assert "drops the offset" in doc, "the doc dropped WHY ::TIMESTAMP is wrong"

    mixed = {"hits": [{"@timestamp": "2026-01-01T10:00:00Z"},
                      {"@timestamp": "2026-01-01T10:00:00.5Z"},
                      {"@timestamp": "2026-01-01T11:30:00+02:00"}]}
    assert _rows(mixed, recipe) == [{"first": "2026-01-01T09:30:00.000000Z"}]
    assert _rows(mixed, f'SELECT min(h."@timestamp") AS first {_HITS}') == [
        {"first": "2026-01-01T10:00:00.5Z"}], "the uncast MIN is supposed to be lexical"
    assert _rows(mixed, f'SELECT min(h."@timestamp"::TIMESTAMP) AS first {_HITS}') == [
        {"first": "2026-01-01T10:00:00.000000Z"}], "`::TIMESTAMP` is supposed to drop the offset"
