"""`defender-sql` on a zoned result (#1126).

duckdb needs `pytz` to hand a zoned timestamp to Python and does not declare it, so every zoned
result — an explicit `::TIMESTAMPTZ`, and also `now()` and `to_timestamp`, which return zoned
values — ended in an uncaught traceback raised from the row fetch, outside the tool's error
handling. `pytz` is now declared next to `duckdb`, and the fetch sits inside the handling, so an
engine error while rows are fetched is the tool's `query error:`.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys

from defender.tests._defender_sql import EXIT_OK, SQL_PY, assert_query_error, run_sql_py

_FIXED_UTC = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{6}Z$")


def test_a_zoned_result_is_written_in_the_fixed_utc_form():
    proc = run_sql_py("SELECT '2026-01-01T12:00:00+02:00'::TIMESTAMPTZ AS tz, "
                      "to_timestamp(1767261600) AS epoch, now() AS n FROM data", stdin='{"x": 1}')
    assert proc.returncode == EXIT_OK, proc.stderr
    rows = json.loads(proc.stdout)
    assert rows[0]["tz"] == "2026-01-01T10:00:00.000000Z"
    assert rows[0]["epoch"] == "2026-01-01T10:00:00.000000Z"
    assert _FIXED_UTC.match(rows[0]["n"]), rows


def test_an_engine_error_while_rows_are_fetched_is_a_query_error():
    """Hiding pytz in the child reproduces a fetch-time engine error with the dependency
    installed."""
    hide_pytz = ("import runpy, sys; sys.modules['pytz'] = None; sys.argv = sys.argv[1:]; "
                 "runpy.run_path(sys.argv[0], run_name='__main__')")
    proc = subprocess.run(
        [sys.executable, "-c", hide_pytz, str(SQL_PY),
         "SELECT '2026-01-01T10:00:00Z'::TIMESTAMPTZ AS tz FROM data"],
        input='{"x": 1}', capture_output=True, text=True, encoding="utf-8", timeout=120,
    )
    assert "Traceback" not in proc.stderr, proc.stderr
    assert_query_error(proc, "a fetch-time engine error was not reported as a query error")
