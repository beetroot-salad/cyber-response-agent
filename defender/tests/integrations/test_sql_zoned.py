"""defender-sql on a zoned result: UTC session zone, and a missing pytz is a missing runtime."""
from __future__ import annotations

import json
import os
import re

import pytest

from defender.tests.support.integrations._defender_sql import EXIT_NO_RUNTIME, EXIT_OK, run_sql_py

_FIXED_UTC = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{6}Z$")
_ZONED = ("SELECT '2026-01-01T03:00:00Z'::TIMESTAMPTZ AS lit, "
          "'2026-01-01 03:00:00'::TIMESTAMP::TIMESTAMPTZ AS from_plain, "
          "date_trunc('day', to_timestamp(1767261600)) AS day, "
          "to_timestamp(1767261600) AS epoch, now() AS n FROM data")


@pytest.mark.parametrize("host_zone", ["UTC", "America/New_York", "Asia/Kolkata", ""])
def test_a_zoned_result_is_the_same_utc_instant_whatever_the_hosts_zone(host_zone):
    proc = run_sql_py(_ZONED, stdin='{"x": 1}', env={**os.environ, "TZ": host_zone})
    assert proc.returncode == EXIT_OK, proc.stderr
    [row] = json.loads(proc.stdout)
    assert {k: row[k] for k in ("lit", "from_plain", "day", "epoch")} == {
        "lit": "2026-01-01T03:00:00.000000Z",
        "from_plain": "2026-01-01T03:00:00.000000Z",
        "day": "2026-01-01T00:00:00.000000Z",
        "epoch": "2026-01-01T10:00:00.000000Z",
    }
    assert _FIXED_UTC.match(row["n"]), row


def _without_pytz(tmp_path, *, box: bool) -> dict[str, str]:
    shadow = tmp_path / "shadow"
    shadow.mkdir(exist_ok=True)
    (shadow / "pytz.py").write_text("raise ImportError('pytz blocked by the test')\n",
                                    encoding="utf-8")
    env = {k: v for k, v in os.environ.items() if k != "DEFENDER_BOX"}
    env["PYTHONPATH"] = os.pathsep.join(p for p in (str(shadow), os.environ.get("PYTHONPATH")) if p)
    if box:
        env["DEFENDER_BOX"] = "1"
    return env


@pytest.mark.parametrize("box", [False, True])
def test_a_missing_pytz_is_a_missing_runtime_on_the_query_that_needs_it(tmp_path, box):
    env = _without_pytz(tmp_path, box=box)
    proc = run_sql_py("SELECT '2026-01-01T03:00:00Z'::TIMESTAMPTZ AS t FROM data",
                      stdin='{"x": 1}', env=env)
    assert proc.returncode == EXIT_NO_RUNTIME, (proc.returncode, proc.stderr)
    assert "Traceback" not in proc.stderr, proc.stderr
    assert "query error" not in proc.stderr, "a missing runtime was reported as the lead's mistake"
    assert "pytz" in proc.stderr, proc.stderr
    if box:
        assert "defender/box/image_cli.py build" in proc.stderr, proc.stderr
        assert ".venv" not in proc.stderr, proc.stderr
    else:
        assert "uv pip install" in proc.stderr, proc.stderr

    # Only that query: one with no zoned value runs in the same environment.
    plain = run_sql_py("SELECT x FROM data", stdin='{"x": 1}', env=env)
    assert plain.returncode == EXIT_OK, plain.stderr
    assert json.loads(plain.stdout) == [{"x": 1}]
