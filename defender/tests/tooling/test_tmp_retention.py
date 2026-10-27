"""A passed test's `tmp_path` and data root are removed when it ends; a failed test's are kept,
so a CI shard's tmp dirs cannot fill the runner's disk (run 40502356215)."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

DEFENDER = Path(__file__).resolve().parents[2]


def test_a_passed_tests_dirs_are_removed_and_a_failed_tests_kept(tmp_path: Path) -> None:
    record = tmp_path / "record"
    record.mkdir()
    cases = Path(__file__).with_name("_tmp_retention_cases.py").relative_to(DEFENDER).as_posix()
    done = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "-p", "no:xdist", cases,
         "--basetemp", str(tmp_path / "base")],
        cwd=DEFENDER, env={**os.environ, "RETENTION_RECORD": str(record)},
        capture_output=True, text=True)
    assert done.returncode == 1, done.stdout  # exactly the one failing case
    passed = json.loads((record / "passed.json").read_text())
    failed = json.loads((record / "failed.json").read_text())
    assert not (Path(passed["tmp_path"]) / "passed").exists()
    assert not (Path(passed["data_root"]) / "passed").exists()
    assert (Path(failed["tmp_path"]) / "failed").exists()
    assert (Path(failed["data_root"]) / "failed").exists()
