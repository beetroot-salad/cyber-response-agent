"""#1366 R17 (kept after #1470): connect's hand-off validator refuses a `config.env` line the old parser tolerated (a duplicate
key, an `export` line), naming the file and the key. The operator's `set-system` and `import` doors that shared the reader
are removed (O10, D-F); a tenant admin's settings travel as the API's key-to-text map."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from defender.tests.support.tenancy import _systems1366 as R

CMDB_CONFIG, CMDB_ACCESS = R.FIXTURE_FOLDERS["cmdb"]

REPO = Path(__file__).resolve().parents[4]
#: (id, the config.env text, the key the refusal names, a value that must not be stored): the declared key beside a line
#: the old reader silently ignored (`export`) or overrode (a duplicate).
R17_LINES = [
    ("duplicate-key", 'CMDB_TIMEOUT_SEC="10"\nCMDB_TIMEOUT_SEC="9917"\n', "CMDB_TIMEOUT_SEC", "9917"),
    ("duplicate-key-first-wins-looking", 'CMDB_TIMEOUT_SEC="9917"\nCMDB_TIMEOUT_SEC="10"\n', "CMDB_TIMEOUT_SEC", "9917"),
    ("export-line", 'CMDB_TIMEOUT_SEC="10"\nexport CMDB_TIMEOUT_SEC="9918"\n', "CMDB_TIMEOUT_SEC", "9918"),
    ("export-only-declared-key", 'export CMDB_TIMEOUT_SEC="9918"\n', "CMDB_TIMEOUT_SEC", "9918"),
]


@pytest.mark.parametrize("row", R17_LINES, ids=[r[0] for r in R17_LINES])
def test_1366_r17_connects_handoff_validator_refuses_a_duplicate_key_and_an_export_line_naming_the_file_and_the_key(tmp_path, row):
    """`validate_scaffold --handoff` judges the folder as the store does: the lines are a failure naming the key and the
    file (DC6), and the report is not a pass; the same folder with the key once passes. (#1366 R17, O11)"""
    import os

    _, text, key, _value = row

    def validated(config: str, label: str) -> tuple[int, str]:
        folder = R.system_folder(tmp_path / label, "cmdb", config=None, access=CMDB_ACCESS)
        (folder / "config.env").write_text(config, encoding="utf-8")
        done = subprocess.run([sys.executable, "-m", "defender.skills.connect.validate_scaffold", "cmdb",
                               "--handoff", str(folder)], cwd=REPO, env={**os.environ, "PYTHONPATH": str(REPO)},
                              capture_output=True, text=True, timeout=120, check=False)
        return done.returncode, done.stdout + done.stderr

    _rc, clean = validated('CMDB_TIMEOUT_SEC="10"\n', "clean")
    assert "the handoff's config.env and access.yaml are a record the store accepts for cmdb" in clean, clean  # control

    _rc, report = validated(text, "bad")

    assert "the handoff's config.env and access.yaml are a record the store accepts" not in report, report
    assert R.lines_naming(report, key, "config.env"), report
    assert "Traceback" not in report, report
