"""The oracle box's runner tree is self-contained (#1315): the transport imports from exactly the
files `box/_oracle.py` ships, so a package door that reaches outside them fails here, not in a
live box."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from defender.box import _oracle

CHECKOUT = Path(__file__).resolve().parents[3]


def test_the_transport_imports_from_the_runner_files_alone(tmp_path):
    for rel in _oracle.RUNNER_FILES:
        dest = tmp_path / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes((CHECKOUT / rel).read_bytes())
    proc = subprocess.run(
        [sys.executable, "-I", "-c",
         "import sys; sys.path.insert(0, sys.argv[1]); import defender.execution.bash_exec",
         str(tmp_path)],
        capture_output=True, text=True, check=False)
    assert proc.returncode == 0, proc.stderr
