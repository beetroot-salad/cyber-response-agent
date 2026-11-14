"""#1485 O5: after the lift and the retirement `lint_run_records` still passes over the real tree, sweeps `learning_store`, and
holds no permission or role entry for the retired cutover import. (No other test runs it over the real tree; CI runs it as a step.)"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from _by_path import load_lint_gate

_GATE = load_lint_gate("lint_run_records")
_REPO = Path(__file__).resolve().parents[3]
_RETIRED_FUNCTIONS = ("cut_over", "_read_learning", "learning_delivery")


def test_o5_the_gate_sweeps_the_lifted_store_and_still_the_rest():
    """`learning_store` is a swept dir, beside `learning`, which stays. (O5, P1)"""
    assert "learning_store" in _GATE.SWEEP_DIRS
    assert {"learning", "jobs", "tenancy", "lifecycle"} <= set(_GATE.SWEEP_DIRS)


def test_o5_the_gate_passes_over_the_real_tree():
    """`python tooling/lint/lint_run_records.py` exits 0 over this checkout (a lifted package it did not sweep would blind it, exit 2). (O5, P1)"""
    done = subprocess.run([sys.executable, "tooling/lint/lint_run_records.py"], cwd=_REPO, capture_output=True, text=True,  # noqa: S603
                          timeout=300, check=False)
    assert done.returncode == 0, (done.returncode, done.stdout[-2000:], done.stderr[-2000:])


def test_o5_no_permission_or_role_entry_remains_for_the_cutover_import():
    """No conversion permission names the old importer's file, the old-folder role, or a cutover function; `learning` stays a banned location name. (O5)"""
    entries = _GATE.CONVERSION_PERMISSIONS
    assert ("scratch_root", "learning/call_folders.py") in entries, "control: the table is the one read"
    stale = {key: sorted(fns) for key, fns in entries.items()
             if key[0] == "learning_root" or key[1].startswith("learning/store/")
             or any(marker in fn for fn in fns for marker in _RETIRED_FUNCTIONS)}
    assert stale == {}, stale
    assert "learning" not in _GATE._ATTRIBUTE_ROLES  # noqa: SLF001 — the role table is the gate's own data
    assert "learning" in _GATE.RECORD_LOCATION_NAMES
