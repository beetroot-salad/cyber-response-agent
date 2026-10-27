"""The API program loads no runtime or `learning` module (#1080; the set is `_spec1080.API_FORBIDDEN`).

Asked of Python rather than the source: each `api` module is imported in a fresh interpreter and
the modules left loaded are read back, so a lazy or conditional import counts as it executes."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from defender.tests.tooling.layout_contracts._spec1080 import api_forbidden

DEFENDER = Path(__file__).resolve().parents[2]
REPO = DEFENDER.parent

_PROBE = """
import importlib, json, sys
importlib.import_module(sys.argv[1])
print(json.dumps(sorted(sys.modules)))
"""


def _loaded(module: str) -> list[str]:
    env = {**os.environ, "PYTHONPATH": os.pathsep.join(
        p for p in (str(REPO), os.environ.get("PYTHONPATH", "")) if p)}
    proc = subprocess.run([sys.executable, "-c", _PROBE, module], capture_output=True, text=True,
                          check=False, cwd=str(REPO), env=env, timeout=180)
    assert proc.returncode == 0, f"importing {module} failed:\n{proc.stderr}"
    return json.loads(proc.stdout.splitlines()[-1])


API_MODULES = sorted(
    "defender.api" + ("" if p.stem == "__init__" else f".{p.stem}")
    for p in (DEFENDER / "api").glob("*.py"))


@pytest.mark.parametrize("module", API_MODULES)
def test_an_api_module_loads_no_runtime_or_learning(module):
    found = api_forbidden(_loaded(module))
    assert not found, f"{module} loads {found}"


def test_the_probe_sees_a_runtime_load():
    """Positive control: a module that does load the runtime is reported."""
    assert "defender.investigation.run_state" in api_forbidden(_loaded("defender.investigation.run_state"))
    # runtime code placed outside `investigation` counts too
    assert "defender.systems.verbs" in api_forbidden(_loaded("defender.systems.verbs"))
