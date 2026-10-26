"""#1080 O4(c), #1131: the API program loads no `runtime` or `learning` module.

Asked of Python itself rather than of the source: each `api` module is imported in a fresh
interpreter and the modules it left loaded are read back, so a lazy door, a conditional import or
any other route counts exactly as it executes."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

DEFENDER = Path(__file__).resolve().parents[2]
REPO = DEFENDER.parent
FORBIDDEN = ("defender.runtime", "defender.learning")

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


def _forbidden(loaded: list[str]) -> list[str]:
    return [m for m in loaded if m in FORBIDDEN or m.startswith(tuple(f + "." for f in FORBIDDEN))]


API_MODULES = sorted(
    "defender.api" + ("" if p.stem == "__init__" else f".{p.stem}")
    for p in (DEFENDER / "api").glob("*.py"))


@pytest.mark.parametrize("module", API_MODULES)
def test_an_api_module_loads_no_runtime_or_learning(module):
    found = _forbidden(_loaded(module))
    assert not found, f"{module} loads {found}"


def test_the_probe_sees_a_runtime_load():
    """Positive control: a module that does load the runtime is reported."""
    assert "defender.runtime.verbs" in _forbidden(_loaded("defender.runtime.verbs"))
