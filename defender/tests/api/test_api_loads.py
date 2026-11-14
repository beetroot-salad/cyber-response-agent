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


#: #1214 r9: what the API's import of `defender.api.app` may not load beyond #1339's allowance (identity's models
#: and SQLAlchemy ORM): the lifecycle node, the database repositories of identity and tenancy, the driver.
_NOT_BY_THE_API = ("defender.lifecycle", "defender.tenancy.postgres", "defender.identity.postgres", "psycopg")


def _found(modules: list[str], name: str) -> list[str]:
    return [m for m in modules if m == name or m.startswith(name + ".")]


@pytest.mark.parametrize("module", API_MODULES)
def test_an_api_module_loads_no_lifecycle_and_no_database_repository_or_driver(module):
    """The API reaches tenancy only through its in-memory twin or an injected repository; `lifecycle` is never loaded (#1214 r9, DC-6)."""
    modules = _loaded(module)
    found = [m for name in _NOT_BY_THE_API for m in _found(modules, name)]
    assert not found, f"{module} loads {found}"


def test_the_not_loaded_probe_sees_a_load():
    """Positive control: the identity database repository and the lifecycle node are reported when imported."""
    assert _found(_loaded("defender.identity.postgres"), "defender.identity.postgres")
    assert _found(_loaded("defender.lifecycle"), "defender.lifecycle")


#: #1083 Am-1: the real server program is a package of its own, `defender/api_server/`, under the same #1080 guard.
API_SERVER_MODULES = sorted(
    "defender.api_server" + ("" if p.stem == "__init__" else f".{p.stem}")
    for p in (DEFENDER / "api_server").rglob("*.py"))
#: The demo's data and the in-memory twins are the demo server's only (Am-1, P1).
_DEMO_ONLY = ("defender.api.demo", "defender.api.fakes")


def test_the_program_glob_finds_the_entry_module():
    """Positive control: the recursive glob over `defender/api_server/` finds `__main__`. (Am-1)"""
    assert "defender.api_server.__main__" in API_SERVER_MODULES
    assert "defender.api_server" in API_SERVER_MODULES


@pytest.mark.parametrize("module", API_SERVER_MODULES)
def test_a_program_module_loads_no_runtime_or_learning(module):
    """Every module of the real server program loads nothing in `API_FORBIDDEN`. (Am-1)"""
    found = api_forbidden(_loaded(module))
    assert not found, f"{module} loads {found}"


@pytest.mark.parametrize("module", API_SERVER_MODULES)
def test_a_program_module_loads_neither_the_demo_nor_the_fakes(module):
    """The real program never loads `defender.api.demo` or `defender.api.fakes`. (Am-1, P1)"""
    modules = _loaded(module)
    found = [m for name in _DEMO_ONLY for m in _found(modules, name)]
    assert not found, f"{module} loads {found}"


def test_the_demo_probe_sees_a_load():
    """Positive control: importing the demo reports both demo-only modules. (Am-1)"""
    modules = _loaded("defender.api.demo")
    assert all(_found(modules, name) for name in _DEMO_ONLY)
