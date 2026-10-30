# ruff: noqa: PT018
"""#1214 attack-3 holes 5, 8, 14 (P6, Flow 4): every `TenantDirectory` method (`generations` and the publish-outcome
write and read included) closes what it opens and refuses a running loop; no tenancy module loads a driver.
"""
from __future__ import annotations

import asyncio
import contextlib
import textwrap
import types
from typing import Any

import pytest

from defender.tests.migrations.test_1339_migrations import run_python
from defender.tests.tenancy.lifecycle_1214.test_1214_directory import ORIGIN, T1, Probe

GENERATION = types.SimpleNamespace(salt="g1", status="live")


class _Probe(Probe):
    """`Probe` whose repositories also answer generations and the publish outcome."""

    def factory(self) -> Any:
        repository = super().factory()
        probe = self

        async def generations(tenant_id: str) -> list[Any]:
            probe.read_loops.append(asyncio.get_running_loop())
            if probe.fail is not None:
                raise probe.fail
            return [GENERATION]

        async def publish_status(tenant_id: str) -> dict[str, str]:
            probe.read_loops.append(asyncio.get_running_loop())
            return {"by": "x"}

        async def record_publish_status(tenant_id: str, line: str, *, by: str) -> None:
            probe.read_loops.append(asyncio.get_running_loop())
            if probe.fail is not None:
                raise probe.fail

        repository.generations, repository.publish_status = generations, publish_status
        repository.record_publish_status = record_publish_status
        return repository


def _directory(probe: Probe) -> Any:
    from defender.tenancy import TenantDirectory

    return TenantDirectory(probe.factory)


def _calls(directory: Any) -> dict[str, Any]:
    from defender import tenancy

    return {
        "state": lambda: directory.state(T1),
        "forge_wiring": lambda: directory.forge_wiring(T1),
        "generations": lambda: directory.generations(T1),
        "record_report": lambda: tenancy.record_report(directory, T1, "fresh abc", by="child"),
        "read_status": lambda: tenancy.read_status(directory, T1),
    }


CALLS = ["state", "forge_wiring", "generations", "record_report", "read_status"]


def _probe() -> _Probe:
    return _Probe(wiring=types.SimpleNamespace(repo="tenants/t1", origin=ORIGIN))


@pytest.mark.parametrize("call", CALLS)
def test_every_directory_call_closes_the_repository_it_opened_in_its_own_loop(call):
    """Each call, `generations` and the outcome write/read included, opens one repository and closes it in the loop that ran it (P6)."""
    probe = _probe()
    do = _calls(_directory(probe))[call]
    do()
    do()
    first, second = probe.read_loops
    assert first is not second
    assert first.is_closed() and second.is_closed()
    assert probe.opened == probe.closed == 2
    assert probe.close_loops == [first, second]


@pytest.mark.parametrize("call", ["state", "forge_wiring", "generations", "record_report"])
def test_a_failing_read_or_write_still_closes_every_repository(call):
    """A failing database leaves no repository open, whichever method asked (P6)."""
    probe = _probe()
    probe.fail = ConnectionError("database away")
    with contextlib.suppress(ConnectionError):  # the best-effort recorder swallows it; the others let it reach the caller
        _calls(_directory(probe))[call]()
    assert probe.opened == probe.closed == 1


@pytest.mark.anyio
@pytest.mark.parametrize("call", CALLS)
async def test_every_directory_call_inside_a_running_loop_is_refused_before_opening_anything(call):
    """Inside a running loop a call raises RuntimeError and opens nothing, never answering from a helper thread (P6, RC-5)."""
    probe = _probe()
    do = _calls(_directory(probe))[call]
    if call == "record_report":  # best effort: it may refuse loudly or log the refusal and record nothing
        with contextlib.suppress(RuntimeError):
            do()
    else:
        with pytest.raises(RuntimeError):
            do()
    assert probe.opened == 0, "a repository was opened inside a running loop"
    assert probe.read_loops == []
    await asyncio.to_thread(do)  # control: from a worker thread the same call runs
    assert probe.opened == probe.closed >= 1


def test_no_tenancy_module_but_the_postgres_one_loads_the_driver_on_import():
    """Importing every module of `defender.tenancy` (and serving every name of its door) loads no psycopg driver (the models' SQLAlchemy is not one; P6, #1339)."""
    probe = run_python(textwrap.dedent("""
        import importlib, pkgutil, sys
        import defender.tenancy as tenancy
        names = [m.name for m in pkgutil.iter_modules(tenancy.__path__) if m.name != "postgres"]
        assert names, "found no tenancy modules"
        for name in names:
            importlib.import_module("defender.tenancy." + name)
        for name in tenancy._HOMES:
            getattr(tenancy, name)
        print(sorted(m for m in sys.modules if m.split(".")[0] in ("psycopg",)) or "none")
    """))
    assert probe.returncode == 0, probe.stderr
    assert probe.stdout.split() == ["none"], probe.stdout
