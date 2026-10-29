"""#1214 (r9 Flow 4, P6): the synchronous `TenantDirectory` facade for host code, and the import rule
(importing `defender.tenancy` loads no database driver until a repository is built; nothing under `box/`
imports tenancy).

The import-rule cases live here, not in `tests/migrations/test_1339_migrations.py` (whose
`test_importing_identity_loads_no_database_driver` is the nearest guard): that file is not in this slice's
edit list beyond r8's changes. They reuse its `run_python` probe.
"""
from __future__ import annotations

import ast
import asyncio
import datetime as dt
import textwrap
import types
from typing import Any

import pytest

from defender.tests.migrations.test_1339_migrations import ROOT, run_python
from defender.tests.support.shared._fixture_uuid import fixture_uuid
from defender.tests.support.shared._pglocks1339 import connections, until
from defender.tests.support.shared._postgres1339 import (  # noqa: F401 — fixture
    execute,
    migrated_database,
)

NOW = dt.datetime(2026, 10, 28, 12, 0, tzinfo=dt.UTC)
T1 = fixture_uuid("tenant:1214-dir-1")
T2 = fixture_uuid("tenant:1214-dir-2")
ORIGIN = "http://forge.test/tenants/t1.git"
#: (state, pending_action, step, step_actor): a row each state may hold (data model).
JOB = {"creating": ("create", "names", "service"), "active": (None, None, None),
       "offboarding": ("offboard", "offboard", "service"), "offboarded": (None, None, None)}


# --- a recording repository: injects answers, implements no policy ------------------------------------


class Probe:
    """What a directory did to the repositories its factory handed out: opens, closes, and the event loop
    each read and close ran in."""

    def __init__(self, *, state: str | None = "active", wiring: Any = None, fail: Exception | None = None) -> None:
        self.state, self.wiring, self.fail = state, wiring, fail
        self.opened = 0
        self.closed = 0
        self.read_loops: list[asyncio.AbstractEventLoop] = []
        self.close_loops: list[asyncio.AbstractEventLoop] = []

    def factory(self) -> Any:
        self.opened += 1
        probe = self

        class Repository:
            async def tenant(self, tenant_id: str) -> Any:
                probe.read_loops.append(asyncio.get_running_loop())
                if probe.fail is not None:
                    raise probe.fail
                return None if probe.state is None else types.SimpleNamespace(id=tenant_id, state=probe.state)

            async def forge_wiring(self, tenant_id: str) -> Any:
                probe.read_loops.append(asyncio.get_running_loop())
                if probe.fail is not None:
                    raise probe.fail
                return probe.wiring

            async def close(self) -> None:
                probe.closed += 1
                probe.close_loops.append(asyncio.get_running_loop())

        return Repository()


def _directory(probe: Probe) -> Any:
    from defender.tenancy import TenantDirectory

    return TenantDirectory(probe.factory)


# --- the facade -----------------------------------------------------------------------------------


@pytest.mark.parametrize("call", ["state", "forge_wiring"])
def test_each_call_runs_in_its_own_event_loop_and_closes_the_repository_it_opened(call):
    """Every call is one asyncio.run: its own loop, closed after; the repository is closed in that loop (P6, #1339 engine rule)."""
    probe = Probe(wiring=types.SimpleNamespace(repo="tenants/t1", origin=ORIGIN))
    directory = _directory(probe)
    getattr(directory, call)(T1)
    getattr(directory, call)(T1)
    first, second = probe.read_loops
    assert first is not second  # a loop kept between calls would be a second design
    assert first.is_closed()
    assert second.is_closed()
    assert probe.opened == probe.closed == 2
    assert probe.close_loops == [first, second]  # disposed in the loop that connected


@pytest.mark.parametrize("call", ["state", "forge_wiring"])
def test_a_failing_read_still_closes_the_repository_and_reaches_the_caller(call):
    """A read that raises propagates and leaves no repository open (P6: no engine left open)."""
    probe = Probe(fail=ConnectionError("database away"))
    with pytest.raises(ConnectionError, match="database away"):
        getattr(_directory(probe), call)(T1)
    assert probe.opened == probe.closed == 1
    probe.fail = None  # control: the same directory answers once the read works
    assert _directory(probe).state(T1) == "active"


def test_state_answers_the_repositorys_state_or_none_for_an_unknown_tenant():
    """`state` is the tenant's state string, None when absent (Flow 4)."""
    assert _directory(Probe(state="offboarding")).state(T1) == "offboarding"
    assert _directory(Probe(state="active")).state(T1) == "active"
    assert _directory(Probe(state=None)).state(T1) is None


def test_forge_wiring_answers_what_the_repository_holds():
    """`forge_wiring` hands back the recorded repo and origin (Flow 4: origin from forge_wiring)."""
    wiring = types.SimpleNamespace(repo="tenants/t1", origin=ORIGIN)
    got = _directory(Probe(wiring=wiring)).forge_wiring(T1)
    assert (got.repo, got.origin) == ("tenants/t1", ORIGIN)


@pytest.mark.anyio
@pytest.mark.parametrize("call", ["state", "forge_wiring"])
async def test_a_call_inside_a_running_loop_is_refused_and_a_worker_thread_may_call(call):
    """Inside a running loop the facade refuses and opens nothing; from a worker thread (the host actor's way) it answers (P6, RC-5)."""
    probe = Probe(wiring=types.SimpleNamespace(repo="tenants/t1", origin=ORIGIN))
    directory = _directory(probe)
    with pytest.raises(RuntimeError):  # GAP-A-1: the type is unpinned; RuntimeError is what asyncio.run itself raises
        getattr(directory, call)(T1)
    assert probe.opened == probe.closed  # whatever it opened it closed
    assert await asyncio.to_thread(getattr(directory, call), T1) is not None  # control: same call, no loop on that thread
    assert probe.opened == probe.closed >= 1


def test_the_directory_is_read_only():
    """Host code can read state and wiring and write nothing: the facade has no request or seeder method (P2)."""
    directory = _directory(Probe())
    assert {"state", "forge_wiring"} <= set(dir(directory))
    assert [n for n in dir(directory) if n.startswith(("request_", "add_", "register"))] == []


def test_a_directory_over_the_in_memory_twin_survives_its_calls():
    """The twin outlives the facade's per-call close: a second call sees the same tenant (P6 with the twin shared by the fixtures)."""
    from defender.tenancy import InMemoryTenantRepository, TenantDirectory

    twin: Any = InMemoryTenantRepository()
    asyncio.run(twin.add_tenant(T1, created_at=NOW, state="active", repo="tenants/t1", origin=ORIGIN))
    directory = TenantDirectory(lambda: twin)
    assert [directory.state(T1), directory.state(T1)] == ["active", "active"]
    assert directory.state(T2) is None  # control: an unseeded tenant is unknown
    assert directory.forge_wiring(T1).origin == ORIGIN
    asyncio.run(twin.request_offboard(T1, now=NOW))
    assert directory.state(T1) == "offboarding"  # and it reads the twin's present state, not a copy


# --- the facade over PostgreSQL ---------------------------------------------------------------------


def _insert(dsn: str, tenant: str, state: str, *, wiring: bool = False) -> None:
    action, step, actor = JOB[state]
    execute(dsn, """INSERT INTO tenancy.tenants (id, created_at, state, pending_action, step, step_actor)
                    VALUES (%s, %s, %s, %s, %s, %s)""", (tenant, NOW, state, action, step, actor))
    if wiring:
        execute(dsn, "INSERT INTO tenancy.forge_wiring (tenant_id, repo, origin) VALUES (%s, %s, %s)",
                (tenant, f"tenants/{tenant}", ORIGIN))


def _postgres_directory(dsn: str) -> Any:
    from defender.tenancy import TenantDirectory
    from defender.tenancy.postgres import PostgresTenantRepository

    return TenantDirectory(lambda: PostgresTenantRepository(dsn))


@pytest.mark.postgres
def test_the_directory_over_postgres_reads_each_state_and_the_wiring_and_leaves_no_connection(migrated_database):  # noqa: F811
    """Over PostgreSQL `state` and `forge_wiring` answer from the tables and no connection stays open (P6, Flow 4)."""
    ids = {state: fixture_uuid(f"tenant:1214-dir-{state}") for state in JOB}
    for state, tenant in ids.items():
        _insert(migrated_database, tenant, state, wiring=state == "active")
    directory = _postgres_directory(migrated_database)
    assert {state: directory.state(tenant) for state, tenant in ids.items()} == {s: s for s in JOB}
    assert directory.state(fixture_uuid("tenant:1214-dir-absent")) is None
    got = directory.forge_wiring(ids["active"])
    assert (got.repo, got.origin) == (f"tenants/{ids['active']}", ORIGIN)

    async def open_connections() -> int:
        return await connections(migrated_database)

    assert asyncio.run(open_connections()) == 0


@pytest.mark.postgres
def test_the_connection_check_sees_an_open_repository(migrated_database):  # noqa: F811
    """Control for the check above: a repository held open shows as connections, and closing it ends them."""
    from defender.tenancy.postgres import PostgresTenantRepository

    _insert(migrated_database, T1, "active")

    async def scenario() -> tuple[int, int]:
        repo = PostgresTenantRepository(migrated_database)
        try:
            await repo.tenants()
            while_open = await connections(migrated_database)
        finally:
            await repo.close()

        async def none_left() -> bool:
            return await connections(migrated_database) == 0

        await until(none_left)
        return while_open, await connections(migrated_database)

    while_open, after = asyncio.run(scenario())
    assert while_open > 0
    assert after == 0


# --- the import rule --------------------------------------------------------------------------------

_PRELUDE = """
import sys
loaded = lambda *names: sorted(m for m in sys.modules if m.split(".")[0] in names)
"""


def _probe(body: str):
    return run_python(_PRELUDE + textwrap.dedent(body))


def test_importing_tenancy_loads_no_database_code():
    """`import defender.tenancy` and its folder rules load no psycopg, SQLAlchemy or Alembic; the package did load (P6, #1339 rule I)."""
    probe = _probe("""
        import defender.tenancy
        from defender.tenancy import accept_tenant, TenantDirectory
        print("tenancy" if "defender.tenancy" in sys.modules else "missing")
        print(loaded("psycopg", "sqlalchemy", "alembic") or "no-database-code")
    """)
    assert probe.returncode == 0, probe.stderr
    assert probe.stdout.split() == ["tenancy", "no-database-code"]


def test_building_the_in_memory_twin_and_a_directory_loads_no_driver():
    """The twin and the facade need no driver, so a process without a database loads none (P6)."""
    probe = _probe("""
        import asyncio
        from defender.tenancy import InMemoryTenantRepository, TenantDirectory
        twin = InMemoryTenantRepository()
        print(TenantDirectory(lambda: twin).state("nobody"))
        print(loaded("psycopg") or "no-driver")
    """)
    assert probe.returncode == 0, probe.stderr
    assert probe.stdout.split() == ["None", "no-driver"]


def test_building_the_postgres_repository_is_what_loads_the_driver():
    """Control for the two above: the same probe sees psycopg once a PostgreSQL repository is built (P6)."""
    pytest.importorskip("psycopg")
    probe = _probe("""
        import asyncio
        from defender.tenancy.postgres import PostgresTenantRepository
        repo = PostgresTenantRepository("postgresql://u:p@127.0.0.1:1/none")
        print(loaded("psycopg") and "driver" or "no-driver")
        asyncio.run(repo.close())
    """)
    assert probe.returncode == 0, probe.stderr
    assert probe.stdout.split() == ["driver"]


def _tenancy_imports(source: str) -> list[str]:
    """Every import in `source` that reaches `tenancy`, absolute or relative."""
    found = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            found += [a.name for a in node.names if a.name.split(".")[:2] == ["defender", "tenancy"]]
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            names = [a.name for a in node.names]
            if module.split(".")[:2] == ["defender", "tenancy"] or (node.level and module.split(".")[0] == "tenancy"):
                found.append(module)
            elif (module == "defender" or node.level) and "tenancy" in names:
                found.append(f"{module}:tenancy")
    return found


def test_the_box_scan_sees_each_way_of_importing_tenancy():
    """Control for the box scan: absolute, from-package and relative spellings are all reported."""
    for source in ("import defender.tenancy", "from defender.tenancy import x", "from defender import tenancy",
                   "from ..tenancy import x", "from .. import tenancy"):
        assert _tenancy_imports(source), source
    assert _tenancy_imports("from defender.records import x\nimport os") == []


def test_nothing_under_box_imports_tenancy():
    """No `box/` module imports tenancy, and importing every box module loads none (P6: the box image has no database code)."""
    box = ROOT / "defender" / "box"
    sources = sorted(box.rglob("*.py"))
    assert sources, "found no box modules to scan"
    offenders = {str(p.relative_to(box)): _tenancy_imports(p.read_text()) for p in sources}
    assert {k: v for k, v in offenders.items() if v} == {}
    modules = [".".join(("defender", "box", *p.relative_to(box).with_suffix("").parts)).removesuffix(".__init__")
               for p in sources]
    probe = _probe(f"""
        import importlib
        for name in {modules!r}:
            importlib.import_module(name)
        print("tenancy" if "defender.tenancy" in sys.modules else "no-tenancy")
        import defender.tenancy
        print("tenancy" if "defender.tenancy" in sys.modules else "no-tenancy")
    """)
    assert probe.returncode == 0, probe.stderr
    assert probe.stdout.split() == ["no-tenancy", "tenancy"]
