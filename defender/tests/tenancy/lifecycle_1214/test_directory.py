# ruff: noqa: PT018
"""#1214 (r9 Flow 4, P6): the synchronous `TenantDirectory` facade for host code, and the import rule
(importing `defender.tenancy` loads no database driver until a repository is built; nothing under `box/`
imports tenancy).

The import-rule cases live here, not in `tests/migrations/test_1339_migrations.py` (whose
`test_importing_identity_loads_no_database_driver` is the nearest guard): that file is not in this slice's
edit list beyond r8's changes. They reuse its `run_python` probe.

#1214 attack-3 hole 15 (P3, Flow 4): a sibling run (`--tenant T --episode E --world W`) is admitted like an ordinary
run: only while the tenant is `active`, and with no directory and no database address it refuses.

#1214 attack-3 holes 1, 2, 4 (Flow 4, P3): the lead drain re-reads the tenant's state at each claim, fails
closed on a directory error, treats offboarded and unknown as not active, and never counts a set-aside claim.
"""
from __future__ import annotations

import ast
import asyncio
import datetime as dt
import textwrap
import types
from typing import Any
import contextlib
import io
import json
from pathlib import Path

import pytest

from defender.tests.migrations.test_1339_migrations import ROOT, run_python
from defender.tests.support.shared._fixture_uuid import fixture_uuid
from defender.tests.support.shared._pglocks1339 import connections, until
from defender.tests.support.shared._postgres1339 import (  # noqa: F401 — fixture
    execute,
    migrated_database,
)
from defender.tests.support.tenancy._active1214 import DSN_ENV, active_directory
from defender.tests.tenancy.lifecycle_1214.test_host_entry import (
    NOT_A_REFUSAL_OF_STATE,
    TENANT,
    _Calls,
    _has,
    _tenant_placed,  # noqa: F401 — autouse fixture
)
from defender.tests.support.shared._locations_1210 import location_path
from defender.tests.tenancy.lifecycle_1214.test_host_entry import (
    _FlipOnFirst,
    _twin_directory,
)
from defender.tests.tenancy.tenant_1108_p4.conftest import p4_tenant  # noqa: F401 — fixture


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


def _connection_errors() -> list[Exception]:
    import sqlalchemy.exc

    return [sqlalchemy.exc.OperationalError("SELECT", {}, Exception("connection failed: refused")),
            sqlalchemy.exc.InterfaceError("SELECT", {}, Exception("connection already closed"))]


@pytest.mark.parametrize("call", ["state", "forge_wiring"])
@pytest.mark.parametrize("which", [0, 1], ids=["OperationalError", "InterfaceError"])
def test_a_database_that_cannot_be_reached_is_records_unreachable(call, which):
    """A read the database cannot answer (the driver's connection-class error) reaches the caller as
    `RecordsUnreachable`, a `TenantRefused` (the transient refusal every host consumer handles), naming the driver's
    first line; the repository is still closed (#1214 Flow 4; PR #1350 review: a blip after process start)."""
    from defender.records.formats import TenantRefused
    from defender.systems.run_tenant import RecordsUnreachable

    probe = Probe(fail=_connection_errors()[which])
    with pytest.raises(RecordsUnreachable) as down:
        getattr(_directory(probe), call)(T1)
    assert isinstance(down.value, TenantRefused)
    assert "could not be reached" in str(down.value), str(down.value)
    assert down.value.__cause__ is probe.fail, "the driver's error is not kept as the cause"
    assert probe.opened == probe.closed == 1


def test_a_database_error_that_is_not_about_the_connection_reaches_the_caller_as_raised():
    """Control: only connection-class errors are translated; a statement the database refuses is not an outage."""
    import sqlalchemy.exc

    from defender.systems.run_tenant import RecordsUnreachable

    refused = sqlalchemy.exc.IntegrityError("INSERT", {}, Exception("duplicate key"))
    with pytest.raises(sqlalchemy.exc.IntegrityError) as raised:
        _directory(Probe(fail=refused)).state(T1)
    assert not isinstance(raised.value, RecordsUnreachable)


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


def _sibling_start(directory: Any = ...) -> str:
    """`run.main` of a sibling up to its first refusal or fault: its text."""
    from defender import run as run_py

    calls = _Calls()
    given = {} if directory is ... else {"directory": directory}
    err = io.StringIO()
    try:
        with contextlib.redirect_stderr(err):
            run_py.main(["--tenant", TENANT, "--episode", "ep-1214", "--world", "w-1214", "--no-learn"], **given,
                        preflight=calls.hook("preflight", 0), visualize=calls.hook("visualize", None),
                        enqueue=calls.hook("enqueue", False), publish=calls.hook("publish", ""),
                        lifecycle=calls.hook("lifecycle", {"output": "", "requests": 0, "truncated_by": None}))
    except SystemExit as refused:
        return f"{refused.code}\n{err.getvalue()}"
    except Exception as failed:  # noqa: BLE001 — past acceptance, the next real refusal
        return f"{type(failed).__name__}: {failed}\n{err.getvalue()}"
    return err.getvalue()


@pytest.mark.parametrize("state", ["creating", "offboarding", "offboarded"])
def test_a_sibling_run_refuses_a_tenant_that_is_not_active_naming_its_state(data_root, state):
    """`--episode` runs refuse a non-`active` tenant naming its state, before the episode is looked up (Flow 4, P3)."""
    refused = _sibling_start(active_directory(data_root, TENANT, state=state))
    _has(refused, "[run.py]", state)
    admitted = _sibling_start(active_directory(data_root, TENANT))
    assert not any(word in admitted.lower() for word in NOT_A_REFUSAL_OF_STATE), f"control: {admitted}"


def test_a_sibling_run_of_an_unknown_tenant_is_refused(data_root):
    """A directory holding no row for the tenant refuses a sibling like an ordinary run (P3)."""
    from defender.tenancy import InMemoryTenantRepository, TenantDirectory

    twin: Any = InMemoryTenantRepository()
    refused = _sibling_start(TenantDirectory(lambda: twin))
    _has(refused, "[run.py]")
    assert "no such tenant" in refused, refused


def test_a_sibling_run_with_no_directory_and_no_database_address_refuses(data_root, monkeypatch):
    """Fails closed: no directory, no address -> a refusal naming the address (Flow 4)."""
    monkeypatch.delenv(DSN_ENV, raising=False)
    _has(_sibling_start(), "[run.py]", DSN_ENV)


#: What the directory answers after the first claim: a state, None (no row), or an error to raise.
AFTER = ["offboarding", "offboarded", "creating", None]


class _Failing(Exception):
    pass


def _scripted(directory: Any) -> tuple[Any, Any]:
    """`directory` with a `state` that can be overridden from now on: (directory, set_answer)."""
    box: dict[str, Any] = {}
    real = directory.state

    def state(tenant_id: Any) -> Any:
        if "answer" in box:
            answer = box["answer"]
            if isinstance(answer, Exception):
                raise answer
            return answer
        return real(tenant_id)

    object.__setattr__(directory, "state", state)
    return directory, lambda answer: box.update(answer=answer)


def _drain(t: Any, tmp_path: Path, monkeypatch: Any, answer: Any) -> tuple[list[str], dict[str, str], Any, Any]:
    """Two queued runs, then ticks of the lead drain with `answer` given after the first claim.
    Returns (labels served over the ticks, run name -> label, paths, directory)."""
    from defender.tests.tenancy.tenant_1108_p4._drain_support import (
        BoxSpy,
        LeadStep,
        drain_paths,
        executed_lead,
        lead_author_drain,
        product_repo,
        queued_run,
    )

    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "1000")
    monkeypatch.setenv("LEARNING_LEAD_AUTHOR_LIFT_THRESHOLD", "1000")
    directory, answer_with = _scripted(_twin_directory(t.tenant_id, t.origin)[0])
    paths = drain_paths(t, product_repo(tmp_path, adapters=("cmdb",)))
    runs = {queued_run(t, paths, label).name: label for label in ("claim-1", "claim-2")}
    inner = LeadStep(executed={r: [executed_lead("cmdb.owner-by-tag")] for r in runs}, edits={})
    step = _FlipOnFirst(inner, lambda: answer_with(answer))
    for _ in range(4):  # repeated ticks: a set-aside claim must not wear out
        with contextlib.suppress(_Failing):
            lead_author_drain(t, paths, box=BoxSpy(), run_lead_author=step, run_pitfalls=lambda *_a, **_k: 0,
                              directory=directory)
    return step.served, runs, paths, directory


@pytest.mark.parametrize("answer", AFTER)
def test_a_claim_of_a_tenant_no_longer_active_stays_queued_uncounted_across_ticks(p4_tenant, tmp_path, monkeypatch, answer):  # noqa: F811
    """Whatever the tenant became after the first claim, the second is never served, keeps `attempts`, and survives repeated ticks (Flow 4)."""
    t = p4_tenant
    served, runs, paths, _ = _drain(t, tmp_path, monkeypatch, answer)
    assert len(served) == 1, served
    unserved = next(label for run, label in runs.items() if run != served[0])
    queued = Path(location_path(paths.state_root)) / "author-queue" / f"case-{unserved}.json"
    assert queued.is_file(), "the claim of a tenant no longer active must stay queued"
    assert json.loads(queued.read_text(encoding="utf-8")).get("attempts", 0) == 0, "a set-aside claim was counted"


def test_a_directory_that_fails_at_the_second_claim_does_not_serve_it(p4_tenant, tmp_path, monkeypatch):  # noqa: F811
    """A state read that raises at the second claim: that claim is not served and is not lost (fails closed, deck PR #678)."""
    t = p4_tenant
    served, runs, paths, _ = _drain(t, tmp_path, monkeypatch, _Failing("database away"))
    assert len(served) == 1, served
    unserved = next(label for run, label in runs.items() if run != served[0])
    root = Path(location_path(paths.state_root)) / "author-queue"
    assert list(root.rglob(f"case-{unserved}.json")), "the unserved claim vanished"


class _Blip:
    """The tenant's repository, until `down` is set: then every read fails as a database that went away after the
    drain started does (the driver's connection-class error)."""

    def __init__(self, twin: Any) -> None:
        self.twin, self.down = twin, False
        self.failed: list[str] = []

    def __getattr__(self, name: str) -> Any:
        if not self.down or name == "close":
            return getattr(self.twin, name)

        async def unreachable(*_a: Any, **_k: Any) -> Any:
            self.failed.append(name)
            import sqlalchemy.exc

            raise sqlalchemy.exc.OperationalError("SELECT", {}, Exception("connection failed: server closed the "
                                                                          "connection unexpectedly"))
        return unreachable


def test_a_database_blip_mid_tick_leaves_the_claim_queued_uncounted_and_the_tick_ends_cleanly(p4_tenant, tmp_path, monkeypatch):  # noqa: F811
    """The tenant records' database goes away after the first claim is served: the next claim is handed back exactly
    as queued (no attempt counted, no failed letter) and no more are taken, the tick ends without a fault, and the
    ticks that meet the outage at their delivery skip; once it is back the claims are served (PR #1350 review: repeated
    blips must not walk a valid row into the "served N times" quarantine)."""
    from defender.tenancy import TenantDirectory
    from defender.tests.tenancy.tenant_1108_p4._drain_support import (
        BoxSpy,
        LeadStep,
        drain_paths,
        executed_lead,
        lead_author_drain,
        product_repo,
        queued_run,
    )

    t = p4_tenant
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "1000")
    monkeypatch.setenv("LEARNING_LEAD_AUTHOR_LIFT_THRESHOLD", "1000")
    blip = _Blip(_twin_directory(t.tenant_id, t.origin)[0]._open())  # noqa: SLF001 — the twin behind the directory
    directory = TenantDirectory(lambda: blip)
    paths = drain_paths(t, product_repo(tmp_path, adapters=("cmdb",)))
    labels = ("claim-1", "claim-2", "claim-3")
    runs = {queued_run(t, paths, label).name: label for label in labels}
    inner = LeadStep(executed={r: [executed_lead("cmdb.owner-by-tag")] for r in runs}, edits={})
    step = _FlipOnFirst(inner, lambda: setattr(blip, "down", True))
    queue = Path(location_path(paths.state_root)) / "author-queue"
    queued = {label: (queue / f"case-{label}.json").read_bytes() for label in labels}

    def tick() -> int:
        return lead_author_drain(t, paths, box=BoxSpy(), run_lead_author=step, run_pitfalls=lambda *_a, **_k: 0,
                                 directory=directory)
    for attempt in ("the tick the blip begins in", "a tick during the outage", "another tick during the outage"):
        assert tick() == 0, f"{attempt}: the tick ended in a fault"
        [served] = step.served
        for unserved in (label for run, label in runs.items() if run != served):
            assert (queue / f"case-{unserved}.json").read_bytes() == queued[unserved], (
                f"{attempt}: a claim the outage met must stay exactly as queued (no attempt counted)")
        if attempt == "the tick the blip begins in":
            assert blip.failed.count("tenant") == 1, f"the tick kept taking claims after the outage: {blip.failed}"
        assert list((queue / "failed").glob("*")) == [], f"{attempt}: a failed letter was written"
        assert not list((queue / "inflight").glob("*")), f"{attempt}: a claim was left in flight"
    blip.down = False
    assert tick() == 0
    assert sorted(step.served) == sorted(runs), "the claim the outage met was not served once the database was back"
