"""Fixtures for #1108 P4; the machinery lives in `_support.py`.

`tick_impl` runs the tick modules' cases once per implementation of the tick's store (#1487 Flow 2, Conformance: "the
existing tick and store-verb tests run over both implementations against one store"): the adapter over the in-process
store and the port over a real post-step helper on the same database. A tick module requests it for every case
(`pytestmark = pytest.mark.usefixtures("tick_impl")`), so it is in each case's fixture closure; a case opts out, to the
adapter alone, with `_drain_support.own_store`. The implementation is carried on the fixture's value, which the case's
tenant holds (`_drain_support.carried_impl`); nothing is kept by a module. Every module is named by its absolute name:
`defender/tests` has no `__init__.py`, so a relative import loads a second copy of it."""
from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path

import pytest

from defender.tests.tenancy.tenant_1108_p4._drain_support import CARRIED, PORT_LANES, TICK_IMPLS, TickImpl
from defender.tests.tenancy.tenant_1108_p4 import _s_b_support as B
from defender.tests.tenancy.tenant_1108_p4._r6_support import WORKTREE
from defender.tests.tenancy.tenant_1108_p4._support import bind_forge, published_tenant

#: The case parameters that name the lane a tick runs: a port case of a lane the port does not serve never reaches the port
#: (its tick is the adapter's), so it is not collected.
LANE_PARAMS = {"lane": {"lead_author": "lead_author"}, "drain": {"lead": "lead_author"}}


@pytest.fixture
def p4_tenant(tmp_path, data_root):
    """The fixture tenant under this test's own data root (`DEFENDER_DATA_ROOT`), its clone a
    real git repo with a live loopback origin, published once for real (`PublishedTenant`)."""
    with published_tenant(tmp_path / "forge", root=data_root) as published:
        yield published


@pytest.fixture(autouse=True)
def data_root(data_root, request, monkeypatch) -> Iterator[Path]:
    """Every case of this folder gets a short data root from the one provider (`support/jobs/_short_root`), whatever fixtures
    it requests: any of them may build a world a helper starts over (`adopt_scene`), whose job socket lives under the root
    and is refused at 108 bytes, which pytest's nested temporary folders (`popen-gwN/data-rootNNN`) overrun from about the
    hundredth test on a worker. This wraps the suite's (`tests/conftest.py`). A case that passed removes its root at once;
    a failed case's stays until the session's end (`_short_roots_removed`)."""
    from defender.tests.support.jobs._short_root import release, short_root
    from defender.tests.support.shared.contracts._data_root_1078 import DATA_ROOT_ENV

    short = short_root()
    monkeypatch.setenv(DATA_ROOT_ENV, str(short))
    yield short
    call = getattr(request.node, "rep_call", None)
    if call is not None and call.passed:
        release(short)


@pytest.fixture(autouse=True, scope="session")
def _short_roots_removed() -> Iterator[None]:
    """The session's short roots (one parent per xdist worker) are removed when it ends, failed cases' included."""
    from defender.tests.support.jobs._short_root import remove_all

    yield
    remove_all()


def pytest_generate_tests(metafunc: pytest.Metafunc) -> None:
    """A case that requests `tick_impl` and drives the tick (it has the `world`) runs over each implementation, unless it
    is marked `own_store`: that one runs once, over the adapter. A module that names `ONLY_TICK_IMPLS` runs its cases over
    those implementations alone: one slice of a case too slow for one file (each file runs on one worker), its other
    implementations in a sibling module."""
    if ("tick_impl" in metafunc.fixturenames and "world" in metafunc.fixturenames
            and not hasattr(metafunc.function, "own_store")):
        metafunc.parametrize("tick_impl", getattr(metafunc.module, "ONLY_TICK_IMPLS", TICK_IMPLS), indirect=True)


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Drop the port cases whose tick is of a lane the port does not serve (the lead lane's port is not in #1487,
    design r5 "Not here", #1546): over the port they would be the adapter's own cases again.

    And keep one port case per test function, its first parametrization: a port case starts a real post-step helper
    process per tick (about eight times an adapter case), and the port's equivalence to the adapter is held by
    `test_1487_tick_store_conformance.py` over every verb and flow, so each test function runs over the port once and over
    the adapter in every parametrization. A module that names `ONLY_TICK_IMPLS` runs only what it names: not thinned."""
    kept, dropped = [], []
    ported: set[tuple[str, str]] = set()
    for item in items:
        params = getattr(getattr(item, "callspec", None), "params", {})
        lane = next((lanes.get(params[name]) for name, lanes in LANE_PARAMS.items() if name in params), None)
        drop = params.get("tick_impl") == "port" and lane is not None and lane not in PORT_LANES
        if params.get("tick_impl") == "port" and not drop and getattr(item.module, "ONLY_TICK_IMPLS", None) is None:
            function = (item.nodeid.split("::", 1)[0], getattr(item, "originalname", item.name))
            drop = function in ported
            ported.add(function)
        (dropped if drop else kept).append(item)
    if dropped:
        config.hook.pytest_deselected(items=dropped)
        items[:] = kept


@pytest.hookimpl(wrapper=True)
def pytest_runtest_makereport(item: pytest.Item, call: pytest.CallInfo):
    """Keep each phase's report on the item, for `tick_impl`'s self-check."""
    report = yield
    setattr(item, f"rep_{report.when}", report)
    return report


@pytest.fixture
def tick_impl(request, tmp_path, monkeypatch):
    """The implementation of the tick's store the case runs over (`param`, else the adapter): a `TickImpl`, carried on the
    case's tenant for `_drain_support.tick_store`. None for a case with no `world` (no tick to give a store). Over the port,
    a case that passed must have reached the port: at its end each helper it started has received a store request, counted
    in the helper, so a tick in a forked child counts (a case that fails already has its own failure to show)."""
    if "world" not in request.fixturenames:
        yield None
        return
    world = request.getfixturevalue("world")
    chosen = TickImpl(getattr(request, "param", "adapter"), world, tmp_path, monkeypatch)
    world.t.carried[CARRIED] = chosen
    try:
        yield chosen
    finally:
        world.t.carried.pop(CARRIED, None)
        chosen.close()
    call = getattr(request.node, "rep_call", None)
    if call is not None and call.passed and (why := chosen.unreached()):
        pytest.fail(f"{why} ({request.node.nodeid}): run it over the adapter only (`own_store`) or drive its tick "
                    f"through the author lane", pytrace=False)


@pytest.fixture
def post_step_helper(request, tmp_path, monkeypatch):
    """`start()`: a real post-step helper over the case's tenant and database (`world`), reading the settings in the
    environment now; closed at the case's end. For a case whose tick is the post-step's, whose store is the port over the
    helper (`PostStepHelper`)."""
    from defender.tests.support.jobs._relay1487 import PostStepHelper, adopt_scene

    world = request.getfixturevalue("world")
    made: list[PostStepHelper] = []

    def start() -> PostStepHelper:
        helper = PostStepHelper(adopt_scene(world.t, world.dsn, monkeypatch), tmp_path)
        made.append(helper)
        return helper

    yield start
    for helper in made:
        helper.close()


@pytest.fixture
def child_env(monkeypatch):
    monkeypatch.setenv("PYTHONPATH", f"{WORKTREE}{os.pathsep}{os.environ.get('PYTHONPATH', '')}")


@pytest.fixture
def tenant(tmp_path, data_root):
    with B.run_tenant(tmp_path, data_root) as t:
        bind_forge(t)
        yield t
