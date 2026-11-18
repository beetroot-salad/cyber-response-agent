"""Fixtures for #1108 P4; the machinery lives in `_support.py`.

`tick_impl` runs the tick modules' cases once per implementation of the tick's store (#1487 Flow 2, Conformance: "the
existing tick and store-verb tests run over both implementations against one store"): the adapter over the in-process
store and the port over a real post-step helper on the same database. A case opts out with `_drain_support.own_store`."""
from __future__ import annotations

import pytest

from ._support import published_tenant

#: The modules whose cases drive the author tick (through `_drain_support.author_drain`, or `_feedback1278.tick`).
TICK_MODULES = {"test_1278_tick", "test_1278_feedback", "test_1278_tick_faults", "test_drains"}


@pytest.fixture
def p4_tenant(tmp_path, data_root):
    """The fixture tenant under this test's own data root (`DEFENDER_DATA_ROOT`), its clone a
    real git repo with a live loopback origin, published once for real (`PublishedTenant`)."""
    with published_tenant(tmp_path / "forge", root=data_root) as published:
        yield published


def pytest_generate_tests(metafunc: pytest.Metafunc) -> None:
    """Each tick case over the adapter and over the port, unless it is marked `own_store`."""
    from ._drain_support import TICK_IMPLS

    if (metafunc.module.__name__.rsplit(".", 1)[-1] in TICK_MODULES and "world" in metafunc.fixturenames
            and not hasattr(metafunc.function, "own_store")):
        metafunc.fixturenames.append("tick_impl")
        metafunc.parametrize("tick_impl", TICK_IMPLS, indirect=True)


@pytest.fixture
def tick_impl(request, tmp_path, monkeypatch):
    """The implementation of the tick's store the case runs over (`param`): `_drain_support.tick_store` hands the case's
    ticks that store. Requested after `world`, whose environment the port's helper reads."""
    from ._drain_support import ACTIVE, TickImpl

    world = request.getfixturevalue("world")
    chosen = TickImpl(getattr(request, "param", "adapter"), world, tmp_path, monkeypatch)
    ACTIVE.append(chosen)
    try:
        yield chosen
    finally:
        ACTIVE.remove(chosen)
        chosen.close()


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
