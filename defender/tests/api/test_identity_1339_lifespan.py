"""#1339 the async identity service behind the API: the harness drives start and sends (O5), and the
lifespan's sender is a task on the app's loop that stops before the repository closes (O5, S-2)."""
from __future__ import annotations

import asyncio
import datetime as _dt
import inspect
import time
from typing import Any

import pytest

pytest.importorskip("fastapi")

from defender.tests.support.api._identity1306 import (  # noqa: E402
    ANN,
    NEW,
    T1,
    World,
    wait_until,
)

INTERVAL = _dt.timedelta(milliseconds=50)


class RecordingRepository:
    """The repository with every awaited call recorded as (name, the loop it ran on)."""

    def __init__(self, inner: Any) -> None:
        self._inner = inner
        self.calls: list[tuple[str, asyncio.AbstractEventLoop]] = []

    def __getattr__(self, name: str) -> Any:
        attr = getattr(self._inner, name)
        if not inspect.iscoroutinefunction(attr):
            return attr

        async def recorded(*args: Any, **kwargs: Any) -> Any:
            self.calls.append((name, asyncio.get_running_loop()))
            return await attr(*args, **kwargs)
        return recorded

    def names(self) -> list[str]:
        return [name for name, _ in self.calls]


def test_the_harness_runs_bootstrap_and_a_send_pass_and_the_api_serves_over_them() -> None:
    """World(start=True) awaits start and one sender pass; the person can then sign in through the API (O5)."""
    world = World(tenants={T1: [ANN]})
    assert world.signin.sends_to(ANN) == 1
    ann = world.sign_in(ANN)
    assert world.invite(ann, T1, NEW).status_code == 202
    assert world.signin.sends_to(NEW) == 0
    world.send_pending()
    assert world.signin.sends_to(NEW) == 1


def test_the_lifespan_sender_runs_on_the_apps_loop_and_stops_before_the_repository_closes() -> None:
    """Start-up pass and later passes run as a task on the app's loop; shutdown is prompt and closes the repository last (O5, S-2)."""
    world = World(tenants={T1: [ANN]}, start=False, send_interval=INTERVAL)
    world.repo = RecordingRepository(world.repo)
    world.build(administrators=(), tenants={T1: [ANN]})
    with world.lifespan_client() as browser:
        assert wait_until(lambda: world.signin.sends_to(ANN) == 1)
        app_loop = browser.portal.call(asyncio.get_running_loop)
        assert wait_until(lambda: world.repo.names().count("claim_set_password") >= 3)  # periodic passes
        leaving = time.monotonic()
    assert time.monotonic() - leaving < 2
    assert {loop for _, loop in world.repo.calls} == {app_loop}
    names = world.repo.names()
    assert names.count("close") == 1, names[-5:]
    assert names[-1] == "close", names[-5:]
    settled = len(names)
    time.sleep(3 * INTERVAL.total_seconds())
    assert len(world.repo.names()) == settled  # nothing ran after shutdown
