"""#1540 Am-5, the no-repeat guard's own controls: the `browser` fixture's contexts carry it however a test opens them
(the `context` fixture, its own `browser.new_context()`), so a `GET` to `/api/*` sent twice within one load fails when the
context closes, and the same two reads across a navigation or a restore do not. A test that repeats on purpose asserts it,
then clears the log. (The dev server's contexts: `test_dev_server.py`.)"""
from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest

from defender.tests.frontend._flow1161 import FAILED, screen
from defender.tests.frontend.conftest import WAIT_MS, requests_of
from defender.tests.support.frontend._browser1161 import path_is, restore_from_cache

READ = "fetch('/api/openapi.json').then(() => true, () => true)"  # a GET to `/api/*` sent by the page itself; its answer is not the guard's business


@pytest.fixture(params=["fixture", "own"])
def opened(request: pytest.FixtureRequest, browser: Any) -> Callable[[], Any]:
    """A way to open a guarded context: the `context` fixture's, or one made by the test itself."""
    if request.param == "fixture":
        fixture_context = request.getfixturevalue("context")
        return lambda: fixture_context

    def own() -> Any:
        made = browser.new_context()
        made.set_default_timeout(WAIT_MS)
        return made

    return own


def _page(world: Any, context: Any, suffix: str = "") -> Any:
    page = context.new_page()
    page.goto(f"{world.origin}/{FAILED}{suffix}")  # a screen that asks the API nothing itself
    screen(page, FAILED)
    return page


def test_1540_am5_a_get_repeated_within_one_load_fails_when_the_context_closes(world, opened):
    """Two identical API GETs in one document fail the context at close, whichever way the test opened it. (Am-5 point 5)"""
    context = opened()
    page = _page(world, context)
    page.evaluate(READ)
    page.evaluate(READ)
    with pytest.raises(AssertionError, match="same API read twice"):
        context.close()
    requests_of(context).clear()  # caused on purpose and asserted above


def test_1540_am5_the_same_get_across_a_navigation_is_not_a_repeat(world, opened):
    """The same API GET once in each of two documents passes: a navigation starts a new load. (Am-5 point 5, control)"""
    context = opened()
    page = _page(world, context)
    page.evaluate(READ)
    page.goto(f"{world.origin}/{FAILED}?again=1")
    screen(page, FAILED)
    page.evaluate(READ)
    context.close()
    sent = [r.url for r in requests_of(context) if r.resource_type == "fetch" and path_is(r.url, "/api")]
    assert sent == [f"{world.origin}/api/openapi.json"] * 2


def test_1540_am5_the_same_get_across_a_restore_from_the_cache_is_not_a_repeat(world, opened):
    """The same API GET once before and once after `restore_from_cache` passes: a restore is a new load. (Am-5 point 5,
    control)"""
    context = opened()
    page = _page(world, context)
    page.evaluate(READ)
    restore_from_cache(page)
    assert requests_of(context).restores, "positive control: the restore was marked on the context's own log"
    page.evaluate(READ)
    context.close()


def test_1540_am5_a_get_repeated_after_a_restore_from_the_cache_fails_when_the_context_closes(world, opened):
    """Two identical API GETs after one `restore_from_cache` fail the context at close: a restore does not excuse a
    repeat within the restored load. (Am-5 point 5)"""
    context = opened()
    page = _page(world, context)
    restore_from_cache(page)
    page.evaluate(READ)
    page.evaluate(READ)
    with pytest.raises(AssertionError, match="same API read twice"):
        context.close()
    requests_of(context).clear()  # caused on purpose and asserted above


def test_1540_am5_a_page_opened_by_the_browser_itself_is_in_a_guarded_context(world, browser):
    """`browser.new_page()` opens its context through the guard too: the page's requests reach that context's log and the
    context is checked at close. (Am-5 point 5, F8)"""
    page = browser.new_page()
    page.goto(f"{world.origin}/{FAILED}")
    screen(page, FAILED)
    assert len(browser.made) == 1, "positive control: the page's context was made by the guarded browser"
    assert requests_of(browser.made[0]), "positive control: the page's requests were logged"
    browser.made[0].close()


@pytest.fixture
def world(shared_world_fresh):
    """These tests change nothing on the server, so the module's tests share one running system (conftest
    `shared_world`), each with a fresh front channel, instead of starting a database, API child and ingress apiece."""
    return shared_world_fresh
