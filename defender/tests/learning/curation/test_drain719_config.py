"""Drain config: the attempt ceiling is bound before any item is claimed, and no tenant-free learning paths remain (#1186).

Retired with the file queue (#1278 A1/D1, design r8 Locks and Items: a tenant's work is rows in the learning store,
keyed by tenant id; there is no state root, queue, lock, graveyard or `LearningState`):
- the queue, consumed, append-lock, drain-lock and graveyard paths resolving under `state_root` and not the worktree,
  and those state files not aborting the next batch: there are no such files;
- the ceiling read once at config build, not in the failure handler (`cfg.max_attempts`): the config has no ceiling,
  the store carries it (`store_knobs`, `tests/learning/store_1278/test_items_1278.py` pins the ceiling itself);
- the pitfalls leg bumping attempts and retiring at the ceiling, retiring only the batch's ids and not the whole queue
  (a row appended mid-tick surviving), and its retire through the locked rotation (`drains._drain_pitfalls`,
  `drain.retire`, `persist.append_pitfalls`): the claim's items and the store's ceiling,
  `tests/learning/store_1278/test_items_1278.py::test_crashes_to_the_ceiling_hold_the_item_for_a_person`;
- a tenant's state refusing a linked learning root (`LearningState.open` over a link), and queues, locks and the
  delivery record belonging to a tenant whichever worktree opens them: the learning folder is not made or read
  any more (`tests/learning/store_1278`: tenant isolation of items; `test_1278_census.py` forbids the file state).
"""
from __future__ import annotations

import pytest

from defender.learning.core import config as learning_config
from defender.learning.core.config import FatalConfigError
from defender.tests.support.learning.core._store1278 import call, finding, migrated_database, world  # noqa: F401 — fixtures
from defender.tests.tenancy.tenant_1108_p4.conftest import p4_tenant  # noqa: F401 — fixture `world` is built on


@pytest.mark.postgres
def test_a_non_integer_ceiling_aborts_the_tick_before_any_item_is_claimed(world, monkeypatch, caplog):  # noqa: F811 — the imported fixture
    """A malformed ceiling refuses the tick (rc 2, `FatalConfigError` logged) before any item is claimed or a curator
    spawned; the control tick with a sane ceiling claims and runs."""
    from defender.tests.tenancy.tenant_1108_p4._drain_support import BoxSpy, author_drain

    w = world
    call(w.dsn, "publish_findings", w.t.tenant_id, "run-1", [finding("f1")], kind="finding")
    reached: list[str] = []

    def trigger(*_a, **_kw):
        reached.append("curator")

    monkeypatch.setenv("LEARNING_AUTHOR_MAX_ATTEMPTS", "abc")
    assert author_drain(w.t, w.paths, trigger=trigger, box=BoxSpy()) == 2
    assert reached == [], "a curator ran under a malformed ceiling"
    assert "LEARNING_AUTHOR_MAX_ATTEMPTS" in caplog.text
    assert {i.key: i.status for i in call(w.dsn, "work", w.t.tenant_id)} == {"f1": "waiting"}
    assert call(w.dsn, "batches", w.t.tenant_id) == []

    monkeypatch.setenv("LEARNING_AUTHOR_MAX_ATTEMPTS", "3")
    assert author_drain(w.t, w.paths, trigger=trigger, box=BoxSpy()) == 0
    assert reached, "the control tick (a sane ceiling) never reached the curator"


def test_the_ceiling_setting_is_a_validated_integer(monkeypatch):
    """The ceiling setting itself refuses a non-integer (the tick test above shows the tick honours that)."""
    monkeypatch.setenv("LEARNING_AUTHOR_MAX_ATTEMPTS", "abc")
    with pytest.raises(FatalConfigError):
        learning_config.author_max_attempts()
    monkeypatch.setenv("LEARNING_AUTHOR_MAX_ATTEMPTS", "4")
    assert learning_config.author_max_attempts() == 4


def test_1186_no_global_learning_paths_or_ambient_factory_remain():
    """The removed tenant-free defaults stay removed, so none can become a production entry."""
    for name in ("DEFAULT_PATHS", "LEARNING_DIR", "loop_paths"):
        assert not hasattr(learning_config, name), f"{name} still supplies tenant-free paths"
