"""Drain retire ceiling: new queue paths live under state_root, ceiling bound at config build, and the pitfalls channel retires at the ceiling."""
from __future__ import annotations

from pathlib import Path

import pytest

from defender.tests.support.learning.curation import _drain719 as h
from defender.tests.support.learning.curation._drain719 import drain  # the not-yet-written target, via the suite's own shim
from defender.learning.author import shared as author_shared  # type: ignore[import-not-found]
from defender.learning.core import drains, persist  # type: ignore[import-not-found]
from defender.learning.core import config as learning_config
from defender.learning.core.config import FatalConfigError, LoopPaths
from defender.learning.core.state import (
    AUTHOR_DRAIN_LOCK, LEAD_AUTHOR_DRAIN_LOCK, LEAD_QUEUE_LOCK, REPO_LOCK, TRY_ONCE,
    FINDINGS, PITFALLS, QUESTIONER_FINDINGS, LearningState,
)  # type: ignore[import-not-found]
from defender.learning.leads import pitfalls_curator  # type: ignore[import-not-found]
from defender.tests.support.learning.core import _state1135
from defender.tests.support.learning.curation._lead_author_1134 import lead_trees


def _graveyard_file(paths, ch) -> Path:
    return paths.state_root / ch.deadletter


def _stuck_file(paths, ch) -> Path:
    return paths.state_root / ch.stuck


def _pitfalls_rows(n: int) -> list[dict]:
    return [h.row_for("pitfalls", f"r:l-{i:03d}:0") for i in range(n)]


# Where the new paths live


def test_new_queue_paths_resolve_under_state_root_not_the_worktree(tmp_path: Path):
    state = tmp_path / "elsewhere"
    paths = h.make_paths(tmp_path, state_dir=state)
    assert paths.state_root == state

    for name in h.ALL_CHANNELS:
        ch = h.channel_of(name)
        targets = [paths.state_root / rel for rel in (ch.queue, ch.consumed, ch.append_lock)]
        targets.append(_graveyard_file(paths, ch))
        if ch.drain_role is not None:
            targets.append(paths.state_root / ch.drain_role.file)
        for p in targets:
            assert state in p.parents, f"{name}: {p} is not under the state root"
            assert paths.repo_root not in p.parents

    cfg = h.cfg_for(paths, "findings", max_attempts=1, invoke_agent=h.committing("s"))
    assert cfg.corpus_dir.is_relative_to(paths.repo_root), "the corpus is repo-rooted"

    ch = h.channel_of("findings")
    h.seed(paths, ch, [h.row_for("findings", "a/0")])
    fault = h.cfg_for(
        paths,
        "findings",
        max_attempts=1,
        invoke_agent=h.raising(author_shared.AuthorError("so the graveyard is written")),
    )
    assert drain.run_batch(cfg=fault) == 2
    assert _graveyard_file(paths, ch).is_file()
    assert not (paths.repo_root / "defender" / "learning" / "_pending").exists()


def test_new_lock_and_graveyard_paths_do_not_abort_the_next_batch(tmp_path: Path):
    paths = h.make_paths(tmp_path)
    ch = h.channel_of("findings")

    for p in (
        paths.state_root / ch.append_lock, paths.state_root / ch.drain_role.file,
        _graveyard_file(paths, ch), _stuck_file(paths, ch),
    ):
        assert p.is_relative_to((paths.state_root / FINDINGS.queue).parent), f"{p} is outside the ignored prefix"

    h.seed(paths, ch, [h.row_for("findings", "a/0")])
    fault = h.cfg_for(
        paths,
        "findings",
        max_attempts=1,
        invoke_agent=h.raising(author_shared.AuthorError("writes the graveyard")),
    )
    assert drain.run_batch(cfg=fault) == 2
    assert _graveyard_file(paths, ch).is_file()
    assert (paths.state_root / ch.drain_role.file).exists()

    h.seed(paths, ch, [h.row_for("findings", "a/1")])
    clean = h.cfg_for(paths, "findings", max_attempts=1, invoke_agent=h.committing("ok"))
    assert drain.run_batch(cfg=clean) == 0, "the new state files aborted the next batch"

    h.seed(paths, ch, [h.row_for("findings", "a/2")])
    stray = h.cfg_for(
        paths,
        "findings",
        max_attempts=9,
        invoke_agent=h.committing(
            "stray",
            also=lambda r, b, c: (c.repo_root / "defender" / "learning" / "stray.lock").write_text("x"),
        ),
    )
    assert drain.run_batch(cfg=stray) == 2, "a path outside the ignored prefix must be seen"


# When the ceiling is bound


def test_a_non_integer_ceiling_aborts_the_tick_before_any_row_is_processed(tmp_path: Path):
    """B3/B4: a malformed ceiling is a loop-level value error, not a queue-level one."""
    paths = h.make_paths(tmp_path)
    ch = h.channel_of("findings")
    rows = [h.row_for("findings", "a/0")]
    h.seed(paths, ch, rows)

    import os

    previous = os.environ.get("LEARNING_AUTHOR_MAX_ATTEMPTS")
    os.environ["LEARNING_AUTHOR_MAX_ATTEMPTS"] = "abc"
    try:
        with pytest.raises(FatalConfigError):
            h.cfg_for(paths, "findings", invoke_agent=h.committing("never"))
    finally:
        if previous is None:
            del os.environ["LEARNING_AUTHOR_MAX_ATTEMPTS"]
        else:
            os.environ["LEARNING_AUTHOR_MAX_ATTEMPTS"] = previous

    assert h.pending(paths, ch) == rows, "no row was processed"
    assert h.graveyard(paths, ch) == []
    assert h.consumed(paths, ch) == []


def test_the_ceiling_is_read_once_per_batch_at_config_build(tmp_path: Path):
    """B5, which is load-bearing for B4, B6 and A6: the ceiling is bound once, at config build,
    rather than re-read inside the failure handler."""
    import os

    paths = h.make_paths(tmp_path)
    ch = h.channel_of("findings")
    h.seed(paths, ch, [h.row_for("findings", "a/0")])

    def lower_then_fail(rows, batch_id, cfg):
        os.environ["LEARNING_AUTHOR_MAX_ATTEMPTS"] = "1"
        raise author_shared.AuthorError("fails after moving the environment")

    cfg = h.cfg_for(paths, "findings", max_attempts=3, invoke_agent=lower_then_fail)
    assert cfg.max_attempts == 3
    try:
        assert drain.run_batch(cfg=cfg) == 2
    finally:
        os.environ.pop("LEARNING_AUTHOR_MAX_ATTEMPTS", None)

    assert h.attempts_of(paths, ch, "a/0") == 1, "the row retired under a ceiling read mid-batch"
    assert h.graveyard(paths, ch) == []


# The pitfalls channel — O8's discriminating case


def test_pitfalls_agent_failure_bumps_attempts_and_retires_at_the_ceiling(
    tmp_path: Path, monkeypatch
):
    """Decision 1 path 1, which flipped demand #0."""
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "2")
    monkeypatch.setenv("LEARNING_AUTHOR_MAX_ATTEMPTS", "2")
    paths = h.make_paths(tmp_path)
    h.seed(paths, PITFALLS, _pitfalls_rows(2))

    with pytest.raises(Exception) as raised:  # noqa: PT011 - the raised class is the subject under test, asserted below
        pitfalls_curator.run_pitfalls(paths=paths, invoke=lambda *a, **k: 7,
                                      trees=lead_trees(paths))
    assert type(raised.value) in tuple(drain.RETIRE_SET), (
        f"the converted rc raises {type(raised.value).__name__}, which is not in the retire set — "
        "it would fall through uncaught and the channel would stay stuck"
    )

    def leg(_paths, _state, box=None, **_kw):
        return pitfalls_curator.run_pitfalls(paths=_paths, state=_state, invoke=lambda *a, **k: 7,
                                             trees=lead_trees(_paths))

    drains._drain_pitfalls(paths, _state1135.state_for_paths(paths), leg)
    assert [r.get("attempts") for r in h.pending(paths, PITFALLS)] == [1, 1], (
        "the converted rc did not bump both rows"
    )
    assert h.graveyard(paths, PITFALLS) == []

    drains._drain_pitfalls(paths, _state1135.state_for_paths(paths), leg)
    assert h.pending(paths, PITFALLS) == []
    grave = h.graveyard(paths, PITFALLS)
    assert sorted(r["pitfall_id"] for r in grave) == ["r:l-000:0", "r:l-001:0"]
    assert [r.get("attempts") for r in grave] == [2, 2]


def test_pitfalls_batch_retires_at_the_ceiling(tmp_path: Path, monkeypatch):
    """O8 on the channel that has no retirement mechanism at all today (C22) — no attempt counter,
    no graveyard, a callback that only logs."""
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "2")
    paths = h.make_paths(tmp_path)
    h.seed(paths, PITFALLS, _pitfalls_rows(2))

    def leg(_paths, _state, box=None, **_kw):
        raise author_shared.AuthorError("pitfalls curation failed")

    for expected in (1, 2):
        drains._drain_pitfalls(paths, _state1135.state_for_paths(paths), leg)
        assert [r.get("attempts") for r in h.pending(paths, PITFALLS)] == [expected, expected], (
            f"attempts did not reach {expected} on tick {expected}"
        )
        assert h.graveyard(paths, PITFALLS) == []

    drains._drain_pitfalls(paths, _state1135.state_for_paths(paths), leg)
    grave = h.graveyard(paths, PITFALLS)
    assert h.pending(paths, PITFALLS) == []
    assert [r.get("attempts") for r in grave] == [3, 3]
    reason = grave[0]["deadletter_reason"]
    assert reason.startswith("batch-error:AuthorError"), reason
    assert "pitfalls curation failed" in reason, (
        "the graveyard kept the class and lost the diagnosis"
    )


def test_pitfalls_retirement_removes_batch_ids_not_the_whole_queue(tmp_path: Path, monkeypatch):
    """A15/P75: "the batch" on pitfalls is `batch_ids`, the set fixed at the drain's own read."""
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "2")
    monkeypatch.setenv("LEARNING_AUTHOR_MAX_ATTEMPTS", "1")
    paths = h.make_paths(tmp_path)
    h.seed(paths, PITFALLS, _pitfalls_rows(2))
    late = h.row_for("pitfalls", "r:l-999:0")

    def leg(_paths, _state, box=None, **_kw):
        rc = pitfalls_curator.run_pitfalls(paths=_paths, state=_state, invoke=lambda *a, **k: 7,
                                           trees=lead_trees(_paths))
        return rc

    def failing_then_append(_paths, _state, box=None, **_kw):
        persist.append_pitfalls([late], state=_state)
        return leg(_paths, _state, box=box)

    drains._drain_pitfalls(paths, _state1135.state_for_paths(paths), failing_then_append)

    survivors = h.pending(paths, PITFALLS)
    assert [r["pitfall_id"] for r in survivors] == ["r:l-999:0"]
    assert survivors[0] == late, "the late row was not bumped or rewritten"
    assert sorted(r["pitfall_id"] for r in h.graveyard(paths, PITFALLS)) == [
        "r:l-000:0",
        "r:l-001:0",
    ]


def test_pitfalls_retire_goes_through_the_locked_rotation(tmp_path: Path):
    """P56, which the flip makes load-bearing: pre-flip this consensus described an unreachable
    branch, because the dominant pitfalls failure never reached the retire path at all."""
    paths = h.make_paths(tmp_path)
    ch = h.channel_of("pitfalls")
    assert (paths.state_root / ch.append_lock).name == ".pitfalls.lock"
    assert ch.drain_role is None
    h.seed(paths, ch, _pitfalls_rows(2))

    worker = h.Background(
        lambda: drain.retire(
            _state1135.state_for_paths(paths), channel=PITFALLS, batch_ids=["r:l-000:0"], reason="pitfalls retire", max_attempts=1
        )
    )
    with h.Holder(paths.state_root / ch.append_lock):
        worker._thread.start()
        assert not worker.finished_within(1.0), "the pitfalls retire took no lock"
        assert h.graveyard(paths, ch) == []
    assert worker.finished_within(20)
    assert [r["pitfall_id"] for r in h.pending(paths, ch)] == ["r:l-001:0"]
    assert [r["pitfall_id"] for r in h.graveyard(paths, ch)] == ["r:l-000:0"]


# #1186 — production paths require an accepted tenant, independently of code checkout.


def test_1186_no_global_learning_paths_or_ambient_factory_remain():
    """O1: the removed public defaults cannot remain an accidental production entry path."""
    for name in ("DEFAULT_PATHS", "LEARNING_DIR", "loop_paths"):
        assert name not in vars(learning_config), f"{name} still supplies tenant-free paths"


@pytest.mark.parametrize("shape", ["plain", "directory-link", "dangling-link"])
def test_1186_tenant_state_requires_a_real_learning_directory(data_root, tmp_path, shape):
    """O1/O6: a selected tenant cannot redirect its state through a root symlink."""
    from defender.learning.core.state import StateRefused
    from defender.tenancy._tenant import TenantRefused
    from defender.tests.support.shared.contracts._data_root_1078 import set_up_tenant
    from defender.tests.tenancy.tenant_1120_piece1 import _spec1120 as H

    tenant = set_up_tenant(data_root)
    target = tenant.learning if shape == "plain" else tmp_path / "outside-state"
    if shape != "dangling-link":
        queue = target / FINDINGS.queue
        queue.parent.mkdir(parents=True)
        queue.write_text('{"finding_id":"boundary/0","run_id":"boundary"}\n', encoding="utf-8")
    if shape != "plain":
        tenant.learning.symlink_to(target, target_is_directory=True)
    before_root, before_target = H.tree_census(data_root), H.tree_census(target)

    def read_selected():
        with LearningState.open(LoopPaths.for_tenant(tenant)) as state:
            return state.rows(FINDINGS)

    if shape == "plain":
        assert read_selected() == [{"finding_id": "boundary/0", "run_id": "boundary"}]
    else:
        with pytest.raises((TenantRefused, FatalConfigError, StateRefused)) as refused:
            read_selected()
        assert str(tenant.learning) in str(refused.value)
        assert tenant.learning.is_symlink()
    if shape == "dangling-link":
        assert not target.exists()
        assert not target.is_symlink()
    assert H.tree_census(data_root) == before_root
    assert H.tree_census(target) == before_target


def test_1186_tenant_paths_keep_state_and_locks_across_author_checkouts(
    data_root: Path, tmp_path: Path, monkeypatch,
):
    """O1/O4: queues, record children and locks belong to a tenant, across worktrees."""
    from defender.tests.support.shared.contracts._data_root_1078 import set_up_tenant
    from defender.tests.support.shared._fixture_uuid import fixture_uuid

    a = set_up_tenant(data_root, fixture_uuid("tenant:learning-a"))
    # Creation admits one tenant per data root; each accepted tenant has its own root.
    b = set_up_tenant(tmp_path / "other-data-root", fixture_uuid("tenant:learning-b"))
    poison = tmp_path / "ambient-state"
    poison.mkdir()
    monkeypatch.setenv("DEFENDER_LEARNING_STATE_DIR", str(poison))
    first = LoopPaths.for_tenant(a)
    second = LoopPaths.for_tenant(b)
    assert first.state_root == a.learning
    assert second.state_root == b.learning
    worktree = tmp_path / "different-author-checkout"
    moved = first.with_repo_root(worktree)
    assert moved.repo_root == worktree
    assert moved.state_root == a.learning

    # A real read/write through each handle rejects roots that only look tenant scoped.
    for root in (a.learning, b.learning):
        root.mkdir(parents=True, exist_ok=True)
    with LearningState.open(first) as sa, LearningState.open(second) as sb, \
            LearningState.open(moved) as same_a:
        for ch in (FINDINGS, QUESTIONER_FINDINGS, PITFALLS):
            row_a = {ch.id_key: "same-id", "run_id": "a", "owner": "a"}
            row_b = {ch.id_key: "same-id", "run_id": "b", "owner": "b"}
            assert sa.append(ch, [row_a]) == (1, 0)
            assert sb.append(ch, [row_b]) == (1, 0)
            assert same_a.rows(ch) == [row_a]
            assert sb.rows(ch) == [row_b]
            assert (a.learning / ch.queue).is_file()
            assert (b.learning / ch.queue).is_file()
            assert (a.learning / ch.append_lock).is_file()
            assert (b.learning / ch.append_lock).is_file()

        sa.record_delivery("same-batch", {"batch_id": "same-batch", "owner": "a"})
        sb.record_delivery("same-batch", {"batch_id": "same-batch", "owner": "b"})
        assert same_a.delivery_rows() == ([("same-batch", {"batch_id": "same-batch", "owner": "a"})], 0)
        assert sb.delivery_rows() == ([("same-batch", {"batch_id": "same-batch", "owner": "b"})], 0)

        # Same-tenant contention is the positive control for cross-tenant independence.
        for role in (AUTHOR_DRAIN_LOCK, LEAD_AUTHOR_DRAIN_LOCK, REPO_LOCK,
                     FINDINGS.drain_role, LEAD_QUEUE_LOCK):
            assert role is not None
            with sa.lock(role, wait=TRY_ONCE) as acquired:
                assert acquired
                with same_a.lock(role, wait=TRY_ONCE) as duplicate:
                    assert not duplicate, f"worktree redirected {role.name} away from tenant A"
                with sb.lock(role, wait=TRY_ONCE) as independent:
                    assert independent, f"tenant A blocked tenant B's {role.name}"
    assert not list(poison.iterdir()), "the ambient state override was used"
