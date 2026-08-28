"""Issue #719, part 5/5 — where the new paths live, when the ceiling is bound, and the
pitfalls channel, which is the discriminating case for O8 because it has no retirement at
all today.

Executable spec, pre-implementation. The design's comment 3 calls the pitfalls ceiling "the one
place where the fold alters what the loop does". That sentence predates §7 and is wrong: the
resolved design changes behaviour in FOUR places — the pitfalls ceiling, a post-agent failure
that now bumps and retires, a commit-time `GitError` that now retires and leaves the corpus
usable, and an externally killed boxed command that now retires instead of reporting success.
The full inventory is in the graph's `handoff.deviations`, where `finalize` and the adversarial
implementer read first. Decision 8 deliberately declines to add a fifth.
"""
from __future__ import annotations

from pathlib import Path

import pytest

import _drain719 as h
from _drain719 import drain  # the not-yet-written target, via the suite's own shim
from defender.learning.author import shared as author_shared  # type: ignore[import-not-found]
from defender.learning.core import drains, persist  # type: ignore[import-not-found]
from defender.learning.core.config import FatalConfigError  # type: ignore[import-not-found]
from defender.learning.leads import pitfalls_curator  # type: ignore[import-not-found]


def _pitfalls_rows(n: int) -> list[dict]:
    return [h.row_for("pitfalls", f"r:l-{i:03d}:0") for i in range(n)]


# Where the new paths live


def test_new_queue_paths_resolve_under_state_root_not_the_worktree(tmp_path: Path):
    """P16: every path this change ADDS — the append-role lock, the drain-role lock and the
    graveyard — resolves under `state_root`, never under the disposable worktree repo root,
    because two drains in two worktrees must share one lock and one queue.

    Scope note, so this consensus is not over-read: it holds for the NEW paths. The CORPUS is
    repo-rooted and stays that way, which is asserted here rather than left implied.

    Driven as well as computed: a real tick with the state root relocated must actually create
    those files there and leave the worktree clean of them."""
    state = tmp_path / "elsewhere"
    paths = h.make_paths(tmp_path, state_dir=state)
    assert paths.state_root == state

    for name in h.ALL_CHANNELS:
        ch = h.channel_of(paths, name)
        targets = [ch.file, ch.consumed, ch.append_lock, drain.graveyard_file(ch)]
        if ch.drain_lock is not None:
            targets.append(ch.drain_lock)
        for p in targets:
            assert state in p.parents, f"{name}: {p} is not under the state root"
            assert paths.repo_root not in p.parents

    cfg = h.cfg_for(paths, "actor_observations", max_attempts=1, invoke_agent=h.committing("s"))
    assert cfg.corpus_dir.is_relative_to(paths.repo_root), "the corpus is repo-rooted"

    ch = h.channel_of(paths, "actor_observations")
    h.seed(ch, [h.row_for("actor_observations", "a/0")])
    fault = h.cfg_for(
        paths,
        "actor_observations",
        max_attempts=1,
        invoke_agent=h.raising(author_shared.AuthorError("so the graveyard is written")),
    )
    assert drain.run_batch(cfg=fault) == 2
    assert drain.graveyard_file(ch).is_file()
    assert not (paths.repo_root / "defender" / "learning" / "_pending").exists()


def test_new_lock_and_graveyard_paths_do_not_abort_the_next_batch(tmp_path: Path):
    """P03/F5: `assert_clean_corpus_dir` and `verify_agent_state` treat any untracked path
    that is not `<corpus>/*.md` as stray, so a new lock or graveyard file placed outside the
    ignored prefix aborts EVERY subsequent batch on that channel. The new paths therefore land
    under the already-ignored pending prefix.

    The paired control is what makes this discriminating rather than vacuous: a file written
    one directory up, outside that prefix, DOES abort the tick — so the observation channel
    can see the difference the demand is about."""
    paths = h.make_paths(tmp_path)
    ch = h.channel_of(paths, "actor_observations")

    for p in (
        ch.append_lock, ch.drain_lock, drain.graveyard_file(ch), drain.stuck_report_file(ch)
    ):
        assert p.is_relative_to(paths.pending_dir), f"{p} is outside the ignored prefix"

    h.seed(ch, [h.row_for("actor_observations", "a/0")])
    fault = h.cfg_for(
        paths,
        "actor_observations",
        max_attempts=1,
        invoke_agent=h.raising(author_shared.AuthorError("writes the graveyard")),
    )
    assert drain.run_batch(cfg=fault) == 2
    assert drain.graveyard_file(ch).is_file()
    assert ch.drain_lock.exists()

    h.seed(ch, [h.row_for("actor_observations", "a/1")])
    clean = h.cfg_for(paths, "actor_observations", max_attempts=1, invoke_agent=h.committing("ok"))
    assert drain.run_batch(cfg=clean) == 0, "the new state files aborted the next batch"

    h.seed(ch, [h.row_for("actor_observations", "a/2")])
    stray = h.cfg_for(
        paths,
        "actor_observations",
        max_attempts=9,
        invoke_agent=h.committing(
            "stray",
            also=lambda r, b, c: (c.repo_root / "defender" / "learning" / "stray.lock").write_text("x"),
        ),
    )
    assert drain.run_batch(cfg=stray) == 2, "a path outside the ignored prefix must be seen"


# When the ceiling is bound


def test_a_non_integer_ceiling_aborts_the_tick_before_any_row_is_processed(tmp_path: Path):
    """B3/B4: a malformed ceiling is a loop-level value error, not a queue-level one. Because
    B5 binds the ceiling at CONFIG BUILD, `env_int`'s `FatalConfigError` is raised before any
    row is read — outside the widened guard, where it stays systemic and cannot be swallowed
    into another attempt against a row that did nothing wrong.

    In-range values, including the falsy 0, stay queue-level and are exercised by their own
    demands."""
    paths = h.make_paths(tmp_path)
    ch = h.channel_of(paths, "actor_observations")
    rows = [h.row_for("actor_observations", "a/0")]
    h.seed(ch, rows)

    import os

    previous = os.environ.get("LEARNING_AUTHOR_MAX_ATTEMPTS")
    os.environ["LEARNING_AUTHOR_MAX_ATTEMPTS"] = "abc"
    try:
        with pytest.raises(FatalConfigError):
            h.cfg_for(paths, "actor_observations", invoke_agent=h.committing("never"))
    finally:
        if previous is None:
            del os.environ["LEARNING_AUTHOR_MAX_ATTEMPTS"]
        else:
            os.environ["LEARNING_AUTHOR_MAX_ATTEMPTS"] = previous

    assert h.pending(ch) == rows, "no row was processed"
    assert h.graveyard(ch) == []
    assert h.consumed(ch) == []


def test_the_ceiling_is_read_once_per_batch_at_config_build(tmp_path: Path):
    """B5, which is load-bearing for B4, B6 and A6: the ceiling is bound once, at config
    build, rather than re-read inside the failure handler. Two consequences pinned here — the
    value the batch uses is the one on the config, so the ceiling is testable by CONSTRUCTING
    a config rather than by mutating the environment; and an environment change made after the
    config exists cannot move the ceiling mid-batch.

    Driven: the environment is lowered to 1 from inside the agent call itself, and the row
    still bumps to 1 under the ceiling of 3 the config was built with instead of retiring."""
    import os

    paths = h.make_paths(tmp_path)
    ch = h.channel_of(paths, "actor_observations")
    h.seed(ch, [h.row_for("actor_observations", "a/0")])

    def lower_then_fail(rows, batch_id, cfg):
        os.environ["LEARNING_AUTHOR_MAX_ATTEMPTS"] = "1"
        raise author_shared.AuthorError("fails after moving the environment")

    cfg = h.cfg_for(paths, "actor_observations", max_attempts=3, invoke_agent=lower_then_fail)
    assert cfg.max_attempts == 3
    try:
        assert drain.run_batch(cfg=cfg) == 2
    finally:
        os.environ.pop("LEARNING_AUTHOR_MAX_ATTEMPTS", None)

    assert h.attempts_of(ch, "a/0") == 1, "the row retired under a ceiling read mid-batch"
    assert h.graveyard(ch) == []


def test_author_timeout_seconds_zero_behavior_is_pinned(tmp_path: Path):
    """A reachable, falsy operator input with no design-stated semantics: `env_int` applies no
    floor, so 0 arrives intact, and `asyncio.wait_for` with 0 times out almost immediately
    rather than disabling the bound — plausibly the opposite of what an operator setting 0
    expects.

    What is pinned is that 0 SURVIVES: it reaches the config and the agent call unchanged
    rather than being coalesced back to the 1800-second default by an `x or DEFAULT` idiom.
    PJ1a is why nothing here asserts elapsed time — the deadline is soft and late, and cannot
    preempt a blocking boxed call, so a timing oracle would pin the wrong thing.

    Driven on the findings channel, because `LEARNING_AUTHOR_TIMEOUT_SECONDS` is the knob that
    channel reads; the observation directions read their own per-direction deadlines."""
    import os

    paths = h.make_paths(tmp_path)
    ch = h.channel_of(paths, "findings")
    h.write_source_refs(paths, "run-Z")
    h.seed(ch, [h.row_for("findings", "run-Z/0")])

    previous = os.environ.get("LEARNING_AUTHOR_TIMEOUT_SECONDS")
    os.environ["LEARNING_AUTHOR_TIMEOUT_SECONDS"] = "0"
    try:
        agent = h.recording(h.committing("zero-timeout"))
        cfg = h.cfg_for(paths, "findings", invoke_agent=agent)
        assert cfg.author_timeout == 0, "0 was promoted back to the default"
        assert drain.run_batch(cfg=cfg) == 0
    finally:
        if previous is None:
            del os.environ["LEARNING_AUTHOR_TIMEOUT_SECONDS"]
        else:
            os.environ["LEARNING_AUTHOR_TIMEOUT_SECONDS"] = previous

    assert agent.calls[0]["cfg"].author_timeout == 0, "the drain re-coalesced the deadline"


# The pitfalls channel — O8's discriminating case


def test_pitfalls_agent_failure_bumps_attempts_and_retires_at_the_ceiling(
    tmp_path: Path, monkeypatch
):
    """Decision 1 path 1, which flipped demand #0. Today `run_pitfalls` signals an authoring
    failure by RETURNING a nonzero code that `_drain_pitfalls` never inspects, so the retire
    callback is not reached at all: C23 drove four consecutive ticks and saw `attempts` stay
    unset on every row, no graveyard, no consumed file — the dominant pitfalls failure is
    discarded silently.

    The discriminating oracle: the agent exits nonzero and raises NOTHING. The rc is converted
    into a fault, the row's attempts bump, and the batch retires at the ceiling like any other
    channel's.

    Under decision 8 the conversion is only half the wiring: the class it raises must be a
    MEMBER of the enumerated retire set, or the converted fault falls through uncaught and the
    channel is exactly as stuck as before — a conversion that changes nothing observable. So the
    raised class is asserted to be a member before the retirement is observed."""
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "2")
    monkeypatch.setenv("LEARNING_AUTHOR_MAX_ATTEMPTS", "2")
    paths = h.make_paths(tmp_path)
    h.seed(paths.pitfalls, _pitfalls_rows(2))

    with pytest.raises(Exception) as raised:  # noqa: PT011 - the raised class is the subject under test, asserted below
        pitfalls_curator.run_pitfalls(paths=paths, invoke=lambda *a, **k: 7)
    assert type(raised.value) in tuple(drain.RETIRE_SET), (
        f"the converted rc raises {type(raised.value).__name__}, which is not in the retire set — "
        "it would fall through uncaught and the channel would stay stuck"
    )

    def leg(_paths, box=None):
        return pitfalls_curator.run_pitfalls(paths=_paths, invoke=lambda *a, **k: 7)

    drains._drain_pitfalls(paths, leg)
    assert [r.get("attempts") for r in h.pending(paths.pitfalls)] == [1, 1], (
        "the converted rc did not bump both rows"
    )
    assert h.graveyard(paths.pitfalls) == []

    drains._drain_pitfalls(paths, leg)
    assert h.pending(paths.pitfalls) == []
    grave = h.graveyard(paths.pitfalls)
    assert sorted(r["pitfall_id"] for r in grave) == ["r:l-000:0", "r:l-001:0"]
    assert [r.get("attempts") for r in grave] == [2, 2]


def test_pitfalls_batch_retires_at_the_ceiling(tmp_path: Path, monkeypatch):
    """O8 on the channel that has no retirement mechanism at all today (C22) — no attempt
    counter, no graveyard, a callback that only logs. Under D9 it routes through the same
    retire path as every other file-queue at the same default ceiling of 3, which is this
    change's one deliberate behavior change.

    Three faulted ticks: the batch survives the first two carrying its count, and leaves on
    the third carrying its reason."""
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "2")
    paths = h.make_paths(tmp_path)
    h.seed(paths.pitfalls, _pitfalls_rows(2))

    def leg(_paths, box=None):
        raise author_shared.AuthorError("pitfalls curation failed")

    for expected in (1, 2):
        drains._drain_pitfalls(paths, leg)
        assert [r.get("attempts") for r in h.pending(paths.pitfalls)] == [expected, expected], (
            f"attempts did not reach {expected} on tick {expected}"
        )
        assert h.graveyard(paths.pitfalls) == []

    drains._drain_pitfalls(paths, leg)
    grave = h.graveyard(paths.pitfalls)
    assert h.pending(paths.pitfalls) == []
    assert [r.get("attempts") for r in grave] == [3, 3]
    # #870 FK-11: the ceiling path files `batch-error:<class>` — two writers append to one
    # `pitfalls.deadletter.jsonl`, and a bare `str(e)` beside `_graveyard_dropped_rows`' named
    # classes leaves a human triaging that file with three classes and a traceback string.
    # The PREFIX is what closes the vocabulary, so it is pinned as a prefix; the MESSAGE rides
    # after the same `:` separator the undeclared class already carries its name after, because
    # the class alone made a timed-out spawn, a refused scope and an attempted section deletion
    # — all `LeadAuthorError` — the same four indistinguishable words in the one durable record
    # this lane leaves.
    reason = grave[0]["deadletter_reason"]
    assert reason.startswith("batch-error:AuthorError"), reason
    assert "pitfalls curation failed" in reason, (
        "the graveyard kept the class and lost the diagnosis"
    )


def test_pitfalls_retirement_removes_batch_ids_not_the_whole_queue(tmp_path: Path, monkeypatch):
    """A15/P75: "the batch" on pitfalls is `batch_ids`, the set fixed at the drain's own read.
    The chosen retire site fires after the inner call stack has unwound, which widens the gap
    between the read and the removal — so a row that arrived inside that gap is outside the
    batch and must survive, count untouched."""
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "2")
    monkeypatch.setenv("LEARNING_AUTHOR_MAX_ATTEMPTS", "1")
    paths = h.make_paths(tmp_path)
    h.seed(paths.pitfalls, _pitfalls_rows(2))
    late = h.row_for("pitfalls", "r:l-999:0")

    def leg(_paths, box=None):
        rc = pitfalls_curator.run_pitfalls(paths=_paths, invoke=lambda *a, **k: 7)
        return rc

    def failing_then_append(_paths, box=None):
        persist.append_pitfalls([late], paths=_paths)
        return leg(_paths, box=box)

    drains._drain_pitfalls(paths, failing_then_append)

    survivors = h.pending(paths.pitfalls)
    assert [r["pitfall_id"] for r in survivors] == ["r:l-999:0"]
    assert survivors[0] == late, "the late row was not bumped or rewritten"
    assert sorted(r["pitfall_id"] for r in h.graveyard(paths.pitfalls)) == [
        "r:l-000:0",
        "r:l-001:0",
    ]


def test_pitfalls_retire_goes_through_the_locked_rotation(tmp_path: Path):
    """P56, which the flip makes load-bearing: pre-flip this consensus described an
    unreachable branch, because the dominant pitfalls failure never reached the retire path at
    all. Decision 1 path 1 supplies the trigger, so it becomes a live parity property — the
    pitfalls removal acquires `.pitfalls.lock` through the same locked rotation the other four
    channels use, and there is no unlocked pitfalls retire path.

    Pitfalls has ONE lock serving both roles (C24), so this is the same file the appender
    takes: held from another actor, the retirement does not proceed."""
    paths = h.make_paths(tmp_path)
    ch = h.channel_of(paths, "pitfalls")
    assert ch.append_lock.name == ".pitfalls.lock"
    assert ch.drain_lock is None
    h.seed(ch, _pitfalls_rows(2))

    worker = h.Background(
        lambda: drain.retire(
            channel=ch, batch_ids=["r:l-000:0"], reason="pitfalls retire", max_attempts=1
        )
    )
    with h.Holder(ch.append_lock):
        worker._thread.start()
        assert not worker.finished_within(1.0), "the pitfalls retire took no lock"
        assert h.graveyard(ch) == []
    assert worker.finished_within(20)
    assert [r["pitfall_id"] for r in h.pending(ch)] == ["r:l-001:0"]
    assert [r["pitfall_id"] for r in h.graveyard(ch)] == ["r:l-000:0"]
