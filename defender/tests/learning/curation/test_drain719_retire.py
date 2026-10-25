"""Drain retire seam: lifetime attempt counts, ceiling, byte-identical untouched rows, systemic retire-write failure, inert empty ticks."""
from __future__ import annotations

from defender.tests.support.shared._locations_1210 import location_path

import dataclasses
from pathlib import Path

import pytest

from defender.tests.support.learning.curation import _curator1134 as C
from defender.tests.support.learning.curation import _drain719 as h
from defender.tests.support.learning.curation._drain719 import drain  # the not-yet-written target, via the suite's own shim
from defender.learning.author import shared as author_shared  # type: ignore[import-not-found]
from defender.learning.core.state import FINDINGS
from defender.tests.support.learning.core import _state1135


# Demand #0 — the return-value contract, after decision 1 flipped its `2` branch


# O6 + O8 — one uniform, bounded retirement into one graveyard


def test_an_intervening_success_does_not_reset_the_attempt_count(tmp_path: Path):
    """Decision 2: the count is LIFETIME."""
    # #1108 P4 (OD12 class ii): the REAL lessons tick over a batch's git-free draft.
    lane = C.draft_lane(tmp_path)
    paths = lane.paths
    ch = h.channel_of("findings")
    h.seed(paths, ch, [h.row_for("findings", "run-I/0")])

    fault = C.draft_author_cfg(lane, max_attempts=2,
        invoke_agent=h.raising(author_shared.AuthorError("first failure")),
    )
    assert drain.run_batch(cfg=fault) == 2
    assert h.attempts_of(paths, ch, "run-I/0") == 1

    def hold_back(rows, batch_id, cfg):
        # Mentioned in NEITHER bucket (§773 C3): the row stays queued exactly as it was,
        # with no counter of any kind bumped — the "clean tick that holds it back" shape.
        return {
            "committed": [],
            "consumed_skip": [],
            "commit_message": "",
        }

    ok = h.recording(hold_back)
    assert drain.run_batch(cfg=C.draft_author_cfg(lane, max_attempts=2, invoke_agent=ok)) == 0
    assert len(ok.calls) == 1, "the successful tick never reached the agent"
    assert h.attempts_of(paths, ch, "run-I/0") == 1, "a clean tick reset the count"

    assert drain.run_batch(cfg=fault) == 2
    assert h.pending(paths, ch) == []
    assert [r["attempts"] for r in h.graveyard(paths, ch)] == [2], "2, not 1 — no reset happened"


# Decision 3 — terminality: consumed ledger, graveyard first


# The ceiling's own domain — 1, 0 and -1


def _retires_on_the_first_failure(tmp_path: Path, ceiling: int) -> None:
    """Shared body for the three ceiling members; each demand's own test drives it."""
    paths = h.make_paths(tmp_path)
    ch = h.channel_of("findings")
    h.seed(paths, ch, [h.row_for("findings", "b/0")])
    cfg = h.cfg_for(
        paths,
        "findings",
        max_attempts=ceiling,
        invoke_agent=h.raising(author_shared.AuthorError("one and done")),
    )
    assert drain.run_batch(cfg=cfg) == 2
    assert h.pending(paths, ch) == []
    assert [r["attempts"] for r in h.graveyard(paths, ch)] == [1]


def test_ceiling_of_one_retires_on_the_first_failure(tmp_path: Path):
    """Fail-fast is the ceiling at 1, not a second mechanism: one failure retires the row into the
    graveyard with `attempts` 1."""
    _retires_on_the_first_failure(tmp_path, 1)


# The seam's edges — what it does not touch, and what stops it


def test_retire_leaves_every_row_outside_the_batch_byte_identical(tmp_path: Path):
    """Retirement is scoped to the ids it was handed."""
    paths = h.make_paths(tmp_path)
    ch = h.channel_of("findings")
    outsiders = [
        h.row_for("findings", "a/1", note="keep me", nested={"x": [1, 2]}),
        h.row_for("findings", "a/2", attempts=7),
    ]
    h.seed(paths, ch, [h.row_for("findings", "a/0"), *outsiders])

    drain.retire(_state1135.state_for_paths(paths), channel=FINDINGS, batch_ids=["a/0"], reason="scoped", max_attempts=1)

    survivors = h.pending_by_id(paths, ch)
    assert sorted(survivors) == ["a/1", "a/2"]
    assert survivors["a/1"] == outsiders[0]
    assert survivors["a/2"] == outsiders[1]


def test_a_failing_retirement_write_stops_the_drain_and_leaves_the_queue_intact(
    tmp_path: Path, monkeypatch
):
    """A11: the retire step's OWN write failing is systemic."""
    paths = h.make_paths(tmp_path)
    ch = h.channel_of("findings")
    h.seed(paths, ch, [h.row_for("findings", "a/0")])
    before = (location_path(paths.state_root) / ch.queue).read_bytes()

    from defender.tests.learning.core.test_881_loop_plumbing import _StateWhoseDiskIsFull

    cfg = h.cfg_for(
        paths,
        "findings",
        max_attempts=1,
        invoke_agent=h.raising(author_shared.AuthorError("triggers a retirement")),
    )
    cfg = dataclasses.replace(cfg, state=_StateWhoseDiskIsFull.over(cfg.state, "deadletter"))
    with pytest.raises(OSError):  # noqa: PT011 - the OS-level append failure's exact subclass is platform-dependent; the point is that it propagates uncaught
        drain.run_batch(cfg=cfg)
    assert (location_path(paths.state_root) / ch.queue).read_bytes() == before, "the queue survives a failed retirement write"


def test_an_all_empty_tick_writes_no_consumed_row_and_no_graveyard_row(tmp_path: Path):
    paths = h.make_paths(tmp_path)
    for name in h.AUTHOR_CHANNELS:
        ch = h.channel_of(name)
        cfg = h.cfg_for(paths, name, invoke_agent=h.raising(AssertionError("never called")))
        assert drain.run_batch(cfg=cfg) == 0
        assert h.consumed(paths, ch) == []
        assert h.graveyard(paths, ch) == []

    ch = h.channel_of("findings")
    h.seed(paths, ch, [h.row_for("findings", "a/0")])
    live = h.cfg_for(
        paths,
        "findings",
        max_attempts=1,
        invoke_agent=h.raising(author_shared.AuthorError("so the sinks can be seen")),
    )
    assert drain.run_batch(cfg=live) == 2
    assert h.graveyard(paths, ch)
    assert h.consumed(paths, ch)


def test_attempt_count_survives_a_fresh_process(tmp_path: Path):
    """P38: `attempts` lives on the queue row, so a second, genuinely separate process picks the
    count up off disk rather than starting over."""
    paths = h.make_paths(tmp_path)
    ch = h.channel_of("findings")
    h.seed(paths, ch, [h.row_for("findings", "a/0")])

    drain.retire(_state1135.state_for_paths(paths), channel=FINDINGS, batch_ids=["a/0"], reason="first process", max_attempts=3)
    assert h.attempts_of(paths, ch, "a/0") == 1

    script = (
        "import sys\n"
        "from pathlib import Path\n"
        "from defender.learning.author import drain\n"
        "from defender.learning.core.config import LoopPaths\n"
        "from defender.learning.core.state import FINDINGS, LearningState\n"
        f"paths = LoopPaths(repo_root=Path(sys.argv[1]), state_dir=Path({str(location_path(paths.state_root))!r}))\n"
        "out = drain.retire(LearningState.open(paths), channel=FINDINGS, batch_ids=['a/0'],\n"
        "                   reason='second process', max_attempts=2)\n"
        "print(out.bumped['a/0'])\n"
    )
    proc = h.run_in_subprocess(script, repo=paths.repo_root)
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == "2", "the fresh process read 1 off the row and bumped to 2"
    assert h.pending(paths, ch) == []
    assert [r["attempts"] for r in h.graveyard(paths, ch)] == [2]
