"""Drain retire set: only the enumerated failure classes fault a claim (rc 2); every other fault propagates; neither decides a fate.

Over the learning store (#1278 D1) a faulted claim writes no fate for its items: the batch's commits say what becomes
of them, and the store's claim counted the attempt.

Retired with the file queue (design r8 Locks and Items, #1278 D1):
- the per-row `attempts` count bumped and untouched across faults, the retirement at the ceiling (`max_attempts`), the
  graveyard row, and the ceiling's timeout reason: the counter and the ceiling are the store's, covered by
  `tests/learning/store_1278/test_items_1278.py::test_crashes_to_the_ceiling_hold_the_item_for_a_person` and
  `test_store_1278.py::test_d8_a_recovery_abandon_keeps_the_attempt_and_the_ceiling_holds_the_item_for_a_person`;
- the stuck-row operator signal (`stuck_records`, a rising `consecutive_ticks`, `held_report.log`): the file is gone, the
  fault is the claim's recorded one (store `fault` column, `tests/learning/store_1278`);
- a plain `OSError` from a queue-lock acquisition classified systemic (`StateRefused`): there is no queue lock;
- `drains._drain_pitfalls` and the pitfalls ceiling bump (`[1, 1]`): the pitfalls leg is the store claim's
  (`test_1278_curator_fates.py` drives the real curators).
"""
from __future__ import annotations

from pathlib import Path

import pytest
from pydantic_ai.exceptions import ModelRetry

from defender.tests.support.learning.curation import _spec773 as S
from defender.learning.author import drain
from defender.learning.author import shared as author_shared  # type: ignore[import-not-found]
from defender.learning.core.config import FatalConfigError, StageAbort  # type: ignore[import-not-found]
from defender.box import BoxFault  # type: ignore[import-not-found]
from defender._git import GitError  # type: ignore[import-not-found]


def _faulting_scene(tmp_path: Path, exc: BaseException):
    return S.build_draft_scene(tmp_path, rows=[S.finding_row("a/0", run_id="a")],
                               curator=S.FakeCurator(raises=exc))


# Only the enumerated `RETIRE_SET` classes fault the claim


@pytest.mark.parametrize("exc", [
    author_shared.AuthorError("a member"),
    ModelRetry("killed"),
    GitError(["git", "commit"], 1, "boom"),
], ids=["AuthorError", "ModelRetry", "GitError"])
def test_a_retire_set_member_faults_the_claim_and_decides_no_fate(tmp_path: Path, exc: BaseException):
    """A `RETIRE_SET` member returns rc 2 (a batch that did not author is not a success) and decides nothing, so a
    channel naming fewer classes fails here."""
    sc = _faulting_scene(tmp_path, exc)

    assert sc.run() == 2, "a member did not fault the batch"
    assert sc.outcomes == {}
    assert sc.head_files() == []


@pytest.mark.parametrize("exc", [
    FileNotFoundError("no such prompt file"),
    StageAbort("abort"),
    FatalConfigError("bad config"),
    BoxFault("box gone"),
    TimeoutError("bare"),
], ids=lambda e: type(e).__name__)
def test_a_failure_in_no_named_class_propagates_and_decides_no_fate(tmp_path: Path, exc: BaseException):
    """A non-member (systemic, config, box, a bare `TimeoutError`) propagates unchanged out of the claim: it is neither
    absorbed as a success nor given a fate for its row."""
    sc = _faulting_scene(tmp_path, exc)

    with pytest.raises(type(exc)):
        sc.run()
    assert sc.outcomes == {}
    assert sc.head_files() == []


def test_externally_killed_box_command_is_not_reported_as_a_successful_batch(tmp_path: Path):
    """`ModelRetry` (a killed box command) is a `RETIRE_SET` member: an `except AuthorError` alone would report the
    batch as a success. The control batch (a clean curator over the same scene) succeeds."""
    assert ModelRetry in tuple(drain.RETIRE_SET), "ModelRetry was dropped from the retire set"
    ok = S.build_draft_scene(tmp_path / "ok", rows=[S.finding_row("a/0", run_id="a")],
                             curator=S.FakeCurator(writes={"l1.md": S.lesson("a/0")}))
    assert ok.run() == 0
    assert ok.head_files() == ["agent/lessons/l1.md"]

    killed = _faulting_scene(tmp_path / "killed", ModelRetry("command timed out after 120s"))
    assert killed.run() != 0, "an absorbed kill is not a successful batch"
    assert killed.outcomes == {}


def test_mid_batch_author_timeout_is_a_member_and_a_bare_timeout_is_not(tmp_path: Path):
    """The batch's wall-clock deadline reaches the drain as an `AuthorError` (`TimeoutError` -> `RunUnprocessable` ->
    `AuthorError`), so it faults the claim (rc 2); a bare `TimeoutError` is not a member and propagates."""
    late = author_shared.AuthorError(
        "curator (batch1) did not complete: curator (curator:batch1) did not complete: TimeoutError()"
    )
    assert _faulting_scene(tmp_path / "late", late).run() == 2

    bare = _faulting_scene(tmp_path / "bare", TimeoutError("bare"))
    with pytest.raises(TimeoutError):
        bare.run()
    assert bare.outcomes == {}
