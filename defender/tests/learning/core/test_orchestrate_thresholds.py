"""A non-numeric loop threshold env var fails loud as exit 2 (FatalConfigError), and the drain's quarantine/requeue/dead-letter behavior."""
from __future__ import annotations

import json

import pytest

from defender.learning.core import cli  # type: ignore[import-not-found]
from defender.learning.core import drains  # type: ignore[import-not-found]
from defender.learning.core import faults  # type: ignore[import-not-found]
from defender.learning.core.state import FINDINGS
from defender.tests.support.learning.core import _state1135
from defender.learning.core.config import (  # type: ignore[import-not-found]
    FatalConfigError,
    RunUnprocessable,
    StageAbort,
    LoopPaths,
)
from defender.learning.leads import lead_author  # type: ignore[import-not-found]


def _paths(tmp_path) -> LoopPaths:
    """`LoopPaths` over `tmp_path` with its learning state root made (never created lazily)."""
    paths = LoopPaths(repo_root=tmp_path)
    paths.state_root.mkdir(parents=True, exist_ok=True)
    return paths


def test_has_curator_work_raises_on_bad_threshold(tmp_path, monkeypatch):
    monkeypatch.setenv("LEARNING_AUTHOR_THRESHOLD", "high")
    with pytest.raises(FatalConfigError):
        drains._has_curator_work(_state1135.state_for_paths(LoopPaths(repo_root=tmp_path)))


def test_has_lead_author_work_raises_on_bad_pitfalls_threshold_with_marker_queued(
    tmp_path, monkeypatch
):
    """The markers-present path: a queued run marker must NOT let a non-numeric LEARNING_PITFALLS_THRESHOLD slip past the gate."""
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "high")
    paths = _paths(tmp_path)
    run_dir = _state1135.curation_run_dir("run-x")
    state = _state1135.state_for_paths(paths)
    _state1135.enqueue_run(state, run_dir)
    with pytest.raises(FatalConfigError, match="LEARNING_PITFALLS_THRESHOLD"):
        drains._has_lead_author_work(state)


def test_lead_author_max_retries_bad_value_raises_fatal_config(tmp_path, monkeypatch):
    """LEAD_AUTHOR_MAX_RETRIES is read inside the lead-author drain (past the wake gate, before the per-marker loop)."""
    monkeypatch.setenv("LEAD_AUTHOR_MAX_RETRIES", "high")
    paths = _paths(tmp_path)
    run_dir = _state1135.curation_run_dir("run-x")
    state = _state1135.state_for_paths(paths)
    _state1135.enqueue_run(state, run_dir)
    with pytest.raises(FatalConfigError, match="LEAD_AUTHOR_MAX_RETRIES"):
        drains._drain_lead_author_markers(
            paths, state, lambda _p, _s, _rd, *, box=None, **_kw: None,
            data_root=drains._data_root())


def test_author_drain_bad_threshold_is_fatal_two(tmp_path, monkeypatch):
    monkeypatch.setenv("LEARNING_AUTHOR_THRESHOLD", "high")
    paths = _paths(tmp_path)
    assert cli._run_stage(lambda: drains.author_drain(paths=paths)) == 2


def test_lead_author_drain_bad_threshold_is_fatal_two(tmp_path, monkeypatch):
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "high")
    paths = _paths(tmp_path)
    assert cli._run_stage(lambda: drains.lead_author_drain(paths=paths)) == 2


def test_lead_author_marker_drain_reraises_fatal_lift_threshold(tmp_path, monkeypatch):
    monkeypatch.setenv("LEARNING_LEAD_AUTHOR_LIFT_THRESHOLD", "high")
    paths = _paths(tmp_path)
    run_dir = _state1135.curation_run_dir("run-x")
    state = _state1135.state_for_paths(paths)
    _state1135.enqueue_run(state, run_dir)

    def _run_lead_author(_paths, _state, _run_dir, *, box=None, **_kw):
        lead_author._lift_threshold()

    with pytest.raises(FatalConfigError):
        drains._drain_lead_author_markers(
            paths, state, _run_lead_author, data_root=drains._data_root())

    failed_dir = paths.state_root / "author-queue" / "failed"
    assert not (failed_dir / f"{run_dir.name}.json").exists()
    assert (paths.state_root / "author-queue" / "inflight" / f"{run_dir.name}.json").exists()


def test_drain_pitfalls_reraises_fatal_config_error(tmp_path):
    """Defense-in-depth (no current trigger): _drain_pitfalls' broad guard swallows a
    curation hiccup, but a FatalConfigError must propagate to exit 2, not be swallowed."""
    paths = _paths(tmp_path)

    def _run_pitfalls(_paths, _state, *, box=None, **_kw):
        raise FatalConfigError("systemic")

    with pytest.raises(FatalConfigError):
        drains._drain_pitfalls(paths, _state1135.state_for_paths(paths), _run_pitfalls)


def test_lead_author_drain_unlinks_marker_on_success(tmp_path, monkeypatch):
    """A clean lead-author run drains the marker: success makes `if drained:` unlink it, so
    it is neither left queued (re-authored every tick) nor quarantined."""
    monkeypatch.delenv("LEAD_AUTHOR_MAX_RETRIES", raising=False)
    paths = _paths(tmp_path)
    run_dir = _state1135.curation_run_dir("run-ok")
    state = _state1135.state_for_paths(paths)
    _state1135.enqueue_run(state, run_dir)

    drains._drain_lead_author_markers(
        paths, state, lambda _p, _s, _rd, *, box=None, **_kw: None,
        data_root=drains._data_root())

    assert not (paths.state_root / "author-queue" / f"{run_dir.name}.json").exists()
    assert not (paths.state_root / "author-queue" / "failed" / f"{run_dir.name}.json").exists()


def test_lead_author_drain_quarantines_a_plain_failure(tmp_path, monkeypatch):
    """A plain (non-systemic) failure is dead-lettered: the marker moves to failed/ with a
    lead-author-error reason and is NOT unlinked as if it had succeeded."""
    monkeypatch.delenv("LEAD_AUTHOR_MAX_RETRIES", raising=False)
    paths = _paths(tmp_path)
    run_dir = _state1135.curation_run_dir("run-boom")
    state = _state1135.state_for_paths(paths)
    _state1135.enqueue_run(state, run_dir)

    def _run_lead_author(_paths, _state, _run_dir, *, box=None, **_kw):
        raise RuntimeError("poison run dir")

    drains._drain_lead_author_markers(
        paths, state, _run_lead_author, data_root=drains._data_root())

    assert not (paths.state_root / "author-queue" / f"{run_dir.name}.json").exists()
    failed = paths.state_root / "author-queue" / "failed" / f"{run_dir.name}.json"
    assert failed.exists()
    assert "lead-author-error" in json.loads(failed.read_text())["failed"]


def test_lead_author_drain_requeues_a_transient_with_bumped_attempts(tmp_path, monkeypatch):
    """A _LeadAuthorRetry must reach the drain's retry handler via `propagate=`, NOT the"""
    monkeypatch.delenv("LEAD_AUTHOR_MAX_RETRIES", raising=False)
    paths = _paths(tmp_path)
    run_dir = _state1135.curation_run_dir("run-transient")
    state = _state1135.state_for_paths(paths)
    _state1135.enqueue_run(state, run_dir)

    def _run_lead_author(_paths, _state, _run_dir, *, box=None, **_kw):
        raise drains._LeadAuthorRetry("rc=None transient")

    drains._drain_lead_author_markers(
        paths, state, _run_lead_author, data_root=drains._data_root())

    marker = paths.state_root / "author-queue" / f"{run_dir.name}.json"
    assert marker.exists()
    assert not (paths.state_root / "author-queue" / "failed" / f"{run_dir.name}.json").exists()
    assert json.loads(marker.read_text())["attempts"] == 1


def test_drain_pitfalls_swallows_a_plain_curation_error(tmp_path):
    paths = _paths(tmp_path)

    def _run_pitfalls(_paths, _state, *, box=None, **_kw):
        raise RuntimeError("curation hiccup")

    drains._drain_pitfalls(paths, _state1135.state_for_paths(paths), _run_pitfalls)


def test_run_or_dead_letter_dead_letters_a_plain_exception():
    """A per-item failure is dead-lettered: the callback fires with the exception and the
    helper reports failure (no re-raise) so the serial drain keeps going."""
    calls: list[Exception] = []

    def _boom():
        raise RuntimeError("poison item")

    ok = faults.run_or_dead_letter(_boom, calls.append)
    assert ok is False
    assert len(calls) == 1
    assert isinstance(calls[0], RuntimeError)


def test_run_or_dead_letter_dead_letters_a_run_unprocessable():
    """A RunUnprocessable is a per-run *data* failure (the ~30 validate.py sites): it must
    dead-letter like any other Exception — only the StageAbort family is special."""
    calls: list[Exception] = []

    def _boom():
        raise RunUnprocessable("malformed report.md")

    ok = faults.run_or_dead_letter(_boom, calls.append)
    assert ok is False
    assert len(calls) == 1
    assert isinstance(calls[0], RunUnprocessable)


def test_run_or_dead_letter_reraises_systemic_faults():
    """The systemic family is NEVER dead-lettered — it re-raises past the guard so it reaches _run_stage as the contracted exit 2."""
    for exc in (StageAbort("systemic fault"), FatalConfigError("non-numeric threshold")):
        calls: list[Exception] = []

        def _boom(exc=exc):
            raise exc

        with pytest.raises((StageAbort, FatalConfigError)):
            faults.run_or_dead_letter(_boom, calls.append)
        assert calls == []


def test_run_or_dead_letter_propagates_declared_control_flow():
    calls: list[Exception] = []

    def _boom():
        raise drains._LeadAuthorRetry("transient")

    with pytest.raises(drains._LeadAuthorRetry):
        faults.run_or_dead_letter(
            _boom, calls.append, propagate=(drains._LeadAuthorRetry,)
        )
    assert calls == []


class _StubBranch:
    """A git-free AuthorBranch stand-in for the full-stage exit-2 assertion. do_work
    raises before finish_batch, so only these three methods are exercised; start_batch
    returns a .git-less dir, on which ClaimGit.reset no-ops."""

    #: What the real `AuthorBranch` cuts a batch from (its default); a box-start fault names it.
    branch_base = "origin/main"

    branch_prefix = "lead-author/"

    def __init__(self, wt: object) -> None:
        self._wt = wt

    def open_pr_exists(self) -> bool:
        return False

    def start_batch(self, batch_id: str):
        return self._wt

    def cleanup(self, wt) -> None:
        pass


def _raise(exc):
    """A zero-arg stage that raises ``exc`` (closure dodges lambda's no-raise limit)."""
    def _stage():
        raise exc
    return _stage


def test_run_stage_maps_stage_abort_to_exit_two():
    assert cli._run_stage(_raise(StageAbort("systemic"))) == 2
    assert cli._run_stage(_raise(FatalConfigError("bad cfg"))) == 2
    assert cli._run_stage(
        _raise(StageAbort("systemic")), allow_run_error=True
    ) == 2


def test_run_stage_propagates_run_unprocessable_on_a_drain():
    """The guard: on a drain path (allow_run_error=False, the default) a leaked
    RunUnprocessable propagates uncaught rather than being mapped to a clean exit 2."""
    with pytest.raises(RunUnprocessable, match="bad run"):
        cli._run_stage(_raise(RunUnprocessable("bad run")))


def test_run_stage_maps_run_unprocessable_to_exit_two_on_direct_run():
    """The direct single-run path (loop.py <run_dir>) has no queue to quarantine into,
    so a bad run maps to the contracted exit 2 — the behavior main() preserves."""
    assert cli._run_stage(
        _raise(RunUnprocessable("bad run")), allow_run_error=True
    ) == 2


def test_run_or_dead_letter_reraises_giterror_not_quarantine():
    """A ``GitError`` (a broken local-state git op) dooms the whole batch, so it must
    re-raise out of the dead-letter guard — never be quarantined as a per-marker failure."""
    from defender import _git  # type: ignore[import-not-found]

    dead_lettered: list[Exception] = []

    def boom():
        raise _git.GitError(["status"], 128, "not a git repository")

    with pytest.raises(_git.GitError):
        faults.run_or_dead_letter(boom, dead_lettered.append)
    assert dead_lettered == []


def test_run_stage_maps_giterror_to_exit_2():
    """At the stage boundary a ``GitError`` becomes the contracted FATAL exit 2."""
    from defender import _git  # type: ignore[import-not-found]

    def stage() -> int:
        raise _git.GitError(["commit"], 1, "pre-commit hook rejected")

    assert cli._run_stage(stage) == 2


def _seed_queue(paths: LoopPaths, lines: list[str]) -> None:
    (paths.state_root / FINDINGS.queue).parent.mkdir(parents=True, exist_ok=True)
    (paths.state_root / FINDINGS.queue).write_text("".join(line + "\n" for line in lines), encoding="utf-8")


def _row(fid: str, **extra) -> str:
    return json.dumps({"finding_id": fid, "run_id": fid.split("/")[0], **extra})


#: The two spellings the gates actually stamp, plus the bucket's. The count keys on the FIELD,
#: never on one of these strings — a reader matching a prefix would miss the other writers.
_HELD_REASONS = (
    "no_ground_truth(direction='adversarial', disposition=None)",
    "no_family_ground_truth(judge_outcome=None)",
    "held_by_something_that_does_not_exist_yet",
)

#: One held row whose reason no gate in the tree spells — see `_HELD_REASONS`.
_UNRECOGNISED_HOLD = _HELD_REASONS[-1]


def test_881_pending_queue_count_measures_rows_the_drain_could_author(tmp_path):
    """#881/O2: `_pending_queue_counts` counts what a tick could take, not file lines."""
    paths = _paths(tmp_path)
    held = [_row(f"h/{i}", held_reason=_HELD_REASONS[i % len(_HELD_REASONS)]) for i in range(5)]

    _seed_queue(paths, held)
    assert drains._pending_queue_counts(_state1135.state_for_paths(paths), FINDINGS)[0] == 0, (
        "five rows the gate has already held were counted as pending work"
    )

    _seed_queue(paths, [_row(f"h/{i}") for i in range(5)])
    assert drains._pending_queue_counts(_state1135.state_for_paths(paths), FINDINGS)[0] == 5, (
        "the same five rows without `held_reason` are authorable and must be counted"
    )

    _seed_queue(paths, [_row("legacy/0", held_reason=_UNRECOGNISED_HOLD)])
    assert drains._pending_queue_counts(_state1135.state_for_paths(paths), FINDINGS)[0] == 0, (
        f"a row held for {_UNRECOGNISED_HOLD!r} was counted as pending work; the count is "
        "reading the reason's prose rather than the field, so any hold whose wording it "
        "does not recognise — a legacy row, a reworded gate — reads as authorable"
    )

    for wordless in ("", None):
        _seed_queue(paths, [_row(f"legacy/{i}", held_reason=wordless) for i in range(5)])
        assert drains._pending_queue_counts(_state1135.state_for_paths(paths), FINDINGS) == (0, 5), (
            f"five rows stamped held_reason={wordless!r} were counted as pending work; the "
            "count is testing whether the reason is TRUTHY rather than whether the field is "
            "there, so a holder that had no wording to give leaves its rows waking the drain "
            "on every tick — O2's own defect, by the one route no gate in the tree spells"
        )

    _seed_queue(paths, ["", _row("h/0"), "   ", ""])
    assert drains._pending_queue_counts(_state1135.state_for_paths(paths), FINDINGS)[0] == 1, "a blank line is not a row"

    # One held row (0) + five lines that are not rows (5) + one authorable row (1). The four
    # JSON-but-not-an-object lines are the ones a `json.loads`-only reader lets through.
    _seed_queue(paths, [
        _row("legacy/0", held_reason=_UNRECOGNISED_HOLD),
        "[1,2]", "null", '"x"', "3", "{not json at all",
        _row("c/0"),
    ])
    assert drains._pending_queue_counts(_state1135.state_for_paths(paths), FINDINGS)[0] == 6, (
        "a line that is not a row is work for the drain's unkeyable retirement and must be "
        "counted — whether it failed to parse at all, or parsed to a list, a null, a string "
        "or a number, none of which is a row"
    )


def test_881_a_deferred_row_still_counts_as_work(tmp_path, monkeypatch):
    """#881/O2, carried into #773's replacement for the retryable forward-check hold."""
    monkeypatch.setenv("LEARNING_AUTHOR_THRESHOLD", "5")
    paths = _paths(tmp_path)

    _seed_queue(paths, [_row(f"fb/{i}", deferrals=1) for i in range(5)])
    assert drains._pending_queue_counts(_state1135.state_for_paths(paths), FINDINGS)[0] == 5, (
        "a deferred row was subtracted from the wake gate; the next tick may still land it, "
        "so it is work and the drain must still wake for it"
    )
    assert drains._has_curator_work(_state1135.state_for_paths(paths)) is True, (
        "five deferred rows left the wake gate shut, so they are never retried — queued and "
        "invisible"
    )

    # The control: the permanent hold on the same address still counts for nothing.
    _seed_queue(paths, [_row(f"h/{i}", held_reason=_HELD_REASONS[0]) for i in range(5)])
    assert drains._pending_queue_counts(_state1135.state_for_paths(paths), FINDINGS)[0] == 0, (
        "a permanent hold counted as work, so the count now subtracts nothing at all"
    )
    assert drains._has_curator_work(_state1135.state_for_paths(paths)) is False


def test_881_the_author_wake_gate_does_not_fire_for_rows_it_would_only_hold_again(
    tmp_path, monkeypatch
):
    """#881/O2: `_has_curator_work` answers for rows that can be AUTHORED."""
    monkeypatch.setenv("LEARNING_AUTHOR_THRESHOLD", "5")
    paths = _paths(tmp_path)
    held = [_row(f"h/{i}", held_reason=_HELD_REASONS[i % len(_HELD_REASONS)]) for i in range(5)]

    _seed_queue(paths, held)
    assert drains._has_curator_work(_state1135.state_for_paths(paths)) is False, (
        "the wake gate fired for five rows the gate has already held; the drain will take "
        "the repo lock, hold them again and write nothing, on every tick, forever"
    )

    _seed_queue(paths, [_row(f"c/{i}") for i in range(5)])
    assert drains._has_curator_work(_state1135.state_for_paths(paths)) is True, (
        "five authorable rows must still wake the drain"
    )

    _seed_queue(paths, [*held, _row("c/0")])
    assert drains._has_curator_work(_state1135.state_for_paths(paths)) is False, (
        "one authorable row beside five held ones is one row of work, not six"
    )

    _seed_queue(paths, [*held, *(_row(f"c/{i}") for i in range(5))])
    assert drains._has_curator_work(_state1135.state_for_paths(paths)) is True, (
        "five authorable rows are five rows of work however many held ones sit beside them"
    )

    _seed_queue(paths, [_row(f"legacy/{i}", held_reason=_UNRECOGNISED_HOLD) for i in range(5)])
    assert drains._has_curator_work(_state1135.state_for_paths(paths)) is False, (
        f"the wake gate fired for five rows held for {_UNRECOGNISED_HOLD!r}; it is reading "
        "the reason's wording rather than the field, so the legacy rows this defect strands "
        "— held by a writer that no longer exists — pin it open exactly as before"
    )
