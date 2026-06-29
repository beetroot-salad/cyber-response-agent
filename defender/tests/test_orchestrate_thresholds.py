"""A non-numeric loop threshold env var must fail loud as the contracted exit 2,
not crash the author-drain stage with an uncaught ValueError (issue #435).

The drain wake gates (`_has_curator_work` / `_has_lead_author_work`) read their
trigger thresholds with `config.env_int`, which raises `LoopError` on a bad value.
The gate runs at the top of `_run_worktree_batch`, before any git/PR work, so the
`LoopError` propagates out of the drain to `_run_stage`, which maps it to rc 2.
"""
from __future__ import annotations

import pytest

from defender.learning.core import config  # type: ignore[import-not-found]
from defender.learning.core import orchestrate  # type: ignore[import-not-found]
from defender.learning.core.config import (  # type: ignore[import-not-found]
    FatalConfigError,
    LoopError,
    LoopPaths,
)
from defender.learning.leads import lead_author  # type: ignore[import-not-found]


# --- env_int -----------------------------------------------------------------

def test_env_int_returns_default_when_unset(monkeypatch):
    monkeypatch.delenv("LEARNING_AUTHOR_THRESHOLD", raising=False)
    assert config.env_int("LEARNING_AUTHOR_THRESHOLD", 5) == 5


def test_env_int_parses_a_numeric_override(monkeypatch):
    monkeypatch.setenv("LEARNING_AUTHOR_THRESHOLD", "12")
    assert config.env_int("LEARNING_AUTHOR_THRESHOLD", 5) == 12


@pytest.mark.parametrize("bad", ["high", "", "5o"])
def test_env_int_raises_loop_error_on_non_numeric(monkeypatch, bad):
    monkeypatch.setenv("LEARNING_AUTHOR_THRESHOLD", bad)
    with pytest.raises(LoopError, match="LEARNING_AUTHOR_THRESHOLD must be an integer"):
        config.env_int("LEARNING_AUTHOR_THRESHOLD", 5)


# --- wake gates raise (not crash) on a bad threshold -------------------------

def test_has_curator_work_raises_on_bad_threshold(tmp_path, monkeypatch):
    monkeypatch.setenv("LEARNING_AUTHOR_THRESHOLD", "high")
    with pytest.raises(LoopError):
        orchestrate._has_curator_work(LoopPaths(repo_root=tmp_path))


def test_has_lead_author_work_raises_on_bad_pitfalls_threshold(tmp_path, monkeypatch):
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "high")
    with pytest.raises(LoopError):
        orchestrate._has_lead_author_work(LoopPaths(repo_root=tmp_path))


def test_has_lead_author_work_raises_on_bad_pitfalls_threshold_with_marker_queued(
    tmp_path, monkeypatch
):
    """The markers-present path: a queued run marker must NOT let a non-numeric
    LEARNING_PITFALLS_THRESHOLD slip past the gate. If the gate short-circuited to True
    on the marker before reading the threshold, the LoopError would only surface later
    inside run_pitfalls, where _drain_pitfalls' broad `except Exception` swallows it
    (exit 0, not the contracted exit 2). The gate reads the threshold up front (#435)."""
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "high")
    paths = LoopPaths(repo_root=tmp_path)
    run_dir = tmp_path / "run-x"
    run_dir.mkdir()
    orchestrate._enqueue_for_authoring(run_dir, paths)
    with pytest.raises(LoopError, match="LEARNING_PITFALLS_THRESHOLD"):
        orchestrate._has_lead_author_work(paths)


def test_lead_author_max_retries_bad_value_raises_loop_error(tmp_path, monkeypatch):
    """LEAD_AUTHOR_MAX_RETRIES is read inside the lead-author drain (past the wake gate,
    before the per-marker loop). A non-numeric value must fail loud as LoopError — which
    _run_stage maps to the contracted exit 2 — not a raw ValueError that escapes the
    LoopError-only catch as an uncontracted exit-1 traceback (#435, same class)."""
    monkeypatch.setenv("LEAD_AUTHOR_MAX_RETRIES", "high")
    paths = LoopPaths(repo_root=tmp_path)
    run_dir = tmp_path / "run-x"
    run_dir.mkdir()
    orchestrate._enqueue_for_authoring(run_dir, paths)
    with pytest.raises(LoopError, match="LEAD_AUTHOR_MAX_RETRIES"):
        orchestrate._drain_lead_author_markers(paths, lambda _p, _rd: None)


# --- the stage contract: bad threshold -> exit 2, never a traceback ----------

def test_author_drain_bad_threshold_is_fatal_two(tmp_path, monkeypatch):
    monkeypatch.setenv("LEARNING_AUTHOR_THRESHOLD", "high")
    paths = LoopPaths(repo_root=tmp_path)
    assert orchestrate._run_stage(lambda: orchestrate.author_drain(paths=paths)) == 2


def test_lead_author_drain_bad_threshold_is_fatal_two(tmp_path, monkeypatch):
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "high")
    paths = LoopPaths(repo_root=tmp_path)
    assert orchestrate._run_stage(lambda: orchestrate.lead_author_drain(paths=paths)) == 2


# --- happy path: a valid threshold + empty queues still short-circuits to 0 ---

def test_drains_skip_cleanly_with_valid_threshold_and_empty_queues(tmp_path, monkeypatch):
    monkeypatch.setenv("LEARNING_AUTHOR_THRESHOLD", "5")
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "5")
    # The author_drain gate also reads the per-direction observation thresholds; clear
    # any ambient non-numeric override so this happy-path assertion can't fail spuriously.
    for sibling in (
        "LEARNING_AUTHOR_ACTOR_THRESHOLD",
        "LEARNING_AUTHOR_ENV_THRESHOLD",
        "LEARNING_AUTHOR_ACTOR_ENV_THRESHOLD",
    ):
        monkeypatch.delenv(sibling, raising=False)
    paths = LoopPaths(repo_root=tmp_path)
    # Empty queues + a parseable threshold -> the gate returns False and the drain
    # skips the worktree without touching git.
    assert orchestrate._run_stage(lambda: orchestrate.author_drain(paths=paths)) == 0
    assert orchestrate._run_stage(lambda: orchestrate.lead_author_drain(paths=paths)) == 0


# --- #438: FatalConfigError punches through the per-marker quarantine guards ---
#
# The lift threshold is read DEEP in the per-marker flow (run() -> _prepare_handoffs
# -> _lift_threshold), under _drain_lead_author_markers' broad `except Exception`.
# Pre-#438 a non-numeric LEARNING_LEAD_AUTHOR_LIFT_THRESHOLD quarantined a healthy
# marker as `lead-author-error` (work lost, cause mislabeled, no exit 2). This is the
# one fatal-config path #437's wake-gate reads did NOT cover.


def test_fatal_config_error_is_a_loop_error():
    """Subclassing LoopError is the contract: _run_stage's `except LoopError -> exit 2`
    must catch FatalConfigError unchanged, while the new type still lets a drain
    distinguish 'abort the stage' from 'quarantine this item'."""
    assert issubclass(FatalConfigError, LoopError)


def test_env_int_raises_fatal_config_error_on_non_numeric(monkeypatch):
    monkeypatch.setenv("LEARNING_LEAD_AUTHOR_LIFT_THRESHOLD", "high")
    with pytest.raises(FatalConfigError, match="LEARNING_LEAD_AUTHOR_LIFT_THRESHOLD"):
        lead_author._lift_threshold()


def test_lead_author_marker_drain_reraises_fatal_lift_threshold(tmp_path, monkeypatch):
    """A non-numeric lift threshold surfaces inside the per-marker run as a
    FatalConfigError. _drain_lead_author_markers must RE-RAISE it (systemic) rather than
    quarantine the marker (the broad-guard disposition for per-item failures)."""
    monkeypatch.setenv("LEARNING_LEAD_AUTHOR_LIFT_THRESHOLD", "high")
    paths = LoopPaths(repo_root=tmp_path)
    run_dir = tmp_path / "run-x"
    run_dir.mkdir()
    orchestrate._enqueue_for_authoring(run_dir, paths)

    # Stand in for the deep read: the real _lift_threshold() (-> env_int) raises the
    # FatalConfigError exactly as run() -> _prepare_handoffs would.
    def _run_lead_author(_paths, _run_dir):
        lead_author._lift_threshold()

    with pytest.raises(FatalConfigError):
        orchestrate._drain_lead_author_markers(paths, _run_lead_author)

    # The marker must NOT have been quarantined — it stays queued to retry once the
    # operator fixes the env (and the drain failed loud instead of losing the work).
    failed_dir = paths.author_queue_dir / "failed"
    assert not (failed_dir / f"{run_dir.name}.json").exists()
    assert (paths.author_queue_dir / f"{run_dir.name}.json").exists()


def test_drain_pitfalls_reraises_fatal_config_error(tmp_path):
    """Defense-in-depth (no current trigger): _drain_pitfalls' broad guard swallows a
    curation hiccup, but a FatalConfigError must propagate to exit 2, not be swallowed."""
    paths = LoopPaths(repo_root=tmp_path)

    def _run_pitfalls(_paths):
        raise FatalConfigError("systemic")

    with pytest.raises(FatalConfigError):
        orchestrate._drain_pitfalls(paths, _run_pitfalls)


class _StubBranch:
    """A git-free AuthorBranch stand-in for the full-stage exit-2 assertion. do_work
    raises before finish_batch, so only these three methods are exercised; start_batch
    returns a .git-less dir, on which _discard_worktree_changes no-ops."""

    branch_prefix = "lead-author/"

    def __init__(self, wt: object) -> None:
        self._wt = wt

    def open_pr_exists(self) -> bool:
        return False

    def start_batch(self, batch_id: str):
        return self._wt

    def cleanup(self, wt) -> None:
        pass


def test_lead_author_drain_bad_lift_threshold_is_fatal_two(tmp_path, monkeypatch):
    """End-to-end: a queued marker + a bad lift threshold drives the whole
    lead_author_drain stage to the contracted exit 2 (not a quarantine, not exit 0)."""
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "5")  # valid: wake gate must pass
    monkeypatch.setenv("LEARNING_LEAD_AUTHOR_LIFT_THRESHOLD", "high")  # the fatal one
    paths = LoopPaths(repo_root=tmp_path)
    run_dir = tmp_path / "run-x"
    run_dir.mkdir()
    orchestrate._enqueue_for_authoring(run_dir, paths)

    wt = tmp_path / "wt"
    wt.mkdir()

    def _run_lead_author(_paths, _run_dir):
        lead_author._lift_threshold()

    rc = orchestrate._run_stage(
        lambda: orchestrate.lead_author_drain(
            paths=paths, run_lead_author=_run_lead_author, branch=_StubBranch(wt)
        )
    )
    assert rc == 2
