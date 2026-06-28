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
from defender.learning.core.config import LoopError, LoopPaths  # type: ignore[import-not-found]


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
