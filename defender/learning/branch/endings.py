"""How a learning job's family step ends (#1344 r5, "End record and outcomes"): the ending typed
where it is raised, and the job-lane hooks the launcher calls.

A job's reason is never read from message text. Each refusal or failure the launcher raises for a
reason in the outcome table is a `JobEnding`: still a `LauncherRefused` (an operator's exit, its
text the operator's whole explanation), and also its job status, reason and a `brief` message
written by our own code, which carries no launcher or run text. The job entry records the
status, reason and brief; nothing reads the exception's text.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from defender.records.job_lane import (
    CONTROL_FAILED,
    ENTRY_ERROR,
    FAMILY_UNUSABLE,
    HISTORY_UNREADABLE,
    JUDGE_FAILED,
    LAUNCH_REFUSED,
    LEARNING_FAILED,
    LEARNING_SKIPPED,
    NO_FORK_POINT,
    SKIPPED_BY_THE_ENTRY,
    SOURCE_UNAVAILABLE,
    VERIFY_REFUSED,
)

__all__ = [
    "CONTROL_FAILED", "ENTRY_ERROR", "FAMILY_UNUSABLE", "HISTORY_UNREADABLE", "JUDGE_FAILED",
    "JobEnding", "JobLaneHooks", "LAUNCH_REFUSED", "LauncherRefused", "NO_FORK_POINT", "SOURCE_UNAVAILABLE",
    "VERIFY_REFUSED", "ending",
]


class LauncherRefused(SystemExit):
    """An episode this launcher will not run, reported as an operator's exit with an
    explanation rather than a traceback."""


class JobEnding(LauncherRefused):
    """A launcher refusal or failure typed at its raise site with a learning job's ending.

    `detail` is the operator's message (the `SystemExit` code, as for any `LauncherRefused`);
    `reason` is one of the outcome table's, its status following from it; `brief` is the
    job's message, our own words naming at most a type."""

    def __init__(self, detail: str, *, reason: str, brief: str) -> None:
        super().__init__(detail)
        self.reason = reason
        self.status = LEARNING_SKIPPED if reason in SKIPPED_BY_THE_ENTRY else LEARNING_FAILED
        self.brief = brief


def ending(detail: str, *, reason: str, brief: str, cause: BaseException | None = None) -> JobEnding:
    """A `JobEnding` to raise, chained to `cause` when there is one."""
    raised = JobEnding(detail, reason=reason, brief=brief)
    raised.__cause__ = cause
    return raised


def _nothing(*_args: Any, **_kwargs: Any) -> None:
    return None


@dataclass
class JobLaneHooks:
    """What the launcher calls back in the job lane (`--job-id`, or the job entry). Every hook is
    optional: an operator launching with `--job-id` gets the job lane's behaviour (episode id =
    job id, width 1, typed endings, the judge's job-lane sink) with no records.

    - `pick(source)`: the fork message id, decided once the source run is open and its stamp
      agrees (the job entry's fork pick, which opens the source's session store itself); `None`
      keeps the command line's.
    - `stage(name)`: a step is starting.
    - `sibling_ended(view, world_ids)`: a sibling has exited; `view` is the episode's
      `EpisodeRuns`, `world_ids` the worlds of every sibling that has run so far.
    - `judged(grade, count)`: the judge's pass returned `grade`; from here the ending is
      decided. `count()` reads how many findings the pass left in the episode.
    - `grade`: the judge's entry (`learning.judge.grade_episode` when `None`)."""

    job_id: str
    pick: Callable[..., int] | None = None
    stage: Callable[[str], None] = _nothing
    sibling_ended: Callable[..., None] = _nothing
    judged: Callable[..., None] = _nothing
    grade: Callable[..., Any] | None = None
