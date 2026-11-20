"""The episode-view route of the closing-record lookup (#1534): world -> the arm roster -> the
arm's run -> `for_run`.

An episode's world verdict is its arm's closing record, read through the episode's run view
(`RunsRepository.episode`), never off the archive tree. The roster decides first: absent or
refused, every world's lookup is `roster-gone` (the pass that needs it refuses whole). With the
roster readable, an arm container that is gone or cannot be held, and an arm whose entry is
refused (a link, a non-directory), are `arm-refused`; an arm whose folder is gone with its
container present never ran, so it is `NeverClosed`."""
from __future__ import annotations

from typing import Any

from defender.records._errors import RunAbsent, RunRefused
from defender.records._tenant_id import TenantRefused

from ._lookup import ARM_REFUSED, ROSTER_GONE, CouldNotLook, Lookup, NeverClosed, fault, for_run


def roster_fault(episode_runs: Any) -> CouldNotLook | None:
    """`roster-gone` when the episode's arm roster is absent or refused, else `None`."""
    found = _arms(episode_runs)
    return found if isinstance(found, CouldNotLook) else None


def _arms(episode_runs: Any) -> dict[str, Any] | CouldNotLook:
    """The episode's roster, read and checked against its manifest once, or `roster-gone`."""
    try:
        arms = episode_runs.arm_ids()
    except (RunRefused, TenantRefused, OSError, ValueError) as refused:
        return fault(ROSTER_GONE, f"episode {episode_runs.episode_id}: {refused}")
    if arms is None:
        return fault(ROSTER_GONE, f"episode {episode_runs.episode_id} has no arm roster")
    return arms


def for_world(episode_runs: Any, world_id: str) -> Lookup:
    """World `world_id`'s closing record through the episode view `episode_runs`: its arm's
    record, `NeverClosed`, or `CouldNotLook` (`roster-gone`, `arm-refused` or any kind the
    run-handle route answers for the arm). The roster is read once, and the arm taken from that
    read: a second read could disagree with the first."""
    arms = _arms(episode_runs)
    if isinstance(arms, CouldNotLook):
        return arms
    arm = arms.get(world_id)
    if arm is None:
        # A world the roster does not name: the view's own refusal, read as before.
        try:
            arm = episode_runs.arm_id(world_id)
        except RunRefused as refused:
            return fault(ROSTER_GONE, f"episode {episode_runs.episode_id}: {refused}")
    if not episode_runs.present:
        return fault(ARM_REFUSED, f"episode {episode_runs.episode_id}: the arm container is "
                                  f"{episode_runs.state} ({episode_runs.unreadable_reason or 'gone'})",
                     run_id=arm)
    try:
        run = episode_runs.open(arm)
    except RunAbsent:
        # The container is there and the arm's folder is not: the arm was never set up.
        return NeverClosed()
    except (RunRefused, TenantRefused, OSError) as refused:
        return fault(ARM_REFUSED, f"episode {episode_runs.episode_id}: arm {arm}: {refused}", run_id=arm)
    return for_run(run)
