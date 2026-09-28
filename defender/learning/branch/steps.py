"""The episode lifecycle's steps, declared once, in launch order.

The launcher (`branch/cli.py`) runs them in this order, the timing record refuses a row naming
any other step, and the episode page renders its stage table in this order. Anything that names
a step names a member of `Step`, never a bare string. The launcher's docstring and
`docs/learning-loop.md` number their reading order with preflight first, so those ordinals are
not this enum's positions.

A leaf module because the launcher sits at the top of the import graph and the record cannot
import it without a cycle.

Not steps: preflight (costs nothing and refuses before the episode has a directory to record
into); the claim and prime in `prepare_episode` (run before `QUESTIONER`, so a total over the
six rows excludes the prime); and teardown, which runs on every exit — from `_launch`'s
`finally` on a rejection or abort, and on the clean path as the hand-back frame
(`cli._cluster_released`) around `JUDGE`, so the cluster is released before the judge's clock
starts and the judge's entry is written before a held hand-back failure is raised.
"""
from __future__ import annotations

from enum import StrEnum


class Step(StrEnum):
    """One step of the episode on the launcher's outer clock; member order is launch order.

    @owns step — the timing row's `step` field takes its value from here and nowhere else.

    The wire-log stage labels that share a word (`stage="questioner"`, `stage="judge"`) belong
    to `AgentRole`, not this enum: the comparator's calls carry the questioner label from inside
    `REVIEW`.

    `VERIFY` and `JUDGE` are one numbered step in the launcher's prose; the judge runs after the
    cluster is handed back so its model calls hold no staged name live. They are two members
    because they are two rows on the clock.
    """

    QUESTIONER = "questioner"
    STAGING = "staging"
    REVIEW = "review"
    RUNS = "runs"
    VERIFY = "verify"
    JUDGE = "judge"


#: The same six, as the ordered tuple a record validates against and a page iterates.
STEPS: tuple[Step, ...] = tuple(Step)
