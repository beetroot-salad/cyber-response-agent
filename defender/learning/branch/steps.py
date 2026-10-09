"""The episode lifecycle's steps, declared once, in launch order.

The launcher (`branch/cli.py`) runs them in this order, the timing record refuses a row naming
any other step, and the episode page renders its stage table in this order. Anything that names
a step names a member of `Step`, never a bare string. The launcher's docstring and
`docs/learning-loop.md` number their reading order with preflight first, so those ordinals are
not this enum's positions.

A leaf module because the launcher sits at the top of the import graph and the record cannot
import it without a cycle.

Not steps: the launch checks (they cost nothing and refuse before the episode has a directory
to record into), and the claim and prime in `prepare_episode` (run before `QUESTIONER`, so a
total over the five rows excludes the prime).
"""
from __future__ import annotations

from enum import StrEnum


class Step(StrEnum):
    """One step of the episode on the launcher's outer clock; member order is launch order.

    @owns step — the timing row's `step` field takes its value from here and nowhere else.

    The wire-log stage labels that share a word (`stage="questioner"`, `stage="judge"`) belong
    to `AgentRole`, not this enum.

    `PREFLIGHT` is the launcher's calibration replay (#1224): every original call through each
    world's oracle and verifier, ending in the write-once outcome record. It is not the
    refusal block the launcher runs before `QUESTIONER` (that one has no row).

    `VERIFY` and `JUDGE` are one numbered step in the launcher's prose. They are two members
    because they are two rows on the clock.
    """

    QUESTIONER = "questioner"
    PREFLIGHT = "preflight"
    RUNS = "runs"
    VERIFY = "verify"
    JUDGE = "judge"


#: The same five, as the ordered tuple a record validates against and a page iterates.
STEPS: tuple[Step, ...] = tuple(Step)
