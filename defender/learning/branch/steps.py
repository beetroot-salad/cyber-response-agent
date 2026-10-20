"""The episode lifecycle's steps, declared once, in launch order."""
from __future__ import annotations

from enum import StrEnum


class Step(StrEnum):
    """One step of the episode on the launcher's outer clock; member order is launch order."""

    QUESTIONER = "questioner"
    PREFLIGHT = "preflight"
    RUNS = "runs"
    VERIFY = "verify"
    JUDGE = "judge"


#: The same five, as the ordered tuple a record validates against and a page iterates.
STEPS: tuple[Step, ...] = tuple(Step)
