"""The episode's steps, in launch order — declared once, here, and read everywhere else.

The launcher (`branch/cli.py::_run_episode`) runs them; the timing record
(`branch/timing.py`) refuses a row naming any other step; the episode page (#1025) renders its
stage table in this order. Each of those spelled the sequence for itself before this module
existed — as literals at the launcher's step frames, as a tuple beside the record, as prose in
the launcher's own docstring — and a rename or a new step touched all of them or drifted.

Why a leaf module rather than the launcher: the launcher is the natural owner, but it is the
top of the import graph — argparse, the review's model runtime — and the record cannot import
it without a cycle. The declaration sits below both.

Against the launcher's numbered prose (`cli.py`'s module docstring): step 1, the preflight
block, is NOT here — it refuses before anything is spent and before the episode has a
directory to record into. Steps 2 to 5 are the first four members; step 6 is `VERIFY`, and
`JUDGE` is J10's tail of it, released from the cluster before it spends its model calls.
"""
from __future__ import annotations

from enum import StrEnum


class Step(StrEnum):
    """One step of the episode, on the launcher's outer clock.

    A `StrEnum` so the timing record's row holds the bare name and a reader's comparison
    against `"runs"` reads naturally; member order IS launch order.
    """

    QUESTIONER = "questioner"
    STAGING = "staging"
    REVIEW = "review"
    RUNS = "runs"
    VERIFY = "verify"
    JUDGE = "judge"


#: The same six, as the ordered tuple a record validates against and a page iterates.
STEPS: tuple[Step, ...] = tuple(Step)
