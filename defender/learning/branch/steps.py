"""THE OWNER OF THE EPISODE LIFECYCLE: its steps, declared once, in launch order.

An episode is one sequence, and this module is where it is written down. The launcher
(`branch/cli.py`) RUNS it in this order but does not define it; the timing record
(`branch/timing.py`) refuses a row naming any other step; the episode page (#1025) renders its
stage table in this order; every docstring, banner and message elsewhere that names a step
names a member of `Step`, never a number and never a bare string. Before this module the
sequence was spelled in three places — numbered prose in the launcher's docstring, a literal
at each of its step frames, a tuple beside the record — and a rename or a new step touched all
three or drifted.

Why a leaf module rather than the launcher: the launcher is the frame that sees every
boundary, but it is the top of the import graph — argparse, the review's model runtime — and
the record cannot import it without a cycle. The declaration sits below everything that reads
it.

WHAT IS NOT A STEP. Preflight — everything the launcher can refuse before anything is spent —
runs before `QUESTIONER` and is deliberately not a member: it costs no model call and no staged
name, and it refuses before the episode has a directory to record into, so there is nothing
for the outer clock to write and nowhere to write it. Teardown is not a step either: it runs
on EVERY exit, inside whichever step ended the episode, and the record's rule is that a step
which raised is not on it.
"""
from __future__ import annotations

from enum import StrEnum


class Step(StrEnum):
    """One step of the episode, on the launcher's outer clock — member order IS launch order.

    @owns step — the timing row's `step` field takes its value from here and nowhere else.

    A `StrEnum` so the record's row holds the bare name, a wire-log stage label reads as the
    same word, and a reader's comparison against `"runs"` reads naturally.

    `VERIFY` and `JUDGE` are one numbered step in the launcher's older prose ("step 6"): the
    judge is J10's tail of it, run after the cluster is handed back so the grade's model calls
    hold no staged name live. They are two members because they are two rows on the clock.
    """

    QUESTIONER = "questioner"
    STAGING = "staging"
    REVIEW = "review"
    RUNS = "runs"
    VERIFY = "verify"
    JUDGE = "judge"


#: The same six, as the ordered tuple a record validates against and a page iterates.
STEPS: tuple[Step, ...] = tuple(Step)
