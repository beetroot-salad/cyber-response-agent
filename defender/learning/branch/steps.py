"""THE OWNER OF THE EPISODE LIFECYCLE: its steps, declared once, in launch order.

An episode is one sequence, and this module is where it is written down. The launcher
(`branch/cli.py`) RUNS it in this order but does not define it; the timing record
(`branch/timing.py`) refuses a row naming any other step; the episode page (#1025) renders its
stage table in this order; every frame, banner and message in the launcher and the record that
names a step names a member of `Step`, never a bare string. The launcher's docstring and
`docs/learning-loop.md` keep a numbered reading order of their own — it puts preflight first,
so its ordinals are not this enum's positions. Before this module the sequence was spelled
only as prose, numbered in the launcher's docstring and by that number wherever another module
referred to a step, and a rename or a new step renumbered all of them or drifted.

Why a leaf module rather than the launcher: the launcher is the frame that sees every
boundary, but it is the top of the import graph — argparse, the review's model runtime — and
the record cannot import it without a cycle. The declaration sits below everything that reads
it.

WHAT IS NOT A STEP. Preflight — everything the launcher can refuse before anything is spent —
runs before `QUESTIONER` and is deliberately not a member: it costs no model call and no staged
name, and it refuses before the episode has a directory to record into, so there is nothing
for the outer clock to write and nowhere to write it. The episode's claim and prime
(`prepare_episode`: the exclusive claim, then every captured row of the source re-dumped into
`served/base.jsonl`) run after that directory exists and before `QUESTIONER`, and are not on
the clock either — the record's six rows start at the questioner, so a total over them
excludes the prime. Teardown is not a step either: it runs
on EVERY exit but never as one — on a rejection or an abort from `_launch`'s `finally`, after
the last frame has closed or unwound; on the clean path as the first thing inside
`_release_and_grade`, BEFORE the `JUDGE` clock starts — and the record's rule is that a step
which raised is not on it.
"""
from __future__ import annotations

from enum import StrEnum


class Step(StrEnum):
    """One step of the episode, on the launcher's outer clock — member order IS launch order.

    @owns step — the timing row's `step` field takes its value from here and nowhere else.

    A `StrEnum` so the record's row holds the bare name and a reader's comparison against
    `"runs"` reads naturally. The wire-log stage labels that happen to share a word
    (`stage="questioner"`, `stage="judge"` on `run_stage`) are the ROLE's — `AgentRole` —
    not this enum's: the comparator's calls carry the questioner label from inside `REVIEW`.

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
