"""The box failures that end a run by name (#1421 O8, O9).

`BoxEnding` is a `BoxFault`, because the handlers that already catch a box fault (the learning
lanes' stage handler, the oracle's replacement flow) must keep catching these; it carries the exit
class the run ends with, as `CallRecordWriteFailed.record` does. The driver ends the run on one in
a single place at each site; the bash tool re-raises the base, so neither ending is turned into a
retry the model cannot act on.
"""
from __future__ import annotations

from typing import ClassVar

from defender.execution.box_codec import BoxFault
from defender.records.run_end import TRUNCATED_BY_BOX_LOST


class BoxEnding(BoxFault):
    """A box failure that ends the run: `exit_class` is the run-end word it is recorded under."""

    exit_class: ClassVar[str]


class BoxLost(BoxEnding):
    """The run's box is unusable: not running, unanswering, or answering in a way only a host bug
    or a bypass of the in-box helper explains. The operator's to fix; the run ends on the first
    command that finds it. Built from one message, as `BoxFault` is."""

    exit_class = TRUNCATED_BY_BOX_LOST

    def __init__(self, message: str) -> None:
        super().__init__(message)
