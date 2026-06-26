"""Regression: the author runner's event summarizer (progress logging) must not
crash on a tool_use block whose command is empty/missing.

A curator agent can emit a Bash tool_use with `command: null` or `""`; the
summarizer ran `(...).splitlines()[0]`, which IndexErrors on an empty string and
took down the whole author driver mid-batch (found via the issue #298 env-author
sanity run). The driver is shared by all four authors, so the guard matters for
every direction."""
from __future__ import annotations


import pytest

from defender.learning.author import runner as runner


@pytest.mark.parametrize("command", [None, "", "   ", "\n"])
def test_summarize_bash_tolerates_empty_command(command) -> None:
    blk = {"type": "tool_use", "name": "Bash", "input": {"command": command}}
    # must not raise; returns a Bash summary (possibly empty cmd)
    out = runner._summarize_tool_use(blk)
    assert out.startswith("tool:Bash")


def test_summarize_bash_keeps_first_line() -> None:
    blk = {"type": "tool_use", "name": "Bash", "input": {"command": "echo hi\nrm x"}}
    assert runner._summarize_tool_use(blk) == "tool:Bash echo hi"
