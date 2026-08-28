"""The run's provenance stamp is readable by no agent, on both read surfaces (#976).

Modelled on `test_wire_log_read_gate.py`, which pins the same posture for the wire log, and
built on its fixtures for the same reason: the deny is only interesting NEXT TO a positive
control, because a gate that also refused `investigation.md` would prove nothing.

WHY THIS FILE EXISTS AT ALL, given the stamp was already suppressed from the workspace map:
suppression removes a NAME from a listing, not a file from reach. The run root sits inside
MAIN's and GATHER's `under(run, SEG)` read shape and the JUDGE's `cat` scope is
`under(run, TREE)`, so before this deny a guessed filename walked straight to the host's
commit and up to fifty repo-relative paths of somebody's uncommitted work — unframed, because
a host-written file is never tagged by `is_untrusted_read`.
"""
from __future__ import annotations

import pytest

pytest.importorskip("pydantic_ai")

from defender import _provenance  # noqa: E402
from defender._provenance import RunProvenance  # noqa: E402
from defender._run_paths import PROVENANCE, RunPaths  # noqa: E402
from defender.runtime import permission  # noqa: E402
# `env` is imported for its FIXTURE effect — pytest resolves `stamped(env)` through the
# module namespace — so the shadowing `noqa` below is the import doing its job, not a slip.
from defender.tests.test_wire_log_read_gate import (  # noqa: E402,F401
    _bash,
    _read,
    env,
)

READERS = ("main", "gather")


@pytest.fixture
def stamped(env):  # noqa: F811 — the imported fixture IS the parameter
    """The shared run-dir fixture with a real stamp in it, written the way production writes."""
    _provenance.write(
        RunPaths(env.run).provenance,
        RunProvenance(commit="a" * 40, dirty=True, dirty_paths=("defender/secret-wip.py",),
                      dirty_path_count=1, scope="defender"),
    )
    return env


@pytest.mark.parametrize("which", READERS)
def test_no_reader_agent_may_read_the_stamp(stamped, which):
    """The two roles whose read shape is the run root's own single segment."""
    decision = _read(stamped, RunPaths(stamped.run).provenance, which)
    assert not decision.allow
    assert "provenance" in decision.reason.lower() or "host" in decision.reason.lower()


@pytest.mark.parametrize("which", READERS)
def test_the_run_root_is_otherwise_still_readable(stamped, which):
    """The positive control. A deny that also refused the investigation would be a broken shape
    rather than a targeted rule, and the arm above could not tell the two apart."""
    assert _read(stamped, stamped.run / "investigation.md", which).allow


@pytest.mark.parametrize("which", READERS)
def test_the_bash_lane_agrees_with_the_read_tool(stamped, which):
    """Both surfaces or neither. The JUDGE's `cat` scope is `under(run, TREE)`, which
    fullmatches a run-root file, so a deny living only in `decide_read` would leave one surface
    admitting the very path the other refuses."""
    assert not _bash(stamped, f"cat {RunPaths(stamped.run).provenance}", which).allow


def test_the_deny_is_rooted_not_a_bare_filename(tmp_path):
    """A confined agent's other read root is a lesson corpus, and a flat name test would make a
    corpus file called `provenance.json` unreadable with a reason about host bookkeeping."""
    run = tmp_path / "run"
    run.mkdir()
    elsewhere = tmp_path / "lessons"
    elsewhere.mkdir()
    (elsewhere / PROVENANCE).write_text("{}\n", encoding="utf-8")
    assert permission.names_run_provenance((run / PROVENANCE).resolve(), run)
    assert not permission.names_run_provenance((elsewhere / PROVENANCE).resolve(), run)


def test_the_deny_holds_for_a_stamp_that_is_not_there_yet(stamped):
    """Keyed on the NAME, not on the file existing: a run whose stamp write failed must not
    become a run where the path is suddenly readable, or the gate would be strongest exactly
    when there is nothing to protect and absent when a later write lands."""
    RunPaths(stamped.run).provenance.unlink()
    assert not _read(stamped, RunPaths(stamped.run).provenance, "main").allow
