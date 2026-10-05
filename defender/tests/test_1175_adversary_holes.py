"""#1175 adversary pass: scenes that a cheating implementation of the #1175 design passed
`test_1175_leads_git_liveness.py` without (F1-F8 of the adversary report on the PR). Each pins
one clause the base suite left open; each was confirmed red against the cheat and green against
an honest seam.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from defender.learning.core.faults import SYSTEMIC_FAULTS
from defender.learning.leads.lead_extraction import LeadAuthorError
from defender.runtime import box as box_mod
from defender.tests._declared869 import GIT_IGNORE, write
from defender.tests.test_1175_leads_git_liveness import (
    BOUND,
    EDIT_LIFT,
    LIFT,
    PYC,
    SKILLS_REL,
    _assert_lead_claim_held,
    _assert_lead_served,
    _assert_tainted_by,
    _edits,
    _failed,
    _fifo,
    _inflight,
    _is_systemic_git_fault,
    _lead_scene,
    _LeadLane,
    _no_curation,
    _put,
    _put_bytes,
    _stall_git,
    _stalled,
    _tick,
    author_markers,
)


# S1 (O5 / M1 "read from the commit"): HEAD's own rules, whatever they are, apply under skills/.
@pytest.mark.parametrize("variant", ["log-rule", "no-python-rules"])
def test_s1_heads_rules_not_a_hardcoded_list(tmp_path, monkeypatch, variant):
    if variant == "log-rule":
        committed = {".gitignore": GIT_IGNORE + "__pycache__/\n*.py[cod]\n*.log\n"}
        plant = _put(f"{SKILLS_REL}elastic/debug.log", "noise\n")
    else:
        committed = {".gitignore": GIT_IGNORE}
        plant = _put_bytes(f"{SKILLS_REL}invlang/__pycache__/__init__.cpython-312.pyc", PYC)
    sc = _lead_scene(tmp_path, monkeypatch, committed=committed)
    got = _tick(sc, run_lead_author=_LeadLane(_edits(EDIT_LIFT, plant)),
                run_pitfalls=_no_curation)
    assert got == ("value", 0), got
    if variant == "log-rule":
        _assert_lead_served(sc, {f"M\t{LIFT}"})
    else:
        assert _inflight(sc.paths) == {}
        [failed] = _failed(sc.paths)
        assert "__pycache__" in failed["failed"], failed


# S2 (M1): a .gitignore committed deeper inside skills/ is refused too.
@pytest.mark.parametrize("committed", ["defender/skills/gather/queries/.gitignore",
                                       "defender/skills/elastic/_draft/.gitignore"])
def test_s2_a_deeper_committed_gitignore_is_refused(tmp_path, monkeypatch, committed):
    sc = _lead_scene(tmp_path, monkeypatch, committed={committed: "*.tmp\n"})
    got = _tick(sc, run_lead_author=_LeadLane(EDIT_LIFT), run_pitfalls=_no_curation)
    result, exc = got
    assert result == "raised", got
    assert isinstance(exc, SYSTEMIC_FAULTS), repr(exc)
    assert not isinstance(exc, box_mod.RunTainted), repr(exc)
    _assert_lead_claim_held(sc)


# S3 (O4): a TRACKED non-.md under skills/ modified before the baseline is not swept in.
def test_s3_a_tracked_baseline_stray_is_not_swept_into_the_commit(tmp_path, monkeypatch):
    sc = _lead_scene(tmp_path, monkeypatch)
    write(sc.wt / "defender/skills/invlang/__init__.py", "# left here before the claim\n")
    got = _tick(sc, run_lead_author=_LeadLane(EDIT_LIFT), run_pitfalls=_no_curation)
    assert got == ("value", 0), got
    _assert_lead_served(sc, {f"M\t{LIFT}"})


# S4 (M3's reason): ignored worktree state outside skills/ survives the cleanup.
def test_s4_cleanup_leaves_ignored_state_outside_skills(tmp_path, monkeypatch):
    sc = _lead_scene(tmp_path, monkeypatch)
    keep = sc.wt / "defender/__pycache__/keep.cpython-312.pyc"
    keep.parent.mkdir(parents=True)
    keep.write_bytes(PYC)
    got = _tick(sc, run_lead_author=_LeadLane(EDIT_LIFT), run_pitfalls=_no_curation)
    assert got == ("value", 0), got
    assert keep.is_file(), "the cleanup deleted ignored state outside skills/"


# S5 (M4 "a bound on every call"; M2 "its internal git_head_sha must also be bounded"):
# stall each post-agent subcommand ALONE.
@pytest.mark.parametrize("sub", ["ls-files", "diff", "commit", "rev-parse"])
def test_s5_each_post_agent_call_is_bounded(tmp_path, monkeypatch, sub):
    sc = _lead_scene(tmp_path, monkeypatch)
    flag = tmp_path / "agent-ran"
    lane = _LeadLane(_edits(EDIT_LIFT, lambda _root: flag.write_text("")), git_timeout=BOUND)
    with monkeypatch.context() as patch:
        shim = _stall_git(tmp_path / "git-shim", patch, {sub}, flag=flag)
        got = _tick(sc, run_lead_author=lane, run_pitfalls=_no_curation, shim=shim)
    result, exc = got
    assert result == "raised", got
    assert _is_systemic_git_fault(exc), repr(exc)
    assert _stalled(shim) == [sub], _stalled(shim)
    _assert_lead_claim_held(sc)


# S6 (O1 / O2 / M1 "replaces C1, C2 and C4"): a FIFO claim 1 left meets claim 2's BASELINE.
def test_s6_a_fifo_left_by_claim_one_hangs_no_later_baseline(tmp_path, monkeypatch):
    sc = _lead_scene(tmp_path, monkeypatch, cases=("case-1", "case-2"))
    site = f"{SKILLS_REL}.gitignore"
    fifo = sc.wt / site
    calls: list[int] = []

    def edit(root: Path) -> None:
        calls.append(1)
        if len(calls) == 1:
            _edits(EDIT_LIFT, _fifo(site))(root)
        else:
            _put(LIFT, "# lift\n\nedited again by claim two.\n")(root)

    lane = _LeadLane(edit, git_timeout=BOUND)
    got = _tick(sc, run_lead_author=lane, run_pitfalls=_no_curation, fifos=[fifo],
                git_timeout=BOUND, what=site)
    assert len(lane.reached) == 2, "claim two never reached its agent"
    _assert_tainted_by(got, fifo)


# S7 (M3): a cleanup git ERROR (not a timeout) after a clean claim ends the tick too.
def test_s7_a_cleanup_git_error_after_a_clean_claim_ends_the_tick(tmp_path, monkeypatch):
    sc = _lead_scene(tmp_path, monkeypatch, cases=("case-a", "case-b"))
    served: list[Path] = []

    def serve(paths, _state, run_dir, *, box=None, on_done):
        served.append(run_dir)
        if len(served) == 1:
            (paths.repo_root / ".git" / "index.lock").write_text("")
        on_done(None)

    got = _tick(sc, run_lead_author=serve, run_pitfalls=_no_curation, git_timeout=BOUND)
    run_a, _run_b = sc.run_dirs
    assert got[0] == "raised", got
    assert isinstance(got[1], SYSTEMIC_FAULTS), repr(got[1])
    assert served == [run_a], "the next claim was served over the first one's leftovers"
    assert author_markers(sc.paths) == ["case-b.json"]


# S8 (M3): a cleanup overrun after a claim that was DEAD-LETTERED (no fault in flight) ends the
# tick too: the refused claim's leftovers must never be what the next claim runs over.
def test_s8_a_cleanup_overrun_after_a_dead_lettered_claim_ends_the_tick(tmp_path, monkeypatch):
    sc = _lead_scene(tmp_path, monkeypatch, cases=("case-a", "case-b"))
    served: list[Path] = []

    def step(paths, _state, run_dir, *, box=None, on_done):
        served.append(run_dir)
        if len(served) == 1:
            (paths.repo_root / LIFT).write_text("# left by a refused claim\n")
            raise LeadAuthorError("refused: out of scope")
        on_done(None)

    with monkeypatch.context() as patch:
        shim = _stall_git(tmp_path / "git-shim", patch, ["reset"])
        got = _tick(sc, run_lead_author=step, run_pitfalls=_no_curation, shim=shim,
                    git_timeout=BOUND)
    run_a, _run_b = sc.run_dirs
    assert got[0] == "raised", got
    assert _is_systemic_git_fault(got[1]), repr(got[1])
    assert served == [run_a], "the next claim was served over the refused claim's leftovers"
    assert [f["case_id"] for f in _failed(sc.paths)] == ["case-a"]
    assert author_markers(sc.paths) == ["case-b.json"]
