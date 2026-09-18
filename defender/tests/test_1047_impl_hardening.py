"""#1047 implementation hardening — defects found by the two adversaries the write-code-from-
spec skill runs against the honest implementation (never against the committed spec), fixed
here with their own regression pins.

None of this is about O1-O3: the committed `test_1047_*.py` files pin the design; this file
pins that the code does what it (now, correctly) claims about itself, and that a handful of
corner-cuts the spec adversary's own from-scratch reimplementation found live are absent from
THIS implementation.

Claims adversary (reads only the code, falsifies its docstrings):

1. `read_world_facts` used to carry a `cut_short` field nothing in production read, and a
   `run_end=` parameter whose only purpose was to spare the one caller that did not need the
   field a second parse. Both are gone: the judge reads the record once, in `_grade_world`.
2. `_archive_run_end` used to be a bespoke lane for one file, with its own reader and its own
   "skipped and reported" arm. Gone too: the record is the seventh single file, copied through
   the same screened lane as the scrub verdict (the other host-side sidecar), and the judge
   alone decides what its bytes mean. The tests here pin what the dissolved shape promises
   instead — one in-process value for both record fields, a named exit reason for a skipped
   forced close, and a parser strict as a whole.

Spec adversary (never sees the code, greens the committed suite with corner-cuts): its own
from-scratch build satisfied all 106 committed tests while leaving `run.py`'s ticket-lane call
site unwired (F1) and hardcoding the graded row's world label in `_grade_world`'s cut-short
reason string (F8) — the suite as committed cannot tell either apart from the honest answer.
Both were independently verified ALREADY CORRECT by reading in this implementation, but the
suite's own blind spot at those two sites is real, so both get a first-party regression test
here rather than resting on a one-time reading. (F2-F7, F9-F11 were checked the same way and
are genuinely absent from or pre-existing/out-of-scope for this implementation — see the PR
body's "Spec adversary" section; they are not repeated as tests because verifying them would
mean re-deriving the design's own forgery-universal machinery `test_1047_forgery_universals.py`
already owns, for exploits this code does not contain.)
"""
from __future__ import annotations

from defender.tests import _spec1047 as S
from defender.tests._spec791 import (
    SpecTail,
    drive_tail,
    loop_paths,
    plant_alert,
    satisfy_entrypoint_keys,
)


def _family():
    return S.mod("learning.judge.family")


def _archive():
    return S.mod("learning.branch.archive")


def _episode_with(tmp_path, worlds=("b",), **kw):
    base, _src = S.runs_base(tmp_path)
    ep = S.episode(tmp_path)
    return ep, {w: S.sibling_run_dir(base, w, **kw) for w in worlds}, base


def test_run_py_tail_takes_both_record_fields_off_the_summary(tmp_path, monkeypatch):
    """Both halves of the run-end record reach the ticket lane from ONE in-process value, the
    driver's summary — `closed_before_cut` is not read back off the sidecar. Driven with a
    summary that says the model had closed and NO sidecar on disk at all: a tail that read the
    second field off disk would hand the lane `False` and leave a ticket open over a verdict
    the run really produced."""
    monkeypatch.setenv("DEFENDER_LEARNING_STATE_DIR", str(tmp_path / "state"))
    satisfy_entrypoint_keys(monkeypatch, tmp_path)
    paths = loop_paths(tmp_path)

    from defender import run as run_py

    tail = SpecTail(paths, truncated_by="aborted", closed_before_cut=True)
    rc = drive_tail(run_py.main, plant_alert(tmp_path / "both"), tail, "--update-ticket")

    assert rc == 0
    assert tail.record_calls, "record_case_ticket was never called at all"
    assert not S.sidecar_path(tail.run_dirs[0]).exists(), (
        "the fixture wrote a sidecar, so nothing below is about the in-process value")
    assert tail.record_calls[0] == {"truncated_by": "aborted", "closed_before_cut": True}, (
        f"run.py's tail split the record between the summary and the disk: {tail.record_calls[0]!r}")


def test_a_failed_record_write_names_itself_in_the_exit_reason(tmp_path):
    """When the record write fails on a forced-close exit, the forced report is skipped
    (`test_a_failed_run_end_write_is_a_reason_not_to_write_the_forced_report`) — and the
    summary SAYS so, beside the real exit rather than in place of it: an ordinary
    `retry-exhausted` exit that should carry a report and mysteriously does not is exactly
    the shape this must not look like, and an exit reason that lost `UnexpectedModelBehavior`
    would be the same loss the other way round.

    Only when a forced report was OWED. A model that had already closed when the cut landed
    holds its own verdict; the record write failing beside it skips nothing, and its exit
    reason stays the ordinary one — the same early return `_close_a_run_cut_short` takes."""
    from defender.runtime import challenge_gate
    from defender.tests import _spec923

    deps, run_dir = _spec923.main_deps(tmp_path / "owed")
    S.sidecar_path(run_dir).mkdir(parents=True, exist_ok=True)
    _run, truncated_by, exit_reason = _spec923.drive_to_retry_exhaustion(deps)
    assert truncated_by == "retry-exhausted"
    assert exit_reason == "UnexpectedModelBehavior+RunEndRecordFailed", (
        f"a skipped forced close left the exit reason at {exit_reason!r}")

    closed_deps, closed_run = _spec923.main_deps(tmp_path / "closed")
    S.sidecar_path(closed_run).mkdir(parents=True, exist_ok=True)
    challenge_gate.ReviewState.of(closed_deps).closed = True
    _run, _t, closed_reason = _spec923.drive_to_retry_exhaustion(closed_deps)
    assert closed_reason == "UnexpectedModelBehavior", (
        f"a run that already held its verdict was told a forced close was skipped: "
        f"{closed_reason!r}")


def test_a_reused_run_id_does_not_inherit_the_previous_attempts_record(tmp_path, monkeypatch):
    """A run id whose dir was removed and reused (the operator's retry) starts with NO run-end
    record beside it: `materialize_run_dir` clears a stale sidecar host-side, before the box
    exists, so an attempt that ends before writing its own (a setup failure, an unhandled
    fault) cannot be archived under the previous attempt's exit class."""
    alert = tmp_path / "fixture.json"
    alert.write_text("{}\n", encoding="utf-8")
    runs_base = tmp_path / "runs"
    monkeypatch.setenv("DEFENDER_RUNS_BASE", str(runs_base))
    run_common = S.mod("run_common")

    run_dir = run_common.materialize_run_dir(alert, "case-1047-retry")
    S.plant_sidecar(run_dir, truncated_by="aborted")
    import shutil
    shutil.rmtree(run_dir)

    again = run_common.materialize_run_dir(alert, "case-1047-retry")

    assert again == run_dir
    assert not S.sidecar_path(again).exists(), (
        "the retry inherited the previous attempt's run-end record")


def test_re_archiving_a_world_whose_sidecar_is_gone_removes_the_stale_record(tmp_path):
    """A world archived once WITH a record and archived again without a sidecar ends with no
    `run_end.json` — the archive makes the destination agree with "a missing artifact means
    the run did not produce one", instead of leaving the earlier attempt's record for the
    judge to read as this run's. A plain file is removed; an alias at the name is still
    refused, never removed (D1)."""
    base, _src = S.runs_base(tmp_path)
    ep = S.episode(tmp_path)
    run_dir = S.sibling_run_dir(base, "b")
    archive = S.mod("learning.branch.archive")

    S.plant_sidecar(run_dir, truncated_by="aborted")
    archive.archive_episode(ep, {"b": run_dir})
    assert (ep / "worlds" / "b" / S.run_end_name()).is_file(), "the control did not archive"

    S.sidecar_path(run_dir).unlink()
    archive.archive_episode(ep, {"b": run_dir})
    assert not (ep / "worlds" / "b" / S.run_end_name()).exists(), (
        "a stale run-end record survived a re-archive whose run has none")
    assert S.graded(S.cut_short_episode(tmp_path / "control"))["b"].get("cut_short") is None


def test_parse_record_is_strict_as_a_whole():
    """`run_end.parse_record` reads exactly the shape the writer writes and nothing else: an
    unrecognized exit class or a non-boolean `closed_before_cut` is NOT a record, rather than
    folding to "not cut short" / "the model had closed" — a corrupted record must fail toward
    "the host said nothing", never toward a verdict."""
    run_end = S.mod("runtime.run_end")
    ok = run_end.parse_record({"truncated_by": "aborted", "closed_before_cut": False})
    assert ok == run_end.RunEnd("aborted", False)
    clean = run_end.parse_record({"truncated_by": None, "closed_before_cut": False})
    assert clean == run_end.RunEnd(None, False)
    assert run_end.parse_record(
        {"truncated_by": "aborted", "closed_before_cut": False, "verdict": "benign"}) == ok, (
        "an extra key changed the record")

    for doc in (
        {"truncated_by": "Aborted", "closed_before_cut": False},   # not a member
        {"truncated_by": "aborted", "closed_before_cut": "false"},  # a truthy string
        {"truncated_by": "aborted", "closed_before_cut": 1},        # not a bool
        {"truncated_by": "aborted"},                                # a field missing
        {"closed_before_cut": False},
        {}, [], None, "aborted",
    ):
        assert run_end.parse_record(doc) is None, f"{doc!r} was read as a record"


def test_run_py_tail_threads_the_exit_class_into_record_case_ticket(tmp_path, monkeypatch):
    """The spec adversary's F1: an implementation that satisfies all 106 committed
    `test_1047_*` tests while leaving `defender.run.main`'s `--update-ticket` call site on the
    OLD no-argument `record_case_ticket(run_dir)` shape ships undetected — every one of
    `test_1047_ticket_lane.py`'s 20 tests drives the real `record_case_ticket` directly, never
    through `run.py`'s tail, and `test_791_curation_boundary.py` only asserts the step was
    REACHED, never with what it was called with.

    Driven for real, through the tail's own injection seam (`SpecTail`, `drive_tail`) — the
    lifecycle fake reports `truncated_by="request-limit"`, exactly as a real cut-short
    investigation's summary would, and the assertion is on `SpecTail.record_calls`, the record
    the seam itself keeps of what it was handed."""
    monkeypatch.setenv("DEFENDER_LEARNING_STATE_DIR", str(tmp_path / "state"))
    satisfy_entrypoint_keys(monkeypatch, tmp_path)
    paths = loop_paths(tmp_path)

    from defender import run as run_py

    tail = SpecTail(paths, truncated_by="request-limit")
    rc = drive_tail(run_py.main, plant_alert(tmp_path / "f1"), tail, "--update-ticket")

    assert rc == 0
    assert tail.record_calls, "record_case_ticket was never called at all"
    assert tail.record_calls[0].get("truncated_by") == "request-limit", (
        f"run.py's tail did not thread the exit class through to record_case_ticket "
        f"(got {tail.record_calls[0]!r}) — the per-exit-class table in ticket_writer.py is "
        "unreachable in production if this call site still uses the old no-argument shape")


def test_cut_short_reason_names_the_actual_world_not_a_hardcoded_label(tmp_path):
    """The spec adversary's F8: `_grade_world`'s cut-short reason string is only ever asserted
    for a world literally named `b` anywhere in the committed suite, so an implementation that
    hardcodes `"world 'b': ..."` instead of interpolating the real label satisfies every one of
    them. Driven on world `c` specifically to catch that substitution."""
    ep = S.cut_short_episode(tmp_path, cut={"c": "aborted"})

    rows = S.graded(ep)

    assert rows["c"]["ungradable_reason"].startswith("world 'c'"), (
        f"the reason names the wrong world: {rows['c']['ungradable_reason']!r}")
