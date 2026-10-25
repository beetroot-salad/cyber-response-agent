from __future__ import annotations

from defender.tests.support.shared._locations_1210 import location_path

from defender.tests.support.learning.branch import _triplet_947 as T

from defender.episodes._episode_handle import Episode
from defender.tests.support.shared.filesystem import _spec1047 as S
from defender.tests.support.sandbox._spec791 import (
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
    base, _src = location_path(S.runs_base)(tmp_path)
    ep = S.episode(tmp_path)
    return ep, {w: S.sibling_run_dir(base, w, **kw) for w in worlds}, base


def test_run_py_tail_takes_both_record_fields_off_the_summary(tmp_path, monkeypatch):
    """Both halves of the run-end record reach the ticket lane from ONE in-process value, the
    driver's summary — `closed_before_cut` is not read back off the sidecar."""
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
    from defender.runtime import challenge_gate
    from defender.tests.support.runtime.engine import _spec923

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


def test_re_archiving_a_world_whose_sidecar_is_gone_removes_the_stale_record(tmp_path):
    base, _src = location_path(S.runs_base)(tmp_path)
    ep = S.episode(tmp_path)
    run_dir = S.sibling_run_dir(base, "b")
    archive = S.mod("learning.branch.archive")

    S.plant_sidecar(run_dir, truncated_by="aborted")
    with Episode.open(ep) as episode:
        archive.archive_episode(episode, {T.world_id(episode.dir, 'b'): run_dir})
        assert (ep / "worlds" / T.world_id(ep, "b") / S.run_end_name()).is_file(), "the control did not archive"

        S.sidecar_path(run_dir).unlink()
        archive.archive_episode(episode, {T.world_id(episode.dir, 'b'): run_dir})
    assert not (ep / "worlds" / T.world_id(ep, "b") / S.run_end_name()).exists(), (
        "a stale run-end record survived a re-archive whose run has none")
    assert S.graded(S.cut_short_episode(tmp_path / "control"))["b"].get("cut_short") is None


def test_parse_record_is_strict_as_a_whole():
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
    ep = S.cut_short_episode(tmp_path, cut={"c": "aborted"})

    rows = S.graded(ep)

    assert rows["c"]["ungradable_reason"].startswith("world 'c'"), (
        f"the reason names the wrong world: {rows['c']['ungradable_reason']!r}")
