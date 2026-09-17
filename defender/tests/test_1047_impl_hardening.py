"""#1047 implementation hardening — defects found by the two adversaries the write-code-from-
spec skill runs against the honest implementation (never against the committed spec), fixed
here with their own regression pins.

None of this is about O1-O3: the committed `test_1047_*.py` files pin the design; this file
pins that the code does what it (now, correctly) claims about itself, and that a handful of
corner-cuts the spec adversary's own from-scratch reimplementation found live are absent from
THIS implementation.

Claims adversary (reads only the code, falsifies its docstrings):

1. `read_world_facts` used to re-derive `run_end.json`'s content even when `_grade_world`'s
   early check had already read it — a second parse of the same file per graded world, and the
   `WorldFacts.cut_short` docstring's "the ONE read... shared" claim was false. Fixed by
   threading the already-known value through a `run_end=` parameter every other caller leaves
   unset.
2. `_archive_run_end`'s docstring claimed a sidecar that exists but cannot be read as a record
   is "SKIPPED AND REPORTED" — matching what `test_1047_archive_record.py`'s own
   `test_an_unreadable_sidecar_is_skipped_and_reported_rather_than_archived` says in its name —
   but nothing was ever printed; only the "skipped" half held. Fixed by reporting to stderr
   exactly when something occupies the sidecar's name and cannot be read (never for a genuinely
   absent sidecar, which stays silent like the six pre-existing single-file artifacts).

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


def test_read_world_facts_trusts_a_precomputed_run_end_value(tmp_path):
    """`read_world_facts(..., run_end=(...))` uses the caller's value instead of re-reading
    `run_end.json` itself.

    Proven by making a fresh read give a DIFFERENT answer than the one passed in: a directory
    occupies the sidecar's archived name, which `_read_run_end_record` folds to `(None,
    False)` — so if `read_world_facts` ignored `run_end=` and re-derived the value itself,
    `facts.cut_short` would come back `None` instead of the `"aborted"` that was passed in.

    Without the `run_end=` parameter at all (pre-fix), this call raises `TypeError` for an
    unexpected keyword argument — the fix is what makes the call possible in the first place."""
    family = _family()
    ep = S.accepted_episode(tmp_path, ledgers={"b": [S.staged_row("b")], "c": []})
    world_dir = ep / "worlds" / "b"
    (world_dir / S.run_end_name()).mkdir(parents=True, exist_ok=True)

    facts = family.read_world_facts(ep, "b", episode_token=S.EPISODE_TOKEN,
                                     run_end=("aborted", True))

    assert facts.cut_short == "aborted", (
        "read_world_facts re-derived run_end.json itself instead of trusting the caller's "
        "already-known value — the file at that name (a directory) would read back as "
        "cut_short=None if it had actually been re-parsed")


def test_read_world_facts_still_reads_it_itself_when_no_value_is_passed(tmp_path):
    """The default path — every caller other than `_grade_world` (render.py, the rest of the
    suite) — is unchanged: with no `run_end=`, the function reads the archived record itself."""
    family = _family()
    ep = S.accepted_episode(tmp_path, ledgers={"b": [S.staged_row("b")], "c": []})
    S.plant_archived_record(ep, "b", truncated_by="request-limit")

    facts = family.read_world_facts(ep, "b", episode_token=S.EPISODE_TOKEN)

    assert facts.cut_short == "request-limit"


def test_archive_reports_a_sidecar_that_exists_but_cannot_be_read(tmp_path, capsys):
    """A sidecar that occupies its name but cannot be read as a record — empty, torn JSON, a
    JSON list, or a directory, the same four shapes
    `test_an_unreadable_sidecar_is_skipped_and_reported_rather_than_archived` drives — now
    actually reaches stderr, closing the gap between that test's name and what it checked (it
    only ever asserted the "skipped" half)."""
    for name, raw in (("empty", ""), ("torn", '{"truncated_by": "abor'),
                      ("list", '[{"truncated_by": "aborted"}]')):
        ep, dirs, _base = _episode_with(tmp_path / name)
        S.plant_sidecar(dirs["b"], raw=raw)
        capsys.readouterr()
        _archive().archive_episode(ep, dirs)
        err = capsys.readouterr().err
        assert "run-end record" in err, f"{name}: an occupied, unreadable sidecar went unreported"

    ep, dirs, _base = _episode_with(tmp_path / "dir")
    S.sidecar_path(dirs["b"]).mkdir(parents=True, exist_ok=True)
    capsys.readouterr()
    _archive().archive_episode(ep, dirs)
    err = capsys.readouterr().err
    assert "run-end record" in err, "a directory squatting the sidecar's name went unreported"


def test_archive_stays_silent_when_the_sidecar_is_simply_absent(tmp_path, capsys):
    """A run dir with NO sidecar at all — the ordinary case for a run that was not cut short,
    or an archive that predates #1047 — is not a refusal and gets no message, exactly like an
    absent optional artifact among the six pre-existing `_single_files` roles."""
    ep, dirs, _base = _episode_with(tmp_path)
    capsys.readouterr()

    _archive().archive_episode(ep, dirs)

    err = capsys.readouterr().err
    assert "run-end record" not in err, "a plainly absent sidecar was reported as though occupied"


def test_run_py_tail_threads_the_exit_class_into_close_case_ticket(tmp_path, monkeypatch):
    """The spec adversary's F1: an implementation that satisfies all 106 committed
    `test_1047_*` tests while leaving `defender.run.main`'s `--update-ticket` call site on the
    OLD no-argument `close_case_ticket(run_dir)` shape ships undetected — every one of
    `test_1047_ticket_lane.py`'s 20 tests drives the real `close_case_ticket` directly, never
    through `run.py`'s tail, and `test_791_curation_boundary.py` only asserts the step was
    REACHED, never with what it was called with.

    Driven for real, through the tail's own injection seam (`SpecTail`, `drive_tail`) — the
    lifecycle fake reports `truncated_by="request-limit"`, exactly as a real cut-short
    investigation's summary would, and the assertion is on `SpecTail.close_calls`, the record
    the seam itself keeps of what it was handed."""
    monkeypatch.setenv("DEFENDER_LEARNING_STATE_DIR", str(tmp_path / "state"))
    satisfy_entrypoint_keys(monkeypatch, tmp_path)
    paths = loop_paths(tmp_path)

    from defender import run as run_py

    tail = SpecTail(paths, truncated_by="request-limit")
    rc = drive_tail(run_py.main, plant_alert(tmp_path / "f1"), tail, "--update-ticket")

    assert rc == 0
    assert tail.close_calls, "close_case_ticket was never called at all"
    assert tail.close_calls[0].get("truncated_by") == "request-limit", (
        f"run.py's tail did not thread the exit class through to close_case_ticket "
        f"(got {tail.close_calls[0]!r}) — the per-exit-class table in ticket_writer.py is "
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
