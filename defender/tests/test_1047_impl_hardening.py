"""#1047 implementation hardening — two defects the claims adversary found in the honest
implementation itself (not in the committed spec), fixed here with their own regression pins.

Both are about the code's own claims about itself, not about O1-O3: the committed
`test_1047_*.py` files pin the design; this file pins that the code does what its own
docstrings, once corrected, now say.

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
"""
from __future__ import annotations

from defender.tests import _spec1047 as S


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
