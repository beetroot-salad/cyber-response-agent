"""A run records the commit it was made against (#976).

Against real throwaway repos rather than a faked git runner — git is local and deterministic,
so the facade is exercised for real (the #389 / #460 philosophy, as `test_git.py` states it).

The property under test is not "a field exists". It is that the record cannot quietly say
something FALSE: an unknown never reads as clean, a capped path sample never hides the true
count, and a run whose tree could not be interrogated at all still runs.
"""
from __future__ import annotations

import json
import os
from dataclasses import fields
from pathlib import Path

import pytest

from defender import _git, _provenance  # type: ignore[import-not-found]
from defender._provenance import RunProvenance  # type: ignore[import-not-found]
from defender._run_paths import PROVENANCE, RunPaths  # type: ignore[import-not-found]
from defender.tests._repo import seed_repo  # type: ignore[import-not-found]


#: The seeded file's path, spelled once: every dirt arm below edits, removes or renames it, and
#: it has to sit under `CODE_SCOPE` for the scoped bit to see it at all.
SEED = f"{_provenance.CODE_SCOPE}/seed.md"


def _repo(tmp_path: Path) -> Path:
    """A throwaway repo with one commit, through `_repo.seed_repo` rather than a fifteenth
    hand-rolled `git init` — that module exists because the same five lines had drifted across
    fourteen sites under five different placeholder identities."""
    repo = tmp_path / "repo"
    (repo / _provenance.CODE_SCOPE).mkdir(parents=True)
    # SEEDED INSIDE THE SCOPE `dirty` speaks for. A file at the repo root would be invisible to
    # every dirt arm below now that the bit is scoped to the code the box mounts, and the arms
    # would pass while measuring nothing.
    (repo / SEED).write_text("seed\n", encoding="utf-8")
    return seed_repo(repo)


def test_clean_tree_records_the_head_sha_and_no_dirt(tmp_path):
    repo = _repo(tmp_path)
    prov = _provenance.capture_tree(repo)
    assert prov.commit == _git.git_head_sha(repo)
    assert prov.dirty is False
    assert prov.dirty_paths == ()
    assert prov.dirty_path_count == 0
    assert prov.unavailable is None


def test_uncommitted_edit_is_recorded_as_dirty_with_the_path(tmp_path):
    repo = _repo(tmp_path)
    (repo / SEED).write_text("edited\n")
    prov = _provenance.capture_tree(repo)
    assert prov.dirty is True
    assert SEED in prov.dirty_paths
    assert prov.dirty_path_count == 1


def test_untracked_file_counts_as_dirty(tmp_path):
    """`--untracked-files=all`: a file nobody added is still a file the sha does not name, so
    a stamp that called this tree clean would be describing bytes that did not run."""
    repo = _repo(tmp_path)
    (repo / _provenance.CODE_SCOPE / "stray.md").write_text("stray\n")
    prov = _provenance.capture_tree(repo)
    assert prov.dirty is True
    assert f"{_provenance.CODE_SCOPE}/stray.md" in prov.dirty_paths


def test_the_path_sample_is_capped_but_the_count_is_not(tmp_path):
    """The cap costs DETAIL and must never cost the FACT — a reader can still tell a small
    edit from a huge one, which is exactly what a silent truncation would hide."""
    repo = _repo(tmp_path)
    total = _provenance.DIRTY_PATH_SAMPLE + 7
    for i in range(total):
        (repo / _provenance.CODE_SCOPE / f"stray-{i:03d}.md").write_text("x\n")
    prov = _provenance.capture_tree(repo)
    assert len(prov.dirty_paths) == _provenance.DIRTY_PATH_SAMPLE
    assert prov.dirty_path_count == total


def test_a_tree_git_cannot_answer_for_records_unknown_not_clean(tmp_path):
    """THE ONE ERROR THIS RECORD MUST NOT MAKE. A directory that is not a repository has no
    sha, and `dirty` stays `None` — collapsing it to `False` would file an unknown as a clean
    bill of health, which every downstream consumer reads as "the sha names the bytes"."""
    plain = tmp_path / "not-a-repo"
    plain.mkdir()
    prov = _provenance.capture_tree(plain)
    assert prov.commit is None
    assert prov.dirty is None
    assert prov.dirty is not False
    assert prov.unavailable is not None


def test_an_unborn_head_is_reported_with_its_reason(tmp_path):
    """A freshly-`init`ed tree has no HEAD to name. It is a different operator problem from
    "git is not installed", so the reason is kept rather than flattened to a bare `None`."""
    repo = tmp_path / "fresh"
    repo.mkdir()
    _git.git(["init", "-q", "-b", "main"], cwd=repo)
    prov = _provenance.capture_tree(repo)
    assert prov.commit is None
    assert prov.dirty is None
    assert prov.unavailable


def test_capture_never_raises_when_git_is_not_on_path(tmp_path, monkeypatch):
    """A run that cannot be stamped still has to run: this is a record, not a gate.

    Driven by emptying PATH rather than by patching the facade, so the exception is the REAL
    one this arm exists for: with no `git` to resolve, `subprocess` raises before git can
    report anything, so it is not a `GitError` and would otherwise escape as an unhandled
    OSError out of run-dir creation — the one shape a `GitError`-only handler misses."""
    repo = _repo(tmp_path)
    monkeypatch.setenv("PATH", str(tmp_path / "empty-bin"))
    prov = _provenance.capture_tree(repo)
    assert prov.commit is None
    assert prov.dirty is None
    assert prov.unavailable is not None
    assert "unavailable" in prov.unavailable


def test_status_failing_after_a_good_sha_keeps_the_sha_and_unknowns_the_dirt(tmp_path):
    """The sha is worth keeping on its own; what is unknown is whether it describes the bytes
    that ran, and `dirty=None` is exactly that statement rather than a discarded record.

    A corrupted index is a REAL split between the two calls rather than an authored one:
    `rev-parse HEAD` reads refs and still answers, while `status` must read the index and
    cannot. Nothing else in this module can produce that asymmetry honestly."""
    repo = _repo(tmp_path)
    head = _git.git_head_sha(repo)
    (repo / ".git" / "index").write_bytes(b"\x00 not an index \xff" * 8)
    prov = _provenance.capture_tree(repo)
    assert prov.commit == head, "a readable HEAD was discarded because the index was not"
    assert prov.dirty is None
    assert prov.unavailable


def test_round_trips_through_disk(tmp_path):
    prov = RunProvenance(
        commit="a" * 40, dirty=True, dirty_paths=("x.md",), dirty_path_count=1
    )
    path = tmp_path / "provenance.json"
    _provenance.write(path, prov)
    assert _provenance.read(path) == prov


def test_a_missing_or_junk_stamp_reads_as_no_stamp(tmp_path):
    """This file sits in the box's rw bind, so a reader must treat whatever is there as
    arbitrary and answer "no usable record" rather than raise out of an archive walk."""
    assert _provenance.read(tmp_path / "absent.json") is None
    junk = tmp_path / "junk.json"
    junk.write_text("not json{")
    assert _provenance.read(junk) is None
    listy = tmp_path / "listy.json"
    listy.write_text(json.dumps(["not", "a", "record"]))
    assert _provenance.read(listy) is None
    wrong_type = tmp_path / "wrong.json"
    wrong_type.write_text(json.dumps({"commit": 17, "dirty": False}))
    assert _provenance.read(wrong_type) is None


def test_a_bool_is_not_accepted_as_the_path_count(tmp_path):
    """`isinstance(True, int)` is True in Python, so a `dirty_path_count` of `true` would
    otherwise be read back as the number 1 — a count nobody wrote."""
    path = tmp_path / "p.json"
    path.write_text(json.dumps({"commit": "a" * 40, "dirty": True, "dirty_path_count": True}))
    rec = _provenance.read(path)
    assert rec is not None
    assert rec.dirty_path_count == 0


def test_materialize_run_dir_stamps_every_run(tmp_path, monkeypatch):
    """Stamped at the ONE place a run the box will EXECUTE is materialised, so no caller can
    forget — the branch launcher materialises its siblings through this same call, which is
    what makes a family's worlds comparable on their code rather than merely assumed to be.
    (The learning loop's ARCHIVED bundle is built elsewhere and carries no stamp — see
    `run_common.materialize_run_dir`, which names that gap where a reader will meet it.)"""
    from defender import run_common

    runs = tmp_path / "runs"
    runs.mkdir()
    monkeypatch.setenv("DEFENDER_RUNS_BASE", str(runs))
    alert = tmp_path / "alert.json"
    alert.write_text(json.dumps({"id": "a1"}))

    run_dir = run_common.materialize_run_dir(alert, "20260101T000000Z-a1")
    stamp = RunPaths(run_dir).provenance
    assert stamp.is_file()
    rec = _provenance.read(stamp)
    assert rec is not None
    # The suite runs inside this repo, so the capture is a real one: a sha, or an explicit
    # reason there is none. What it must never be is silence.
    assert rec.commit is not None or rec.unavailable is not None


def test_the_stamp_is_not_named_in_the_model_facing_map(tmp_path):
    """The map IS the model's directory view. The run's record of its own build is
    infrastructure the operator reads, not a surface the investigator should reason about."""
    from defender.scripts import workspace_map

    # `PROVENANCE`, not the literal, on BOTH sides: a test that spells the filename itself
    # agrees with a stale suppression rather than with the accessor, which is the one way this
    # assertion could pass while the stamp was back in the model's view under its new name.
    assert PROVENANCE in workspace_map._UNLISTED
    run_dir = tmp_path / "run"
    paths = RunPaths(run_dir)
    paths.gather_raw.mkdir(parents=True)
    _provenance.write(paths.provenance, RunProvenance(commit="a" * 40, dirty=False))
    assert paths.provenance.name not in workspace_map.workspace_map(run_dir)


@pytest.mark.parametrize("dirty", [True, False, None])
def test_the_three_valued_dirt_survives_the_round_trip(tmp_path, dirty):
    """`None` must come back as `None`. A JSON round trip that folded it to `false` would
    reintroduce the exact lie the three-valued field exists to prevent."""
    path = tmp_path / "p.json"
    _provenance.write(path, RunProvenance(commit="a" * 40, dirty=dirty))
    rec = _provenance.read(path)
    assert rec is not None, "the round trip lost the record entirely"
    assert rec.dirty is dirty


def test_a_git_that_cannot_be_EXECUTED_is_recorded_rather_than_raised(tmp_path, monkeypatch):
    """The failure an absent-binary arm does NOT cover.

    A `git` that resolves and cannot be exec'd raises a BARE `OSError` (ENOEXEC) — not
    `FileNotFoundError`, not a `SubprocessError` — and so do the fork/pipe failures a loaded
    host produces (ENOMEM, EMFILE). A handler that names three OSError subclasses lets every
    one of them out of `materialize_run_dir`, which turns a record into a hard startup crash
    that also leaves a half-built run dir behind and wedges the run id."""
    repo = _repo(tmp_path)
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    broken = fake_bin / "git"
    broken.write_text("this is not a program\n", encoding="utf-8")
    broken.chmod(0o755)
    monkeypatch.setenv("PATH", str(fake_bin))

    prov = _provenance.capture_tree(repo)
    assert prov.commit is None
    assert prov.dirty is None
    assert prov.unavailable


def test_a_stamp_that_is_a_planted_link_reads_as_no_stamp(tmp_path):
    """The read-side twin of the refusal `write` already makes. This file sits in the box's rw
    bind, so an entry at its name may be a link the model planted — and following it would hand
    back whatever it points at AS this run's record of what it ran against."""
    real = tmp_path / "elsewhere.json"
    _provenance.write(real, RunProvenance(commit="b" * 40, dirty=False))
    planted = tmp_path / PROVENANCE
    planted.symlink_to(real)
    assert _provenance.read(planted) is None


def test_a_deeply_nested_payload_reads_as_no_stamp(tmp_path):
    """`json.loads` raises `RecursionError` on deep nesting, and it is not a `ValueError` — the
    omission `learning/branch/capture.py` already paid for once, where one such row escaped
    every frame and killed the episode."""
    path = tmp_path / PROVENANCE
    path.write_text("[" * 200_000 + "]" * 200_000, encoding="utf-8")
    assert _provenance.read(path) is None


@pytest.mark.parametrize(
    "doc",
    [
        {},
        {"commit": None, "dirty": None},
        {"commit": None, "dirty": False},
        # `dirty is True` with no sha is no more producible than `dirty is False` with none —
        # the guard is the RULE ("no answer about the dirt without a commit behind it"), not
        # the one shape of it that is scariest. Admitting this one also printed an announce
        # line reading `commit=unavailable (None)`.
        {"commit": None, "dirty": True},
        # `isinstance("", str)` is True, so an EMPTY sha walks past a `commit is None` guard
        # and lands as the clean bill of health with nothing behind it — the identical error,
        # spelled with a string instead of a null, and `[run.py] commit=` on the operator's
        # line.
        {"commit": "", "dirty": False},
        {"commit": "", "dirty": None},
    ],
)
def test_a_record_capture_cannot_produce_is_not_a_record(tmp_path, doc):
    """Type-checking each field alone is not enough. An object saying NOTHING would otherwise
    answer "this run carries a stamp" to a caller whose only question is whether one exists,
    and an answer about the dirt with no sha behind it is the clean bill of health with nothing
    behind it — the one error the record must not make. Every `commit is None` path in
    `capture_tree` leaves `dirty` at `None` and sets a reason."""
    path = tmp_path / PROVENANCE
    path.write_text(json.dumps(doc), encoding="utf-8")
    assert _provenance.read(path) is None


@pytest.mark.parametrize(
    ("rec", "expected"),
    [
        (None, "commit=unrecorded"),
        (RunProvenance(commit=None, dirty=None, unavailable="git: no"), "commit=unavailable"),
        (RunProvenance(commit="a" * 40, dirty=False), "commit=aaaaaaaaaaaa"),
        (
            RunProvenance(commit="a" * 40, dirty=True, dirty_paths=("x",), dirty_path_count=3),
            "+dirty (3 paths)",
        ),
        (
            RunProvenance(commit="a" * 40, dirty=None, unavailable="git status: broken index"),
            "+dirt-unknown (git status: broken index)",
        ),
        # A corrupted count read back as its default must not become a QUANTITY on the line.
        (RunProvenance(commit="a" * 40, dirty=True, dirty_path_count=0), "+dirty"),
    ],
)
def test_the_announce_line_says_what_the_record_says(tmp_path, capsys, rec, expected):
    """The stamp's one consumer on the day it lands, and the line an operator actually reads.

    Every branch is pinned because each is a different CLAIM: no stamp, no sha, a clean sha, a
    dirty sha with its size, and the three-valued middle — git answered for HEAD and then could
    not answer for the tree — which must read as neither clean nor dirty and must carry the
    reason."""
    from defender import run  # noqa: PLC0415 — run.py re-execs into the venv at import

    run_dir = tmp_path / "run"
    run_dir.mkdir()
    if rec is not None:
        _provenance.write(RunPaths(run_dir).provenance, rec)

    run._announce_provenance(run_dir)

    line = capsys.readouterr().err
    assert expected in line, line
    if rec is not None and rec.dirty is False:
        assert "dirty" not in line, "a clean tree was marked"
    if rec is not None and rec.dirty is True and not rec.dirty_path_count:
        assert "paths" not in line, "a count nobody wrote reached the operator's line"


def test_every_field_reaches_the_wire_and_comes_back(tmp_path):
    """`as_json` spells the wire shape out, which makes it a SECOND census of the class's
    fields — so this arm derives the expected set from `dataclasses.fields` rather than from a
    list typed here. Without it, a sixth field is silently dropped by the writer and defaulted
    by `from_obj`, and the round-trip arms above keep passing on the five they do spell: a
    stamp claiming a completeness it does not have, which for a provenance record is the whole
    failure mode."""
    declared = {f.name for f in fields(RunProvenance)}
    on_disk = json.loads(RunProvenance(commit="a" * 40, dirty=False).as_json())
    assert set(on_disk) == declared, (
        f"the wire shape and the record's fields disagree: {declared ^ set(on_disk)}"
    )
    rich = RunProvenance(
        commit="a" * 40, dirty=True, dirty_paths=("x.md", "y.md"), dirty_path_count=2,
        unavailable=None,
    )
    path = tmp_path / PROVENANCE
    _provenance.write(path, rich)
    assert _provenance.read(path) == rich


def test_a_rename_counts_both_paths_the_sha_fails_to_name(tmp_path):
    """The count must not UNDER-report, which is the direction that would be a lie.

    With rename detection on, `git mv a b` is a single `R  b` record whose original `a` rides
    as the record's trailing field — which `_git.git_status` consumes and drops — so two paths
    that differ from HEAD are counted once and the vanished one is named nowhere. `capture_tree`
    asks with `no_renames=True` so the same move reports `D  a` + `A  b`."""
    repo = _repo(tmp_path)
    (repo / _provenance.CODE_SCOPE / "moved.md").write_text("moved\n", encoding="utf-8")
    _git.git(["add", "-A"], cwd=repo)
    _git.git(["commit", "-qm", "add"], cwd=repo)
    scope = _provenance.CODE_SCOPE
    _git.git(["mv", f"{scope}/moved.md", f"{scope}/elsewhere.md"], cwd=repo)

    prov = _provenance.capture_tree(repo)
    assert prov.dirty is True
    assert set(prov.dirty_paths) == {
        f"{scope}/moved.md", f"{scope}/elsewhere.md",
    }, prov.dirty_paths
    assert prov.dirty_path_count == 2, "a rename hid the path the sha no longer names"


def test_one_dirty_path_earning_two_status_records_is_counted_once(tmp_path):
    """`git status -z` emits one record per (path, reason) and a single path can earn two:
    `git rm --cached foo` leaves `D  foo` AND `?? foo`. Counting records would overstate the
    dirt — in exactly the direction `DIRTY_PATH_SAMPLE`'s comment promises the count never
    does — and would spend two of the sample's 50 slots on one file."""
    repo = _repo(tmp_path)
    _git.git(["rm", "--cached", "-q", SEED], cwd=repo)

    prov = _provenance.capture_tree(repo)
    assert prov.dirty is True
    assert prov.dirty_paths == (SEED,), prov.dirty_paths
    assert prov.dirty_path_count == 1, "one dirty path was counted once per status record"


# --------------------------------------------------------------------------- #
# The scoped dirt, the build stamp, the non-fatal write, the shared family
# capture, the archive copy, and the read gate (#976 follow-ups).
# --------------------------------------------------------------------------- #


def test_dirt_is_scoped_to_the_code_the_box_mounts(tmp_path):
    """A scratch file outside the mounted package must not mark the run dirty.

    The bit exists for ONE consumer — the refusal a fork or an archive makes — and a bit that
    a note in `docs/` sets is True on a working machine nearly always, so that consumer would
    either refuse everything or learn to ignore it."""
    repo = _repo(tmp_path)
    (repo / "docs").mkdir()
    (repo / "docs" / "note.md").write_text("scratch\n")
    (repo / "experiments").mkdir()
    (repo / "experiments" / "x.py").write_text("x\n")
    prov = _provenance.capture_tree(repo)
    assert prov.dirty is False, f"an out-of-scope edit set the bit: {prov.dirty_paths}"
    assert prov.scope == _provenance.CODE_SCOPE


def test_dirt_inside_the_mounted_code_still_counts(tmp_path):
    repo = _repo(tmp_path)
    (repo / _provenance.CODE_SCOPE / "thing.py").write_text("x\n")
    prov = _provenance.capture_tree(repo)
    assert prov.dirty is True
    assert prov.dirty_paths == (f"{_provenance.CODE_SCOPE}/thing.py",)


def test_the_scope_travels_in_the_record(tmp_path):
    """Recorded rather than assumed: the day the scope changes, every already-archived stamp
    starts meaning something different, and a recomputed episode has no other way to know
    which of the two it is holding."""
    repo = _repo(tmp_path)
    path = tmp_path / "p.json"
    _provenance.write(path, _provenance.capture_tree(repo))
    assert json.loads(path.read_text())["scope"] == _provenance.CODE_SCOPE
    assert _provenance.read(path).scope == _provenance.CODE_SCOPE


def test_a_stamp_written_before_the_scope_field_still_reads(tmp_path):
    """A record with no scope is a real record of a real run. Refusing it would make every
    already-archived episode unreadable to settle a question about a field it never carried."""
    path = tmp_path / "old.json"
    path.write_text(json.dumps({"commit": "a" * 40, "dirty": False}))
    rec = _provenance.read(path)
    assert rec is not None
    assert rec.scope is None


def test_the_build_stamp_answers_when_git_cannot(tmp_path, monkeypatch):
    """The shipped runtime image carries neither git nor repository metadata, so without this
    every containerised run files `unavailable` while carrying a file that LOOKS like the drift
    problem was solved."""
    plain = tmp_path / "no-repo"
    plain.mkdir()
    monkeypatch.setenv("PATH", str(tmp_path / "empty-bin"))
    prov = _provenance.capture_tree(plain, environ={_provenance.BUILD_COMMIT_ENV: "b" * 40})
    assert prov.commit == "b" * 40
    assert prov.unavailable is not None
    assert _provenance.BUILD_COMMIT_ENV in prov.unavailable


def test_the_build_stamp_never_claims_a_clean_tree(tmp_path, monkeypatch):
    """THE POINT OF THE FALLBACK'S RESTRAINT. The image documents mounting a workspace over
    its baked code, so nothing at runtime can confirm the bytes on disk are the bytes built —
    a fallback that answered `False` would invent the one assurance this record refuses to."""
    plain = tmp_path / "no-repo"
    plain.mkdir()
    monkeypatch.setenv("PATH", str(tmp_path / "empty-bin"))
    prov = _provenance.capture_tree(plain, environ={_provenance.BUILD_COMMIT_ENV: "c" * 40})
    assert prov.dirty is None
    assert prov.dirty is not False


def test_an_empty_build_stamp_is_no_stamp(tmp_path, monkeypatch):
    plain = tmp_path / "no-repo"
    plain.mkdir()
    monkeypatch.setenv("PATH", str(tmp_path / "empty-bin"))
    for value in ("", "   "):
        prov = _provenance.capture_tree(plain, environ={_provenance.BUILD_COMMIT_ENV: value})
        assert prov.commit is None, f"{value!r} was read as a commit"


def test_a_live_sha_is_never_replaced_by_a_stale_baked_one(tmp_path):
    """Git answered for HEAD; only the working-tree question failed. Falling back here would
    swap a true sha for whatever an image was built from months ago."""
    repo = _repo(tmp_path)
    head = _git.git_head_sha(repo)
    (repo / ".git" / "index").write_bytes(b"\x00 not an index \xff" * 8)
    prov = _provenance.capture_tree(repo, environ={_provenance.BUILD_COMMIT_ENV: "d" * 40})
    assert prov.commit == head
    assert prov.dirty is None


def test_a_read_refuses_a_hard_link_the_write_would_refuse(tmp_path):
    """The two guards are twins by CONSTRUCTION now, not by a comment. The old screen was an
    `S_ISREG` lstat, which accepts a hard link — the one alias shape `O_NOFOLLOW` cannot
    refuse, and therefore the one the write side goes out of its way to catch."""
    real = tmp_path / "real.json"
    _provenance.write(real, RunProvenance(commit="a" * 40, dirty=False))
    link = tmp_path / "provenance.json"
    os.link(real, link)
    assert _provenance.read(link) is None, "a hard-linked stamp was read as this run's own"
    # EMLINK, not ELOOP: `_io._refuse_unless_plain` distinguishes the two alias shapes by
    # errno because `O_NOFOLLOW` never fires for a hard link, so ELOOP would name a cause a
    # hard-link plant cannot produce.
    with pytest.raises(OSError, match="aliased entry"):
        _provenance.write(link, RunProvenance(commit="b" * 40, dirty=False))


def test_a_stamp_that_cannot_be_written_does_not_take_the_run_down(tmp_path, monkeypatch, capsys):
    """`capture_tree` goes to some length never to raise; a write that raised beside it would
    hand that promise back. Worse, it arrives AFTER the run dir exists, so an escaping OSError
    burns the run id — the retry an operator reaches for is refused forever."""
    from defender import run_common

    runs = tmp_path / "runs"
    runs.mkdir()
    monkeypatch.setenv("DEFENDER_RUNS_BASE", str(runs))
    alert = tmp_path / "alert.json"
    alert.write_text(json.dumps({"id": "a1"}))
    # A real failure, not an authored exception: a DIRECTORY at the stamp's name is one of the
    # shapes `write_guarded` refuses, and it is the shape a previous crashed run can leave.
    run_id = "20260101T000000Z-wedge"
    (runs / run_id).mkdir()
    (runs / run_id / PROVENANCE).mkdir()

    def _materialize():
        # `materialize_run_dir` refuses an existing dir, so drive `_stamp` directly — it is the
        # seam that owns the promise, and the arm is about the promise rather than the caller.
        run_common._stamp(runs / run_id / PROVENANCE, None)

    _materialize()
    assert "could not stamp" in capsys.readouterr().err


def test_a_family_shares_one_capture(tmp_path, monkeypatch):
    """Hoisted above the loop: taken per world, a commit landing mid-launch gives siblings
    different records, and the family would differ in its code as well as in the axis the
    questioner declared — the very thing the stamp exists to make noticeable."""
    from defender import run_common

    runs = tmp_path / "runs"
    runs.mkdir()
    monkeypatch.setenv("DEFENDER_RUNS_BASE", str(runs))
    alert = tmp_path / "alert.json"
    alert.write_text(json.dumps({"id": "a1"}))
    shared = RunProvenance(commit="e" * 40, dirty=False, scope=_provenance.CODE_SCOPE)
    stamps = []
    for world in ("a", "b", "c"):
        run_dir = run_common.materialize_run_dir(
            alert, f"20260101T000000Z-{world}", provenance=shared
        )
        stamps.append(_provenance.read(RunPaths(run_dir).provenance))
    assert stamps == [shared, shared, shared]
    assert len({s.commit for s in stamps}) == 1


def test_without_a_shared_capture_each_run_takes_its_own(tmp_path, monkeypatch):
    """The default is unchanged for every other caller — the keyword only lets a launcher that
    HAS a family answer once for all of it."""
    from defender import run_common

    runs = tmp_path / "runs"
    runs.mkdir()
    monkeypatch.setenv("DEFENDER_RUNS_BASE", str(runs))
    alert = tmp_path / "alert.json"
    alert.write_text(json.dumps({"id": "a1"}))
    run_dir = run_common.materialize_run_dir(alert, "20260101T000000Z-solo")
    rec = _provenance.read(RunPaths(run_dir).provenance)
    assert rec is not None
    assert rec.commit is not None or rec.unavailable is not None
