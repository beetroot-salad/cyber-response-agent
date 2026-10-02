"""#1134 curator step (v3, ported from v2), through the drain entry point: a planted entry at a
lesson name is never
deleted, never read through and never written through by the curator tick; O5.3's routing holds;
and a snapshot the tick cannot take stops the tick before the agent.

Every scene is `_spec773.build_scene` driven through `drain.run_batch(cfg=...)`, the one batch
body both channels reach: real repo, real queue, real gate, rotation and commit; only the curator,
repair and verifier model calls are fakes, entering through the config's seams. The config is the
real builder's over the author drain's open trees (`_curator1134.author_trees`), so `cfg.corpus` is
the held `lessons/` mount and `cfg.tree_for` the trees' lookup. A plant is made by the fake agent
itself (its `also=` hook), the way a box process would leave it, and where a fault is under test
the same hook raises it right after planting, so `_undo_agent_edits` is the first host code that
meets the plant.

Some scenes swap the config's held corpus (`dataclasses.replace(cfg, corpus=...)`) for one on the
same root that journals its calls, refuses a read (`JournalHeld`), or is held over an `os_` that
fails a call the way a full disk does or refuses a listing (`FailsOn`, `RefusesFolder`): what the
tick then does shows that every corpus touch goes through `cfg.corpus`.

The paths O5.2 names (each used to unlink a link and now refuses it, leaving it for the scrub):

- `_restore_corpus`'s fault sweep — an unattributable link-lesson (`_cited_ids` cites nothing
  through a refused read, O5.1) faults the tick with `AuthorError`, which retires as before;
- `_put_back` via `_revert_non_md_strays` — NOT under O5.3's containment, so the `NotPlainEntry`
  propagates out of `run_batch` (a stuck tick naming `NotPlainEntry`);
- `_put_back` via `_revert_strays` on the fault path, into the SIBLING corpus (a mount of the same
  label, judged through its own `Held`) — logged, the fault routes unchanged;
- `_restore_unapproved_files` (non-fault) — its `NotPlainEntry` propagates.

O5.3, settled: on the fault path only, a `NotPlainEntry` (symlink, hard link, FIFO, folder AT the
name) is logged at WARNING naming the entry and the original fault propagates unchanged (same
object): a `RETIRE_SET` member retires (rc 2, bumped), any other class re-raises and is the stuck
record's `fault_class`. Anything else (a linked holding folder's plain `ELOOP`, ENOSPC, EIO,
EACCES) still replaces the fault. v1's declared deviation (a FIFO at a new name replacing the
fault) is gone and is pinned gone.

Addendum 2's correction (C1/C2): the before-state is git's read of the tick-start commit, and
the fault sweep asks `git status` which names the agent made; no folder is listed. A name git
does not report (a gitignored file, a FIFO or socket at a new name) survives the fault undo.

Every guard has its positive control: the same address holding a plain file, or nothing.
"""
from __future__ import annotations

import dataclasses
import errno
import logging
import os
import shutil
import stat
from pathlib import Path

import pytest

from defender._io import NotPlainEntry
from defender.learning.author import drain
from defender.tests import _spec773 as S
from defender.tests._curator1134 import (
    OUT_MARK,
    FailsOn,
    JournalHeld,
    is_link_to,
    leaf_refusal,
    lesson_text,
    move_out_and_link,
    plant_fifo,
    plant_folder,
    plant_hardlink,
    plant_link,
    plant_socket,
    put,
    seamed_trees,
    warnings_naming,
)
from defender.tests._shared_readers_1134 import RefusesFolder, kernel_watch
from defender.tests.test_1111_rooted_io import census, raised_by

#: The name the agent plants at: distinctive, so a log line naming it names this entry.
PLANTED = "planted-lesson.md"
SEEDED = "seeded-lesson.md"


def _outside(tmp_path: Path, name: str = "secret.md", text: str | None = None) -> Path:
    at = tmp_path / "outside" / name
    put(at, text if text is not None else lesson_text("f1", mark=OUT_MARK))
    return at


def _scene(tmp_path: Path, **kw):
    """One findings row (`f1`), its ground truth written, and `SEEDED` committed in the corpus so
    the tick-start snapshot holds it."""
    kw.setdefault("seed_corpus", {SEEDED: lesson_text("f0")})
    return S.build_scene(tmp_path, **kw)


def _run(sc, *, fifo: Path | None = None):
    """`drain.run_batch(cfg=...)`: `("rc", n)` or `("raised", exc)`. A scene with a planted FIFO
    runs under `test_1111`'s deadline, so a regression that opens it fails rather than hangs;
    every other scene runs inline, with no deadline to miss on a loaded box."""
    box: dict = {}

    def go():
        box["rc"] = drain.run_batch(cfg=sc.cfg)

    if fifo is not None:
        exc = raised_by(go, fifo=fifo)
    else:
        try:
            go()
        except Exception as e:  # noqa: BLE001 — the scene's outcome, whatever its type
            exc = e
        else:
            exc = None
    return ("raised", exc) if exc is not None else ("rc", box["rc"])


def _stuck_classes(sc) -> list[str]:
    return [r.get("fault_class") for r in S.stuck_records(sc.channel)]


def _plain_os_error(exc: BaseException | None, code: int) -> bool:
    return isinstance(exc, OSError) and type(exc) is not NotPlainEntry and exc.errno == code


# ---------------------------------------------------------------------------------------
# O5.1 + O5.2 at _restore_corpus: an unattributable link-lesson faults and is left
# ---------------------------------------------------------------------------------------


@pytest.mark.parametrize("channel", ["lessons", "questioner"])
def test_a_link_lesson_citing_the_batch_is_unattributable_and_left_for_the_scrub(
    tmp_path, caplog, channel,
):
    """The curator leaves `PLANTED` as a symlink to an outside lesson that cites the batch's row.
    Read through the held corpus it cites nothing (O5.1), so the tick faults with `AuthorError`
    (unattributable) and retires as ever: rc 2, the row bumped, nothing committed. The fault
    sweep's unlink is refused (O5.2), logged by name (O5.3) and the link left; the target is
    never opened or written. Both channels.

    Catches: today's `_cited_ids(repo_root / rel)`, which follows the link, attributes it, hands
    the outside text to the verifier and commits the link."""
    caplog.set_level(logging.WARNING)
    fid = "f1" if channel == "lessons" else "w1"
    target = _outside(tmp_path, text=lesson_text(fid, mark=OUT_MARK))
    at_holder: dict = {}

    def plant(rows, batch_id, cfg):
        at_holder["at"] = cfg.corpus_dir / PLANTED
        plant_link(at_holder["at"], target)

    curator = S.FakeCurator(also=plant)
    sc = (_scene(tmp_path, curator=curator) if channel == "lessons"
          else S.build_questioner_scene(tmp_path, curator=curator))
    before = census(target.parent)

    with kernel_watch(opens=[target]) as events:
        got = _run(sc)
        seen = events()

    assert got == ("rc", 2), got
    assert sc.pending_by_id()[fid].get("attempts") == 1
    assert sc.head_files() == []
    assert is_link_to(at_holder["at"], target)
    assert warnings_naming(caplog, PLANTED), caplog.text
    assert seen == [], f"the link's target was opened or read: {seen}"
    assert census(target.parent) == before
    assert all(OUT_MARK not in c.lesson_text for c in sc.verifier.calls)


def test_control_the_same_bytes_as_a_plain_lesson_are_attributed_and_committed(tmp_path):
    """The positive control at the same name: the outside lesson's bytes as a plain file cite
    `f1`, are judged, approved and committed; `f1` is consumed as committed."""
    body = lesson_text("f1", mark=OUT_MARK)
    sc = _scene(tmp_path, curator=S.FakeCurator(writes={PLANTED: body}))

    assert _run(sc) == ("rc", 0)
    assert sc.head_files() == [f"defender/lessons/{PLANTED}"]
    assert sc.head_text(f"defender/lessons/{PLANTED}") == body
    assert sc.category_of("f1") == "consumed_committed"


def test_control_an_unattributable_plain_lesson_is_swept_by_the_fault_restore(tmp_path):
    """The positive control for the sweep at the same name: a plain file citing nothing from the
    batch faults the tick (rc 2) and the fault restore removes it."""
    sc = _scene(tmp_path, curator=S.FakeCurator(writes={PLANTED: lesson_text("not-this-batch")}))

    assert _run(sc) == ("rc", 2)
    assert not os.path.lexists(sc.corpus / PLANTED)
    assert sc.head_files() == []


# ---------------------------------------------------------------------------------------
# O5.2 at _put_back via _revert_non_md_strays (settle; no O5.3 containment)
# ---------------------------------------------------------------------------------------


@pytest.mark.parametrize("kind", ["symlink", "hard link"])
def test_a_non_md_link_stray_in_the_corpus_is_refused_and_the_tick_is_stuck(
    tmp_path, caplog, kind,
):
    """The curator writes an attributable lesson and leaves `notes.txt` as a symlink (or a hard
    link) to an outside file. The settle step's `_put_back` refuses to unlink it; that refusal is
    not on the fault path, so the `NotPlainEntry` propagates out of `run_batch`, the stuck record
    names `NotPlainEntry`, nothing is committed, and the link is left. The undo that runs on the
    way out removes the lesson and passes over the link it cannot remove.

    Catches: today's `is_file()` + `unlink()`, which removes the link and commits the lesson."""
    caplog.set_level(logging.WARNING)
    target = _outside(tmp_path, "secret.txt", f"host notes {OUT_MARK}\n")
    holder: dict = {}

    def plant(rows, batch_id, cfg):
        holder["at"] = cfg.corpus_dir / "notes.txt"
        (plant_link if kind == "symlink" else plant_hardlink)(holder["at"], target)

    sc = _scene(tmp_path, curator=S.FakeCurator(writes={PLANTED: lesson_text("f1")}, also=plant))

    result, got = _run(sc)

    assert result == "raised", got
    assert leaf_refusal(got), repr(got)
    assert _stuck_classes(sc) == ["NotPlainEntry"]
    assert sc.head_files() == []
    if kind == "symlink":
        assert is_link_to(holder["at"], target)
    else:
        assert os.stat(holder["at"]).st_ino == os.stat(target).st_ino
    assert not (sc.corpus / PLANTED).exists()
    assert (target.read_text()) == f"host notes {OUT_MARK}\n"


def test_control_a_non_md_plain_stray_is_reverted_and_the_tick_commits(tmp_path):
    sc = _scene(tmp_path, curator=S.FakeCurator(
        writes={PLANTED: lesson_text("f1"), "notes.txt": "a plain stray\n"}))

    assert _run(sc) == ("rc", 0)
    assert not (sc.corpus / "notes.txt").exists()
    assert sc.head_files() == [f"defender/lessons/{PLANTED}"]


# ---------------------------------------------------------------------------------------
# O5.2 at _put_back via _revert_strays, into the SIBLING corpus (fault path)
# ---------------------------------------------------------------------------------------


def _with_sibling(sc) -> Path:
    """Commit a `lessons-questioner/` corpus into the scene's repo (the second mount of the
    author label, already held by the scene's trees), and re-base the scene on that commit."""
    sibling = sc.paths.lessons_questioner_dir
    put(sibling / ".gitkeep", "")
    S.git(sc.repo, "add", "-A")
    S.git(sc.repo, "commit", "-q", "-m", "sibling corpus")
    sc.base_sha = sc.head_sha()
    return sibling


@pytest.mark.parametrize("kind", ["symlink", "hard link", "plain-control"])
def test_a_stray_in_the_sibling_corpus_goes_through_the_sibling_mount(tmp_path, kind, caplog):
    """H2: the lessons curator plants `lessons-questioner/PLANTED` (outside its own corpus,
    inside the sibling mount) and faults with `AuthorError`. On the fault path `_revert_strays`
    judges the name through the sibling's `Held`: a symlink or hard link is refused, logged by
    name and left, and the fault still retires (rc 2). The positive control, a plain file at the
    same name, is removed.

    Catches: today's `is_file()` + `unlink()`, which follows and removes the link; and a
    `_put_back` that falls back to the plain path for anything outside its own corpus."""
    caplog.set_level(logging.WARNING)
    target = _outside(tmp_path)
    holder: dict = {}

    def plant_and_fault(rows, batch_id, cfg):
        at = cfg.repo_root / "defender" / "lessons-questioner" / PLANTED
        holder["at"] = at
        if kind == "plain-control":
            put(at, lesson_text("f1"))
        else:
            (plant_link if kind == "symlink" else plant_hardlink)(at, target)
        raise drain.AuthorError("injected after the plant")

    sc = _scene(tmp_path, curator=S.FakeCurator(also=plant_and_fault))
    _with_sibling(sc)
    before = census(target.parent)

    got = _run(sc)

    assert got == ("rc", 2), got
    assert sc.pending_by_id()["f1"].get("attempts") == 1
    if kind == "plain-control":
        assert not os.path.lexists(holder["at"])
        assert census(target.parent) == before
    else:
        if kind == "symlink":
            assert is_link_to(holder["at"], target)
        else:
            assert os.stat(holder["at"]).st_ino == os.stat(target).st_ino
        assert warnings_naming(caplog, PLANTED), caplog.text
        assert target.read_bytes() == before["secret.md"][1]


# ---------------------------------------------------------------------------------------
# O5.2 at _restore_unapproved_files (non-fault; the refusal propagates)
# ---------------------------------------------------------------------------------------


def test_a_link_left_by_the_repair_at_an_unapproved_name_is_refused_and_propagates(tmp_path):
    """The curator writes `PLANTED` citing `f1`; the verifier calls it BAD; the repair spawn
    replaces it with a symlink to an outside lesson citing `f1`. Pass 2 reads the name through
    the held corpus: refused, so `""` (O5.1), so the file is unapproved and `f1` terminal. The
    restore of unapproved files refuses to unlink the link and the `NotPlainEntry` propagates out
    of `run_batch`: a stuck record naming it, nothing committed, the link left, and the target's
    bytes never handed to the verifier.

    Catches: today's pass-2 read through the link (the verifier sees the outside text) and
    `_restore_unapproved_files`' `unlink()`, which removes the link and returns rc 0."""
    target = _outside(tmp_path)
    holder: dict = {}

    def relink(pairs, batch_id, cfg):
        holder["at"] = cfg.corpus_dir / PLANTED
        plant_link(holder["at"], target)

    sc = _scene(tmp_path,
                curator=S.FakeCurator(writes={PLANTED: lesson_text("f1")}),
                verifier=S.FakeVerifier(verdicts={PLANTED: "BAD"}),
                repair=S.FakeRepair(also=relink))
    before = census(target.parent)

    with kernel_watch(opens=[target]) as events:
        result, got = _run(sc)
        seen = events()

    assert sc.repair.spawned == 1
    assert result == "raised", got
    assert leaf_refusal(got), repr(got)
    assert _stuck_classes(sc) == ["NotPlainEntry"]
    assert sc.head_files() == []
    assert is_link_to(holder["at"], target)
    assert seen == []
    assert census(target.parent) == before
    assert all(OUT_MARK not in c.lesson_text for c in sc.verifier.calls)


def test_control_a_plain_file_left_by_the_repair_at_an_unapproved_name_is_removed(tmp_path):
    """The positive control at the same name: the repair leaves the outside lesson's bytes as a
    plain file; pass 2 still judges it BAD, `f1` is terminal, and the restore removes the file.
    The tick completes (rc 0) and commits nothing."""
    body = lesson_text("f1", mark=OUT_MARK)
    sc = _scene(tmp_path,
                curator=S.FakeCurator(writes={PLANTED: lesson_text("f1")}),
                verifier=S.FakeVerifier(verdicts={PLANTED: "BAD"}),
                repair=S.FakeRepair(writes={PLANTED: body}))

    assert _run(sc) == ("rc", 0)
    assert not os.path.lexists(sc.corpus / PLANTED)
    assert sc.head_files() == []
    assert sc.category_of("f1") == "consumed_forward_bad"


# ---------------------------------------------------------------------------------------
# O5.3: a leaf refusal on the fault path is logged; the original fault routes unchanged
# ---------------------------------------------------------------------------------------

PLANTS = ["symlink", "hard link", "fifo", "socket", "folder"]


def _plant_over_seeded(kind: str, target: Path, fault: BaseException):
    """The agent replaces snapshot name `SEEDED` by a symlink / hard link to `target` (an outside
    file whose bytes differ from the snapshot's), a FIFO, a UNIX socket, or a folder — or just
    rewrites it (`"none"`) — then raises `fault`."""

    def agent(rows, batch_id, cfg):
        at = cfg.corpus_dir / SEEDED
        if kind == "symlink":
            plant_link(at, target)
        elif kind == "hard link":
            plant_hardlink(at, target)
        elif kind == "fifo":
            plant_fifo(at)
        elif kind == "socket":
            plant_socket(at)
        elif kind == "folder":
            plant_folder(at)
        else:
            put(at, "the agent rewrote the seeded lesson\n")
        raise fault

    return agent


def _unwritten(entries: dict[str, tuple]) -> dict[str, tuple]:
    """`census` without a regular file's link count: the agent's own hard-link plant raises the
    outside file's count to 2 and the plant is left in place by design, so only its bytes and
    mtime say whether the restore wrote through it."""
    return {k: v[:3] if v[0] == "file" else v for k, v in entries.items()}


def _plant_left(kind: str, at: Path, target: Path) -> bool:
    if kind == "symlink":
        return is_link_to(at, target)
    if kind == "hard link":
        return os.stat(at).st_ino == os.stat(target).st_ino
    if kind == "fifo":
        return stat.S_ISFIFO(os.lstat(at).st_mode)
    if kind == "socket":
        return stat.S_ISSOCK(os.lstat(at).st_mode)
    return at.is_dir() and not at.is_symlink()


@pytest.mark.parametrize("kind", PLANTS)
def test_o5_3_a_retire_member_still_retires_over_a_plant_at_a_snapshot_name(
    tmp_path, kind, caplog,
):
    """(i) `AuthorError` (a `RETIRE_SET` member) with a symlink, hard link, FIFO, UNIX socket or
    folder at snapshot name `SEEDED`: the restore's rewrite is refused (`NotPlainEntry`), logged
    at WARNING by name, and the fault still routes as before — rc 2, `f1` bumped, no stuck record
    for a class other than the fault's. The plant is left; the outside file is neither read nor
    written. (FIFO, socket and folder are O5.3's settled widening: v1 let their refusal replace
    the fault.)

    Catches: today's restore, which reads a link's target and whose refusal replaces the
    `AuthorError`; v1's alias-mark catch, which lets a FIFO's or folder's refusal through; and
    (E09) a catch that passes over only the plants it can name, re-raising a socket's refusal."""
    caplog.set_level(logging.WARNING)
    target = _outside(tmp_path, text=lesson_text("f0", mark=OUT_MARK))
    sc = _scene(tmp_path, curator=S.FakeCurator(
        also=_plant_over_seeded(kind, target, drain.AuthorError("injected after the plant"))))
    before = census(target.parent)

    with kernel_watch(reads=[target]) as events:
        got = _run(sc, fifo=sc.corpus / SEEDED if kind == "fifo" else None)
        seen = events()

    assert got == ("rc", 2), got
    assert sc.pending_by_id()["f1"].get("attempts") == 1
    assert set(_stuck_classes(sc)) <= {"AuthorError"}
    assert _plant_left(kind, sc.corpus / SEEDED, target)
    assert warnings_naming(caplog, SEEDED), caplog.text
    assert seen == []
    assert _unwritten(census(target.parent)) == _unwritten(before)


@pytest.mark.parametrize("kind", PLANTS)
def test_o5_3_a_non_member_fault_propagates_unchanged_over_a_plant(tmp_path, kind, caplog):
    """(ii) `RuntimeError` (not a member) with the same plant: that same `RuntimeError` object
    propagates out of `run_batch`, the stuck record's `fault_class` is `RuntimeError`, the row
    stays queued unbumped, and the plant is left, logged by name.

    Catches: the restore's refusal replacing the fault (the stuck record would name it)."""
    caplog.set_level(logging.WARNING)
    target = _outside(tmp_path, text=lesson_text("f0", mark=OUT_MARK))
    fault = RuntimeError("injected after the plant")
    sc = _scene(tmp_path, curator=S.FakeCurator(also=_plant_over_seeded(kind, target, fault)))
    before = census(target.parent)

    result, got = _run(sc, fifo=sc.corpus / SEEDED if kind == "fifo" else None)

    assert result == "raised", got
    assert got is fault
    assert _stuck_classes(sc) == ["RuntimeError"]
    assert sc.pending_by_id()["f1"].get("attempts") is None
    assert _plant_left(kind, sc.corpus / SEEDED, target)
    assert warnings_naming(caplog, SEEDED), caplog.text
    assert _unwritten(census(target.parent)) == _unwritten(before)


@pytest.mark.parametrize("fault", ["AuthorError", "RuntimeError"])
def test_o5_3_control_with_nothing_planted_the_snapshot_file_is_restored(tmp_path, fault):
    """The positive control for both routes: the agent rewrites `SEEDED` (no plant) and faults.
    The restore puts the snapshot bytes back; `AuthorError` retires (rc 2), `RuntimeError`
    propagates and is recorded stuck."""
    exc = drain.AuthorError("injected") if fault == "AuthorError" else RuntimeError("injected")
    sc = _scene(tmp_path, curator=S.FakeCurator(also=_plant_over_seeded("none", Path(), exc)))

    got = _run(sc)

    if fault == "AuthorError":
        assert got == ("rc", 2), got
        assert sc.pending_by_id()["f1"].get("attempts") == 1
    else:
        assert got == ("raised", exc), got
        assert _stuck_classes(sc) == ["RuntimeError"]
    assert (sc.corpus / SEEDED).read_text() == lesson_text("f0")


def test_a_fifo_at_a_new_name_is_left_and_the_fault_still_retires(tmp_path, caplog):
    """v1's declared deviation, gone: a FIFO at a name the snapshot never held, then
    `AuthorError`. `git status` does not report a FIFO, so the sweep (which asks git what the
    agent made, C1) never meets it: the tick retires (rc 2, `f1` bumped), nothing is logged for
    it (C2), and the FIFO is never opened and is left for the scrub.

    Catches: v1's alias-mark catch, under which the FIFO's unmarked refusal replaced the fault,
    and a sweep that opens what it finds."""
    caplog.set_level(logging.WARNING)
    holder: dict = {}

    def agent(rows, batch_id, cfg):
        holder["at"] = cfg.corpus_dir / PLANTED
        plant_fifo(holder["at"])
        raise drain.AuthorError("injected after the plant")

    sc = _scene(tmp_path, curator=S.FakeCurator(also=agent))

    got = _run(sc, fifo=sc.corpus / PLANTED)

    assert got == ("rc", 2), got
    assert sc.pending_by_id()["f1"].get("attempts") == 1
    assert stat.S_ISFIFO(os.lstat(holder["at"]).st_mode)
    assert warnings_naming(caplog, PLANTED) == [], caplog.text


# ---------------------------------------------------------------------------------------
# O5.3: anything but the leaf refusal still propagates and replaces the fault
# ---------------------------------------------------------------------------------------


def test_a_linked_folder_holding_a_snapshot_name_replaces_the_fault(tmp_path):
    """The agent moves folder `sub/` (holding snapshot name `sub/lesson.md`) outside, links it back
    and rewrites the lesson there, then raises `AuthorError`. The rewrite of `sub/lesson.md` meets
    the linked HOLDING folder: a plain `OSError(ELOOP)` — no leaf refusal — propagates in place of
    the fault, recorded stuck as `OSError`, `f1` not bumped. Nothing is written into the moved
    folder, and the link is left."""
    outside = tmp_path / "outside"
    moved = outside / "moved-sub"

    def agent(rows, batch_id, cfg):
        move_out_and_link(cfg.corpus_dir / "sub", moved)
        put(moved / "lesson.md", lesson_text("f0", mark=OUT_MARK))
        raise drain.AuthorError("injected after the plant")

    sc = _scene(tmp_path, seed_corpus={"sub/lesson.md": lesson_text("f0")},
                curator=S.FakeCurator(also=agent))

    result, got = _run(sc)

    assert result == "raised", got
    assert _plain_os_error(got, errno.ELOOP), repr(got)
    assert _stuck_classes(sc) == ["OSError"]
    assert sc.pending_by_id()["f1"].get("attempts") is None
    assert is_link_to(sc.corpus / "sub", moved)
    assert (moved / "lesson.md").read_text() == lesson_text("f0", mark=OUT_MARK)


@pytest.mark.parametrize("recreated", [False, True], ids=["removed", "removed-and-remade"])
def test_a_corpus_mount_the_agent_removed_replaces_the_fault(tmp_path, recreated):
    """The agent removes the whole corpus folder (and, in one case, makes an empty folder at its
    spelling), then raises `AuthorError`. The fault undo writes `SEEDED` back through the held
    mount, whose root is the removed folder: the write fails with `FileNotFoundError` — no leaf
    refusal — which propagates in place of the fault, recorded stuck under its own class, `f1`
    not bumped; nothing is written at the folder's spelling (declared: main's restore remade the
    folder by its path and retired).

    Catches: a restore that falls back to the corpus's spelling when the held root is gone."""

    def agent(rows, batch_id, cfg):
        shutil.rmtree(cfg.corpus_dir)
        if recreated:
            cfg.corpus_dir.mkdir()
        raise drain.AuthorError("injected after the removal")

    sc = _scene(tmp_path, curator=S.FakeCurator(also=agent))

    result, got = _run(sc)

    assert result == "raised", got
    assert type(got) is FileNotFoundError, repr(got)
    assert _stuck_classes(sc) == ["FileNotFoundError"]
    assert sc.pending_by_id()["f1"].get("attempts") is None
    assert (os.listdir(sc.corpus) == []) if recreated else not os.path.lexists(sc.corpus)


@pytest.mark.parametrize("kind", ["fifo", "hard link", "socket", "plain file"])
def test_a_non_folder_at_a_holding_folders_name_replaces_the_fault(tmp_path, kind, caplog):
    """E01: the agent replaces holding folder `sub/` (snapshot name `sub/lesson.md`) by a FIFO, a
    hard link to an outside file, or a UNIX socket, then raises `AuthorError`. The sweep's unlink
    of `sub` is the leaf refusal (logged, passed over), but the rewrite of `sub/lesson.md` then
    meets a NON-DIRECTORY holding folder: `NotADirectoryError`, exactly — no leaf refusal, so
    O5.3 does not contain it — propagates in place of the fault, recorded stuck under its own
    class, `f1` not bumped; the plant is left.

    The positive control is a plain file at `sub`: the sweep removes it like any stray, the
    rewrite makes `sub/` again and restores `sub/lesson.md`, and the fault retires (rc 2, bumped).

    Catches: an O5.3 catch widened to `NotADirectoryError`, under which the tick retires with
    `sub/lesson.md` never restored."""
    caplog.set_level(logging.WARNING)
    target = _outside(tmp_path, text=lesson_text("f0", mark=OUT_MARK))

    def agent(rows, batch_id, cfg):
        at = cfg.corpus_dir / "sub"
        if kind == "fifo":
            plant_fifo(at)
        elif kind == "hard link":
            plant_hardlink(at, target)
        elif kind == "socket":
            plant_socket(at)
        else:
            put(at, "a plain file where the folder was\n")
        raise drain.AuthorError("injected after the plant")

    sc = _scene(tmp_path, seed_corpus={"sub/lesson.md": lesson_text("f0")},
                curator=S.FakeCurator(also=agent))
    at = sc.corpus / "sub"

    result, got = _run(sc, fifo=at if kind == "fifo" else None)

    if kind == "plain file":
        assert (result, got) == ("rc", 2), got
        assert sc.pending_by_id()["f1"].get("attempts") == 1
        assert (at / "lesson.md").read_text() == lesson_text("f0")
        return
    assert result == "raised", got
    assert type(got) is NotADirectoryError, repr(got)
    assert _stuck_classes(sc) == ["NotADirectoryError"]
    assert sc.pending_by_id()["f1"].get("attempts") is None
    st = os.lstat(at)
    assert {"fifo": stat.S_ISFIFO, "hard link": stat.S_ISREG,
            "socket": stat.S_ISSOCK}[kind](st.st_mode)
    if kind == "hard link":
        assert st.st_ino == os.stat(target).st_ino


@pytest.mark.parametrize(("verb", "code"), [
    ("rename", errno.ENOSPC), ("unlink", errno.EIO), ("unlink", errno.EACCES),
], ids=["rewrite-ENOSPC", "sweep-EIO", "sweep-EACCES"])
def test_a_failing_disk_on_the_fault_restore_replaces_the_fault(tmp_path, verb, code):
    """H6: the agent rewrites snapshot name `SEEDED` (or leaves a stray lesson) and raises
    `AuthorError`; the restore's rename of `SEEDED` then fails on a full disk (`ENOSPC`), or the
    sweep's unlink of the stray fails (`EIO`, `EACCES`), on `cfg.corpus`. That is no leaf
    refusal, so it is not passed over: the `OSError` propagates out of `run_batch` in place of
    the fault, recorded stuck under its own class, `f1` not bumped.

    Catches: an O5.3 catch wider than `NotPlainEntry`, under which the tick retires (rc 2) over a
    half-restored corpus. Control: `test_o5_3_control_with_nothing_planted_...`."""

    def agent(rows, batch_id, cfg):
        if verb == "rename":
            put(cfg.corpus_dir / SEEDED, "the agent rewrote the seeded lesson\n")
        else:
            put(cfg.corpus_dir / PLANTED, lesson_text("f1"))
        raise drain.AuthorError("injected after the write")

    sc = _scene(tmp_path, curator=S.FakeCurator(also=agent))
    seam = FailsOn(verb, code)
    trees = seamed_trees(sc.paths, seam)
    sc.cfg = dataclasses.replace(sc.cfg, corpus=trees.mount(sc.corpus))

    result, got = _run(sc)

    assert result == "raised", got
    assert _plain_os_error(got, code), repr(got)
    assert _stuck_classes(sc) == [type(got).__name__]
    assert sc.pending_by_id()["f1"].get("attempts") is None
    assert seam.raised >= 1


# ---------------------------------------------------------------------------------------
# The before-state is git's: one git cannot read stops the tick before the agent (C1)
# ---------------------------------------------------------------------------------------


def test_a_before_state_git_cannot_read_raises_out_of_run_batch_before_the_agent(tmp_path):
    """The tick-start before-state cannot be read: `SEEDED`'s blob is missing from the object
    store (the worktree and the index's stat cache still say clean, so the clean gate passes).
    `_snapshot_corpus` raises from `_capture_pre_state`, before the agent, as the read-only
    probe's `GitProbeError` (not a `RETIRE_SET` member): it comes out of `run_batch`, the stuck
    record is written, no row is bumped, nothing is committed, the agent was never spawned, and
    `SEEDED` is untouched.

    Catches: a before-state that leaves the unreadable lesson out (after which the fault-path
    restore would delete it), or a git failure that retires the batch."""
    sc = _scene(tmp_path, seed_corpus={SEEDED: lesson_text("f0"), "sub/x.md": lesson_text("f0")},
                curator=S.FakeCurator(writes={PLANTED: lesson_text("f1")}))
    oid = S.git(sc.repo, "rev-parse", f"HEAD:defender/lessons/{SEEDED}").stdout.strip()
    (sc.repo / ".git" / "objects" / oid[:2] / oid[2:]).unlink()

    result, got = _run(sc)

    assert result == "raised", got
    assert type(got) is drain.GitProbeError, repr(got)
    assert not isinstance(got, drain.RETIRE_SET)
    assert "corpus before-state" in str(got), got
    assert sc.curator.calls == [], "the agent was spawned over a before-state the tick never read"
    [record] = S.stuck_records(sc.channel)
    assert record.get("fault_class") == "GitProbeError", record
    assert sc.pending_by_id()["f1"].get("attempts") is None
    assert sc.head_files() == []
    assert (sc.corpus / SEEDED).read_text() == lesson_text("f0")


@pytest.mark.parametrize("route", ["control", "step", "reopen", "scandir"])
def test_a_corpus_the_held_mount_cannot_read_still_has_its_before_state(tmp_path, route):
    """The positive control, and C1's point: the before-state is read from git, not through the
    held mount. Over the real `os` (`control`), or over a mount that refuses (EACCES) `SEEDED`'s
    open or the corpus folder's listing on one route, the tick-start before-state still holds
    every tracked file (nested included) with its bytes, the agent is spawned, and the tick
    commits.

    Catches: a before-state read through the mount (v2's walk + `read_bytes`), which raises (or
    leaves the file out) here."""
    sc = _scene(tmp_path, seed_corpus={SEEDED: lesson_text("f0"), "sub/x.md": lesson_text("f0")},
                curator=S.FakeCurator(writes={PLANTED: lesson_text("f1")}))
    if route != "control":
        at = sc.corpus / SEEDED if route == "step" else sc.corpus
        trees = seamed_trees(sc.paths, RefusesFolder(at, route, errno.EACCES))
        sc.cfg = dataclasses.replace(sc.cfg, corpus=trees.mount(sc.corpus))

    assert drain._capture_pre_state(sc.cfg).snapshot == {
        ".gitkeep": b"", SEEDED: lesson_text("f0").encode(),
        "sub/x.md": lesson_text("f0").encode()}
    assert _run(sc) == ("rc", 0)
    assert len(sc.curator.calls) == 1
    assert sc.head_files() == [f"defender/lessons/{PLANTED}"]


def test_a_nested_lesson_the_agent_rewrote_is_restored_on_the_fault_path(tmp_path):
    """C1 through the drain: the agent rewrites the tracked nested lesson `nested/deep/l1.md`,
    leaves a nested stray beside it, and raises `AuthorError`. The fault undo writes the lesson
    back from the git before-state and sweeps the stray (both names git reports); the tick
    retires (rc 2, `f1` bumped) and the corpus is clean again.

    Catches: a before-state limited to the corpus's own entries, under which the rewrite stays
    and the next tick's clean gate refuses."""

    def agent(rows, batch_id, cfg):
        put(cfg.corpus_dir / "nested" / "deep" / "l1.md", "the agent's edit\n")
        put(cfg.corpus_dir / "nested" / "deep" / "stray.md", lesson_text("f1"))
        raise drain.AuthorError("injected after the edit")

    sc = _scene(tmp_path, seed_corpus={SEEDED: lesson_text("f0"),
                                       "nested/deep/l1.md": lesson_text("f0", mark="original")},
                curator=S.FakeCurator(also=agent))

    assert _run(sc) == ("rc", 2)
    assert sc.pending_by_id()["f1"].get("attempts") == 1
    assert (sc.corpus / "nested/deep/l1.md").read_text() == lesson_text("f0", mark="original")
    assert not (sc.corpus / "nested/deep/stray.md").exists()
    assert S.git(sc.repo, "status", "--porcelain", "--", str(sc.corpus)).stdout == ""


def test_a_gitignored_name_the_agent_made_survives_a_faulted_tick(tmp_path):
    """C2 (declared), through the drain: the corpus ignores `*.log`; the agent writes `x.log` and
    a stray `y.md`, then raises `AuthorError`. The fault undo sweeps what git reports (`y.md`)
    and leaves `x.log`, which git does not (main's recursive sweep deleted it); the tick retires
    (rc 2)."""

    def agent(rows, batch_id, cfg):
        put(cfg.corpus_dir / "x.log", "ignored by git\n")
        put(cfg.corpus_dir / "y.md", lesson_text("f1"))
        raise drain.AuthorError("injected after the writes")

    sc = _scene(tmp_path, seed_corpus={SEEDED: lesson_text("f0"), ".gitignore": "*.log\n"},
                curator=S.FakeCurator(also=agent))

    assert _run(sc) == ("rc", 2)
    assert (sc.corpus / "x.log").read_text() == "ignored by git\n"
    assert not (sc.corpus / "y.md").exists()


# ---------------------------------------------------------------------------------------
# Every corpus touch of the tick is `cfg.corpus`'s: the `Held` the config carries (H5/H7)
# ---------------------------------------------------------------------------------------


def _journal(sc, log: list, **kw) -> None:
    """Swap the scene's held corpus for a `JournalHeld` on the same root, logging into `log`."""
    sc.cfg = dataclasses.replace(sc.cfg, corpus=JournalHeld(sc.corpus, log, **kw))


def test_the_snapshot_attribution_and_fault_restore_use_cfg_corpus(tmp_path):
    """The curator leaves `PLANTED` citing nothing from the batch, so the tick faults
    (unattributable) and retires. Over a `cfg.corpus` that journals its calls, with the agent's
    own mark in the same log: before the agent ran, no byte read and no listing went through it
    for the before-state (that is git's, C1); after, the attribution read `PLANTED` through it,
    and the fault restore swept `PLANTED` with its `unlink` and compared `SEEDED`'s bytes through
    it.

    Catches: an attribution read or a fault restore made through a `Held` of its own on the same
    root — the same answers on a plain tree, but not the handle the lane's trees hold — and a
    before-state read through the mount."""
    log: list = []
    sc = _scene(tmp_path, curator=S.FakeCurator(
        writes={PLANTED: lesson_text("not-this-batch")},
        also=lambda *_a: log.append(("agent",))))
    _journal(sc, log)

    assert _run(sc) == ("rc", 2)

    agent = log.index(("agent",))
    before, after = log[:agent], log[agent + 1:]
    assert not [e for e in before if e[0] == "read_bytes"], before
    assert {("read", PLANTED), ("read_bytes", PLANTED)} & set(after), after
    assert ("unlink", PLANTED) in after, after
    assert ("read_bytes", SEEDED) in after, after
    assert not os.path.lexists(sc.corpus / PLANTED)


@pytest.mark.parametrize("refused", [True, False], ids=["refused", "control"])
def test_attribution_asks_cfg_corpus_and_a_refused_read_cites_nothing(tmp_path, refused):
    """The curator writes a plain `PLANTED` citing `f1`, but `cfg.corpus`'s view refuses to read
    it (as it refuses a hard link). Attribution asks `cfg.corpus`, so the lesson cites nothing:
    the tick faults unattributable and retires (rc 2, `f1` bumped), no verifier call, nothing
    committed. The control, the same view refusing nothing: judged, approved, committed.

    Catches: attribution and judging over a handle of their own, which reads the file the
    config's view refused and commits it."""
    sc = _scene(tmp_path, curator=S.FakeCurator(writes={PLANTED: lesson_text("f1")}))
    _journal(sc, [], refuse=(PLANTED,) if refused else ())

    got = _run(sc)

    if refused:
        assert got == ("rc", 2), got
        assert sc.pending_by_id()["f1"].get("attempts") == 1
        assert sc.verifier.calls == []
        assert sc.head_files() == []
    else:
        assert got == ("rc", 0), got
        assert sc.head_files() == [f"defender/lessons/{PLANTED}"]


#: What the scene's `cfg.corpus` appends to `PLANTED`'s text: the plain file never holds it.
AS_THE_VIEW_READS_IT = "\n<!-- as cfg.corpus reads it -->\n"


def test_the_verifier_judges_the_text_cfg_corpus_reads(tmp_path):
    """The judge reads each changed file through `cfg.corpus.view()`: over a view whose text read
    of `PLANTED` carries a line the plain file lacks, every verifier call for `PLANTED` sees that
    line; the commit, which is git's, holds the file's own bytes.

    Catches: a judge reading through a handle of its own."""
    body = lesson_text("f1")
    sc = _scene(tmp_path, curator=S.FakeCurator(writes={PLANTED: body}))
    _journal(sc, [], extra={PLANTED: AS_THE_VIEW_READS_IT})

    assert _run(sc) == ("rc", 0)

    texts = sc.verifier.texts_for(PLANTED)
    assert texts, sc.verifier.calls
    assert all(AS_THE_VIEW_READS_IT.strip() in t for t in texts), texts
    assert sc.head_text(f"defender/lessons/{PLANTED}") == body
