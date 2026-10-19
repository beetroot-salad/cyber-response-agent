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
    return [r.get("fault_class") for r in S.stuck_records(sc.paths, sc.channel)]


def _plain_os_error(exc: BaseException | None, code: int) -> bool:
    return isinstance(exc, OSError) and type(exc) is not NotPlainEntry and exc.errno == code


@pytest.mark.parametrize("channel", ["lessons", "questioner"])
def test_a_link_lesson_citing_the_batch_is_unattributable_and_left_for_the_scrub(
    tmp_path, caplog, channel,
):
    caplog.set_level(logging.WARNING)
    fid = "f1" if channel == "lessons" else "w1"
    target = _outside(tmp_path, text=lesson_text(fid, mark=OUT_MARK))
    at_holder: dict = {}

    def plant(rows, batch_id, cfg):
        at_holder["at"] = cfg.corpus_dir / PLANTED
        plant_link(at_holder["at"], target)

    curator = S.FakeCurator(also=plant)
    sc = (_scene(tmp_path, curator=curator) if channel == "lessons"
          else S.build_questioner_scene(tmp_path, curator=curator, rows=[S.world_row(fid)]))
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


@pytest.mark.parametrize("kind", ["symlink", "hard link"])
def test_a_non_md_link_stray_in_the_corpus_is_refused_and_the_tick_is_stuck(
    tmp_path, caplog, kind,
):
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
    if kind != "hard link":
        assert seen == []
    assert _unwritten(census(target.parent)) == _unwritten(before)
    assert not [n for n, row in census(sc.corpus).items()
                if row[0] == "file" and OUT_MARK.encode() in row[1]
                and (kind != "hard link" or n != SEEDED)], "the target's bytes were copied in"


@pytest.mark.parametrize("kind", PLANTS)
def test_o5_3_a_non_member_fault_propagates_unchanged_over_a_plant(tmp_path, kind, caplog):
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


def test_a_linked_folder_holding_a_snapshot_name_replaces_the_fault(tmp_path):
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


def test_a_before_state_git_cannot_read_raises_out_of_run_batch_before_the_agent(tmp_path):
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
    [record] = S.stuck_records(sc.paths, sc.channel)
    assert record.get("fault_class") == "GitProbeError", record
    assert sc.pending_by_id()["f1"].get("attempts") is None
    assert sc.head_files() == []
    assert (sc.corpus / SEEDED).read_text() == lesson_text("f0")


@pytest.mark.parametrize("route", ["control", "step", "reopen", "scandir"])
def test_a_corpus_the_held_mount_cannot_read_still_has_its_before_state(tmp_path, route):
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

    def agent(rows, batch_id, cfg):
        put(cfg.corpus_dir / "x.log", "ignored by git\n")
        put(cfg.corpus_dir / "build" / "out.bin", "ignored by git too\n")
        put(cfg.corpus_dir / "y.md", lesson_text("f1"))
        raise drain.AuthorError("injected after the writes")

    sc = _scene(tmp_path, seed_corpus={SEEDED: lesson_text("f0"),
                                       ".gitignore": "*.log\nbuild/\n"},
                curator=S.FakeCurator(also=agent))

    assert _run(sc) == ("rc", 2)
    assert (sc.corpus / "x.log").read_text() == "ignored by git\n"
    assert (sc.corpus / "build" / "out.bin").read_text() == "ignored by git too\n"
    assert not (sc.corpus / "y.md").exists()


def _journal(sc, log: list, **kw) -> None:
    """Swap the scene's held corpus for a `JournalHeld` on the same root, logging into `log`."""
    sc.cfg = dataclasses.replace(sc.cfg, corpus=JournalHeld(sc.corpus, log, **kw))


@pytest.mark.parametrize("refused", [True, False], ids=["refused", "control"])
def test_attribution_asks_cfg_corpus_and_a_refused_read_cites_nothing(tmp_path, refused):
    sc = _scene(tmp_path, curator=S.FakeCurator(writes={PLANTED: lesson_text("f1")}))
    _journal(sc, [], refuse=(PLANTED,) if refused else ())

    got = _run(sc)

    if refused:
        assert got == ("rc", 2), got
        assert sc.pending_by_id()["f1"].get("attempts") == 1
        assert sc.head_files() == []
    else:
        assert got == ("rc", 0), got
        assert sc.head_files() == [f"defender/lessons/{PLANTED}"]


#: What the scene's `cfg.corpus` appends to `PLANTED`'s text: the plain file never holds it.
AS_THE_VIEW_READS_IT = "\n<!-- as cfg.corpus reads it -->\n"
