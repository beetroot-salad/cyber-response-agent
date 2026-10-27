"""#1134 curator step through the drain tick: box output in the lane is never followed, never
attributed through a link, never committed but as a plain in-lane lesson, and a faulted claim
leaves the lane at its base.

Every scene is a batch's git-free draft (`_spec773.build_draft_scene`); what landed is read from
the batch branch (`agent/...`). Drafts are never scrubbed: a claim reset re-syncs the draft from
git objects, so a faulted claim's lane is observed back at its base.
"""
from __future__ import annotations

import dataclasses
import logging
import os
import stat
from pathlib import Path

import pytest

from defender.learning.author import drain
from defender.tests.support.learning.curation import _spec773 as S
from defender.tests.support.learning.curation._curator1134 import (
    OUT_MARK,
    JournalHeld,
    lesson_text,
    plant_fifo,
    plant_folder,
    plant_hardlink,
    plant_link,
    plant_socket,
    put,
    warnings_naming,
)
from defender.tests.support.learning.curation._shared_readers_1134 import kernel_watch
from defender.tests.shared.filesystem.test_1111_rooted_io import census, raised_by

#: The name the agent plants at: distinctive, so a log line naming it names this entry.
PLANTED = "planted-lesson.md"
SEEDED = "seeded-lesson.md"
#: The draft lane's repo-relative spelling.
LESSONS = "agent/lessons"


def _outside(tmp_path: Path, name: str = "secret.md", text: str | None = None) -> Path:
    at = tmp_path / "outside" / name
    put(at, text if text is not None else lesson_text("f1", mark=OUT_MARK))
    return at


def _scene(tmp_path: Path, **kw):
    """One findings row (`f1`) over a draft lane whose export commit holds `SEEDED`."""
    kw.setdefault("seed_corpus", {SEEDED: lesson_text("f0")})
    return S.build_draft_scene(tmp_path, **kw)


def _run(sc, *, fifo: Path | None = None):
    """`drain.run_batch(cfg=...)`: `("rc", n)` or `("raised", exc)`. A scene with a planted FIFO
    runs under `test_1111`'s deadline, so a regression that opens it fails rather than hangs."""
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


#: The lane's counted-attempt classes (`drain.RETIRE_SET`'s `AuthorError`) plus the ChangeSet's
#: claim refusal: a stuck record of either is the attempt's bookkeeping, never an unhandled crash.
_COUNTED = {"AuthorError", "DeliveryRefused"}


def _refused_claim_routed(sc, got, fid: str) -> None:
    """A refused claim returns rc 0 (routed, not a stage failure), lands nothing, leaves the draft
    at the batch base, and keeps its row queued with one attempt counted (not consumed,
    graveyarded or stuck as a crash) for a retry up to the ceiling."""
    assert got == ("rc", 0), got
    assert sc.head_files() == []
    assert sc.draft_drift() == []
    assert sc.pending_by_id()[fid].get("attempts") == 1
    assert fid not in sc.consumed_by_id()
    assert all(r.get(sc.channel.id_key) != fid for r in sc.graveyard())
    assert set(_stuck_classes(sc)) <= _COUNTED


def _plain_single(at: Path, text: str) -> bool:
    """`at` is a plain, single-linked regular file holding exactly `text` (the base's bytes)."""
    st = os.lstat(at)
    return stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and at.read_text() == text


@pytest.mark.parametrize("channel", ["lessons", "questioner"])
def test_a_link_lesson_citing_the_batch_is_a_refused_claim_and_nothing_lands(
    tmp_path, caplog, channel,
):
    """A link the box leaves in its lane, its target citing the batch, is never followed: the
    ChangeSet refuses the claim before attribution reads it, and the refused claim is routed and
    logged naming the entry."""
    caplog.set_level(logging.WARNING)
    fid = "f1" if channel == "lessons" else "w1"
    target = _outside(tmp_path, text=lesson_text(fid, mark=OUT_MARK))

    def plant(rows, batch_id, cfg):
        plant_link(cfg.corpus_dir / PLANTED, target)

    curator = S.FakeCurator(also=plant)
    sc = (_scene(tmp_path, curator=curator) if channel == "lessons"
          else S.build_questioner_draft_scene(tmp_path, curator=curator, rows=[S.world_row(fid)]))
    before = census(target.parent)

    with kernel_watch(opens=[target]) as events:
        got = _run(sc)
        seen = events()

    _refused_claim_routed(sc, got, fid)
    assert not os.path.lexists(sc.corpus / PLANTED)
    assert warnings_naming(caplog, PLANTED), caplog.text
    assert seen == [], f"the link's target was opened or read: {seen}"
    assert census(target.parent) == before


def test_control_the_same_bytes_as_a_plain_lesson_are_attributed_and_committed(tmp_path):
    """Control at the same name: the outside lesson's bytes as a plain draft file cite `f1`, land
    on the batch branch with those bytes, and `f1` is consumed as committed."""
    body = lesson_text("f1", mark=OUT_MARK)
    sc = _scene(tmp_path, curator=S.FakeCurator(writes={PLANTED: body}))

    assert _run(sc) == ("rc", 0)
    assert sc.head_files() == [f"{LESSONS}/{PLANTED}"]
    assert sc.head_text(f"{LESSONS}/{PLANTED}") == body
    assert sc.category_of("f1") == "consumed_committed"


def test_control_an_unattributable_plain_lesson_is_gone_from_the_draft_after_the_fault(tmp_path):
    """A plain lesson citing nothing from the batch faults the tick (rc 2), nothing lands, and the
    claim's reset leaves no trace of it in the draft."""
    sc = _scene(tmp_path, curator=S.FakeCurator(writes={PLANTED: lesson_text("not-this-batch")}))

    assert _run(sc) == ("rc", 2)
    assert not os.path.lexists(sc.corpus / PLANTED)
    assert sc.head_files() == []


@pytest.mark.parametrize("kind", ["symlink", "hard link"])
def test_a_non_md_alias_in_the_lane_never_lands_and_its_target_is_never_written(
    tmp_path, caplog, kind,
):
    """A non-`.md` alias of a host file in the lane never lands and the host file is never
    written; a symlink refuses the whole claim, so the lesson beside it does not land either."""
    caplog.set_level(logging.WARNING)
    target = _outside(tmp_path, "secret.txt", f"host notes {OUT_MARK}\n")

    def plant(rows, batch_id, cfg):
        (plant_link if kind == "symlink" else plant_hardlink)(cfg.corpus_dir / "notes.txt", target)

    sc = _scene(tmp_path, curator=S.FakeCurator(writes={PLANTED: lesson_text("f1")}, also=plant))

    got = _run(sc)

    assert f"{LESSONS}/notes.txt" not in sc.head_files()
    assert target.read_text() == f"host notes {OUT_MARK}\n"
    if kind == "symlink":
        _refused_claim_routed(sc, got, "f1")
        assert not os.path.lexists(sc.corpus / "notes.txt")


def test_control_an_unrelated_fault_beside_a_link_is_not_routed_as_a_refused_claim(tmp_path):
    """Control for the refused-claim routing: the same symlink plant, but the curator raises an
    unrelated fault (outside `RETIRE_SET`), which propagates unchanged and sticks; the row is not
    charged an attempt."""
    target = _outside(tmp_path, "secret.txt", f"host notes {OUT_MARK}\n")
    fault = RuntimeError("unrelated, after the plant")

    def plant(rows, batch_id, cfg):
        plant_link(cfg.corpus_dir / "notes.txt", target)
        raise fault

    sc = _scene(tmp_path, curator=S.FakeCurator(writes={PLANTED: lesson_text("f1")}, also=plant))

    assert _run(sc) == ("raised", fault)
    assert _stuck_classes(sc) == ["RuntimeError"]
    assert sc.pending_by_id()["f1"].get("attempts") is None
    assert sc.head_files() == []
    assert target.read_text() == f"host notes {OUT_MARK}\n"


def test_control_a_non_md_plain_stray_never_lands_and_the_tick_commits(tmp_path):
    """Control: a plain non-`.md` stray in the lane never lands and is gone from the draft after
    the claim; the lesson beside it lands."""
    sc = _scene(tmp_path, curator=S.FakeCurator(
        writes={PLANTED: lesson_text("f1"), "notes.txt": "a plain stray\n"}))

    assert _run(sc) == ("rc", 0)
    assert not (sc.corpus / "notes.txt").exists()
    assert sc.head_files() == [f"{LESSONS}/{PLANTED}"]


PLANTS = ["symlink", "hard link", "fifo", "socket", "folder"]


def _plant_over_seeded(kind: str, target: Path, fault: BaseException):
    """The agent replaces base name `SEEDED` by a symlink / hard link to `target` (an outside
    file whose bytes differ from the base's), a FIFO, a UNIX socket, or a folder — or just
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
    outside file's count, so only its bytes and mtime say whether anything wrote through it."""
    return {k: v[:3] if v[0] == "file" else v for k, v in entries.items()}


@pytest.mark.parametrize("kind", PLANTS)
def test_o5_3_a_retire_member_still_retires_over_a_plant_at_a_base_name(tmp_path, kind):
    """A retiring fault over a plant at a base name still retires (rc 2, one attempt); nothing
    reads or writes through the plant, and the lane is back at its base."""
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
    if kind != "hard link":
        assert seen == []
    assert _unwritten(census(target.parent)) == _unwritten(before)
    assert _plain_single(sc.corpus / SEEDED, lesson_text("f0"))
    assert sc.head_files() == []


@pytest.mark.parametrize("kind", PLANTS)
def test_o5_3_a_non_member_fault_propagates_unchanged_over_a_plant(tmp_path, kind):
    """A non-retiring fault over a plant propagates unchanged and sticks, the row unattempted;
    nothing writes through the plant and the lane is back at its base."""
    target = _outside(tmp_path, text=lesson_text("f0", mark=OUT_MARK))
    fault = RuntimeError("injected after the plant")
    sc = _scene(tmp_path, curator=S.FakeCurator(also=_plant_over_seeded(kind, target, fault)))
    before = census(target.parent)

    result, got = _run(sc, fifo=sc.corpus / SEEDED if kind == "fifo" else None)

    assert result == "raised", got
    assert got is fault
    assert _stuck_classes(sc) == ["RuntimeError"]
    assert sc.pending_by_id()["f1"].get("attempts") is None
    assert _unwritten(census(target.parent)) == _unwritten(before)
    assert _plain_single(sc.corpus / SEEDED, lesson_text("f0"))
    assert sc.head_files() == []


@pytest.mark.parametrize("fault", ["AuthorError", "RuntimeError"])
def test_o5_3_control_with_nothing_planted_the_base_file_is_back(tmp_path, fault):
    """Control: a plain rewrite of a base lesson before either fault is undone; each fault routes
    as above."""
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


def test_a_fifo_at_a_new_name_is_never_opened_and_the_fault_still_retires(tmp_path):
    """A FIFO the box leaves at a new name is never opened (deadline), the fault retires (rc 2,
    one attempt) and the lane holds no FIFO after the claim."""
    holder: dict = {}

    def agent(rows, batch_id, cfg):
        holder["at"] = cfg.corpus_dir / PLANTED
        plant_fifo(holder["at"])
        raise drain.AuthorError("injected after the plant")

    sc = _scene(tmp_path, curator=S.FakeCurator(also=agent))

    got = _run(sc, fifo=sc.corpus / PLANTED)

    assert got == ("rc", 2), got
    assert sc.pending_by_id()["f1"].get("attempts") == 1
    assert not os.path.lexists(holder["at"])


def test_a_nested_lesson_the_agent_rewrote_is_back_at_its_base_after_the_fault(tmp_path):
    """A nested base lesson the agent rewrote is back at its base bytes and a nested new lesson is
    gone after a retiring fault; nothing lands."""

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
    assert sc.head_files() == []


def _journal(sc, log: list, **kw) -> None:
    """Swap the scene's held corpus for a `JournalHeld` on the same draft lane, logging into `log`."""
    sc.cfg = dataclasses.replace(sc.cfg, corpus=JournalHeld(sc.corpus, log, **kw))


@pytest.mark.parametrize("refused", [True, False], ids=["refused", "control"])
def test_attribution_reads_the_claims_own_bytes_never_the_corpus_again(tmp_path, refused):
    """Attribution reads a lesson's citations from the claim's change set (the bytes its commit
    carries, read once from the draft with no link followed), never through the lane's held
    corpus a second time. So a corpus read that would be refused is never made, and the cited
    lesson lands either way."""
    log: list = []
    sc = _scene(tmp_path, curator=S.FakeCurator(writes={PLANTED: lesson_text("f1")}))
    _journal(sc, log, refuse=(PLANTED,) if refused else ())

    got = _run(sc)

    assert got == ("rc", 0), got
    assert sc.head_files() == [f"{LESSONS}/{PLANTED}"]
    assert ("read", PLANTED) not in log, f"the held corpus was read again: {log}"


@pytest.mark.parametrize("mode", ["same mode", "made executable"])
def test_a_hard_link_holding_a_lessons_exact_bytes_is_never_committed(tmp_path, mode):
    """A base lesson the box hard-links to a host file holding its exact bytes (or those bytes
    made executable) is an aliased entry the ChangeSet refuses: a refused claim, so nothing lands
    (not even the new lesson), the draft is reset to plain base files, and the host file is
    unchanged."""
    holder: dict = {}

    def alias_seeded(rows, batch_id, cfg):
        at = cfg.corpus_dir / SEEDED
        target = tmp_path / "outside" / "seeded-copy.md"
        put(target, at.read_bytes())
        if mode == "made executable":
            os.chmod(target, 0o755)
        plant_hardlink(at, target)
        holder["target"] = target

    sc = _scene(tmp_path, curator=S.FakeCurator(writes={PLANTED: lesson_text("f1")},
                                                also=alias_seeded))

    got = _run(sc)
    assert "target" in holder, "the box never planted the hard link (vacuous)"
    _refused_claim_routed(sc, got, "f1")
    assert sc.head_text(f"{LESSONS}/{SEEDED}") == lesson_text("f0")
    assert holder["target"].read_text() == lesson_text("f0")
    assert (sc.corpus / SEEDED).read_text() == lesson_text("f0")
    assert not os.path.lexists(sc.corpus / PLANTED)
    reset = os.stat(sc.corpus / SEEDED)
    assert stat.S_ISREG(reset.st_mode), "the reset left a non-file"
    assert reset.st_nlink == 1, "the reset left the alias"
    assert reset.st_ino != os.stat(holder["target"]).st_ino, "the draft still shares the host inode"
