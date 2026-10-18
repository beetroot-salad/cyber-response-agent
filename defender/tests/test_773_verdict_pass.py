"""#773 — the drain's vouching step (M3.2), what survived the forward check's deletion (#1166).
"""
from __future__ import annotations

from defender.tests import _spec773 as S

LESSON = "defender/lessons/l1.md"

# ---------------------------------------------------------------------------
# M3.2 — vouching, on every channel, over every changed corpus file
# ---------------------------------------------------------------------------


def test_a_changed_file_citing_no_batch_finding_raises_author_error_773(tmp_path):
    """A changed corpus file whose citations do not intersect this batch's ids is unvouched,
    and M3.2's disposition for that is `AuthorError`."""
    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1")],
        curator=S.FakeCurator(writes={"stray.md": S.lesson("someone-elses-id")},
                              committed=["f1"]),
    )
    assert sc.run() == 2
    assert sc.corpus_files() == []
    assert sc.pending_by_id()["f1"]["attempts"] == 1


def test_a_file_whose_citations_match_head_no_longer_passes_vouching_773(tmp_path):
    """The HEAD-provenance exemption is gone (M3.2/C13)."""
    seeded = {"old.md": S.lesson("older-batch-id")}
    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1")],
        seed_corpus=seeded,
        curator=S.FakeCurator(
            writes={"old.md": S.lesson("older-batch-id", body="edited body")},
            committed=["f1"],
        ),
    )
    assert sc.run() == 2

    control = S.build_scene(
        tmp_path / "control",
        rows=[S.finding_row("f1", run_id="f1")],
        seed_corpus=seeded,
        curator=S.FakeCurator(writes={"old.md": S.lesson("older-batch-id", "f1")}),
    )
    assert control.run() == 0
    assert "defender/lessons/old.md" in control.head_files()


def test_a_file_whose_bytes_return_to_head_after_editing_no_longer_exempts_itself_from_vouching_773(
    tmp_path,
):
    """Two arms of the same removal."""
    seeded = {"old.md": S.lesson("older-batch-id", body="original")}

    def edit_then_restore(rows, batch_id, cfg):
        target = cfg.corpus_dir / "old.md"
        target.write_text(S.lesson("older-batch-id", body="scribbled"), encoding="utf-8")
        target.write_text(S.lesson("older-batch-id", body="original"), encoding="utf-8")

    unchanged = S.build_scene(
        tmp_path / "restored",
        rows=[S.finding_row("f1", run_id="f1")],
        seed_corpus=seeded,
        curator=S.FakeCurator(writes={"l1.md": S.lesson("f1")}, also=edit_then_restore),
    )
    assert unchanged.run() == 0
    assert unchanged.head_files() == [LESSON]

    still_dirty = S.build_scene(
        tmp_path / "dirty",
        rows=[S.finding_row("f1", run_id="f1")],
        seed_corpus=seeded,
        curator=S.FakeCurator(
            writes={"old.md": S.lesson("older-batch-id", body="rewritten")},
            committed=["f1"],
        ),
    )
    assert still_dirty.run() == 2


def test_curator_reports_no_commits_but_leaves_dirty_corpus_edits_773(tmp_path):
    """A curator that reports NOTHING committed and leaves a well-cited edit never reaches
    M3 at all."""
    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1")],
        curator=S.FakeCurator(writes={"l1.md": S.lesson("f1")}, committed=[]),
    )
    assert sc.run() == 2
    assert sc.head_files() == []
    assert "l1.md" not in sc.corpus_files()
    reported = " ".join(
        [r.get("deadletter_reason", "") for r in sc.graveyard()]
        + [r.get("reason", "") for r in S.stuck_records(sc.paths, sc.channel)]
    )
    assert "reported no commits but left edits" in reported


def test_curator_reports_committed_but_leaves_the_corpus_clean_773(tmp_path):
    """The SAME gate, the OPPOSITE mismatch."""
    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1")],
        curator=S.FakeCurator(writes={}, committed=["f1"]),
    )
    assert sc.run() == 2
    assert sc.head_files() == []
    assert sc.category_of("f1") is None
    reported = " ".join(
        [r.get("deadletter_reason", "") for r in sc.graveyard()]
        + [r.get("reason", "") for r in S.stuck_records(sc.paths, sc.channel)]
    )
    assert "reported committed" in reported and "unchanged" in reported  # noqa: PT018 — locked spec test (#773), suppressed not split


def test_a_first_spawn_deletion_of_a_pre_existing_lesson_still_passes_vouching_773(tmp_path):
    """N6."""
    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1")],
        seed_corpus={"old.md": S.lesson("older-batch-id")},
        curator=S.FakeCurator(writes={"l1.md": S.lesson("f1")}, deletes=("old.md",)),
    )
    assert sc.run() == 0
    assert sc.head_text("defender/lessons/old.md") is None
