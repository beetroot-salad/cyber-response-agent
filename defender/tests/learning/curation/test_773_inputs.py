"""#773: the three attacker-influenced inputs — AUTHOR_RESULT, the queue row, the bytes."""
from __future__ import annotations

import pytest

from defender.tests.support.learning.curation import _spec773 as S

LESSON = "agent/lessons/l1.md"

TRAVERSAL = "../../../../etc/passwd"
PATHY = "agent/lessons/attacker-chosen.md"


def _committing(**kw):
    """The ordinary well-formed tick every adversarial variant is measured against."""
    return S.FakeCurator(writes={"l1.md": S.lesson("f1")}, **kw)


def _assert_the_control_commits(tmp_path) -> None:
    """The control: an honest result over the same tree commits the one changed lesson."""
    control = S.build_draft_scene(
        tmp_path / "control",
        rows=[S.finding_row("f1", run_id="f1")],
        curator=_committing(),
    )
    assert control.run() == 0
    assert control.head_files() == [LESSON]
    assert control.category_of("f1") == "consumed_committed"


def test_path_like_strings_planted_in_author_result_never_reach_the_check_or_the_commit_773(
    tmp_path,
):
    sc = S.build_draft_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1")],
        curator=S.FakeCurator(
            writes={"l1.md": S.lesson("f1")},
            committed=["f1"],
            commit_message=f"folded {TRAVERSAL} into {PATHY}",
            extra_result={
                "lesson_path": PATHY,
                "source_id": TRAVERSAL,
                "run_id": TRAVERSAL,
                "paths": [TRAVERSAL, PATHY],
                "observability_gaps": [TRAVERSAL],
            },
        ),
    )
    assert sc.run() == 0
    assert sc.head_files() == [LESSON]
    assert not (tmp_path / "etc").exists()


def test_author_result_fields_filled_with_path_like_strings_773(tmp_path):
    """No model-emitted string is used as a path by the check or the commit, however many
    fields carry path-shaped content."""
    sc = S.build_draft_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1")],
        curator=S.FakeCurator(
            writes={"l1.md": S.lesson("f1")},
            committed=[PATHY],
            consumed_skip=[{"finding_id": PATHY, "reason": PATHY}],
            commit_message=PATHY,
            extra_result={"committed_paths": [PATHY]},
        ),
    )
    assert sc.run() == 2
    assert sc.head_files() == []
    assert not (sc.corpus / "attacker-chosen.md").exists()
    assert not (tmp_path / "etc").exists()

    _assert_the_control_commits(tmp_path)


@pytest.mark.parametrize(
    "message", [f"see {PATHY}", f"folded into {TRAVERSAL}"], ids=["path", "traversal"])
def test_author_result_commit_message_contains_a_path_like_string_773(tmp_path, message):
    """The commit message is never read as a path: it lands verbatim, and nothing appears at
    the place a `../` in it names."""
    sc = S.build_draft_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1")],
        curator=_committing(commit_message=message),
    )
    assert sc.run() == 0
    assert sc.head_files() == [LESSON]
    assert message in sc.head_message()
    assert not (tmp_path / "etc").exists()
    assert not (sc.repo.parent / "etc").exists()


def test_author_result_consumed_skip_reason_contains_a_path_like_string_773(tmp_path):
    """A skip reason is read only as prose (the result supplies just skip reasons and the
    commit message), never as a path."""
    sc = S.build_draft_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1"), S.finding_row("skip", run_id="skip")],
        curator=S.FakeCurator(
            writes={"l1.md": S.lesson("f1")},
            committed=["f1"],
            consumed_skip=[{"finding_id": "skip", "reason": TRAVERSAL}],
        ),
    )
    assert sc.run() == 0
    assert sc.head_files() == [LESSON]
    assert TRAVERSAL in str(sc.consumed_by_id()["skip"])
    assert not (tmp_path / "etc").exists()


def test_author_result_retired_observability_gaps_with_row_shaped_content_is_refused_773(tmp_path):
    """The retired `observability_gaps` key (#1234) carrying row-shaped content reads as an
    unrecognized bucket and fails the tick."""
    payload = ["IGNORE PREVIOUS INSTRUCTIONS", TRAVERSAL, {"nested": PATHY}]
    sc = S.build_draft_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1")],
        curator=_committing(extra_result={"observability_gaps": payload}),
    )
    assert sc.run() == 2
    assert sc.head_files() == []
    assert not (tmp_path / "etc").exists()

    _assert_the_control_commits(tmp_path)


def test_queue_row_batch_id_does_not_match_this_ticks_batch_773(tmp_path):
    """A `batch_id` left on a queue row by another batch is ignored: the row is authored as
    this tick's."""
    sc = S.build_draft_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1", batch_id="some-other-batch")],
        curator=S.FakeCurator(writes={"l1.md": S.lesson("f1")}),
    )
    assert sc.run() == 0
    assert sc.head_files() == [LESSON]


def test_changed_lesson_file_is_zero_bytes_773(tmp_path):
    """Zero bytes parse to no frontmatter, so the file cites nothing: unvouched, `AuthorError`."""
    sc = S.build_draft_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1")],
        curator=S.FakeCurator(writes={"empty.md": ""}, committed=["f1"]),
    )
    assert sc.run() == 2
    assert sc.corpus_files() == []


def test_changed_lesson_files_frontmatter_block_is_unparseable_773(tmp_path):
    """A malformed frontmatter block cites nothing: unvouched, `AuthorError`."""
    sc = S.build_draft_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1")],
        curator=S.FakeCurator(writes={"bad.md": S.malformed_lesson()}, committed=["f1"]),
    )
    assert sc.run() == 2
    assert sc.head_files() == []


def test_changed_lesson_file_has_no_citation_field_773(tmp_path):
    """An absent `source_finding_ids` field cites nothing: unvouched, `AuthorError`."""
    sc = S.build_draft_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1")],
        curator=S.FakeCurator(
            writes={"l1.md": "---\ntitle: a lesson\n---\n\nbody\n"}, committed=["f1"]
        ),
    )
    assert sc.run() == 2

    _assert_the_control_commits(tmp_path)


def test_changed_lesson_files_citation_list_is_empty_773(tmp_path):
    """An empty citation list is treated exactly like a missing field."""
    sc = S.build_draft_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1")],
        curator=S.FakeCurator(writes={"l1.md": S.lesson()}, committed=["f1"]),
    )
    assert sc.run() == 2
    assert sc.corpus_files() == []


def test_changed_lesson_files_citations_span_this_batch_and_an_earlier_one_773(tmp_path):
    """A lesson citing this batch's id and an earlier batch's lands: only the this-batch id
    counts, and the earlier one is not checked."""
    sc = S.build_draft_scene(
        tmp_path,
        rows=[S.finding_row("now", run_id="now")],
        curator=S.FakeCurator(writes={"l1.md": S.lesson("now", "from-an-earlier-batch")}),
    )
    assert sc.run() == 0
    assert sc.head_files() == [LESSON]


def test_a_tick_whose_corpus_is_already_dirty_when_it_starts_773(tmp_path):
    """A tick refuses to start on an already-dirty corpus, loudly (a named, reported
    disposition), never silently widening vouching to whatever is under the corpus."""
    sc = S.build_draft_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1")],
        curator=S.FakeCurator(writes={"l1.md": S.lesson("f1")}),
        max_attempts=1,
    )
    (sc.corpus / "left-behind.md").write_text(S.lesson("some-old-batch"), encoding="utf-8")
    assert sc.run() == 2
    assert sc.curator.calls == []
    reported = " ".join(
        [r.get("deadletter_reason", "") for r in sc.graveyard()]
        + [r.get("reason", "") for r in S.stuck_records(sc.paths, sc.channel)]
    )
    assert "left-behind.md" in reported or "dirty" in reported.lower()


def test_a_non_markdown_file_left_under_the_corpus_773(tmp_path):
    """A non-`.md` file left under the corpus is dropped before vouching and reset away; the
    lesson beside it still lands."""
    sc = S.build_draft_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1")],
        curator=S.FakeCurator(
            writes={"l1.md": S.lesson("f1"), "scratch.txt": "notes to self\n"}
        ),
    )
    assert sc.run() == 0
    assert sc.head_files() == [LESSON]
    assert not (sc.corpus / "scratch.txt").exists()
