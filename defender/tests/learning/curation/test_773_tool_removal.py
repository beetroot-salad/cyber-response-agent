"""#773: the curator partitions a batch into committed and consumed-skip only; the questioner
channel keeps vouching without a verdict step."""
from __future__ import annotations


from defender.tests.support.learning.curation import _spec773 as S

LESSON = "defender/lessons/l1.md"
QLESSON = "defender/lessons-questioner/w1.md"


def test_the_curator_partitions_the_batch_into_committed_and_consumed_skip_only_773(tmp_path):
    """`FINDINGS_BUCKETS` declares exactly `committed` and `consumed_skip`;"""
    from defender.learning.author.lessons import run as lessons_run

    assert [b.name for b in lessons_run.FINDINGS_BUCKETS] == ["committed", "consumed_skip"]
    assert all(b.reason_field != "forward_bad_reason" for b in lessons_run.FINDINGS_BUCKETS)

    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("ok", run_id="ok"), S.finding_row("skip", run_id="skip")],
        curator=S.FakeCurator(
            writes={"l1.md": S.lesson("ok")},
            committed=["ok"],
            consumed_skip=[{"finding_id": "skip", "reason": "dup"}],
        ),
    )
    assert sc.run() == 0
    assert sc.category_of("ok") == "consumed_committed"
    assert sc.category_of("skip") == "consumed_skip"


def test_author_result_carries_an_unrecognized_bucket_key_773(tmp_path):
    for stray in ("held_forward_bad", "some_key_nobody_declared"):
        sc = S.build_scene(
            tmp_path / stray,
            rows=[S.finding_row("f1", run_id="f1")],
            curator=S.FakeCurator(
                writes={"l1.md": S.lesson("f1")},
                extra_result={stray: [{"finding_id": "f1", "reason": "r"}]},
            ),
        )
        assert sc.run() == 2, stray
        assert sc.head_files() == [], stray


def test_author_result_consumed_skip_bucket_is_missing_773(tmp_path):
    """A MISSING bucket key is an empty list, not a violation."""
    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1")],
        curator=S.FakeCurator(
            writes={"l1.md": S.lesson("f1")},
            result={"committed": ["f1"], "commit_message": "one finding"},
        ),
    )
    assert sc.run() == 0
    assert sc.head_files() == [LESSON]
    assert sc.category_of("f1") == "consumed_committed"


def test_a_citation_of_an_earlier_batch_finding_is_not_verified_773(tmp_path):
    """N1."""
    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("now", run_id="now")],
        seed_corpus={"old.md": S.lesson("earlier-batch-id")},
        curator=S.FakeCurator(writes={"l1.md": S.lesson("now", "earlier-batch-id")}),
    )
    assert sc.run() == 0


def test_a_questioner_tick_runs_vouching_and_no_verdict_step_773(tmp_path):
    """The questioner channel vouches every changed corpus file."""
    sc = S.build_questioner_scene(
        tmp_path,
        rows=[S.world_row("w1")],
        curator=S.FakeCurator(writes={"w1.md": S.lesson("w1")}),
    )
    assert sc.run() == 0
    assert sc.head_files() == [QLESSON]


def test_the_questioner_channel_still_refuses_an_unvouched_file_773(tmp_path):
    """The questioner channel still refuses an unvouched file."""
    sc = S.build_questioner_scene(
        tmp_path,
        rows=[S.world_row("w1")],
        curator=S.FakeCurator(writes={"stray.md": S.lesson("not-this-batch")},
                              committed=["w1"]),
    )
    assert sc.run() == 2
    assert sc.head_files() == []

    control = S.build_questioner_scene(
        tmp_path / "control",
        rows=[S.world_row("w1")],
        curator=S.FakeCurator(writes={"w1.md": S.lesson("w1")}),
    )
    assert control.run() == 0
    assert control.head_files() == [QLESSON]


def test_a_questioner_tick_with_a_changed_file_citing_no_batch_finding_773(tmp_path):
    """Unvouched → `AuthorError`, the SAME disposition as on the lessons channel."""
    sc = S.build_questioner_scene(
        tmp_path,
        rows=[S.world_row("w1")],
        curator=S.FakeCurator(writes={"orphan.md": S.lesson("someone-else")},
                              committed=["w1"]),
    )
    assert sc.run() == 2
    assert sc.corpus_files() == []


def test_a_questioner_tick_whose_curator_committed_nothing_773(tmp_path):
    sc = S.build_questioner_scene(
        tmp_path,
        rows=[S.world_row("w1")],
        curator=S.FakeCurator(writes={}, committed=[],
                              consumed_skip=[{"finding_id": "w1", "reason": "nothing to say"}]),
    )
    assert sc.run() == 0
    assert sc.head_files() == []
    assert sc.category_of("w1") == "consumed_skip"


def test_the_questioner_tick_skips_only_the_verdict_stage_not_the_surrounding_ordering_773(
    tmp_path,
):
    """`forward_check=None` skips M3.3-4 and M4 ONLY."""
    sc = S.build_questioner_scene(
        tmp_path,
        rows=[S.world_row("w1"), S.world_row("w2")],
        curator=S.FakeCurator(writes={"w1.md": S.lesson("w1")}, committed=["w1", "w2"]),
    )
    assert sc.run() == 0
    assert sc.head_files() == [QLESSON]
    assert sc.category_of("w1") == "consumed_committed"
    assert sc.category_of("w2") is None
