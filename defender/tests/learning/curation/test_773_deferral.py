"""#773: bounded deferral and conservation of findings: the fate each claimed row gets from a tick.

Every tick runs over a batch's git-free draft (`_spec773.build_draft_scene`). A tick's fates are the
`outcomes` map the claim fills (#1278 D1): `deferred`, `skipped`, or none (a committed row stays in the batch; a
row in no bucket returns to waiting by the tick's citation rule).

Retired with the file queue (#1278 D1, design r8 Locks and Items; the store owns the counters, the ceilings and the
wake gate, and no queue file is rotated or locked):
- the `deferrals` counter bump, its graveyard at the ceiling, ten consecutive deferring ticks, the deferral ceiling
  reason, the `deferrals`/`attempts` counters moving independently, a deferred row as the wake gate sees it
  (`_pending_queue_counts`), and a tick that both defers and closes its rotation: covered by
  `tests/learning/store_1278/test_items_1278.py::test_a_deferred_item_waits_with_a_deferral_counted_and_dies_at_the_ceiling`
  and `::test_deferrals_and_attempts_are_separate_counters_with_the_deferral_ceiling_of_its_own`;
- the held report's `deferred` group (the report file is gone: the fate and its reason are the item's);
- a rotation that expires against the append lock / repo lock at the tick's close, leaving the queue as it was (no
  queue file, no append lock, no rotation: design r8 Locks).
"""
from __future__ import annotations

from defender.tests.support.learning.curation import _spec773 as S

LESSON = "agent/lessons/l1.md"
LESSON2 = "agent/lessons/l2.md"


def _orphan_tick(tmp_path, **kw):
    """The plainest deferral: a finding reported committed that no approved file cites."""
    return S.build_draft_scene(
        tmp_path,
        rows=[S.finding_row("a", run_id="a"), S.finding_row("orphan", run_id="orphan")],
        curator=S.FakeCurator(writes={"l1.md": S.lesson("a")}, committed=["a", "orphan"]),
        **kw,
    )


def test_a_row_reported_committed_that_no_file_cites_is_deferred_and_the_cited_one_stays_in_the_batch_773(tmp_path):
    """The deferral fate itself: the uncited-but-reported row is `deferred` (never consumed, never skipped), the
    cited one is named nowhere, and the lesson lands."""
    sc = _orphan_tick(tmp_path)
    assert sc.run() == 0
    assert set(sc.outcomes) == {("finding", "orphan")}
    assert sc.fate("orphan") == ("deferred", None)
    assert sc.head_files() == [LESSON]


def test_a_finding_cited_by_two_approved_files_is_committed_once_and_named_nowhere_773(tmp_path):
    sc = S.build_draft_scene(
        tmp_path,
        rows=[S.finding_row("shared", run_id="shared")],
        curator=S.FakeCurator(
            writes={"l1.md": S.lesson("shared"), "l2.md": S.lesson("shared")},
            committed=["shared"],
        ),
    )
    assert sc.run() == 0
    assert sc.head_files() == [LESSON, LESSON2]
    assert sc.outcomes == {}, "a committed finding is not given a second ending"


def test_every_batch_row_reaches_exactly_one_disposition_773(tmp_path):
    """The conservation invariant, over a tick that produces all three endings at once: committed (cited, named
    nowhere, stays in the batch), skipped with the curator's reason, and deferred."""
    sc = S.build_draft_scene(
        tmp_path,
        rows=[
            S.finding_row("ok", run_id="ok"),
            S.finding_row("skip", run_id="skip"),
            S.finding_row("orphan", run_id="orphan"),
        ],
        curator=S.FakeCurator(
            writes={"l1.md": S.lesson("ok")},
            committed=["ok", "orphan"],
            consumed_skip=[{"finding_id": "skip", "reason": "already taught"}],
        ),
    )
    assert sc.run() == 0
    assert sc.fate("ok") is None and sc.head_files() == [LESSON]
    assert sc.fate("skip") == ("skipped", "already taught")
    assert sc.fate("orphan") == ("deferred", None)
    assert set(sc.outcomes) == {("finding", "skip"), ("finding", "orphan")}


def test_a_batch_row_the_curator_mentions_nowhere_and_no_file_cites_773(tmp_path):
    """A row the curator mentions in no bucket and that no changed file cites is decided nothing: no deferral, no
    skip, no death (the tick returns it to waiting)."""
    sc = S.build_draft_scene(
        tmp_path,
        rows=[S.finding_row("named", run_id="named"), S.finding_row("ghost", run_id="ghost")],
        curator=S.FakeCurator(writes={"l1.md": S.lesson("named")}, committed=["named"]),
    )
    assert sc.run() == 0
    assert sc.fate("ghost") is None
    assert sc.outcomes == {}


def test_each_skipped_row_gets_its_skip_exactly_once_even_when_nothing_is_committed_773(tmp_path):
    """A claim that commits nothing still ends every row the curator skipped, each with its own fate."""
    sc = S.build_draft_scene(
        tmp_path,
        rows=[S.finding_row("dup", run_id="dup"), S.finding_row("skip", run_id="skip")],
        curator=S.FakeCurator(
            committed=[],
            consumed_skip=[{"finding_id": "dup", "reason": "dup"},
                           {"finding_id": "skip", "reason": "dup"}],
        ),
    )
    assert sc.run() == 0
    assert sc.commit_count() == 1
    assert sc.named("skipped") == {"dup": "dup", "skip": "dup"}
    assert len(sc.outcomes) == 2


def test_a_tick_whose_batch_faults_before_reaching_the_deferred_list_computation_773(
    tmp_path,
):
    """A batch that faults while authoring never reaches the deferral step: the uncited row
    is not deferred (the unfaulted control defers it)."""
    sc = S.build_draft_scene(
        tmp_path,
        rows=[S.finding_row("bad", run_id="bad"), S.finding_row("orphan", run_id="orphan")],
        curator=S.FakeCurator(
            writes={"l1.md": S.lesson("bad")},
            committed=["bad", "orphan"],
            raises=S.author_error("faulted in the authoring region"),
        ),
    )
    assert sc.run() == 2
    assert sc.fate("orphan") is None
    assert sc.head_files() == []

    control = S.build_draft_scene(
        tmp_path / "control",
        rows=[S.finding_row("bad", run_id="bad"), S.finding_row("orphan", run_id="orphan")],
        curator=S.FakeCurator(
            writes={"l1.md": S.lesson("bad")}, committed=["bad", "orphan"]
        ),
    )
    assert control.run() == 0
    assert control.fate("orphan") == ("deferred", None)
    assert control.head_files() == ["agent/lessons/l1.md"]


QLESSON = "agent/lessons-questioner/w1.md"


def test_the_curator_partitions_the_batch_into_committed_and_consumed_skip_only_773(tmp_path):
    """`FINDINGS_BUCKETS` declares exactly `committed` and `consumed_skip`, and a tick sorts
    its rows into those two."""
    from defender.learning.author.lessons import run as lessons_run

    assert [b.name for b in lessons_run.FINDINGS_BUCKETS] == ["committed", "consumed_skip"]
    assert all(b.reason_field != "forward_bad_reason" for b in lessons_run.FINDINGS_BUCKETS)

    sc = S.build_draft_scene(
        tmp_path,
        rows=[S.finding_row("ok", run_id="ok"), S.finding_row("skip", run_id="skip")],
        curator=S.FakeCurator(
            writes={"l1.md": S.lesson("ok")},
            committed=["ok"],
            consumed_skip=[{"finding_id": "skip", "reason": "dup"}],
        ),
    )
    assert sc.run() == 0
    assert sc.fate("ok") is None
    assert sc.fate("skip") == ("skipped", "dup")


def test_author_result_carries_an_unrecognized_bucket_key_773(tmp_path):
    for stray in ("held_forward_bad", "some_key_nobody_declared"):
        sc = S.build_draft_scene(
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
    """A missing bucket key is an empty list, not a violation."""
    sc = S.build_draft_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1")],
        curator=S.FakeCurator(
            writes={"l1.md": S.lesson("f1")},
            result={"committed": ["f1"], "commit_message": "one finding"},
        ),
    )
    assert sc.run() == 0
    assert sc.head_files() == [LESSON]
    assert sc.fate("f1") is None


def test_the_questioner_channel_still_refuses_an_unvouched_file_773(tmp_path):
    """An unvouched file fails the questioner tick as it does the lessons tick (`AuthorError`,
    the draft reset); the control lands."""
    sc = S.build_questioner_draft_scene(
        tmp_path,
        rows=[S.world_row("w1")],
        curator=S.FakeCurator(writes={"stray.md": S.lesson("not-this-batch")},
                              committed=["w1"]),
    )
    assert sc.run() == 2
    assert sc.head_files() == []
    assert sc.corpus_files() == []

    control = S.build_questioner_draft_scene(
        tmp_path / "control",
        rows=[S.world_row("w1")],
        curator=S.FakeCurator(writes={"w1.md": S.lesson("w1")}),
    )
    assert control.run() == 0
    assert control.head_files() == [QLESSON]


def test_a_questioner_tick_whose_curator_committed_nothing_773(tmp_path):
    sc = S.build_questioner_draft_scene(
        tmp_path,
        rows=[S.world_row("w1")],
        curator=S.FakeCurator(writes={}, committed=[],
                              consumed_skip=[{"finding_id": "w1", "reason": "nothing to say"}]),
    )
    assert sc.run() == 0
    assert sc.head_files() == []
    assert sc.fate("w1") == ("skipped", "nothing to say")


def test_the_questioner_channel_does_not_consume_a_committed_row_no_file_cites_773(tmp_path):
    """On the questioner channel too, a row claimed committed that no file cites is not
    consumed, while the cited one lands."""
    sc = S.build_questioner_draft_scene(
        tmp_path,
        rows=[S.world_row("w1"), S.world_row("w2")],
        curator=S.FakeCurator(writes={"w1.md": S.lesson("w1")}, committed=["w1", "w2"]),
    )
    assert sc.run() == 0
    assert sc.head_files() == [QLESSON]
    assert sc.fate("w1") is None
    assert sc.fate("w2") == ("deferred", None)
