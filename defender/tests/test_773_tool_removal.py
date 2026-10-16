"""#773 — M1's deletion and O7's untouched sibling. (M2's per-channel check wiring and O10's
key preflight went with the check, #1166.)
"""
from __future__ import annotations



from defender.tests import _spec773 as S

LESSON = "defender/lessons/l1.md"
QLESSON = "defender/lessons-questioner/w1.md"


# ---------------------------------------------------------------------------
# M1 — the curator writes, never checks
# ---------------------------------------------------------------------------


def test_the_curator_partitions_the_batch_into_committed_and_consumed_skip_only_773(tmp_path):
    """`FINDINGS_BUCKETS` declares exactly `committed` and `consumed_skip`; the
    `held_forward_bad` bucket and its `forward_bad_reason` field are gone.

    A lesson the check refuses is no longer a bucket the curator reports into — it is a
    verdict the drain computes. Positive control: both surviving buckets still route a row
    to its own disposition."""
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
    """An AUTHOR_RESULT carrying ANY key outside `{committed, consumed_skip}` fails partition
    validation explicitly — including the removed `held_forward_bad`, and including a key
    that was never recognised at all.

    §7 FK-29, the human's decision, on a fact the probe established:
    `validate_agent_result_partition` (`shared.py:205-229`) is an ALLOW-LIST — it reads only
    recognised buckets and never flags an unrecognised key — so once M1 drops
    `held_forward_bad` from `FINDINGS_BUCKETS`, a curator still emitting it would NOT be
    caught. The demand it sharpens was green for the wrong reason."""
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
    """A MISSING bucket key is an empty list, not a violation: a curator that committed
    everything and skipped nothing need not spell the empty bucket.

    §7 FK-29's other half, and the positive control the strictness demand needs — a closed
    schema that also rejects absence would fault every ordinary tick."""
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
    """N1: findings from EARLIER batches cited by a folded file are not re-verified. Only
    this batch's rows carry a live direction and ground truth.

    The file cites one this-batch id and one earlier-batch id; exactly one pair is minted.
    Corpus-wide regression is `evals/held_out.py`'s job, not this delta's."""
    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("now", run_id="now")],
        seed_corpus={"old.md": S.lesson("earlier-batch-id")},
        curator=S.FakeCurator(writes={"l1.md": S.lesson("now", "earlier-batch-id")}),
    )
    assert sc.run() == 0


# ---------------------------------------------------------------------------
# O7 — the questioner channel keeps today's behaviour
# ---------------------------------------------------------------------------


def test_a_questioner_tick_runs_vouching_and_no_verdict_step_773(tmp_path):
    """The questioner channel vouches every changed corpus file: M3.2, the explicit-list
    commit and the tree-derived `committed` all apply. (No channel runs a verdict step since
    #1166.)

    A PARITY demand: the constraint enforced on the lessons channel's access to the corpus
    is enforced on the questioner's too."""
    sc = S.build_questioner_scene(
        tmp_path,
        rows=[S.world_row("w1")],
        curator=S.FakeCurator(writes={"w1.md": S.lesson("w1")}),
    )
    assert sc.run() == 0
    assert sc.head_files() == [QLESSON]


def test_the_questioner_channel_still_refuses_an_unvouched_file_773(tmp_path):
    """The questioner channel still refuses an unvouched file: its `lambda r: True` exempt
    predicate governs the VERDICT step only, never vouching.

    O7 names the #852 vouching gate explicitly, and this is the arm a channel with every row
    exempt would lose if `exempt` were read one step too early. Positive control: a properly
    cited file on the same channel does commit."""
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
    """Unvouched → `AuthorError`, the SAME disposition as on the lessons channel.

    The parity is the point: the questioner's exempt predicate is about the verdict step,
    and its vouching is the lessons channel's vouching."""
    sc = S.build_questioner_scene(
        tmp_path,
        rows=[S.world_row("w1")],
        curator=S.FakeCurator(writes={"orphan.md": S.lesson("someone-else")},
                              committed=["w1"]),
    )
    assert sc.run() == 2
    assert sc.corpus_files() == []


def test_a_questioner_tick_whose_curator_committed_nothing_773(tmp_path):
    """Vouching is now REACHED on a questioner tick that committed nothing — today it is
    skipped, because the #852 gate sits inside `if committed:` (G13) — and it has no work,
    so the observable outcome is unchanged: nothing committed, nothing refused.

    The behaviour delta is invisible from outside on this tick, which is exactly why the
    demand is written against a tick where it IS visible (the previous test) as well."""
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
    """`forward_check=None` skips M3.3-4 and M4 ONLY: vouching, the explicit-list commit and
    the tree-derived `committed` all still run, in the same relative order as the lessons
    channel.

    Observed as the ordering's consequences rather than as the order itself: the commit
    names exactly the vouched file, and the consumption is keyed on that commit."""
    sc = S.build_questioner_scene(
        tmp_path,
        rows=[S.world_row("w1"), S.world_row("w2")],
        curator=S.FakeCurator(writes={"w1.md": S.lesson("w1")}, committed=["w1", "w2"]),
    )
    assert sc.run() == 0
    assert sc.head_files() == [QLESSON]
    assert sc.category_of("w1") == "consumed_committed"
    assert sc.category_of("w2") is None


