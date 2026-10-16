"""#1007 — the `subject` partition, the second queue channel, and who owns a row's identity.

O1/M6 splits findings by `subject` into two channels; O8/M10 keeps the DEFENDER vocabulary
pinned; A3 settles that the PASS owns a row's identity and the model owns only its content.

#1234 CHANGED TWO THINGS THIS FILE ONCE PINNED. A finding's subject is now the reply list it is
filed under (`investigator_findings` -> defender, `world_findings` -> world), not a `subject`
key the model writes; and the world vocabulary is CLOSED (M4: `unreachable`, `incoherent`,
`mislabelled`), where #1007's G-3 had kept it open. The per-channel asymmetry is kept: each
channel's appender admits its own vocabulary and refuses the other's.
"""
from __future__ import annotations

import json
import threading

import pytest

from defender.learning.core.state import FINDINGS, QUESTIONER_FINDINGS, LearningState
from defender.tests import _world_1007 as W
from defender.tests._curator1134 import author_trees
from defender.tests.judge_contrast_1234 import _spec1234 as S

#: The finding id every hand-fed row here carries unless a scenario says otherwise.
FID = f"{W.EPISODE_ID}/b/0/0"

#: The three keys only a DEFENDER row carries (#1234 M7); the rest is the head both share.
DEFENDER_ONLY = (S.CONTRAST, S.ON_PATH, S.DOUBT)


def queue_row(**over) -> dict:
    """One defender queue row as `enqueue.build_finding_row` mints it (#1234's shape:
    `contrast_evidence`, `on_verdict_path`, `world_label_doubted`; no `judge_outcome`)."""
    over.setdefault("type", "lead-set")
    return S.defender_row(over.pop("finding_id", FID), **over)


def world_row(**over) -> dict:
    """One questioner-channel row: the shared finding-row head plus `world`, `systems`,
    `provenance` and `subject` — a design world finding (a plan-class citation)."""
    return S.world_row(over.pop("finding_id", FID), **over)


def world_reply(**kw) -> str:
    """A world-scope reply's TEXT carrying the given filed lists (bucket `none` by default)."""
    kw.setdefault("bucket", S.NO_BUCKET)
    kw.setdefault("systems", [])
    return S.as_text(S.world_reply(**kw))


# ---------------------------------------------------------------------------------------
# O1/M6 — the partition, at the validator and at both appenders
# ---------------------------------------------------------------------------------------


def test_world_row_refused_at_the_defender_appender(tmp_path):
    """A `subject: world` row may not reach the DEFENDER findings channel.

    Observably true: handing `append_rows` a world-subject row raises this design's refusal and
    leaves `_pending/findings.jsonl` untouched; the same row handed to the questioner appender
    lands. The positive control is what makes the refusal a fact about routing rather than
    about an appender that refuses everything.

    What failure looks like: world findings on the defender queue, where the lessons gate reads
    them and the defender corpus grows advice about worlds it cannot act on.
    """
    enqueue = W.mod("learning.judge.enqueue")
    paths = W.loop_paths(tmp_path)

    with pytest.raises(W.refusals()):
        enqueue.append_rows(tmp_path, [world_row()], state=W.learning_state(paths))

    assert W.queue_rows(paths, FINDINGS) == [], "the refused world row still landed"
    enqueue.append_world_rows(tmp_path, [world_row()], state=W.learning_state(paths))
    assert [r["subject"] for r in W.queue_rows(paths, QUESTIONER_FINDINGS)] == [W.SUBJECT_WORLD]


def test_each_channel_gates_a_row_type_against_its_own_vocabulary(tmp_path):
    """Each channel's appender checks a row's `type` against ITS OWN vocabulary: the
    questioner channel admits the world-finding buckets, the defender channel the queueable
    defender types, and neither admits the other's (#1234 M4 closed the world side; #1007 R2's
    per-channel asymmetry is kept).

    Observably true: a world row typed `incoherent` is appended and stored verbatim, while the
    same string on a defender row is refused; a world row typed with a defender type, or with
    a string no vocabulary holds, is refused.

    What failure looks like: one shared validator, so either every world finding is refused as
    an unqueueable defender type, or a defender type rides onto the questioner channel and the
    questioner corpus learns from advice about an investigation.
    """
    enqueue = W.mod("learning.judge.enqueue")
    cfg = W.mod("learning.core.config")
    paths = W.loop_paths(tmp_path)
    assert "incoherent" not in cfg.QUEUEABLE_FINDING_TYPES

    enqueue.append_world_rows(tmp_path, [world_row(type="incoherent")],
                              state=W.learning_state(paths))

    assert [r["type"] for r in W.queue_rows(paths, QUESTIONER_FINDINGS)] == ["incoherent"]
    with pytest.raises(W.refusals()):
        enqueue.append_rows(tmp_path, [queue_row(type="incoherent")],
                            state=W.learning_state(paths))
    for foreign in ("lead-set", "a-bucket-nobody-listed"):
        with pytest.raises(W.refusals()):
            enqueue.append_world_rows(tmp_path, [world_row(type=foreign, finding_id="x/b/0/9")],
                                      state=W.learning_state(paths))
    assert len(W.queue_rows(paths, QUESTIONER_FINDINGS)) == 1


def test_lessons_gate_refuses_direction_world_loudly(tmp_path):
    """The defender curator's own gate refuses a `direction: world` row it should never see.

    Observably true: `_gate_findings` handed a world-direction row raises rather than routing
    it — the second screen behind the appender, and the one that would otherwise turn a
    mis-routed row into an authored defender lesson. Loudly, because a silent hold would leave
    the row queued forever with nothing saying why.

    What failure looks like: the gate falls through to the direction branch and holds the row
    as `retired_direction(...)` — indistinguishable from an ordinary un-authorable finding.
    """
    author = W.mod("learning.author.lessons.run")
    paths = W.loop_paths(tmp_path)
    cfg = author.build_author_config(paths, trees=author_trees(paths), state=LearningState.open(paths))

    with pytest.raises(W.refusals()):
        author._gate_findings([queue_row(direction=W.SUBJECT_WORLD, subject=W.SUBJECT_WORLD)],
                              cfg)


# ---------------------------------------------------------------------------------------
# O8/M10 + R2 — the defender side stays pinned, the selector is per subject
# ---------------------------------------------------------------------------------------


# ---------------------------------------------------------------------------------------
# M6 — the second channel's own shape
# ---------------------------------------------------------------------------------------


def test_the_questioner_channel_declares_its_own_append_lock_and_shares_the_drain_lock(
        tmp_path):
    """The questioner channel gets its OWN append lock and consumed file, and SHARES the drain
    lock with the findings channel.

    Observably true: `QUESTIONER_FINDINGS`'s `queue`, `consumed` and `append_lock` are distinct
    from the findings channel's, and its drain role is the findings channel's, so its lock file
    is the byte-identical path. Sharing the drain lock is what keeps two curators from holding
    one worktree at once; a per-channel drain lock would give that up for nothing.

    What failure looks like: a second channel whose drain lock is genuinely separate. Two
    curators then enter one worktree concurrently and the batch's commit races itself.
    """
    paths = W.loop_paths(tmp_path)
    root, findings, questioner = paths.state_root, FINDINGS, QUESTIONER_FINDINGS

    assert (root / questioner.queue).name == W.QUESTIONER_QUEUE_FILENAME
    assert root / questioner.queue != root / findings.queue
    assert root / questioner.consumed != root / findings.consumed
    assert root / questioner.append_lock != root / findings.append_lock, (
        "the two channels share an append lock, so an appender on one blocks the other")
    assert root / questioner.drain_role.file == root / findings.drain_role.file, (
        f"the questioner channel's drain lock is {root / questioner.drain_role.file} — a separate "
        "lock gives up the mutual exclusion that keeps two curators out of one worktree")
    assert questioner.id_key == "finding_id"


def test_a_world_queue_row_is_a_full_finding_row_plus_four_fields(tmp_path):
    """A questioner-channel row is a full `FindingRow` head plus `world`, `systems`,
    `provenance` and `subject` — not a reduced shape of its own (#1224: `systems` replaced
    `pattern` and `holding_system`; #1234: the three defender-only fields stay off it).

    Observably true: the row that lands carries every key of the head a defender row carries
    (so any reader of a finding row can read it) with `run_id` the episode id, `finding_id` the
    idempotency key and `direction: world`, plus the four world-lane fields.

    What failure looks like: a bespoke five-key row. Every shared reader — the drain's
    idempotency, the curator's provenance list, the malformed-line counter — then needs a
    second code path, and the ones that do not get it read the row as malformed.
    """
    enqueue = W.mod("learning.judge.enqueue")
    paths = W.loop_paths(tmp_path)

    enqueue.append_world_rows(tmp_path, [world_row()], state=W.learning_state(paths))

    landed = W.queue_rows(paths, QUESTIONER_FINDINGS)[0]
    for key in queue_row():
        if key not in DEFENDER_ONLY:
            assert key in landed, f"the world row is missing the finding-row key {key!r}"
    assert landed["direction"] == W.SUBJECT_WORLD
    assert landed["run_id"] == W.EPISODE_ID
    for key in ("world", "systems", "provenance", "subject"):
        assert key in landed, f"the world row is missing {key!r}"


def test_two_appends_of_one_finding_id_land_once(tmp_path):
    """The questioner channel is idempotent on `finding_id`, exactly as the defender one is.

    Observably true: appending the same row twice leaves one row on the queue. The channel
    declares `id_key="finding_id"`, and a re-graded episode must not double-author a lesson.

    What failure looks like: a plain append. A re-grade of one episode then produces a second
    identical lesson, and the corpus grows one copy per retry.
    """
    enqueue = W.mod("learning.judge.enqueue")
    paths = W.loop_paths(tmp_path)

    enqueue.append_world_rows(tmp_path, [world_row()], state=W.learning_state(paths))
    enqueue.append_world_rows(tmp_path, [world_row()], state=W.learning_state(paths))

    rows = W.queue_rows(paths, QUESTIONER_FINDINGS)
    assert [r["finding_id"] for r in rows] == [f"{W.EPISODE_ID}/b/0/0"], (
        f"one finding id landed twice: {rows}")


# ---------------------------------------------------------------------------------------
# The closed world vocabulary (#1234 M4), made mechanical
# ---------------------------------------------------------------------------------------


def test_a_non_string_world_bucket_is_refused(tmp_path):
    """A world bucket must be a STRING of the vocabulary — never a list, number or mapping.

    Observably true: `bucket: ["incoherent"]` (and the other non-strings) on a world finding is
    refused at `validate_reply`. The value becomes a queue row's `type` and a lesson's
    frontmatter key; an unhashable value there raises `TypeError` out of a membership test
    whose whole contract is to answer with this design's refusal.

    What failure looks like: the membership test meets a list-valued bucket and raises the
    wrong class, taking a whole batch down.
    """
    run = W.mod("learning.judge.run")

    run.validate_reply(world_reply(world=[S.wf("incoherent")]))      # the control
    for bad in (["incoherent"], 7, {"a": 1}, None):
        with pytest.raises(W.refusals()):
            run.validate_reply(world_reply(world=[S.wf(bad)]))


def test_an_empty_whitespace_or_unlisted_world_bucket_is_refused_never_normalised(tmp_path):
    """An empty, whitespace-only or unlisted world bucket is REFUSED — the vocabulary is
    closed (#1234 M4 replaced #1007's open one), and nothing is trimmed or coerced into it.

    Observably true: `""`, `"   "`, `"\t\n"` and a string no list holds are each refused at
    `validate_reply`, while every one of the three world-finding buckets is admitted and kept
    exactly as written.

    What failure looks like: the validator normalises (`"  incoherent "` becomes `incoherent`)
    or admits a drifting string, and the questioner queue carries a type its routing and its
    curator have no rule for.
    """
    run = W.mod("learning.judge.run")

    for bucket in sorted(run.WORLD_FINDING_BUCKETS):
        parsed = run.validate_reply(world_reply(world=[S.wf(bucket)]))
        assert parsed.world_findings[0].bucket == bucket
    for raw in ("", "   ", "\t\n", "shape-invention"):
        with pytest.raises(W.refusals()):
            run.validate_reply(world_reply(world=[S.wf(raw)]))


def test_a_world_finding_cannot_borrow_a_defender_bucket_and_the_list_decides_the_channel(
        tmp_path):
    """A world finding may not spell its bucket like a defender one; the LIST a finding is
    filed under — never the string — decides which channel its row is built for.

    Observably true: a world finding bucketed `lead-set` is refused at `validate_reply`, and
    the questioner appender refuses a `lead-set` world row; the same `lead-set` filed as an
    investigator finding validates, and a defender row of that type lands on the findings
    channel.

    What failure looks like: the bucket string is used to infer the subject, and the moment a
    model spells a world finding `lead-quality` the row is authored as a defender lesson.
    """
    run = W.mod("learning.judge.run")
    enqueue = W.mod("learning.judge.enqueue")
    paths = W.loop_paths(tmp_path)

    with pytest.raises(W.refusals()):
        run.validate_reply(world_reply(world=[S.wf("lead-set")]))
    parsed = run.validate_reply(world_reply(investigator=[S.inv("lead-set")]))
    assert [f.bucket for f in parsed.investigator_findings] == ["lead-set"]

    with pytest.raises(W.refusals()):
        enqueue.append_world_rows(tmp_path, [world_row(type="lead-set")],
                                  state=W.learning_state(paths))
    enqueue.append_rows(tmp_path, [queue_row(type="lead-set")], state=W.learning_state(paths))
    assert W.queue_rows(paths, QUESTIONER_FINDINGS) == []
    assert len(W.queue_rows(paths, FINDINGS)) == 1


# ---------------------------------------------------------------------------------------
# The rows themselves: what the pass owns and what the model owns (A3)
# ---------------------------------------------------------------------------------------


def test_a_defender_queue_row_carries_its_subject_key(tmp_path):
    """A defender row carries `subject: defender` EXPLICITLY, rather than by absence.

    Observably true: the row that lands on `_pending/findings.jsonl` has the key with that
    value. Once two channels exist, "no subject key" and "subject: defender" are two different
    facts, and a reader that infers the first from the second cannot tell a pre-change row from
    a mis-routed one.

    What failure looks like: the defender lane is left untouched "because nothing changed", and
    every consumer downstream has to guess.
    """
    enqueue = W.mod("learning.judge.enqueue")
    paths = W.loop_paths(tmp_path)

    enqueue.append_rows(tmp_path, [queue_row()], state=W.learning_state(paths))

    assert W.queue_rows(paths, FINDINGS)[0]["subject"] == W.SUBJECT_DEFENDER
    # REQUIRED, not merely carried: a row that reached the appender without one would
    # otherwise land and read as a defender row by default, which is the inference this key
    # exists to remove. Without this half the assertion above passes on an appender that
    # copies whatever it is handed.
    bare = queue_row()
    bare.pop("subject")
    with pytest.raises(W.refusals()):
        enqueue.append_rows(tmp_path, [bare], state=W.learning_state(paths))
    assert len(W.queue_rows(paths, FINDINGS)) == 1, "the subject-less row landed anyway"


def test_a_defender_subject_row_cannot_reach_the_questioner_curator(tmp_path):
    """The partition holds in BOTH directions: a defender row may not reach the questioner
    channel either.

    Observably true: `append_world_rows` refuses a `subject: defender` row and the questioner
    channel stays empty; the questioner curator, driven over a channel seeded with such a row,
    authors nothing from it. The security dive states both directions and only one of them had
    a demand — the reverse leak is the one that puts defender advice into the corpus the
    QUESTIONER reads back at call 1, one hop from authoring the next family.

    What failure looks like: the guard is written as "world rows go here", with nothing saying
    what may not.
    """
    enqueue = W.mod("learning.judge.enqueue")
    paths = W.loop_paths(tmp_path)

    with pytest.raises(W.refusals()):
        enqueue.append_world_rows(tmp_path, [queue_row()], state=W.learning_state(paths))

    assert W.queue_rows(paths, QUESTIONER_FINDINGS) == []


def test_a_model_supplied_world_is_ignored_and_the_draws_own_directory_wins(
        tmp_path, monkeypatch):
    """`world` is stamped from the draw's own world directory; a model-supplied `world` is
    ignored.

    Observably true: b's design finding claiming `world: c`, and c's claiming `world: b`, land
    on the questioner queue stamped `b` and `c` respectively, each id naming its own world,
    because those are the worlds the draws were about. Identity belongs to the pass; the model
    owns content only.

    What failure looks like: a model relabels its own finding onto a sibling, and a lesson is
    authored about a world that never had the property described.
    """
    built = W.contrast_family(tmp_path, monkeypatch)
    judge = S.judge({
        "b": S.world_reply(S.NO_BUCKET, [], world=[S.wf(world="c")]),
        "c": S.world_reply(S.NO_BUCKET, [], world=[S.wf(evidence=[S.plan_ptr("c")],
                                                        world="b")])})

    S.grade(built, judge)

    rows = [r for r in S.questioner_queue() if r["provenance"] == "model"]
    assert {r["world"] for r in rows} == {"b", "c"}, (
        f"the model's own `world` value reached the row: {[r['world'] for r in rows]}")
    for row in rows:
        assert row["finding_id"].split("/")[1] == row["world"], (
            f"row {row['finding_id']} is stamped for world {row['world']!r} — the id and the "
            "stamp name different worlds")


def test_every_family_level_finding_carries_a_null_world(tmp_path, monkeypatch):
    """A family-level finding is about the FAMILY, so its `world` is null.

    Observably true: a design finding from the family call (a plan pointer at the family-level
    part of the manifest) lands with `world: None` and `source_run_dir` naming the episode dir
    rather than a world's archive.

    What failure looks like: the family finding is stamped onto whichever world happened to be
    drawn last, and a family-level observation is authored as a lesson about one world.
    """
    built = W.contrast_family(tmp_path, monkeypatch)
    judge = S.judge({S.FAMILY: S.family_reply(world=[S.wf(evidence=[S.plan_ptr()])])})

    S.grade(built, judge)

    family_rows = [r for r in S.questioner_queue() if r["finding_id"].split("/")[1] == "family"]
    assert family_rows, "the family draw enqueued nothing at all"
    for row in family_rows:
        assert row["world"] is None, f"a family finding is stamped world={row['world']!r}"
        assert row["source_run_dir"].endswith(built.ep.name), (
            f"a family finding's source_run_dir is {row['source_run_dir']!r}, not the episode")


def test_a_family_findings_identity_is_minted_by_the_pass_not_by_the_model(
        tmp_path, monkeypatch):
    """A family finding is keyed on `(episode, "family", draw, index)`.

    Observably true: the `finding_id` of a family-level row is exactly
    `<episode_id>/family/<draw>/<index>` — a coordinate the pass composes — and two findings of
    one draw get distinct indices. `family` is a reserved world label, so this coordinate can
    never collide with a per-world one.

    What failure looks like: the id is minted from model-supplied content, and two runs of the
    same episode produce two ids for one finding — defeating the idempotency the whole queue
    keys on.
    """
    built = W.contrast_family(tmp_path, monkeypatch)
    judge = S.judge({S.FAMILY: S.family_reply(world=[
        S.wf("unreachable", evidence=[S.plan_ptr()]),
        S.wf("incoherent", evidence=[S.plan_ptr()], finding_id="model-chosen")])})

    S.grade(built, judge)

    ids = [r["finding_id"] for r in S.questioner_queue() if "/family/" in r["finding_id"]]
    assert len(ids) == 2, f"the two family findings did not both reach the queue: {ids}"
    for fid in ids:
        episode_id, label, draw, index = fid.split("/")
        assert episode_id == built.ep.name, f"{fid} names episode {episode_id!r}"
        assert label == "family", f"{fid} is keyed on world {label!r}, not the family"
        assert draw.isdigit(), f"{fid}'s draw coordinate is {draw!r}"
        assert index.isdigit(), f"{fid}'s finding index is {index!r}"
    assert len(set(ids)) == len(ids), f"two family findings share one id: {ids}"


def test_a_world_row_missing_systems_or_subject_is_refused_at_the_appender(tmp_path):
    """`systems` and `subject` are REQUIRED at the questioner appender (#1224: `systems`
    replaced `pattern` and `holding_system`).

    Observably true: a world row missing either is refused and nothing lands; a
    complete row lands. The appender is the LAST screen — M7's curator gate is idempotency-only
    — so a row that gets past here reaches the corpus unchecked.

    What failure looks like: the appender trusts the builder, a hand-built or replayed row
    arrives without `systems`, and the questioner's own selector at call 1 can never match it
    to an episode.
    """
    enqueue = W.mod("learning.judge.enqueue")
    paths = W.loop_paths(tmp_path)

    for missing in ("systems", "subject"):
        row = world_row()
        row.pop(missing)
        with pytest.raises(W.refusals()):
            enqueue.append_world_rows(tmp_path, [row], state=W.learning_state(paths))
    assert W.queue_rows(paths, QUESTIONER_FINDINGS) == []
    enqueue.append_world_rows(tmp_path, [world_row()], state=W.learning_state(paths))
    assert len(W.queue_rows(paths, QUESTIONER_FINDINGS)) == 1


def test_a_not_measured_world_queues_no_defender_row_and_still_queues_its_world_findings(
        tmp_path, monkeypatch):
    """The world lane does NOT share the defender lane's refusal: a world the judge files
    `unreachable` is not measured (#1234 I4), so it queues no defender row — and its design
    world finding still reaches the questioner (I5).

    Observably true: world b's reply carries an investigator finding and an `unreachable` world
    finding citing the plan; the defender queue holds no row from b, while the questioner queue
    holds exactly the `unreachable` one. (#1007 pinned this over the retired `discard` word;
    #1234's not-measured rule is the per-world rule that replaced it.)

    What failure looks like: one early return above both appends. The worlds that produce the
    most interesting questioner findings — the ones the defender lane declines to grade — are
    exactly the ones silently dropped.
    """
    built = W.contrast_family(tmp_path, monkeypatch)
    judge = S.judge({"b": S.world_reply("lead-quality", ["idp"], investigator=[S.inv()],
                                        world=[S.wf("unreachable")])})

    S.grade(built, judge)

    assert S.from_world(S.defender_queue(), "b") == [], (
        "a not-measured world still enqueued a defender row")
    assert [r["type"] for r in S.from_world(S.questioner_queue(), "b")
            if r["provenance"] == "model"] == ["unreachable"], (
        "the not-measured world's design finding was taken with the defender rows")


def test_an_ungradable_world_enqueues_nothing_on_either_channel(tmp_path, monkeypatch):
    """A world that cannot be graded at all enqueues no findings of EITHER subject.

    Observably true: a world whose archive carries no `report.md` fails the usability read
    (#1234 A3) and is ungradable, and neither channel receives a row for it — while a gradable
    sibling on the SAME pass enqueues on both. The control is what makes the emptiness a fact
    about the ungradable world rather than about a queue nothing ever reaches.

    What failure looks like: the world lane runs anyway over an archive that is not there, and
    the questioner corpus learns that a world it cannot read is badly authored.
    """
    built = W.contrast_family(tmp_path, monkeypatch, S.triad(c={"reached": None}))
    reply = S.world_reply("lead-quality", ["idp"], investigator=[S.inv()],
                          world=[S.wf("mislabelled")])
    judge = S.judge({"b": reply, "c": reply})

    S.grade(built, judge)

    assert S.row(built, "c").get("ungradable") or S.row(built, "c").get("malformed"), (
        f"world c without a report was graded: {S.row(built, 'c')}")
    assert not judge.called("c"), "the ungradable world was put to the judge"
    for name, queue in (("defender", S.defender_queue()), ("questioner", S.questioner_queue())):
        rows = [r for r in queue if r.get("world") == "c" or "/c/" in r.get("finding_id", "")]
        assert rows == [], f"an ungradable world enqueued {rows} on the {name} channel"
    assert S.from_world(S.defender_queue(), "b"), (
        "the control failed — the gradable sibling enqueued no defender row")
    assert S.from_world(S.questioner_queue(), "b"), (
        "the control failed — the gradable sibling enqueued no questioner row")


def test_a_world_row_reusing_a_consumed_defender_finding_id_still_reaches_its_own_curator(
        tmp_path):
    """`finding_id` now feeds TWO channels from ONE id space; consumption on one channel must
    not suppress the other.

    Observably true: with a finding id already recorded as consumed on the DEFENDER channel,
    a questioner row carrying that same id is still drained to the questioner curator. The
    demand is on the READ side — every reader that keys on `finding_id` now joins across a
    space it did not before, and a lookup that misses silently falls back rather than failing.

    What failure looks like: one shared consumed-id set. A world finding whose id collides with
    an already-authored defender one is dropped forever, with nothing anywhere recording that a
    row was skipped.
    """
    drains = W.mod("learning.core.drains")
    enqueue = W.mod("learning.judge.enqueue")
    paths = W.loop_paths(tmp_path)
    shared_id = f"{W.EPISODE_ID}/b/0/0"
    (paths.state_root / FINDINGS.queue).parent.mkdir(parents=True, exist_ok=True)
    (paths.state_root / FINDINGS.consumed).write_text(
        json.dumps(queue_row(finding_id=shared_id,
                             consumed_category="consumed_idempotent")) + "\n",
        encoding="utf-8")
    enqueue.append_world_rows(tmp_path, [world_row(finding_id=shared_id)],
                              state=W.learning_state(paths))

    # #881 (merged from main) renamed the drain's counter to `_pending_queue_counts`,
    # returning `(authorable, held)` rather than one int — this row carries no `held_reason`,
    # so it counts on the authorable side.
    pending, held = drains._pending_queue_counts(W.learning_state(paths), QUESTIONER_FINDINGS)

    assert held == 0, f"the row was held, not suppressed: {held}"
    assert pending == 1, (
        "the world row was suppressed by a defender-channel consumption of the same id — the "
        "two channels are sharing one id space AND one consumption record")


def test_two_episodes_appending_at_once_lose_no_questioner_row(tmp_path):
    """Two episodes grading into one questioner channel at once lose no row and tear no line.

    Observably true: two threads each appending a batch under a genuine interleaving leave
    every row present and every line parseable as JSON. The channel is `serialized-append`, and
    its append lock is what serialises it — the drain reads this file whole.

    What failure looks like: a plain `open(..., "a")` per row. One episode's write lands inside
    another's line, and both rows become one unreadable line the drain counts as malformed.
    """
    enqueue = W.mod("learning.judge.enqueue")
    paths = W.loop_paths(tmp_path)
    batches = [[world_row(finding_id=f"ep-{n}/b/0/{i}", run_id=f"ep-{n}")
                for i in range(12)] for n in (1, 2)]
    errors: list[BaseException] = []
    start = threading.Barrier(2)

    def drive(rows):
        try:
            start.wait(timeout=5)
            enqueue.append_world_rows(tmp_path, rows, state=W.learning_state(paths))
        except BaseException as bad:                       # noqa: BLE001 — reported below
            errors.append(bad)

    threads = [threading.Thread(target=drive, args=(b,)) for b in batches]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=20)

    assert errors == [], f"an appender raised under interleaving: {errors!r}"
    landed = W.queue_rows(paths, QUESTIONER_FINDINGS)
    assert len(landed) == 24, f"{24 - len(landed)} rows were lost under interleaving"


def test_a_malformed_line_on_either_channel_is_skipped_and_counted_never_silently_absent(
        tmp_path):
    """A malformed line on EITHER channel is skipped and COUNTED — the same reading on both.

    Observably true: a queue file and a served ledger each carrying one unparseable line report
    a non-zero malformed count alongside their good rows. Parity across the two sinks is the
    property: a reader that counts on one and silently drops on the other makes a partial
    measurement look complete on exactly one of them.

    What failure looks like: the new channel is read with a bare `json.loads` in a `try`, the
    row vanishes, and a lesson that was enqueued is never authored with nothing saying so.
    """
    io_mod = W.mod("_io")
    paths = W.loop_paths(tmp_path)
    (paths.state_root / FINDINGS.queue).parent.mkdir(parents=True, exist_ok=True)
    channel = paths.state_root / QUESTIONER_FINDINGS.queue
    channel.write_text(
        json.dumps(world_row()) + "\n{not json\n" + json.dumps(world_row(finding_id="x/2")) + "\n",
        encoding="utf-8")
    ledger = tmp_path / "served.jsonl"
    ledger.write_text(json.dumps(W.served_row()) + "\ntorn{\n", encoding="utf-8")

    queue_rows, queue_bad = io_mod.read_jsonl_rows_report(channel)
    ledger_rows, ledger_bad = io_mod.read_jsonl_rows_report(ledger)

    assert (len(queue_rows), queue_bad) == (2, 1), (
        f"the questioner queue read {len(queue_rows)} rows / {queue_bad} malformed")
    assert (len(ledger_rows), ledger_bad) == (1, 1), (
        f"the served ledger read {len(ledger_rows)} rows / {ledger_bad} malformed")
