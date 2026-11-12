"""#1007: the `subject` partition, the second queue channel, and who owns a row's identity."""
from __future__ import annotations

import json

import pytest

from defender.learning.core.state import FINDINGS, QUESTIONER_FINDINGS
from defender.tests.support.learning.branch import _world_1007 as W
from defender.tests.support.learning.judge import _gate_1278 as G
from defender.tests.learning.judge.contrast_contracts import _spec1234 as S

#: The finding id every hand-fed row here carries unless a scenario says otherwise.
FID = f"{W.EPISODE_ID}/b/0/0"

#: The three keys only a DEFENDER row carries; the rest is the head both share.
DEFENDER_ONLY = (S.CONTRAST, S.ON_PATH, S.DOUBT)


def queue_row(**over) -> dict:
    """One defender queue row as `enqueue.build_finding_row` mints it (no `judge_outcome`)."""
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


def test_world_row_refused_at_the_defender_appender(tmp_path):
    """A `subject: world` row may not reach the DEFENDER findings channel."""
    enqueue = W.mod("learning.judge.enqueue")
    paths = W.loop_paths(tmp_path)

    with pytest.raises(W.refusals()):
        enqueue.append_rows(tmp_path, [world_row()], state=W.learning_state(paths))

    assert W.queue_rows(paths, FINDINGS) == [], "the refused world row still landed"
    enqueue.append_world_rows(tmp_path, [world_row()], state=W.learning_state(paths))
    assert [r["subject"] for r in W.queue_rows(paths, QUESTIONER_FINDINGS)] == [W.SUBJECT_WORLD]


def test_each_channel_gates_a_row_type_against_its_own_vocabulary(tmp_path):
    """Each channel's appender checks a row's `type` against ITS OWN vocabulary."""
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
    """The defender curator's own gate refuses a `direction: world` row it should never see."""
    author = W.mod("learning.author.lessons.run")
    cfg = G.lessons_cfg(G.gate_lane(tmp_path))

    with pytest.raises(W.refusals()):
        author._gate_findings([queue_row(direction=W.SUBJECT_WORLD, subject=W.SUBJECT_WORLD)],
                              cfg)


def test_the_two_findings_channels_are_distinct_and_keyed_on_finding_id():
    """The questioner channel is a channel of its own, keyed on `finding_id` like the defender's.
    (Retired with the file queue: its own append lock and consumed file, and the drain lock it shared with the
    findings channel. The channels are two item kinds in the store, `finding` and `questioner_finding`, one lane
    under the store claim, design r8 "Locks"; the same key in two kinds being two items is
    tests/learning/store_1278/test_store_1278.py::test_d5_the_same_key_in_two_kinds_is_two_items.)"""
    assert QUESTIONER_FINDINGS.name != FINDINGS.name
    assert QUESTIONER_FINDINGS.id_key == FINDINGS.id_key == "finding_id"


def test_a_world_queue_row_is_a_full_finding_row_plus_four_fields(tmp_path):
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


def test_a_non_string_world_bucket_is_refused(tmp_path):
    """A world bucket must be a STRING of the vocabulary — never a list, number or mapping."""
    run = W.mod("learning.judge.run")

    run.validate_reply(world_reply(world=[S.wf("incoherent")]))      # the control
    for bad in (["incoherent"], 7, {"a": 1}, None):
        with pytest.raises(W.refusals()):
            run.validate_reply(world_reply(world=[S.wf(bad)]))


def test_an_empty_whitespace_or_unlisted_world_bucket_is_refused_never_normalised(tmp_path):
    """The world-bucket vocabulary is closed: nothing is trimmed or coerced into it."""
    run = W.mod("learning.judge.run")

    for bucket in sorted(run.WORLD_FINDING_BUCKETS):
        parsed = run.validate_reply(world_reply(world=[S.wf(bucket)]))
        assert parsed.world_findings[0].bucket == bucket
    for raw in ("", "   ", "\t\n", "shape-invention"):
        with pytest.raises(W.refusals()):
            run.validate_reply(world_reply(world=[S.wf(raw)]))


def test_a_world_finding_cannot_borrow_a_defender_bucket_and_the_list_decides_the_channel(
        tmp_path):
    """A world finding may not spell its bucket like a defender one; the LIST a finding is filed
    under — never the string — decides which channel its row is built for."""
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


def test_a_defender_queue_row_carries_its_subject_key(tmp_path):
    """A defender row carries `subject: defender` EXPLICITLY, rather than by absence."""
    enqueue = W.mod("learning.judge.enqueue")
    paths = W.loop_paths(tmp_path)

    enqueue.append_rows(tmp_path, [queue_row()], state=W.learning_state(paths))

    assert W.queue_rows(paths, FINDINGS)[0]["subject"] == W.SUBJECT_DEFENDER
    bare = queue_row()
    bare.pop("subject")
    with pytest.raises(W.refusals()):
        enqueue.append_rows(tmp_path, [bare], state=W.learning_state(paths))
    assert len(W.queue_rows(paths, FINDINGS)) == 1, "the subject-less row landed anyway"


def test_a_defender_subject_row_cannot_reach_the_questioner_curator(tmp_path):
    """The partition holds in BOTH directions: a defender row may not reach the questioner channel
    either."""
    enqueue = W.mod("learning.judge.enqueue")
    paths = W.loop_paths(tmp_path)

    with pytest.raises(W.refusals()):
        enqueue.append_world_rows(tmp_path, [queue_row()], state=W.learning_state(paths))

    assert W.queue_rows(paths, QUESTIONER_FINDINGS) == []


def test_a_model_supplied_world_is_ignored_and_the_draws_own_directory_wins(
        tmp_path, monkeypatch):
    """`world` is stamped from the draw's own world directory; a model-supplied `world` is ignored."""
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


def test_a_family_findings_identity_is_minted_by_the_pass_not_by_the_model(
        tmp_path, monkeypatch):
    """A family finding is keyed on `(episode, "family", draw, index)`."""
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
    """The world lane does NOT share the defender lane's refusal."""
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
    """A world that cannot be graded at all enqueues no findings of EITHER subject."""
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


# Retired: test_a_world_row_reusing_a_consumed_defender_finding_id_still_reaches_its_own_curator (the defender
# channel's `consumed` file must not suppress the same id on the questioner channel; `drains._pending_queue_counts`).
# Consumption records and the pending count are file-queue mechanics replaced by the store (design r8: an item is
# `(tenant, kind, key)`); that one id in two kinds is two independent items is
# tests/learning/store_1278/test_store_1278.py::test_d5_the_same_key_in_two_kinds_is_two_items.
#
# Retired: test_two_episodes_appending_at_once_lose_no_questioner_row (two threads appending 12 rows each to one
# queue file). The queue file and its append lock are replaced by the store's insert (design r8 "Locks");
# no row lost or doubled under concurrent inserts is the store's contract
# (tests/learning/store_1278/test_items_1278.py).


def test_a_malformed_line_on_either_channel_is_skipped_and_counted_never_silently_absent(
        tmp_path):
    """A malformed line on EITHER channel is skipped and COUNTED — the same reading on both."""
    # The reader is the one the served ledger and every other jsonl record is read with; the findings queue file it was
    # first written for is gone (#1278), so the questioner-shaped lines are read from a plain file.
    io_mod = W.mod("_io")
    channel = tmp_path / "questioner.jsonl"
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
