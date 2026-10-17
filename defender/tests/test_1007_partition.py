"""#1007 — the `subject` partition, the second queue channel, and who owns a row's identity."""
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
    """The questioner channel gets its OWN append lock and consumed file, and SHARES the drain lock
    with the findings channel."""
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
    """A questioner-channel row is a full `FindingRow` head plus `world`, `systems`, `provenance`
    and `subject` ."""
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
    """The questioner channel is idempotent on `finding_id`, exactly as the defender one is."""
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
    """A world bucket must be a STRING of the vocabulary — never a list, number or mapping."""
    run = W.mod("learning.judge.run")

    run.validate_reply(world_reply(world=[S.wf("incoherent")]))      # the control
    for bad in (["incoherent"], 7, {"a": 1}, None):
        with pytest.raises(W.refusals()):
            run.validate_reply(world_reply(world=[S.wf(bad)]))


def test_an_empty_whitespace_or_unlisted_world_bucket_is_refused_never_normalised(tmp_path):
    """An empty, whitespace-only or unlisted world bucket is REFUSED — the vocabulary is closed
    (#1234 M4 replaced #1007's open one), and nothing is trimmed or coerced into it."""
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


# ---------------------------------------------------------------------------------------
# The rows themselves: what the pass owns and what the model owns (A3)
# ---------------------------------------------------------------------------------------


def test_a_defender_queue_row_carries_its_subject_key(tmp_path):
    """A defender row carries `subject: defender` EXPLICITLY, rather than by absence."""
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


def test_every_family_level_finding_carries_a_null_world(tmp_path, monkeypatch):
    """A family-level finding is about the FAMILY, so its `world` is null."""
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
    """`systems` and `subject` are REQUIRED at the questioner appender (#1224: `systems` replaced
    `pattern` and `holding_system`)."""
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


def test_a_world_row_reusing_a_consumed_defender_finding_id_still_reaches_its_own_curator(
        tmp_path):
    """`finding_id` now feeds TWO channels from ONE id space; consumption on one channel must not
    suppress the other."""
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
    """Two episodes grading into one questioner channel at once lose no row and tear no line."""
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
    """A malformed line on EITHER channel is skipped and COUNTED — the same reading on both."""
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
