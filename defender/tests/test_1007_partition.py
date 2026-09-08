"""#1007 — the `subject` partition, the second queue channel, and who owns a row's identity.

O1/M6 splits findings by `subject` into two channels; O8/M10 keeps the DEFENDER vocabulary
pinned while the world side stays open (15-resolutions R2); A3 settles that the PASS owns a
row's identity and the model owns only its content.

THE WORLD VOCABULARY IS OPEN, BY HUMAN DECISION (accepted gap G-3). No test in this file
asserts a closed world set. The positive demand is the opposite one: an unlisted world bucket
is ADMITTED, stored verbatim, and read by `subject` rather than by membership.

RED AGAINST HEAD is the expected state.
"""
from __future__ import annotations

import json
import shutil
import threading
from pathlib import Path

import pytest

from defender.tests import _world_1007 as W


def episode_with_worlds(tmp_path: Path, monkeypatch, *, labels=("b",)) -> Path:
    _base, _src, root = W.configured_layout(tmp_path, monkeypatch)
    docs = [W.base_world()] + [W.world_doc(x) for x in labels]
    ep = W.episode(tmp_path, doc=W.family_doc(worlds=docs), root=root)
    for label in labels:
        W.archived_world(ep, label)
        W.write_served(ep, label, [W.served_row(world=label)])
    W.write_review(ep, worlds={
        label: W.reviewed_world(label=label) for label in labels})
    W.write_samples(ep)
    return ep


def queue_row(**over) -> dict:
    """One twelve-key defender queue row, as `enqueue._build_row` mints it, plus `subject`."""
    row = {
        "schema_version": 1,
        "finding_id": f"{W.EPISODE_ID}/b/0/0",
        "run_id": W.EPISODE_ID,
        "alert_rule_key": "rule-5710",
        "direction": "family",
        "subject": W.SUBJECT_DEFENDER,
        "type": "lead-set",
        "subject_anchor": "lead l-001",
        "subject_topic": "coverage",
        "finding": "the sibling never asked — no query named the corpus",
        "judge_outcome": "survived",
        "citations": [],
        "source_run_dir": f"episodes/{W.EPISODE_ID}/worlds/b",
    }
    row.update(over)
    return row


def world_row(**over) -> dict:
    """One questioner-channel row: a full `FindingRow` plus the four world-lane fields."""
    row = queue_row(
        subject=W.SUBJECT_WORLD, direction=W.SUBJECT_WORLD, type="story-overlay-gap",
        finding_id=f"{W.EPISODE_ID}/b/0/0",
        world="b", pattern=W.EVENTS_PATTERN, holding_system="elastic",
        provenance="model")
    row.update(over)
    return row


# ---------------------------------------------------------------------------------------
# O1/M6 — the partition, at the validator and at both appenders
# ---------------------------------------------------------------------------------------


def test_every_finding_carries_a_subject(tmp_path):
    """A finding without a `subject` is refused; each of the two literals is admitted.

    Observably true: `validate_reply` refuses a reply whose finding names no subject, and
    admits one naming `defender` and one naming `world`, carrying the value through to the
    parsed finding. The partition is the whole of M6 — a finding whose subject nobody stated is
    a finding no channel can route.

    What failure looks like: `subject` defaults to `defender`, and every world finding the
    judge ever writes is authored into the DEFENDER corpus as advice about an investigation.
    """
    run = W.mod("learning.judge.run")
    refusals = W.refusals()

    for subject in (W.SUBJECT_DEFENDER, W.SUBJECT_WORLD):
        parsed = run.validate_reply(W.reply_text(findings=[W.finding(
            subject=subject, bucket="lead-set" if subject == W.SUBJECT_DEFENDER else "a-bucket")]))
        assert parsed.findings[0].subject == subject

    bare = W.finding()
    bare.pop("subject")
    with pytest.raises(refusals):
        run.validate_reply(W.reply_text(findings=[bare]))


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
        enqueue.append_rows(tmp_path, [world_row()], queue_dir=paths.pending_dir)

    assert W.queue_rows(paths.findings) == [], "the refused world row still landed"
    enqueue.append_world_rows(tmp_path, [world_row()], queue_dir=paths.pending_dir)
    assert [r["subject"] for r in W.queue_rows(W.questioner_channel(paths))] == [W.SUBJECT_WORLD]


def test_defender_row_still_reaches_the_findings_channel(tmp_path):
    """The defender lane is UNCHANGED by the partition.

    Observably true: a `subject: defender` row appended through `append_rows` lands on
    `_pending/findings.jsonl` with its twelve keys intact. This is the survival half of the
    split, and it is the control every negative in this file rests on.

    What failure looks like: the partition refuses both directions, and the loop that already
    works stops working in a way every world-side assertion would still pass through.
    """
    enqueue = W.mod("learning.judge.enqueue")
    paths = W.loop_paths(tmp_path)

    appended = enqueue.append_rows(tmp_path, [queue_row()], queue_dir=paths.pending_dir)

    assert appended == 1
    landed = W.queue_rows(paths.findings)
    assert [r["finding_id"] for r in landed] == [f"{W.EPISODE_ID}/b/0/0"]
    assert landed[0]["type"] == "lead-set"


def test_a_defender_row_with_direction_world_is_refused_at_the_appender_too(tmp_path):
    """The DEFENDER lane's own appender refuses a hand-fed row whose `direction` disagrees with
    its `subject` — the same screen `_validate_world_row` already carries for the questioner
    lane, now symmetric.

    `build_finding_row` derives `direction` from `subject` (`test_direction_is_derived_from_
    subject_so_disagreement_is_unrepresentable`), so the pass's own producer can never mint a
    disagreeing row — but `append_rows` is documented to take rows "handed in from anywhere",
    and only the questioner-lane validator checked the pair for agreement. Without this screen,
    a hand-fed `subject: defender` / `direction: world` row would land on the defender channel
    unnoticed.

    Observably true: `queue_row(direction=W.SUBJECT_WORLD)` — otherwise a fully valid defender
    row — is refused, and nothing lands.

    What failure looks like: the row is silently accepted, landing a `direction: world` row on
    the channel the defender curator's own gate (keyed on `direction`) and the appender's
    `subject` gate could then read differently.
    """
    enqueue = W.mod("learning.judge.enqueue")
    paths = W.loop_paths(tmp_path)

    with pytest.raises(W.refusals()):
        enqueue.append_rows(
            tmp_path, [queue_row(direction=W.SUBJECT_WORLD)], queue_dir=paths.pending_dir)

    assert W.queue_rows(paths.findings) == [], "the disagreeing row still landed"


def test_a_world_row_type_is_not_gated_against_the_defender_vocabulary(tmp_path):
    """The questioner channel's appender does NOT check a row's `type` against
    `QUEUEABLE_FINDING_TYPES`.

    Observably true: a world row whose `type` is a string no defender vocabulary contains is
    appended and stored verbatim, while the same string on a `subject: defender` row is
    refused. The vocabularies are asymmetric on purpose (R2) and the asymmetry has to be
    enforced per channel, not per row shape.

    What failure looks like: the shared validator is reused unchanged, so every world finding
    the judge writes is refused as an unqueueable type — the open vocabulary closed by
    accident, one function away from the decision that opened it.
    """
    enqueue = W.mod("learning.judge.enqueue")
    cfg = W.mod("learning.core.config")
    paths = W.loop_paths(tmp_path)
    novel = "a-bucket-nobody-listed"
    assert novel not in cfg.QUEUEABLE_FINDING_TYPES

    enqueue.append_world_rows(tmp_path, [world_row(type=novel)], queue_dir=paths.pending_dir)

    assert [r["type"] for r in W.queue_rows(W.questioner_channel(paths))] == [novel]
    with pytest.raises(W.refusals()):
        enqueue.append_rows(tmp_path, [queue_row(type=novel)], queue_dir=paths.pending_dir)


def test_lessons_gate_refuses_direction_world_loudly(tmp_path):
    """The defender curator's own gate refuses a `direction: world` row it should never see.

    Observably true: `_gate_findings` handed a world-direction row raises rather than routing
    it — the second screen behind the appender, and the one that would otherwise turn a
    mis-routed row into an authored defender lesson. Loudly, because a silent hold would leave
    the row queued forever with nothing saying why.

    What failure looks like: the gate falls through to the ground-truth branch, asks
    `disposition_for` about an episode id, gets `None`, and holds the row as
    `no_ground_truth` — indistinguishable from an ordinary un-authorable finding.
    """
    author = W.mod("learning.author.lessons.run")
    paths = W.loop_paths(tmp_path)
    cfg = author.build_author_config(paths)

    with pytest.raises(W.refusals()):
        author._gate_findings([queue_row(direction=W.SUBJECT_WORLD, subject=W.SUBJECT_WORLD)],
                              cfg)


def test_lessons_gate_still_passes_a_family_row(tmp_path):
    """The defender curator's gate still routes a `direction: family` row exactly as today.

    Observably true: a family-direction defender row survives `_gate_findings` — it is held,
    consumed or authored by the incumbent family partition, and is NOT refused. This is the
    positive control for the refusal above: without it, a gate that raised on everything would
    read as correct.

    What failure looks like: the new refusal is written on `direction != "family"` and takes
    the whole incumbent defender lane down with it.
    """
    author = W.mod("learning.author.lessons.run")
    paths = W.loop_paths(tmp_path)
    cfg = author.build_author_config(paths)

    to_author, held, consumed = author._gate_findings([queue_row()], cfg)

    assert len(to_author) + len(held) + len(consumed) == 1, (
        "the family row was neither authored, held nor consumed — the gate dropped it")


# ---------------------------------------------------------------------------------------
# O8/M10 + R2 — the defender side stays pinned, the selector is per subject
# ---------------------------------------------------------------------------------------


def test_the_vocabulary_census_pins_the_defender_sets_to_their_members(tmp_path):
    """The three surviving defender vocabularies keep exactly their current members.

    Observably true: `PIPELINE_FINDING_TYPES`, `FAMILY_ONLY_FINDING_TYPES` and their union
    `QUEUEABLE_FINDING_TYPES` are the exact sets they are today. This is a non-regression pin
    on a loop already in use: no world bucket joins them, and the two names the design doc also
    listed (`ALL_FINDING_TYPES`, `BENIGN_ALL_FINDING_TYPES`) do not exist and are not restored.

    What failure looks like: a world bucket is added to the queueable set "so the appender lets
    it through", which re-opens the defender lane to strings the defender curator cannot author
    from — the exact coupling R2's asymmetry exists to prevent.
    """
    cfg = W.mod("learning.core.config")

    assert set(cfg.PIPELINE_FINDING_TYPES) == {
        "lead-set", "lead-quality", "analyze-discipline", "observability"}
    assert set(cfg.FAMILY_ONLY_FINDING_TYPES) == {"decision-discipline"}
    assert cfg.QUEUEABLE_FINDING_TYPES == (
        cfg.PIPELINE_FINDING_TYPES | cfg.FAMILY_ONLY_FINDING_TYPES)
    for gone in ("ALL_FINDING_TYPES", "BENIGN_ALL_FINDING_TYPES"):
        assert not hasattr(cfg, gone), f"{gone} was restored; R2 declined it"


def test_the_bucket_enum_is_selected_by_subject(tmp_path):
    """`_BUCKET_ENUM` becomes a per-SUBJECT lookup: the defender arm is the queueable set, the
    world arm admits any string.

    Observably true: the selector answers with `frozenset(QUEUEABLE_FINDING_TYPES)` for
    `defender` and with an arm that admits an arbitrary string for `world`. It is the SELECTOR
    that is per subject, not two hand-written validators — one lookup means the two arms cannot
    drift into disagreeing about which subject they are validating.

    What failure looks like: two copies of the membership test, one of which keeps checking the
    defender set for a world finding.
    """
    run = W.mod("learning.judge.run")
    cfg = W.mod("learning.core.config")

    assert run._BUCKET_ENUM[W.SUBJECT_DEFENDER] == frozenset(cfg.QUEUEABLE_FINDING_TYPES)
    world_arm = run._BUCKET_ENUM[W.SUBJECT_WORLD]
    assert "any-string-at-all" in world_arm, (
        "the world arm of the selector is a closed set — R2 opened it deliberately")


def test_a_defender_family_row_is_gated_exactly_as_today(tmp_path):
    """A `subject: defender`, `direction: family` row travels the incumbent path unchanged.

    Observably true: such a row validates at `append_rows`, lands on the findings channel, and
    is routed by `_gate_findings`'s family partition — the same three steps, in the same order,
    with the same outcomes as before this change. The `subject` key rides along and changes
    nothing on this lane.

    What failure looks like: the partition is threaded through the defender lane as well, and
    #921's whole family loop is re-litigated by a change that was supposed to leave it alone.
    """
    enqueue = W.mod("learning.judge.enqueue")
    author = W.mod("learning.author.lessons.run")
    paths = W.loop_paths(tmp_path)

    assert enqueue.append_rows(tmp_path, [queue_row()], queue_dir=paths.pending_dir) == 1
    landed = W.queue_rows(paths.findings)[0]
    to_author, held, consumed = author._gate_findings([landed],
                                                      author.build_author_config(paths))

    assert landed["direction"] == "family"
    assert len(to_author) + len(held) + len(consumed) == 1


# ---------------------------------------------------------------------------------------
# M6 — the second channel's own shape
# ---------------------------------------------------------------------------------------


def test_the_questioner_channel_declares_its_own_append_lock_and_shares_the_drain_lock(
        tmp_path):
    """The questioner channel gets its OWN append lock and consumed file, and SHARES the drain
    lock with the findings channel.

    Observably true: `paths.questioner_findings` is a `QueueChannel` whose `file`, `consumed`
    and `append_lock` are distinct from the findings channel's, and whose `drain_lock` is the
    byte-identical path. Sharing the drain lock is what keeps two curators from holding one
    worktree at once; a per-channel drain lock would give that up for nothing, and — because
    `LoopPaths.findings` hardcodes a DIRECTORY-level `.lock` name — a channel that "declares its
    own" at the same pending dir resolves to the same file anyway.

    What failure looks like: a second channel whose drain lock is genuinely separate. Two
    curators then enter one worktree concurrently and the batch's commit races itself.
    """
    paths = W.loop_paths(tmp_path)
    findings, questioner = paths.findings, W.questioner_channel(paths)

    assert questioner.file.name == W.QUESTIONER_QUEUE_FILENAME
    assert questioner.file != findings.file
    assert questioner.consumed != findings.consumed
    assert questioner.append_lock != findings.append_lock, (
        "the two channels share an append lock, so an appender on one blocks the other")
    assert questioner.drain_lock == findings.drain_lock, (
        f"the questioner channel's drain lock is {questioner.drain_lock} — a separate lock "
        "gives up the mutual exclusion that keeps two curators out of one worktree")
    assert questioner.id_key == "finding_id"


def test_a_world_queue_row_is_a_full_finding_row_plus_four_fields(tmp_path):
    """A questioner-channel row is a full `FindingRow` plus `world`, `pattern`,
    `holding_system` and `subject` — not a reduced shape of its own.

    Observably true: the row that lands carries every key the defender row carries (so any
    reader of a finding row can read it) with `run_id` the episode id, `finding_id` the
    idempotency key and `direction: world`, plus the four world-lane fields.

    What failure looks like: a bespoke five-key row. Every shared reader — the drain's
    idempotency, the curator's provenance list, the malformed-line counter — then needs a
    second code path, and the ones that do not get it read the row as malformed.
    """
    enqueue = W.mod("learning.judge.enqueue")
    paths = W.loop_paths(tmp_path)

    enqueue.append_world_rows(tmp_path, [world_row()], queue_dir=paths.pending_dir)

    landed = W.queue_rows(W.questioner_channel(paths))[0]
    for key in queue_row():
        assert key in landed, f"the world row is missing the finding-row key {key!r}"
    assert landed["direction"] == W.SUBJECT_WORLD
    assert landed["run_id"] == W.EPISODE_ID
    for key in ("world", "pattern", "holding_system", "subject"):
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

    enqueue.append_world_rows(tmp_path, [world_row()], queue_dir=paths.pending_dir)
    enqueue.append_world_rows(tmp_path, [world_row()], queue_dir=paths.pending_dir)

    rows = W.queue_rows(W.questioner_channel(paths))
    assert [r["finding_id"] for r in rows] == [f"{W.EPISODE_ID}/b/0/0"], (
        f"one finding id landed twice: {rows}")


# ---------------------------------------------------------------------------------------
# The open world vocabulary, made mechanical
# ---------------------------------------------------------------------------------------


def test_a_non_string_world_bucket_is_refused(tmp_path):
    """A world bucket must be a STRING — openness is about which strings, not about which types.

    Observably true: `bucket: ["lead-set"]` on a `subject: world` finding is refused at
    `validate_reply`. The value becomes a queue row's `type` and a lesson's frontmatter key; an
    unhashable or non-string value there raises `TypeError` out of a membership test whose
    whole contract is to answer with this design's refusal.

    What failure looks like: the open arm accepts anything, and a list-valued bucket reaches
    the appender, where `row_type not in QUEUEABLE_FINDING_TYPES` raises the wrong class and
    takes a whole batch down.
    """
    run = W.mod("learning.judge.run")

    for bad in ([W.MECHANICAL_WORLD_BUCKET], 7, {"a": 1}, None):
        with pytest.raises(W.refusals()):
            run.validate_reply(W.reply_text(findings=[W.world_finding(bucket=bad)]))


def test_an_empty_or_whitespace_world_bucket_is_admitted_and_stored_verbatim(tmp_path):
    """An empty or whitespace-only world bucket is ADMITTED and stored exactly as written.

    Observably true: `bucket: ""` and `bucket: "   "` both survive `validate_reply` with the
    string unchanged — no trim, no coercion to a default. The vocabulary is open this round by
    human decision, and "unusable" is a judgement a later reader makes, not one this validator
    is authorised to make.

    What failure looks like: the validator normalises or rejects, and the very drift the human
    wanted to OBSERVE for a few live episodes is filtered out before anyone can see it.
    """
    run = W.mod("learning.judge.run")

    for raw in ("", "   ", "\t\n"):
        parsed = run.validate_reply(W.reply_text(findings=[W.world_finding(bucket=raw)]))
        assert parsed.findings[0].bucket == raw, (
            f"the bucket {raw!r} came back as {parsed.findings[0].bucket!r} — it was "
            "normalised, which is a vocabulary decision this round declined to take")


def test_a_world_bucket_spelled_like_a_defender_bucket_is_admitted_and_read_by_subject(
        tmp_path):
    """A world finding may spell its bucket exactly like a defender one; `subject` — never the
    string — decides which vocabulary applies.

    Observably true: `subject: world, bucket: lead-set` validates and routes to the questioner
    channel, while `subject: defender, bucket: lead-set` routes to the findings channel. The
    two rows are distinguishable by subject alone.

    What failure looks like: the bucket string is used to infer the subject. The moment a
    model spells a world finding `lead-quality`, the row is authored as a defender lesson.
    """
    run = W.mod("learning.judge.run")
    enqueue = W.mod("learning.judge.enqueue")
    paths = W.loop_paths(tmp_path)

    parsed = run.validate_reply(W.reply_text(findings=[W.world_finding(bucket="lead-set")]))
    assert parsed.findings[0].subject == W.SUBJECT_WORLD
    assert parsed.findings[0].bucket == "lead-set"

    enqueue.append_world_rows(tmp_path, [world_row(type="lead-set")],
                              queue_dir=paths.pending_dir)
    enqueue.append_rows(tmp_path, [queue_row(type="lead-set")], queue_dir=paths.pending_dir)
    assert len(W.queue_rows(W.questioner_channel(paths))) == 1
    assert len(W.queue_rows(paths.findings)) == 1


def test_a_near_miss_subject_is_refused_with_no_case_fold_and_no_trim(tmp_path):
    """`subject` is exactly two string literals. No case-fold, no trim, anywhere.

    Observably true: `"World"`, `" world"`, `"world "` and `"DEFENDER"` are all refused at the
    validator, and the same near-misses are refused at the questioner appender. Refusing at
    both is the point: the appender is the last screen (the questioner channel's own gate is
    idempotency-only), and a normalisation at one site and not the other is how the selector
    and the guard come to disagree about which channel a row belongs on.

    What failure looks like: `subject.strip().lower()` at one site. A row then validates as
    `world` and appends as something the defender gate reads.
    """
    run = W.mod("learning.judge.run")
    enqueue = W.mod("learning.judge.enqueue")
    paths = W.loop_paths(tmp_path)

    for near in ("World", " world", "world ", "DEFENDER", "defender\n", "worlds"):
        with pytest.raises(W.refusals()):
            run.validate_reply(W.reply_text(findings=[W.finding(subject=near)]))
        with pytest.raises(W.refusals()):
            enqueue.append_world_rows(tmp_path, [world_row(subject=near)],
                                      queue_dir=paths.pending_dir)
    assert W.queue_rows(W.questioner_channel(paths)) == []


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

    enqueue.append_rows(tmp_path, [queue_row()], queue_dir=paths.pending_dir)

    assert W.queue_rows(paths.findings)[0]["subject"] == W.SUBJECT_DEFENDER
    # REQUIRED, not merely carried: a row that reached the appender without one would
    # otherwise land and read as a defender row by default, which is the inference this key
    # exists to remove. Without this half the assertion above passes on an appender that
    # copies whatever it is handed.
    bare = queue_row()
    bare.pop("subject")
    with pytest.raises(W.refusals()):
        enqueue.append_rows(tmp_path, [bare], queue_dir=paths.pending_dir)
    assert len(W.queue_rows(paths.findings)) == 1, "the subject-less row landed anyway"


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
        enqueue.append_world_rows(tmp_path, [queue_row()], queue_dir=paths.pending_dir)

    assert W.queue_rows(W.questioner_channel(paths)) == []


def test_a_model_supplied_world_is_ignored_and_the_draws_own_directory_wins(
        tmp_path, monkeypatch):
    """`world` is stamped from the draw's own world directory; a model-supplied `world` is
    ignored.

    Observably true: a per-world finding whose reply claims `world: c` lands on the queue with
    `world: b`, because b is the world that draw was about. Identity belongs to the pass; the
    model owns content only.

    What failure looks like: a model relabels its own finding onto a sibling, and a lesson is
    authored about a world that never had the property described.
    """
    paths = W.loop_paths(tmp_path)
    judge_mod = W.mod("learning.judge")
    ep = episode_with_worlds(tmp_path, monkeypatch, labels=("b", "c"))
    judge = W.FakeJudge(W.reply_document(findings=[W.world_finding(world="c")]))

    judge_mod.grade_episode(ep, judge=judge, queue_dir=paths.pending_dir)

    rows = [r for r in W.queue_rows(W.questioner_channel(paths)) if r["provenance"] == "model"]
    assert {r["world"] for r in rows} == {"b", "c"}, (
        f"the model's own `world` value reached the row: {[r['world'] for r in rows]}")
    for row in rows:
        assert row["world"] in row["finding_id"], (
            f"row {row['finding_id']} is stamped for world {row['world']!r} — the id and the "
            "stamp name different worlds")


def test_every_family_level_finding_carries_a_null_world(tmp_path, monkeypatch):
    """A family-level finding is about the FAMILY, so its `world` is null.

    Observably true: a finding from the family draw lands with `world: None` and
    `source_run_dir` naming the episode dir rather than a world's archive. This is one of the
    two structural pins that survive the open vocabulary — the bucket clause of O6's falsifier
    was struck (A1) because the family reply is itself `subject: world` and takes the freeform
    arm, so it cannot fire.

    What failure looks like: the family finding is stamped onto whichever world happened to be
    drawn last, and a family-level observation is authored as a lesson about one world.
    """
    paths = W.loop_paths(tmp_path)
    judge_mod = W.mod("learning.judge")
    ep = episode_with_worlds(tmp_path, monkeypatch, labels=("b", "c"))
    judge = W.FakeJudge(W.reply_document(
        findings=[W.world_finding(bucket="undiscriminating-family")]))

    judge_mod.grade_episode(ep, judge=judge, queue_dir=paths.pending_dir)

    family_rows = [r for r in W.queue_rows(W.questioner_channel(paths))
                   if "family" in r["finding_id"]]
    assert family_rows, "the family draw enqueued nothing at all"
    for row in family_rows:
        assert row["world"] is None, f"a family finding is stamped world={row['world']!r}"
        assert row["source_run_dir"].endswith(ep.name), (
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
    paths = W.loop_paths(tmp_path)
    judge_mod = W.mod("learning.judge")
    ep = episode_with_worlds(tmp_path, monkeypatch)
    judge = W.FakeJudge(W.reply_document(findings=[
        W.world_finding(bucket="undiscriminating-family"),
        W.world_finding(bucket="a-second-family-reading"),
    ]))

    judge_mod.grade_episode(ep, judge=judge, queue_dir=paths.pending_dir)

    ids = [r["finding_id"] for r in W.queue_rows(W.questioner_channel(paths))
           if "/family/" in r["finding_id"]]
    assert ids, "no family-keyed row was enqueued"
    for fid in ids:
        episode_id, label, draw, index = fid.split("/")
        assert episode_id == ep.name, f"{fid} names episode {episode_id!r}"
        assert label == "family", f"{fid} is keyed on world {label!r}, not the family"
        assert draw.isdigit(), f"{fid}'s draw coordinate is {draw!r}"
        assert index.isdigit(), f"{fid}'s finding index is {index!r}"
    assert len(set(ids)) == len(ids), f"two family findings share one id: {ids}"


def test_direction_is_derived_from_subject_so_disagreement_is_unrepresentable(tmp_path):
    """`direction` is DERIVED from `subject` at the builder — a row whose two fields disagree
    cannot be built.

    Observably true: the builder, asked for a row of each subject, produces `direction: world`
    and `direction: family` respectively, and takes no `direction` argument at all. Derivation
    beats refusal here: a refusal leaves the wrong state constructible and only rejects it at a
    boundary somebody may forget to cross, and the defender curator's gate keys on `direction`
    while the appender keys on `subject`.

    What failure looks like: both are passed in, one call site fills them from different
    places, and a `subject: world` / `direction: family` row is authored as a defender lesson.
    """
    enqueue = W.mod("learning.judge.enqueue")
    import inspect

    for subject, expected in ((W.SUBJECT_WORLD, W.SUBJECT_WORLD),
                              (W.SUBJECT_DEFENDER, "family")):
        row = enqueue.build_finding_row(
            run_id=W.EPISODE_ID, label="b", draw="0", index=0, subject=subject,
            finding=W.finding(subject=subject), alert_rule_key="rule-5710",
            judge_outcome="survived")
        assert row["subject"] == subject
        assert row["direction"] == expected, (
            f"subject={subject!r} built direction={row['direction']!r}")
    params = inspect.signature(enqueue.build_finding_row).parameters
    assert "direction" not in params, (
        "the builder still takes `direction` as an argument, so a caller can still make the "
        "two fields disagree")


def test_a_world_row_missing_pattern_holding_system_or_subject_is_refused_at_the_appender(
        tmp_path):
    """`pattern`, `holding_system` and `subject` are REQUIRED at the questioner appender.

    Observably true: a world row missing any one of the three is refused and nothing lands; a
    complete row lands. The appender is the LAST screen — M7's curator gate is idempotency-only
    — so a row that gets past here reaches the corpus unchecked.

    What failure looks like: the appender trusts the builder, a hand-built or replayed row
    arrives without `pattern`, and the questioner's own selector at call 1 can never match it
    to an episode.
    """
    enqueue = W.mod("learning.judge.enqueue")
    paths = W.loop_paths(tmp_path)

    for missing in ("pattern", "holding_system", "subject"):
        row = world_row()
        row.pop(missing)
        with pytest.raises(W.refusals()):
            enqueue.append_world_rows(tmp_path, [row], queue_dir=paths.pending_dir)
    assert W.queue_rows(W.questioner_channel(paths)) == []
    enqueue.append_world_rows(tmp_path, [world_row()], queue_dir=paths.pending_dir)
    assert len(W.queue_rows(W.questioner_channel(paths))) == 1


def test_a_re_grade_appends_no_second_mechanical_world_finding(tmp_path, monkeypatch):
    """The mechanical world finding takes a FIXED synthetic draw and index, so a re-grade is
    absorbed by idempotency.

    Observably true: grading an episode twice leaves exactly one mechanical row on the
    questioner channel. The mechanical pass is arithmetic over the episode dir — it has no draw
    of its own — so a coordinate derived from a counter would mint a new id per re-grade.

    What failure looks like: an operator re-grades a repaired episode and the corpus gains a
    duplicate lesson for every mechanical finding of every world.
    """
    paths = W.loop_paths(tmp_path)
    judge_mod = W.mod("learning.judge")
    _base, _src, root = W.configured_layout(tmp_path, monkeypatch)
    doc = W.family_doc(worlds=[W.base_world(), W.world_doc(
        "b", ov=W.overlay(elastic=W.elastic_overlay(inject=[{"_id": "i1"}])))])
    ep = W.episode(tmp_path, doc=doc, root=root)
    W.archived_world(ep, "b")
    W.write_served(ep, "b", [W.served_row(world="b")])
    W.write_samples(ep)
    W.write_review(ep, worlds={"b": W.reviewed_world(
        label="b", reachability=W.reachability_block(
            reachable_by_capture=False,
            capture_replays=[W.replay_entry("k1", differs=False)]))})

    judge_mod.grade_episode(ep, judge=W.FakeJudge(W.reply_document()),
                            queue_dir=paths.pending_dir)
    (ep / W.JUDGE_NAME).unlink()        # force a genuine re-grade, not the existing-record path
    judge_mod.grade_episode(ep, judge=W.FakeJudge(W.reply_document()),
                            queue_dir=paths.pending_dir)

    mech = [r for r in W.queue_rows(W.questioner_channel(paths))
            if r.get("provenance") == "mechanical"]
    assert len(mech) == 1, f"a re-grade minted a second mechanical row: {mech}"


def test_an_unqueueable_defender_finding_does_not_suppress_the_world_findings(
        tmp_path, monkeypatch):
    """The world lane does NOT share the defender lane's unqueueable early return.

    Observably true: an episode whose defender findings are all unqueueable (a `discard`
    outcome, which IS the family's verdict word and is never a defender failure to author from)
    still enqueues its world findings. The two lanes answer different questions and one lane's
    early return must not take the other with it.

    What failure looks like: `if not defender_rows: return` above both appends. The worlds that
    produce the most interesting questioner findings — the ones the defender lane declines to
    grade — are exactly the ones silently dropped.
    """
    paths = W.loop_paths(tmp_path)
    judge_mod = W.mod("learning.judge")
    ep = episode_with_worlds(tmp_path, monkeypatch)
    judge = W.FakeJudge(W.reply_document(
        outcome="discard",
        findings=[W.finding(), W.world_finding(bucket="a-world-reading")]))

    judge_mod.grade_episode(ep, judge=judge, queue_dir=paths.pending_dir)

    assert [r for r in W.queue_rows(paths.findings)] == [], (
        "a discard episode still enqueued a defender row")
    assert [r["type"] for r in W.queue_rows(W.questioner_channel(paths))
            if r["provenance"] == "model"] == ["a-world-reading"], (
        "the discard outcome took the world findings with it")


def test_an_ungradable_world_enqueues_nothing_on_either_channel(tmp_path, monkeypatch):
    """A world that cannot be graded at all enqueues no findings of EITHER subject.

    Observably true: a world missing its archived record is `ungradable`, and neither channel
    receives a row for it — while a gradable sibling on the SAME drive enqueues on both. The
    control is what makes the emptiness a fact about the ungradable world rather than about a
    queue nothing ever reaches.

    What failure looks like: the world lane runs anyway over an archive that is not there, and
    the questioner corpus learns that a world it cannot read is badly authored.
    """
    paths = W.loop_paths(tmp_path)
    judge_mod = W.mod("learning.judge")
    ep = episode_with_worlds(tmp_path, monkeypatch, labels=("b", "c"))
    for stray in (ep / "worlds" / "c").glob("*"):
        if stray.is_dir():
            shutil.rmtree(stray)
        else:
            stray.unlink()
    judge = W.FakeJudge(W.reply_document(
        findings=[W.finding(), W.world_finding(bucket="a-world-reading")]))

    judge_mod.grade_episode(ep, judge=judge, queue_dir=paths.pending_dir)

    for channel in (paths.findings, W.questioner_channel(paths)):
        rows = [r for r in W.queue_rows(channel) if r.get("world") == "c" or "/c/" in
                r.get("finding_id", "")]
        assert rows == [], f"an ungradable world enqueued {rows} on {channel.file.name}"
    assert any("/b/" in r["finding_id"] for r in W.queue_rows(paths.findings)), (
        "the control failed — the gradable sibling enqueued nothing either")


def test_a_questioner_queue_row_carries_no_defender_verdict_word(tmp_path):
    """A world row is about the WORLD, and carries no defender verdict on it.

    Observably true: no key of a questioner-channel row holds `caught`, `survived` or
    `undecidable`. A defender verdict on a world's row is the category error O1 exists to
    prevent — it invites the curator to author a lesson about the defender into the corpus the
    questioner reads.

    What failure looks like: `judge_outcome` is filled from the episode's `verdict_word`, and
    a lesson about how to author worlds opens by telling the reader the defender survived.
    """
    enqueue = W.mod("learning.judge.enqueue")
    paths = W.loop_paths(tmp_path)

    enqueue.append_world_rows(tmp_path, [world_row()], queue_dir=paths.pending_dir)

    landed = W.queue_rows(W.questioner_channel(paths))[0]
    rendered = json.dumps(landed)
    for word in ("caught", "survived", "undecidable"):
        assert word not in rendered, (
            f"the world row carries the defender verdict word {word!r}: {landed}")


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
    paths.pending_dir.mkdir(parents=True, exist_ok=True)
    paths.findings.consumed.write_text(
        json.dumps(queue_row(finding_id=shared_id,
                             consumed_category="consumed_idempotent")) + "\n",
        encoding="utf-8")
    enqueue.append_world_rows(tmp_path, [world_row(finding_id=shared_id)],
                              queue_dir=paths.pending_dir)

    # #881 (merged from main) renamed the drain's counter to `_pending_queue_counts`,
    # returning `(authorable, held)` rather than one int — this row carries no `held_reason`,
    # so it counts on the authorable side.
    pending, held = drains._pending_queue_counts(W.questioner_channel(paths).file)

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
            enqueue.append_world_rows(tmp_path, rows, queue_dir=paths.pending_dir)
        except BaseException as bad:                       # noqa: BLE001 — reported below
            errors.append(bad)

    threads = [threading.Thread(target=drive, args=(b,)) for b in batches]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=20)

    assert errors == [], f"an appender raised under interleaving: {errors!r}"
    landed = W.queue_rows(W.questioner_channel(paths))
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
    paths.pending_dir.mkdir(parents=True, exist_ok=True)
    channel = W.questioner_channel(paths)
    channel.file.write_text(
        json.dumps(world_row()) + "\n{not json\n" + json.dumps(world_row(finding_id="x/2")) + "\n",
        encoding="utf-8")
    ledger = tmp_path / "served.jsonl"
    ledger.write_text(json.dumps(W.served_row()) + "\ntorn{\n", encoding="utf-8")

    queue_rows, queue_bad = io_mod.read_jsonl_rows_report(channel.file)
    ledger_rows, ledger_bad = io_mod.read_jsonl_rows_report(ledger)

    assert (len(queue_rows), queue_bad) == (2, 1), (
        f"the questioner queue read {len(queue_rows)} rows / {queue_bad} malformed")
    assert (len(ledger_rows), ledger_bad) == (1, 1), (
        f"the served ledger read {len(ledger_rows)} rows / {ledger_bad} malformed")
