"""#1007 — M5: the family-level call, and the identity it must not collide with.

One call per draw, judging what no single world can: whether the family as a whole separated
anything. It is shown every world's overlay, the review record and every mechanical row,
withholding none — and its reply may name no world.

A1 (§7) STRUCK O6's bucket clause: the family reply is itself `subject: world` and takes the
freeform arm of the selector, so a falsifier phrased as "its reply carries a per-world bucket"
cannot fire. The two structural pins that remain decidable are kept — a family finding carries
`world: null` (tested with the queue rows, in `test_1007_partition.py`) and never
`subject: defender` (below).

RED AGAINST HEAD is the expected state.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from defender.tests import _world_1007 as W


def family_episode(tmp_path: Path, monkeypatch, *, labels=("b", "c"),
                   stories=None) -> Path:
    _base, _src, root = W.configured_layout(tmp_path, monkeypatch)
    docs = [W.base_world()] + [
        W.world_doc(x, story=(stories or {}).get(x, f"world {x}'s story"),
                    ov=W.overlay(elastic=W.elastic_overlay(inject=[{"_id": f"i{x}"}])))
        for x in labels]
    ep = W.episode(tmp_path, doc=W.family_doc(worlds=docs), root=root)
    for label in labels:
        W.archived_world(ep, label)
        W.write_served(ep, label, [W.served_row(world=label)])
    W.write_review(ep, worlds={label: W.reviewed_world(label=label) for label in labels})
    W.write_samples(ep)
    return ep


def grade(ep: Path, judge, **kw):
    return W.mod("learning.judge").grade_episode(ep, judge=judge, **kw)


def test_the_family_call_is_shown_every_world(tmp_path, monkeypatch):
    """The family prompt carries EVERY world — overlays, the review record, every mechanical
    row, and the base disposition — withholding none.

    Observably true: the family draw's prompt names each world's own story and each world's
    label, and carries the review record's per-world entries. The per-world calls are the ones
    that must not see siblings; the family call's whole question is about the set, so
    withholding any member makes the question unanswerable.

    What failure looks like: the family call is handed a summary, or the same
    graded-world-only manifest the per-world calls get. It is then asked whether the family
    discriminated while being shown one world.
    """
    stories = {"b": "b-only-story-marker", "c": "c-only-story-marker"}
    ep = family_episode(tmp_path, monkeypatch, stories=stories)
    judge = W.FakeJudge(W.reply_document())

    grade(ep, judge)

    prompt = judge.family_prompts
    assert prompt, f"no family-level call was made: agent ids {judge.agent_ids}"
    for marker in stories.values():
        assert marker in prompt[0], (
            f"the family prompt withholds {marker!r} — it is shown fewer than every world")
    assert "reachability" in prompt[0], "the family prompt carries no review record"


def test_the_family_reply_may_not_name_a_world(tmp_path):
    """A family-level finding may not carry a per-world `world` value.

    Observably true: a reply from the family call whose finding names a world is refused — the
    pass owns identity, and a family finding is about the family. The parity control is that
    the same finding from a per-world draw is accepted, so the refusal is about the CALL, not
    about the field.

    What failure looks like: a model attributes a family-level observation to whichever world
    it found most memorable, and the questioner corpus grows a lesson about a world that did
    not have the property.
    """
    run = W.mod("learning.judge.run")

    with pytest.raises(W.refusals()):
        run.validate_reply(W.reply_text(findings=[W.world_finding(world="b")]),
                           scope="family")
    parsed = run.validate_reply(W.reply_text(findings=[W.world_finding()]), scope="world")
    assert parsed.findings[0].subject == W.SUBJECT_WORLD


def test_the_family_reply_admits_a_family_level_finding(tmp_path, monkeypatch):
    """The positive control: a family-level finding with no world stands and reaches the queue.

    Observably true: a family reply carrying an `undiscriminating-family` finding validates and
    lands as a `subject: world`, `world: null` row on the questioner channel. Without this the
    refusal above would read as correct on a family call whose replies are all discarded.

    What failure looks like: the family lane validates nothing at all, and M5 is a paid model
    call whose output reaches no artifact.
    """
    paths = W.loop_paths(tmp_path)
    ep = family_episode(tmp_path, monkeypatch)
    judge = W.FakeJudge(W.reply_document(
        findings=[W.world_finding(bucket="undiscriminating-family")]))

    grade(ep, judge, queue_dir=paths.pending_dir)

    rows = [r for r in W.queue_rows(W.questioner_channel(paths))
            if r["type"] == "undiscriminating-family"]
    assert rows, "the family finding reached no queue row"
    assert rows[0]["world"] is None, f"a family finding is stamped world={rows[0]['world']!r}"
    assert rows[0]["subject"] == W.SUBJECT_WORLD


def test_the_family_agent_id_cannot_collide_with_a_world_label(tmp_path, monkeypatch):
    """`family` becomes a RESERVED world label, so the family call's agent id and trace name
    cannot collide with a world's.

    Observably true: the manifest refuses a world labelled `family`, and the family draw's
    agent id is in the reserved namespace. Two calls sharing one agent id share one wire log
    file, and this sink is `serialized-append` — the two streams interleave into one document
    neither can be read out of.

    What failure looks like: a questioner authors a world called `family`, and that world's
    per-world judge trace and the family call's trace are one file.
    """
    family_mod = W.mod("runtime.branch._family")

    assert "family" in family_mod.RESERVED_WORLD_LABELS, (
        f"RESERVED_WORLD_LABELS is {family_mod.RESERVED_WORLD_LABELS} — a world may still be "
        "called `family`")
    with pytest.raises(W.refusals()):
        family_mod.parse_family(W.family_doc(worlds=[
            W.base_world(), W.world_doc("family")]))

    ep = family_episode(tmp_path, monkeypatch)
    judge = W.FakeJudge(W.reply_document())
    grade(ep, judge)
    assert judge.family_prompts, "no family call was made"
    world_ids = [a for a in judge.agent_ids if "family" not in a]
    assert set(judge.agent_ids) - set(world_ids), "the family call reuses a world's agent id"


def test_the_family_call_emits_no_defender_finding(tmp_path, monkeypatch):
    """The family call never produces a `subject: defender` finding.

    Observably true: a family reply carrying a defender-subject finding is refused, and no row
    for it reaches the defender findings channel. The family call grades the FAMILY; a defender
    finding out of it would be authored from a view that never looked at an investigation.

    What failure looks like: the family reply is validated with the per-world validator, a
    `lead-set` finding rides through, and the defender corpus gains a lesson derived from a
    call that read no investigation document at all.
    """
    paths = W.loop_paths(tmp_path)
    ep = family_episode(tmp_path, monkeypatch)
    judge = W.FakeJudge(W.reply_document(findings=[W.finding()]))

    grade(ep, judge, queue_dir=paths.pending_dir)

    assert judge.family_prompts, (
        f"no family call was made at all, so the absence below proves nothing: "
        f"{judge.agent_ids}")
    from_family = [r for r in W.queue_rows(paths.findings) if "/family/" in r["finding_id"]]
    assert from_family == [], (
        f"the family call produced defender queue rows: {from_family}")


def test_disagreeing_family_draws_resolve_by_majority_as_today(tmp_path, monkeypatch):
    """Family draws that disagree resolve by majority — the same rule the per-world draws use.

    Observably true: three family draws returning two `gradable` and one `discard` resolve to
    `gradable`, and the record says so. The resolution rule is the incumbent one; this change
    adds a second call to the fan-out, not a second way of settling it.

    What failure looks like: the family draw is treated as authoritative on its own, so a
    single unlucky draw decides the episode's family-level outcome — the exact noise the
    majority rule exists to absorb.
    """
    ep = family_episode(tmp_path, monkeypatch)
    judge = W.FakeJudge(
        W.reply_document(outcome="gradable"),
        W.reply_document(outcome="gradable"),
        W.reply_document(outcome="gradable"),
        W.reply_document(outcome="gradable"),
        W.reply_document(outcome="gradable"),
        W.reply_document(outcome="gradable"),
        W.reply_document(outcome="gradable"),
        W.reply_document(outcome="gradable"),
        W.reply_document(outcome="discard"),
    )

    result = grade(ep, judge, draws=3)

    assert result.family_outcome == "gradable", (
        f"three family draws (2 gradable, 1 discard) resolved to {result.family_outcome!r}")


def test_the_family_call_is_made_even_when_there_is_nothing_to_separate(
        tmp_path, monkeypatch):
    """The family call is UNCONDITIONAL — an episode with nothing to separate is exactly the
    episode it exists to say so about.

    Observably true: an episode whose worlds all agree, all reach the same disposition and show
    no difference still makes the family call. "Nothing separated these worlds" is the family
    judge's own most useful answer; gating the call on there being something to say makes it
    unsayable.

    What failure looks like: `if contrasting_worlds: run_family_draw()`. The undiscriminating
    families — the ones the questioner most needs to learn from — are the only ones never
    graded.
    """
    ep = family_episode(tmp_path, monkeypatch)
    doc = W.read_yaml(ep / W.REVIEW_NAME)
    for label in ("b", "c"):
        doc["worlds"][label]["reachability"] = W.reachability_block(
            reachable_by_capture=False, capture_replays=[W.replay_entry("k1", differs=False)])
    W.write_yaml(ep / W.REVIEW_NAME, doc)
    judge = W.FakeJudge(W.reply_document())

    grade(ep, judge)

    assert judge.family_prompts, (
        f"no family call was made for an undiscriminating episode: {judge.agent_ids}")


def test_a_faulted_family_draw_isolates_and_leaves_verdict_word_intact(
        tmp_path, monkeypatch):
    """A faulted family draw costs its own draw and nothing else.

    Observably true: with the family call raising and every per-world draw completing, the
    per-world rows are equal FIELD FOR FIELD to the rows the same episode grades without the
    family call, `verdict_word` is unchanged, and `judge.yaml` is still written. Whole rows and
    not one column: `withheld_reason`, `world_findings`, `sample_unavailable` and every other
    per-world field are as much a part of "the per-world rows are what they are" as the bucket
    is, and a comparison of one field is green for a family fault that corrupted the rest.
    The family call is an addition to the pass, so its failure may not unwind the pass.

    What failure looks like: the exception escapes the draw loop and the whole episode's grade
    is thrown away AFTER every per-world model call has been paid for — the blast radius the
    malformed-reply arm already exists to eliminate, re-introduced by a new call site.
    """
    ep = family_episode(tmp_path, monkeypatch)
    clean = W.FakeJudge(W.reply_document())
    baseline = grade(ep, clean)
    (ep / W.JUDGE_NAME).unlink()

    faulting = W.FakeJudge(W.reply_document(), fault=W.Fault(fail_on=("family",)))
    result = grade(ep, faulting)

    assert any("family" in a for a in faulting.agent_ids), (
        f"no family call was attempted, so no family fault was induced and the equalities "
        f"below hold vacuously: {faulting.agent_ids}")
    assert (ep / W.JUDGE_NAME).is_file(), "a faulted family draw took the whole pass down"
    assert result.verdict_word == baseline.verdict_word
    faulted_rows = {r["world"]: r for r in result.worlds}
    clean_rows = {r["world"]: r for r in baseline.worlds}
    drifted = {
        world: {k: (clean_rows.get(world, {}).get(k), row.get(k))
                for k in set(row) | set(clean_rows.get(world, {}))
                if row.get(k) != clean_rows.get(world, {}).get(k)}
        for world, row in faulted_rows.items()
        if row != clean_rows.get(world)
    }
    assert set(faulted_rows) == set(clean_rows), (
        f"the faulted pass graded worlds {sorted(faulted_rows)} and the clean one "
        f"{sorted(clean_rows)} — a family fault changed WHICH worlds were graded")
    assert drifted == {}, (
        f"a faulted family draw changed per-world fields (world -> {{field: (clean, faulted)}}): "
        f"{drifted} — the family call is an addition to the pass and its failure may not reach "
        "a per-world row at all")


def test_the_family_trace_filename_cannot_collide_with_a_worlds_own(tmp_path):
    """The family call's trace filename cannot collide with a world's, even though the colon
    fold that makes the filename is not injective.

    Observably true: `judge:family:3` and a world whose label folded to `family_3` would compose
    one wire-log filename, and the manifest refuses that world label — so the collision is
    unconstructible rather than merely unlikely. The wire log is `serialized-append` and
    nothing there would raise: two streams simply interleave in one file.

    What failure looks like: the family call is given an agent id in the same namespace worlds
    use, and one episode's family trace and one world's trace are one document — with the
    10-32K-token prompts of both interleaved line by line.
    """
    family_mod = W.mod("runtime.branch._family")
    observe = W.mod("runtime.observe")

    def trace_name(agent_id: str) -> str:
        return observe.stage_trace_path(
            Path("/tmp"), f"{agent_id.replace(':', '_')}_framed_trace.jsonl").name

    assert trace_name("judge:family:3") == trace_name("judge_family_3"), (
        "the colon fold is injective after all — this test's premise moved")
    for colliding in ("family", "family_3"):
        with pytest.raises(W.refusals()):
            family_mod.parse_family(W.family_doc(worlds=[
                W.base_world(), W.world_doc(colliding)]))
