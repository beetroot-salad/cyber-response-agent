"""#1007 — M5: the family-level call, and the identity it must not collide with.

One call per draw, judging what no single world can: whether the family as a whole separated
anything. It is shown every usable run — each one's header (story, facts), contrast row and
fact surfaces — and pre-flight's record, withholding none (#1234 M6, which replaced #1224's
overlays and judged rows: the family call reads no per-world reply, P-c).

The family reply files family-scope world findings only (#1234 M6: no verdict word, no
investigator finding). A family finding carries `world: null` (tested with the queue rows, in
`test_1007_partition.py`) and never reaches the defender channel (below).
"""
from __future__ import annotations

from pathlib import Path

import pytest

from defender.tests import _world_1007 as W
from defender.tests.judge_contrast_1234 import _spec1234 as S


def family_episode(tmp_path: Path, monkeypatch, *, worlds=None, **kw):
    """An archived, accepted triad (control `a`, planted `b` and `c`) — #1234's builder."""
    return W.contrast_family(tmp_path, monkeypatch, worlds, **kw)


#: A family-scope design finding: a plan pointer at the manifest's family-level part.
def family_finding(bucket: str = "unreachable", **over):
    over.setdefault("evidence", [S.plan_ptr()])
    return S.wf(bucket, **over)


def family_rows(queue) -> list[dict]:
    return [r for r in queue if str(r.get("finding_id", "")).split("/")[1:2] == ["family"]]


def test_the_family_call_is_shown_every_world(tmp_path, monkeypatch):
    """The family prompt carries EVERY world — stories, facts and pre-flight's record —
    withholding none.

    Observably true: the family draw's prompt names each planted world's own story and fact
    and carries pre-flight's outcome. The family call's whole question is about the set, so
    withholding any member makes the question unanswerable.

    What failure looks like: the family call is handed a summary, or one world's context. It is
    then asked whether the family discriminated while being shown one world.
    """
    built = family_episode(tmp_path, monkeypatch, outcome_reason="PREFLIGHT-REASON-MARKER")
    judge = S.judge()

    S.grade(built, judge)

    prompts = judge.prompts_for(S.FAMILY)
    assert prompts, f"no family-level call was made: agent ids {judge.agent_ids}"
    for label in ("b", "c"):
        assert S.marker(label, "story") in prompts[0], (
            f"the family prompt withholds world {label}'s story")
        assert S.marker(label, f"fact-f-{label}") in prompts[0], (
            f"the family prompt withholds world {label}'s facts")
    assert "PREFLIGHT-REASON-MARKER" in prompts[0], (
        "the family prompt carries no pre-flight record")


def test_the_family_reply_may_not_name_a_world(tmp_path, monkeypatch):
    """A family-level finding may not attribute itself to a world: the pass owns identity.

    Observably true: a family reply whose finding carries `world: b` validates — the validator
    ignores a model's own `world` key rather than refusing the reply (`run._parse_world_finding`
    reads only the finding's own fields) — and the queue row it becomes is stamped
    `world: null`, the family's, whatever the model wrote. The parity control is that the same
    reply's finding reaches the questioner channel at all, so the null is a stamp, not an empty
    pass.

    What failure looks like: a model attributes a family-level observation to whichever world
    it found most memorable, and the questioner corpus grows a lesson about a world that did
    not have the property.
    """
    built = family_episode(tmp_path, monkeypatch)
    judge = S.judge({S.FAMILY: S.family_reply(world=[family_finding(world="b")])})

    S.grade(built, judge)

    rows = family_rows(S.questioner_queue())
    assert rows, "the family finding reached no queue row, so the stamp below proves nothing"
    assert {r["world"] for r in rows} == {None}, (
        f"a family finding carried the model's own world onto the queue: {rows}")


def test_the_family_reply_admits_a_family_level_finding(tmp_path, monkeypatch):
    """The positive control: a family-level finding with no world stands and reaches the queue.

    Observably true: a family reply carrying an `unreachable` design finding validates and
    lands as a `subject: world`, `world: null` row on the questioner channel. Without this the
    refusal above would read as correct on a family call whose replies are all discarded.

    What failure looks like: the family lane validates nothing at all, and M5 is a paid model
    call whose output reaches no artifact.
    """
    built = family_episode(tmp_path, monkeypatch)
    judge = S.judge({S.FAMILY: S.family_reply(world=[family_finding("unreachable")])})

    S.grade(built, judge)

    rows = [r for r in family_rows(S.questioner_queue()) if r["type"] == "unreachable"]
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

    built = family_episode(tmp_path, monkeypatch)
    judge = S.judge()
    S.grade(built, judge)
    family_ids = judge.calls_for(S.FAMILY)
    assert family_ids, "no family call was made"
    world_ids = [a for a in judge.agent_ids if a not in family_ids]
    assert world_ids, "no world call was made, so there is nothing to collide with"
    assert not set(family_ids) & set(world_ids), "the family call reuses a world's agent id"


def test_grade_episode_itself_refuses_a_world_labeled_family(tmp_path, monkeypatch):
    """`grade_episode` refuses a world labeled `family` ON ITS OWN — not merely through
    `parse_family`, which the test above shows refuses it too, but which `grade_episode` never
    calls (`family_mod.parse_family` is the LAUNCHER's manifest parse; `grade_episode` reads its
    own manifest and never runs the launcher's `check_identities`).

    Observably true: an episode whose manifest was hand-assembled with a world literally
    labeled `family` — bypassing the launcher entirely, as a re-entered or hand-repaired episode
    could — is refused by `grade_episode` itself, at `_check_world_labels`, before any finding
    row is built off it.

    What failure looks like: `grade_episode` mints a `worlds/family/judge/` archive and a
    `judge:family:<n>` agent id for that world's OWN per-world draws, landing in the exact
    files and exact agent-id namespace the family-level call (M5) uses for itself.
    """
    built = family_episode(tmp_path, monkeypatch, worlds=S.triad(family={}))
    judge = S.judge()
    with pytest.raises(W.refusals(), match="reserved"):
        S.grade(built, judge)
    assert judge.calls == 0, f"the pass called the judge before refusing: {judge.agent_ids}"


def test_the_family_call_emits_no_defender_finding(tmp_path, monkeypatch):
    """The family call never produces a `subject: defender` finding.

    Observably true: a family reply carrying an investigator (defender) finding is refused
    (#1234 M6: the family reply files family-scope world findings only), and no row for it
    reaches the defender findings channel. The family call grades the FAMILY; a defender
    finding out of it would be authored from a view that never looked at an investigation.

    What failure looks like: the family reply is validated with the per-world validator, a
    `lead-set` finding rides through, and the defender corpus gains a lesson derived from a
    call that read no investigation document at all.
    """
    built = family_episode(tmp_path, monkeypatch)
    judge = S.judge({S.FAMILY: S.family_reply(**{S.INVESTIGATOR: [S.inv("lead-set")]})})

    S.grade(built, judge)

    assert judge.called(S.FAMILY), (
        f"no family call was made at all, so the absence below proves nothing: "
        f"{judge.agent_ids}")
    assert S.family_row(built).get("completed_draws") == 0, (
        f"a family reply carrying an investigator finding completed a draw: "
        f"{S.family_row(built)}")
    from_family = family_rows(S.defender_queue())
    assert from_family == [], (
        f"the family call produced defender queue rows: {from_family}")


def test_family_draws_combine_by_union(tmp_path, monkeypatch):
    """The family call's draws combine by UNION (#1234 A13): every completed draw's design
    findings reach the questioner, each under its own id.

    Observably true: three family draws filing three different design findings leave all
    three on the questioner queue, keyed `<episode>/family/<draw>/<index>` for draws 0, 1 and
    2. (#1007 pinned a majority over the family's verdict word; #1234 retired the word and
    settled the family's combination as a union.)

    What failure looks like: only one draw's findings are kept (the first, or a majority's),
    and a family flaw one draw saw is lost because the others did not file it.
    """
    built = family_episode(tmp_path, monkeypatch)
    judge = S.judge({(S.FAMILY, n): S.family_reply(world=[family_finding(bucket)])
                     for n, bucket in enumerate(("unreachable", "incoherent", "mislabelled"))})

    S.grade(built, judge, draws=3)

    assert len(judge.calls_for(S.FAMILY)) == 3, (
        f"the family call was not drawn three times: {judge.agent_ids}")
    rows = family_rows(S.questioner_queue())
    assert sorted((r["finding_id"].split("/")[2], r["type"]) for r in rows) == [
        ("0", "unreachable"), ("1", "incoherent"), ("2", "mislabelled")], (
        f"the family's draws did not combine by union: {rows}")


def test_the_family_call_is_made_even_when_there_is_nothing_to_separate(
        tmp_path, monkeypatch):
    """The family call is UNCONDITIONAL — an episode with nothing to separate is exactly the
    episode it exists to say so about.

    Observably true: an episode whose planted worlds all tell one story, declare the
    control's disposition, and are all judged to have no bucket (`none`) still makes the
    family call. "Nothing separated these worlds" is the family judge's own most useful answer;
    gating the call on there being something to say makes it unsayable.

    What failure looks like: `if contrasting_worlds: run_family_draw()`. The undiscriminating
    families — the ones the questioner most needs to learn from — are the only ones never
    graded.
    """
    same = {"story": "the same story", "declared": "benign"}
    built = family_episode(tmp_path, monkeypatch, worlds=S.triad(b=same, c=same))
    judge = S.judge()                      # every world call answers bucket `none`

    S.grade(built, judge)

    for label in ("b", "c"):
        assert judge.called(label), f"world {label} went ungraded: {judge.agent_ids}"
    assert judge.called(S.FAMILY), (
        f"no family call was made for an undiscriminating episode: {judge.agent_ids}")


def test_a_faulted_family_draw_isolates_and_leaves_the_per_world_rows_intact(
        tmp_path, monkeypatch):
    """A faulted family draw costs its own draw and nothing else.

    Observably true: with the family call raising and every per-world draw completing, the
    per-world rows are equal FIELD FOR FIELD to the rows the same episode grades with a clean
    family call, `judge.yaml` is still written, and the family row records that it completed
    no draw and why. Whole rows and not one column: `bucket`, `systems`, `draws` and every
    other per-world field are as much a part of "the per-world rows are what they are" as any
    one is, and a comparison of one field is green for a family fault that corrupted the rest.

    What failure looks like: the exception escapes the draw loop and the whole episode's grade
    is thrown away AFTER every per-world model call has been paid for — the blast radius the
    malformed-reply arm already exists to eliminate, re-introduced by a new call site.
    """
    replies = {"b": S.world_reply("lead-quality", ["idp"], investigator=[S.inv()])}
    clean_built = family_episode(tmp_path / "clean", monkeypatch)
    baseline = S.grade(clean_built, S.judge(dict(replies)))
    built = family_episode(tmp_path / "faulted", monkeypatch)

    faulting = S.judge(dict(replies), fail={S.FAMILY})
    result = S.grade(built, faulting)

    assert faulting.called(S.FAMILY), (
        f"no family call was attempted, so no family fault was induced and the equalities "
        f"below hold vacuously: {faulting.agent_ids}")
    assert (built.ep / W.JUDGE_NAME).is_file(), "a faulted family draw took the whole pass down"
    assert (baseline.family or {}).get("completed_draws") == 1, baseline.family
    family = result.family or {}
    assert family.get("completed_draws") == 0, (
        f"the faulted family call was recorded as having answered: {family}")
    assert family.get("draws_failed_reason"), (
        f"the faulted family call's row does not say why it completed no draw: {family}")
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
