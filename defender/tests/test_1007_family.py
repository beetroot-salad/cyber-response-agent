"""#1007 — M5: the family-level call, and the identity it must not collide with."""
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
    """The family prompt carries EVERY world — stories, facts and pre-flight's record — withholding
    none."""
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
    """A family-level finding may not attribute itself to a world: the pass owns identity."""
    built = family_episode(tmp_path, monkeypatch)
    judge = S.judge({S.FAMILY: S.family_reply(world=[family_finding(world="b")])})

    S.grade(built, judge)

    rows = family_rows(S.questioner_queue())
    assert rows, "the family finding reached no queue row, so the stamp below proves nothing"
    assert {r["world"] for r in rows} == {None}, (
        f"a family finding carried the model's own world onto the queue: {rows}")


def test_the_family_reply_admits_a_family_level_finding(tmp_path, monkeypatch):
    """The positive control: a family-level finding with no world stands and reaches the queue."""
    built = family_episode(tmp_path, monkeypatch)
    judge = S.judge({S.FAMILY: S.family_reply(world=[family_finding("unreachable")])})

    S.grade(built, judge)

    rows = [r for r in family_rows(S.questioner_queue()) if r["type"] == "unreachable"]
    assert rows, "the family finding reached no queue row"
    assert rows[0]["world"] is None, f"a family finding is stamped world={rows[0]['world']!r}"
    assert rows[0]["subject"] == W.SUBJECT_WORLD


def test_the_family_agent_id_cannot_collide_with_a_world_label(tmp_path, monkeypatch):
    """`family` becomes a RESERVED world label, so the family call's agent id and trace name cannot
    collide with a world's."""
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
    """`grade_episode` refuses a world labeled `family` ON ITS OWN ."""
    built = family_episode(tmp_path, monkeypatch, worlds=S.triad(family={}))
    judge = S.judge()
    with pytest.raises(W.refusals(), match="reserved"):
        S.grade(built, judge)
    assert judge.calls == 0, f"the pass called the judge before refusing: {judge.agent_ids}"


def test_the_family_call_emits_no_defender_finding(tmp_path, monkeypatch):
    """The family call never produces a `subject: defender` finding."""
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
    """The family call's draws combine by UNION (#1234 A13): every completed draw's design findings
    reach the questioner, each under its own id."""
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
    """The family call is UNCONDITIONAL — an episode with nothing to separate is exactly the episode
    it exists to say so about."""
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
    """A faulted family draw costs its own draw and nothing else."""
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
    """The family call's trace filename cannot collide with a world's, even though the colon fold
    that makes the filename is not injective."""
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
