"""#921 — where the judge runs, what it is triggered by, and what it leaves behind.

**J10, settled at the §7 human seam: the judge runs at the TAIL of the step runner**
(`cli._run_episode`), after the archive step (`verify_family`) and before the return — NOT in
`_launch`'s post-teardown cleanup path. The design's own sentence said "after teardown"; a probe
found that frame production-dead on this route (teardown fires in `_launch`'s `finally`, after
`_run_episode` has already returned, and `_run_episode`'s own teardown at `cli.py:931` is never
reached), and A9 removed the reason the design preferred it — every sibling is waited for before
the archive step, so no container is live either side of the slot. Demand #0 was provisional on
that fork and is settled by it: every drive point in this suite hangs off this answer.

RED against `d1b8b06a`: `cli.main` has no `judge=` seam, `learning/judge/` does not exist, and
nothing at base reads `review.yaml`'s outcome to decide what to do next.
"""
from __future__ import annotations

import json

import pytest

from defender.tests import _judge_921 as J
from defender.tests import _triplet_947 as T


@pytest.fixture(autouse=True)
def _tmp_roots(tmp_path, monkeypatch):
    """Both CONFIGURED roots point inside `tmp_path` for every scenario in this file.

    Without it a scenario takes its runs base from `tmp_path` and its episode dir from the
    production resolver, so `episode_dir_for` answers about the developer's and CI's REAL roots
    and the assertions compare two different trees.
    """
    monkeypatch.setenv(T.RUNS_BASE_ENV, str(tmp_path / "defender-runs"))
    monkeypatch.setenv(T.EPISODES_BASE_ENV, str(tmp_path / "episodes-root"))


def _cli():
    return T.mod("learning.branch.cli")


def _launch(tmp_path, *, judge=None, spawn=None, argv_extra=(), **seams):
    """Drive ONE whole episode through the real launcher, judge included.

    The judge is reached through `cli.main`'s injected `judge=` seam and never by patching a
    module attribute: the design named no seam for the judge's model call, so the seam is part
    of the contract and driving every launcher scenario through it is what discharges it.
    """
    base, src = T.runs_base(tmp_path)
    episode_dir = _cli().episode_dir_for(T.EPISODE_ID)
    if spawn is None:
        spawn = J.FakeSibling(episode_dir)
    if judge is None:
        judge = J.FakeJudge(default=J.as_reply_text(J.reply_doc()))
    seams.setdefault("door", T.FakeDoor())
    seams.setdefault("questioner",
                     T.FakeAgent(T.family_doc(), T.world_doc("b"), T.world_doc("c")))
    seams.setdefault("adapters", T.FakeAdapters())
    seams.setdefault("invoke", T.FakeAgent(*["same"] * 24))
    seams.setdefault("preflight", T.no_preflight)
    rc = _cli().main([str(src), str(T.BRANCH_MESSAGE_ID), "--continuation-prompt", "go",
                      *argv_extra],
                     spawn=spawn, judge=judge, **seams)
    return rc, judge, episode_dir


# ---------------------------------------------------------------------------------------
# demand #0 — the return-value contract
# ---------------------------------------------------------------------------------------


def test_921_episode_grade_is_the_artifacts_the_launcher_leaves(tmp_path):
    """Driving the launcher over an accepted episode leaves exactly three artifact sets and
    returns nothing that carries the grade: `worlds/<X>/judge/<n>.yaml` one per world per draw,
    `episodes/<id>/judge.yaml` once, and one appended row per finding in `findings.jsonl`.

    The chain has no single return value; its observable contract is WRITTEN ARTIFACTS, and the
    launcher's own status stays what it always was — about the LAUNCH, not about the grade. The
    judge is called at the tail of `_run_episode`, after the archive step and before the return
    (J10), so the worlds it grades are the ones `verify_family` has just archived.

    `render` is the one pure function whose RETURN is the contract (a `JudgeInput`); the family
    pass returns the `FamilyGrade` it writes, and the enqueue returns the appended-row count,
    the shape `_io.append_jsonl(path, rows) -> int` already has.
    """
    judge = J.FakeJudge(default=J.as_reply_text(J.reply_doc()))
    rc, judge, ep = _launch(tmp_path, judge=judge)

    assert rc in (0, 1), "the launcher's status is still about the LAUNCH, not about the grade"
    assert (ep / "judge.yaml").is_file(), "the family record was never written"
    graded = [label for label in ("b", "c") if J.draw_files(ep, label)]
    assert graded == ["b", "c"], "a non-control world was archived and never graded"
    for label in graded:
        assert J.draw_files(ep, label), f"world {label} has no per-draw reply on disk"

    grade = J.judge_record(ep)
    assert grade.get("episode_outcome"), "the family record carries no episode outcome"
    assert judge.calls == len(graded) * grade["draws"]["configured"], (
        "one model call per world per draw is the contract; the seam saw a different count")


# ---------------------------------------------------------------------------------------
# the trigger
# ---------------------------------------------------------------------------------------


def test_921_rejected_and_incomplete_episodes_are_not_graded(tmp_path):
    """Only an `accepted` episode is graded; `rejected` and `incomplete` are recorded as "not
    graded, reason" rather than passing silently.

    Base's own reader gates on `incomplete` ALONE and admits `rejected` (G14), so the
    grade-only-on-accepted rule is #921's and not the base's — and an `incomplete` episode can
    still hold cleanly archived worlds, which is exactly why the refusal has to be RECORDED
    rather than expressed as an absent file. Positive control in the same drive: the accepted
    episode does get graded, so the negative cannot pass on a judge that never runs.
    """
    judge_mod = J.mod("learning.judge")
    seen = {}
    for outcome in ("accepted", "rejected", "incomplete"):
        ep = J.accepted_episode(tmp_path / outcome, outcome=outcome)
        judge = J.FakeJudge(default=J.as_reply_text(J.reply_doc()))
        judge_mod.grade_episode(ep, judge=judge, runs_base=tmp_path / outcome / "defender-runs")
        seen[outcome] = (judge.calls, (ep / "judge.yaml").is_file())
        if outcome != "accepted":
            record = J.judge_record(ep)
            assert record["not_graded"]["reason"], (
                f"an episode recorded {outcome!r} was skipped with no reason on the record")
            assert outcome in json.dumps(record["not_graded"]), (
                "the recorded reason does not name the outcome that caused it")

    assert seen["accepted"][0] > 0, "the accepted episode was not graded — the control failed"
    assert seen["rejected"][0] == 0, "a rejected episode reached the model"
    assert seen["incomplete"][0] == 0, "an incomplete episode reached the model"


def test_921_the_trigger_reads_the_single_episode_outcome_key_step_six_wrote(tmp_path):
    """`review.yaml` carries ONE `episode.outcome` key, not two.

    Step 4 writes a human sentence into it and step 6's `merge_review` OVERWRITES that with its
    enum value on every episode that reaches step 6 (P8, executed end to end: the step-4
    sentence is then absent from the file entirely), so by the time the judge runs the key
    always holds step 6's word; `decision` beside it is step 4's and is not the trigger. Drive a
    full episode and read the key back off disk.
    """
    import yaml

    rc, judge, ep = _launch(tmp_path)
    record = yaml.safe_load((ep / "review.yaml").read_text(encoding="utf-8"))

    assert isinstance(record["episode"]["outcome"], str)
    assert "worlds reviewed" not in record["episode"]["outcome"], (
        "step 4's descriptive sentence survived into the archived record; P8 says step 6 "
        "overwrites it, and a judge reading a sentence where an enum is expected reads the "
        "wrong half")
    assert record["episode"]["outcome"] in ("accepted", "rejected", "incomplete")
    # `decision` is step 4's, sits beside it, and is NOT what the trigger reads.
    assert "decision" in record["episode"]
    graded = J.judge_record(ep) if (ep / "judge.yaml").exists() else {}
    assert bool(graded) is (record["episode"]["outcome"] == "accepted"), (
        "the grade did not follow the one key the trigger is specified to read")


def test_921_existing_judge_yaml_stops_a_second_grade(tmp_path):
    """A present `judge.yaml` stops a second grade, and a present-but-unreadable one is a
    refusal rather than a pass.

    Note what the presence gate does NOT say: nothing in it records whether the ENQUEUE ran, so
    a crash between the family write and the enqueue would orphan that episode's findings
    forever, with `judge.yaml` present and the episode unrerunnable (re-running the same
    source-run + branch-point pair is refused outright). That is why J11 moves the write to
    last; this demand pins the gate itself. Positive control: the same episode with no
    `judge.yaml` IS graded, so the negative cannot pass on a judge that never runs.
    """
    judge_mod = J.mod("learning.judge")
    ep = J.accepted_episode(tmp_path)
    base = tmp_path / "defender-runs"

    first = J.FakeJudge(default=J.as_reply_text(J.reply_doc()))
    judge_mod.grade_episode(ep, judge=first, runs_base=base)
    assert first.calls > 0, "the control failed: the first pass never reached the model"
    before = (ep / "judge.yaml").read_text(encoding="utf-8")

    second = J.FakeJudge(default=J.as_reply_text(J.reply_doc()))
    judge_mod.grade_episode(ep, judge=second, runs_base=base)
    assert second.calls == 0, "a second grade ran over an episode already graded"
    assert (ep / "judge.yaml").read_text(encoding="utf-8") == before

    # J11: readability, not just presence — a `judge.yaml` that cannot be read back as a family
    # grade is not evidence that the episode was graded.
    (ep / "judge.yaml").write_text("\x00not: [a, family, grade", encoding="utf-8")
    third = J.FakeJudge(default=J.as_reply_text(J.reply_doc()))
    with pytest.raises(J.refusals()):
        judge_mod.grade_episode(ep, judge=third, runs_base=base)


# ---------------------------------------------------------------------------------------
# write discipline and completion
# ---------------------------------------------------------------------------------------


def test_921_both_episode_write_sinks_go_through_write_guarded(tmp_path):
    """Both episode sinks are written through `write_guarded` into a tree #947 screens as
    box-reachable: `worlds/<X>/judge/<n>.yaml` and `episodes/<id>/judge.yaml`.

    `mode="replace"` stages to an unpredictable name and `os.replace`s, so the target holds the
    old bytes or the complete new bytes and never a partial write; it refuses an ALIASED target
    and clobbers an ordinary one (P4, executed). The refusal is the observable this drives: a
    symlink planted at either sink's path is refused rather than written THROUGH, which is what
    a bare `write_text` would do.
    """
    judge_mod = J.mod("learning.judge")
    ep = J.accepted_episode(tmp_path)
    base = tmp_path / "defender-runs"
    outside = tmp_path / "outside.yaml"
    outside.write_text("untouched\n", encoding="utf-8")
    (ep / "judge.yaml").symlink_to(outside)

    with pytest.raises(J.refusals()):
        judge_mod.grade_episode(
            ep, judge=J.FakeJudge(default=J.as_reply_text(J.reply_doc())), runs_base=base)
    assert outside.read_text(encoding="utf-8") == "untouched\n", (
        "the family record was written THROUGH an aliased target")

    # The per-draw sink, same guarantee, same refusal.
    (ep / "judge.yaml").unlink()
    draw_dir = ep / "worlds" / "b" / "judge"
    draw_dir.mkdir(parents=True, exist_ok=True)
    (draw_dir / "0.yaml").symlink_to(outside)
    with pytest.raises(J.refusals()):
        judge_mod.grade_episode(
            ep, judge=J.FakeJudge(default=J.as_reply_text(J.reply_doc())), runs_base=base)
    assert outside.read_text(encoding="utf-8") == "untouched\n"


def test_921_judge_yaml_is_written_last_and_carries_the_enqueued_and_completed_counts(tmp_path):
    """`judge.yaml` is written LAST, after the enqueue, and carries the enqueued row count and
    the per-world completed-draw counts (J11, settled at the §7 seam).

    That one ordering is what makes the presence gate mean something: `judge.yaml`'s presence
    otherwise says nothing about whether the enqueue ran, and a crash between the family write
    and the enqueue orphans that episode's findings forever on an episode that cannot be re-run.
    With the counts on the record, "graded with nothing to report" is distinguishable from
    "never graded" and a resumed invocation's decision is derivable.

    Driven by failing the enqueue through the real primitive: the queue's pending directory is
    made unwritable, so the append raises where it really would, and the assertion is that no
    `judge.yaml` exists afterwards.
    """
    judge_mod = J.mod("learning.judge")
    ep = J.accepted_episode(tmp_path)
    base = tmp_path / "defender-runs"

    grade = judge_mod.grade_episode(
        ep, judge=J.FakeJudge(default=J.as_reply_text(J.reply_doc())), runs_base=base)
    record = J.judge_record(ep)
    assert record["enqueued_rows"] == grade.enqueued_rows
    assert record["enqueued_rows"] > 0, "a gradable episode with findings enqueued nothing"
    completed = {row["world"]: row["completed_draws"] for row in record["worlds"]}
    assert completed, "the family record carries no per-world rows at all"
    assert all(n > 0 for n in completed.values()), (
        "the family record does not carry a per-world completed-draw count")

    # The ordering itself: an enqueue that cannot land leaves NO family record behind.
    ep2 = J.accepted_episode(tmp_path / "second")
    queue_dir = tmp_path / "second" / "queue"
    queue_dir.mkdir(parents=True, exist_ok=True)
    queue_dir.chmod(0o500)
    try:
        with pytest.raises(J.refusals()):
            judge_mod.grade_episode(
                ep2, judge=J.FakeJudge(default=J.as_reply_text(J.reply_doc())),
                runs_base=tmp_path / "second" / "defender-runs", queue_dir=queue_dir)
    finally:
        queue_dir.chmod(0o700)
    assert not (ep2 / "judge.yaml").exists(), (
        "the family record was written before the enqueue: its presence would then certify an "
        "enqueue that never happened")


def test_921_the_three_knobs_are_resolved_once_and_an_oversized_lead_is_truncated_with_a_marker(
        tmp_path, monkeypatch):
    """The three operator knobs — draws-per-world, the judge's model/effort, and the render's
    payload cap — are resolved ONCE at the top of the episode-grading pass, their resolved
    values are recorded on the family record beside the draw count, and a lead whose join
    exceeds the cap is TRUNCATED with an explicit marker rather than dropped silently (J15).

    Reading once per pass is not tidiness. Because a retry clobbers each existing draw file in
    place rather than erroring and no cleanup step exists (P4), a draws knob that SHRINKS
    between two attempts is the only way stale draw files survive — so re-reading it per world
    is what makes the retry story non-deterministic. And a dropped lead is invisible to the
    judge AND to the reader of its reply, while Scale records 10-32K input tokens per call, so a
    cap that fires is an event worth seeing.

    The knob names carry no `DEFENDER_` prefix, matching `QUESTIONER_EFFORT`: run1/G23 executed
    that convention, and a judge knob spelled with the prefix would be unsettable.
    """
    judge_mod = J.mod("learning.judge")
    monkeypatch.setenv(J.DRAWS_KNOB, "2")
    monkeypatch.setenv(J.MODEL_KNOB, "kimi-k3")
    monkeypatch.setenv(J.EFFORT_KNOB, "xhigh")
    monkeypatch.setenv(J.CAP_KNOB, "400")

    ep = J.accepted_episode(tmp_path)
    # One lead whose joined payload cannot fit the cap, through the real archived artifact.
    world = ep / "worlds" / "b"
    (world / "gather_summaries" / "l-001.md").write_text(
        "x" * 4000 + "\nTAIL-OF-THE-OVERSIZED-LEAD\n", encoding="utf-8")

    judge = J.FakeJudge(default=J.as_reply_text(J.reply_doc()))
    judge_mod.grade_episode(ep, judge=judge, runs_base=tmp_path / "defender-runs")

    record = J.judge_record(ep)
    assert record["draws"]["configured"] == 2
    assert record["knobs"] == {"draws": 2, "model": "kimi-k3", "effort": "xhigh",
                               "payload_cap": 400}, (
        "the resolved knob values are not recorded beside the draw count")
    assert len(J.draw_files(ep, "b")) == 2, "the draws knob was not honoured once per pass"

    prompt = judge.prompts[0]
    assert "TAIL-OF-THE-OVERSIZED-LEAD" not in prompt, "the cap did not fire"
    assert "truncated" in prompt.lower(), (
        "the oversized lead was dropped with no marker: a dropped lead is invisible to the "
        "judge and to the reader of its reply")
    assert "l-001" in prompt, "the truncated lead vanished from the view entirely"
