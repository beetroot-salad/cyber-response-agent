"""#921 — where the judge runs, what it is triggered by, and what it leaves behind."""
from __future__ import annotations


import pytest

from defender.tests.support.learning.judge import _judge_921 as J
from defender.tests.support.learning.branch import _triplet_947 as T
from defender.tests.support.learning.core import _state1135
from defender.learning.core.config import LoopPaths
from defender.learning.core.state import LearningState, StateRefused
from defender.tests.support.learning.core._state1135 import env_state


@pytest.fixture(autouse=True)
def _tmp_roots(tmp_path, monkeypatch):
    """Both CONFIGURED roots point inside `tmp_path` for every scenario in this file.

    Without it a scenario takes its runs base from `tmp_path` and its episode dir from the
    production resolver, so `episode_dir_for` answers about the developer's and CI's REAL roots
    and the assertions compare two different trees.
    """
    monkeypatch.setenv(T.RUNS_BASE_ENV, str(tmp_path / "defender-runs"))
    monkeypatch.setenv(T.EPISODES_BASE_ENV, str(tmp_path / "episodes-root"))
    _state1135.set_state_dir(monkeypatch, tmp_path / "learning-state")


def _cli():
    return T.mod("learning.branch.cli")


def _tenant_paths():
    """#1078: the tenant `T.runs_base` (or `d9_tenant`) already created."""
    return T.current_tenant()


_EMPTY: dict = {"rows": []}


class _LazySibling(J.FakeSibling):
    """`J.FakeSibling`, its episode directory resolved when the launcher first starts a child
    (the launcher names the directory; the test does not). #1187: `J.FakeSibling` itself now
    finds the episode from each child's `--tenant` and `--episode` (the launcher mints the id),
    so this is the plain double, kept under its name for the scenarios that construct it."""


def _launch_judge() -> J.FakeJudge:
    """A judge double answering in the launched family's own served systems (#1224's fixture
    tenant serves `idp`, not the archived fixtures' `elastic`)."""
    return J.scripted_judge(default=J.as_reply_text(J.reply_doc(systems=["idp"])))


def _launch(tmp_path, *, judge=None, spawn=None, **seams):
    """Drive ONE whole episode through the real launcher, judge included.

    The judge is reached through `cli.main`'s injected `judge=` seam and never by patching a
    module attribute: the design named no seam for the judge's model call, so the seam is part
    of the contract and driving every launcher scenario through it is what discharges it.
    #1224: the launch runs over the live-oracle suite's fixture tenant, with a pre-flight
    oracle that serves the one captured call unchanged.
    """
    from defender.tests.learning.oracle.live_contracts import _spec1224 as S

    est = S.estate(tmp_path)
    if spawn is None:
        spawn = _LazySibling()
    if judge is None:
        judge = _launch_judge()
    launched = S.launch(tmp_path, est,
                        calls=[S.Call("idp", "query", S.query_params("user:alice"), _EMPTY)],
                        oracle=S.oracle(then=S.submit(_EMPTY, S.EMPTY_CLAIM)),
                        verifier=S.passing_verifier(), spawn=spawn, judge=judge, **seams)
    return launched.rc, judge, launched.ep


def test_921_episode_grade_is_the_artifacts_the_launcher_leaves(tmp_path):
    rc, judge, ep = _launch(tmp_path)

    assert rc in (0, 1), "the launcher's status is still about the LAUNCH, not about the grade"
    assert (ep / "judge.yaml").is_file(), "the family record was never written"
    graded = [label for label in ("b", "c") if J.draw_files(ep, label)]
    assert graded == ["b", "c"], "a non-control world was archived and never graded"
    for label in graded:
        assert J.draw_files(ep, label), f"world {label} has no per-draw reply on disk"

    grade = J.judge_record(ep)
    # #1234: the episode word is retired (A17); what the record carries for each graded world
    # is its row and its A6 commit state.
    assert [row["world"] for row in grade["worlds"]] == ["b", "c"], (
        "the family record carries no row per graded world")
    assert all(row.get("state") == "queued" for row in grade["worlds"]), (
        "a graded world's row was not committed")
    # #1007 M5 adds ONE MORE caller (the family-level draw) beside the per-world ones — one
    # call per world per draw, PLUS one call per draw for the family.
    assert judge.calls == (len(graded) + 1) * grade["draws"]["configured"], (
        "one model call per world per draw plus one per-draw family call is the contract; the "
        "seam saw a different count")


def test_921_unaccepted_episodes_are_not_graded(tmp_path):
    no_record = J.sym("learning.branch.outcome", "NO_RECORD")
    seen = {}
    for outcome in ("accepted", "unusable", "refused", "incomplete"):
        ep = J.accepted_episode(tmp_path / outcome, outcome=outcome)
        judge = J.scripted_judge()
        J.grade_at(ep, judge=judge, state=env_state())
        seen[outcome] = (judge.calls, (ep / "judge.yaml").is_file())
        if outcome != "accepted":
            record = J.judge_record(ep)
            assert record["not_graded"]["reason"], (
                f"an episode recorded {outcome!r} was skipped with no reason on the record")
            word = no_record if outcome == "incomplete" else outcome
            assert record["not_graded"]["outcome"] == word, (
                f"the record does not name the outcome that caused it: {record['not_graded']}")

    assert seen["accepted"][0] > 0, "the accepted episode was not graded — the control failed"
    assert seen["unusable"][0] == 0, "an unusable episode reached the model"
    assert seen["refused"][0] == 0, "a refused episode reached the model"
    assert seen["incomplete"][0] == 0, "an episode with no outcome word reached the model"


def test_921_the_trigger_reads_the_outcome_record_preflight_wrote(tmp_path):
    import yaml

    rc, judge, ep = _launch(tmp_path)
    record = yaml.safe_load((ep / "outcome.yaml").read_text(encoding="utf-8"))

    assert record["outcome"] in ("accepted", "unusable", "refused")
    assert not (ep / "review.yaml").exists(), "a launch still wrote the retired review record"
    graded = J.judge_record(ep) if (ep / "judge.yaml").exists() else {}
    assert bool(graded) is (record["outcome"] == "accepted"), (
        "the grade did not follow the one record the trigger is specified to read")
    assert record["outcome"] == "accepted", (
        "positive control: the launch's one served call calibrated, so the episode is accepted")


def test_921_existing_judge_yaml_stops_a_second_grade(tmp_path):
    ep = J.accepted_episode(tmp_path)

    first = J.scripted_judge()
    J.grade_at(ep, judge=first, state=env_state())
    assert first.calls > 0, "the control failed: the first pass never reached the model"
    before = (ep / "judge.yaml").read_text(encoding="utf-8")

    second = J.scripted_judge()
    J.grade_at(ep, judge=second, state=env_state())
    assert second.calls == 0, "a second grade ran over an episode already graded"
    assert (ep / "judge.yaml").read_text(encoding="utf-8") == before

    # J11: readability, not just presence — a `judge.yaml` that cannot be read back as a family
    # grade is not evidence that the episode was graded.
    (ep / "judge.yaml").write_text("\x00not: [a, family, grade", encoding="utf-8")
    third = J.scripted_judge()
    with pytest.raises(J.refusals()):
        J.grade_at(ep, judge=third, state=env_state())


def test_921_both_episode_write_sinks_go_through_write_guarded(tmp_path):
    ep = J.accepted_episode(tmp_path)
    outside = tmp_path / "outside.yaml"
    outside.write_text("untouched\n", encoding="utf-8")
    (ep / "judge.yaml").symlink_to(outside)

    with pytest.raises(J.refusals()):
        J.grade_at(
            ep, judge=J.FakeJudge(default=J.as_reply_text(J.reply_doc())), state=env_state())
    assert outside.read_text(encoding="utf-8") == "untouched\n", (
        "the family record was written THROUGH an aliased target")

    # The per-draw sink, same guarantee, same refusal.
    (ep / "judge.yaml").unlink()
    draw_dir = ep / "worlds" / "b" / "judge"
    draw_dir.mkdir(parents=True, exist_ok=True)
    (draw_dir / "0.yaml").symlink_to(outside)
    with pytest.raises(J.refusals()):
        J.grade_at(
            ep, judge=J.FakeJudge(default=J.as_reply_text(J.reply_doc())), state=env_state())
    assert outside.read_text(encoding="utf-8") == "untouched\n"

    # POSITIVE CONTROL, same episode, same channel: with neither link the same grade lands both
    # sinks as plain files — so each refusal above was the link's, not the episode failing to
    # open at all (which a bare `pytest.raises(J.refusals())` would also accept; #1187 sweep).
    (draw_dir / "0.yaml").unlink()
    J.grade_at(ep, judge=J.FakeJudge(default=J.as_reply_text(J.reply_doc())), state=env_state())
    assert (ep / "judge.yaml").is_file(), "control: the unlinked grade wrote no judge.yaml"
    assert not (ep / "judge.yaml").is_symlink(), "control: judge.yaml is not a plain file"
    assert outside.read_text(encoding="utf-8") == "untouched\n"


def test_921_judge_yaml_is_written_last_and_carries_the_enqueued_and_completed_counts(tmp_path):
    ep = J.accepted_episode(tmp_path)

    grade = J.grade_at(
        ep, judge=J.FakeJudge(default=J.as_reply_text(J.reply_doc())), state=env_state())
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
    # An enqueue that cannot land: the queue's holding folder is a regular file (a permission
    # bit would not bind a root test runner, and the handle owns the root's layout now).
    (queue_dir / "_pending").write_text("not a directory", encoding="utf-8")
    refused = LearningState.open(LoopPaths(repo_root=tmp_path / "second", state_dir=queue_dir))
    # `StateRefused` is deliberately not an `OSError`, so it is not folded into `JudgeRefused`.
    with pytest.raises((*J.refusals(), StateRefused)):
        J.grade_at(
            ep2, judge=J.FakeJudge(default=J.as_reply_text(J.reply_doc())),
            state=refused)
    states = {row["world"]: row.get("state") for row in J.judge_record(ep2)["worlds"]}
    assert "queued" not in states.values(), (
        f"a row whose append failed was committed `queued`: {states} — its presence would then "
        "certify an enqueue that never happened")
    assert states.get("b") == "queueing", f"the failed commit is not on world b's row: {states}"
    with pytest.raises(J.refusals()) as rerun:
        J.grade_at(ep2, judge=J.scripted_judge(), state=refused)
    assert "queueing" in str(rerun.value), "the re-run did not refuse the uncommitted row"


def test_921_the_three_knobs_are_resolved_once_and_an_oversized_lead_is_truncated_with_a_marker(
        tmp_path, monkeypatch):
    monkeypatch.setenv(J.DRAWS_KNOB, "2")
    monkeypatch.setenv(J.MODEL_KNOB, "kimi-k3")
    monkeypatch.setenv(J.EFFORT_KNOB, "xhigh")
    monkeypatch.setenv(J.CAP_KNOB, "3000")

    ep = J.accepted_episode(tmp_path)
    # One lead whose joined payload cannot fit the cap, through the real archived artifact.
    world = ep / "worlds" / "b"
    (world / "gather_summaries" / "l-001.md").write_text(
        "x" * 4000 + "\nTAIL-OF-THE-OVERSIZED-LEAD\n", encoding="utf-8")

    judge = J.FakeJudge(default=J.as_reply_text(J.reply_doc()))
    J.grade_at(ep, judge=judge, state=env_state())

    record = J.judge_record(ep)
    assert record["draws"]["configured"] == 2
    assert record["knobs"] == {"draws": 2, "model": "kimi-k3", "effort": "xhigh",
                               "payload_cap": 3000}, (
        "the resolved knob values are not recorded beside the draw count")
    assert len(J.draw_files(ep, "b")) == 2, "the draws knob was not honoured once per pass"

    prompt = judge.prompts[0]
    assert "TAIL-OF-THE-OVERSIZED-LEAD" not in prompt, "the cap did not fire"
    assert "truncated" in prompt.lower(), (
        "the oversized lead was dropped with no marker: a dropped lead is invisible to the "
        "judge and to the reader of its reply")
    assert "l-001" in prompt, "the truncated lead vanished from the view entirely"


    layout = J.mod("learning.judge.layout")
    manifest = J.read_manifest_at(ep)
    ctx = J.render_at(ep, "b", payload_cap=3000)
    blocks = [block for _title, section in layout.world_layout(ctx, manifest).sections
              for block in section]
    charged = sum(layout._block_cost(block) for block in blocks
                  if "VIEW 1" not in str(block[0]))
    assert charged <= 3000, "the rendered views together exceed the operator's payload cap"
