"""#921 — the outcome vocabulary, the 08-16 fixture, and the corrected write census.

THE DESIGN'S OWN SECURITY CENSUS IS WRONG AND THIS FILE CARRIES THE CORRECTION. It names two new
write sinks — `worlds/<X>/judge/` and `episodes/<id>/judge.yaml`. There are THREE:
`learning/branch/seams.py::model_seam` builds a `StageContext(learning_run_dir=episode_dir)` and
`_pydantic_stage.run_stage` writes every call's FULL wire stream to
`<episode_dir>/wire_logs/<agent_id>_trace.jsonl` — the seam's own docstring says "THE TRACE LANDS
IN THE EPISODE". #921's per-world judge calls multiply that stream by worlds x draws, each
carrying the whole 10-32K-token prompt verbatim, so the undeclared sink holds the LARGEST
artifact in the tree. J14, settled: declare it in the census and note in the same sentence that
it is already denied to the model, so the fix is a census correction rather than a mechanism.

RED against `d1b8b06a`: `_vocab.py` has no `JUDGE_OUTCOME_ENUM` and no normalizer for one.
(#1234 retired both, A4/A18; their one-home successor is `learning/core/retired.py`.)
"""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from defender.tests import _drain719 as D
from defender.tests import _judge_921 as J
from defender.tests import _tenants1106 as T1106  # noqa: E402
from defender.tests import _state1135


@pytest.fixture(autouse=True)
def _tmp_roots(tmp_path, monkeypatch):
    monkeypatch.setenv(J.RUNS_BASE_ENV, str(tmp_path / "defender-runs"))
    monkeypatch.setenv(J.EPISODES_BASE_ENV, str(tmp_path / "episodes-root"))
    # The learning STATE root too, so the shared findings queue this pass appends to is
    # this test's own and not the checkout's real `learning/_pending/`. Isolation belongs
    # here rather than in the appender: a production path that picks a different queue when
    # an env var is unset is a pass whose rows can land where no drain reads.
    _state1135.set_state_dir(monkeypatch, tmp_path / "learning-state")


def _vocab():
    return J.mod("_vocab")


# ---------------------------------------------------------------------------------------
# D1 / M4 — the vocabulary (#1234: `JUDGE_OUTCOME_ENUM` and its normalizer are retired, A4/A18)
# ---------------------------------------------------------------------------------------


def test_921_every_surface_tests_membership_through_the_shipped_normalizer(tmp_path):
    """#1234 rewrite (A4, A18): the family word and its normalizer are retired, and the name
    `judge_outcome` has ONE home (`learning/core/retired.py`) that every reader refuses it
    through. What this pinned survives as the cross-surface agreement: the SAME row carrying
    the retired name — in any spelling of its value — gets ONE answer at every surface. The
    reply's validator refuses the reply word by name, the appender refuses the row by name and
    writes nothing, and the gate holds the row naming it (never authors it). A row admitted at
    one surface and refused at its sibling is the canonical fail-open, the #785 shape — one
    parser, six interpreters, three of which disagreed.

    Positive control: the same row without the retired key is appended and authored.
    """
    variant = "  Survived "
    JudgeRefused = J.sym("learning.judge", "JudgeRefused")

    # 1. the reply's validation
    run_mod = J.mod("learning.judge.run")
    with pytest.raises(JudgeRefused, match="episode_outcome"):
        run_mod.validate_reply(J.as_reply_text(J.reply_doc(episode_outcome=" Gradable ")))

    # 2. the appender's refusal
    ep = J.accepted_episode(tmp_path, ledgers={"b": [J.oracle_row("b")], "c": []})
    J.grade_at(ep, judge=J.scripted_judge(), draws=1, state=_state1135.env_state())
    enqueue = J.mod("learning.judge.enqueue")
    row = dict(D.finding_row("ep-1/b/0/0", run_id="ep-1", direction="family"),
               type="lead-set", subject="defender",
               subject_anchor="l-001", subject_topic="topic",
               source_run_dir="episodes/ep-1/worlds/b",
               contrast_evidence=["worlds/b/report.md", "worlds/a/report.md"],
               on_verdict_path=True, world_label_doubted=False)
    retired = dict(row, judge_outcome=variant)
    with pytest.raises(JudgeRefused, match="judge_outcome"):
        enqueue.append_rows(ep, [retired], state=_state1135.env_state())
    clean = {k: v for k, v in row.items() if k != "judge_outcome"}
    assert enqueue.append_rows(ep, [clean], state=_state1135.env_state()) == 1, (
        "the positive control failed: the appender refused the row without the retired name")

    # 3. the gate's routing
    paths = D.make_paths(tmp_path / "gate")
    channel = D.channel_of("findings")
    D.seed(paths, channel, [dict(retired, finding_id="ep-1/b/0/1"),
                            dict(clean, finding_id="ep-1/b/0/2")])
    agent = D.recording(D.committing("variant"))
    assert J.mod("learning.author.drain").run_batch(
        cfg=D.cfg_for(paths, "findings", invoke_agent=agent)) == 0
    assert [r["finding_id"] for r in agent.calls[0]["rows"]] == ["ep-1/b/0/2"], (
        "the gate authored a row the appender refused; that disagreement IS the fail-open")
    assert [r["finding_id"] for r in D.pending(paths, channel)] == ["ep-1/b/0/1"], (
        "the retired-name row was consumed rather than held")


# ---------------------------------------------------------------------------------------
# the corrected security write census
# ---------------------------------------------------------------------------------------


def test_921_the_three_judge_write_sinks_are_the_only_ones_and_land_on_distinct_paths(tmp_path):
    """Grading one family writes into EXACTLY THREE places under the episode dir —
    `worlds/<X>/judge/<n>.yaml`, `episodes/<id>/judge.yaml`, and
    `wire_logs/<agent_id>_trace.jsonl` — and every path is distinct across worlds and draws.

    The design's census names only the first two; the wire log is the third and it holds the
    largest artifact in the tree. This is a DEMAND rather than a claim because a census that is
    not driven is a sentence: the episode tree is enumerated before and after a real grading
    pass, and the difference is the census.
    """
    ep = J.accepted_episode(tmp_path, ledgers={"b": [J.oracle_row("b")], "c": []})
    before = {p.relative_to(ep) for p in ep.rglob("*") if p.is_file()}
    # The family call answers a family-scope reply SO ITS DRAWS ALSO LAND: a refused family
    # reply writes nothing, and the family sink would be invisible to the census that exists to
    # catch exactly a new sink. All three callers write and the count below is over the whole
    # write surface.
    J.grade_at(
        ep, judge=J.scripted_judge(),
        draws=2,
        state=_state1135.env_state())
    after = {p.relative_to(ep) for p in ep.rglob("*") if p.is_file()}
    created = sorted(after - before)

    sinks: dict[str, list[Path]] = {"judge.yaml": [], "worlds": [], "wire_logs": []}
    for rel in created:
        if rel == Path("judge.yaml"):
            sinks["judge.yaml"].append(rel)
        elif rel.parts[0] == "worlds" and "judge" in rel.parts:
            sinks["worlds"].append(rel)
        elif rel.parts[0] == "wire_logs":
            sinks["wire_logs"].append(rel)
        else:
            pytest.fail(f"grading wrote a FOURTH sink nobody censused: {rel}")

    assert len(sinks["judge.yaml"]) == 1
    assert len(sinks["worlds"]) == 6, (
        "three callers (two worlds and #1007 M5's family-level draw) x two draws did not give "
        f"six reply files: {sinks['worlds']}")
    # #1007 M5 adds a THIRD caller (the family-level draw) beside the two per-world ones —
    # 3 callers x 2 draws = 6 wire logs, not 4.
    assert len(sinks["wire_logs"]) == 6, (
        "the wire log is the third sink and it is written once per call; the design's census "
        "names it not at all")
    assert len(created) == len(set(created)), "two writes landed on one path"


def test_921_the_wire_log_holding_the_framed_prompt_is_not_reachable_from_a_box(tmp_path):
    """Every judge call re-persists the whole framed-untrusted prompt AND the whole reply
    VERBATIM into `<episode_dir>/wire_logs/`, multiplied by worlds x draws at 10-32K input
    tokens per call.

    The sink is already denied to the model outright (`files.names_wire_log_dir`, both read
    surfaces, every role), so the fix is a census correction and this demand is its witness:
    assert the denial holds for a BOX BOUND INTO THE EPISODE TREE, where a sibling's run dir is
    `{episode_dir}/runs/<id>-<label>` and the episode dir is its parent.

    Positive control: the sibling's OWN run-root artifacts still read, so the denial is one
    directory rather than a policy that refuses everything.
    """
    pytest.importorskip("pydantic_ai")
    from defender.agents import MAIN_DEF
    from defender.runtime import permission
    from defender.runtime.agent_definition import compile_policy_for

    ep = J.accepted_episode(tmp_path, ledgers={"b": [J.oracle_row("b")], "c": []})
    J.grade_at(
        ep, judge=J.FakeJudge(default=J.as_reply_text(J.reply_doc())),
        draws=1,
        state=_state1135.env_state())
    traces = J.wire_logs(ep)
    assert traces, "the judge left no wire log at all; there is nothing to deny"

    runs = ep / "runs"
    run_dir = J.sibling_run_dir(runs, "b")
    dfn = tmp_path / "defender"
    (dfn / "lessons").mkdir(parents=True, exist_ok=True)
    env = SimpleNamespace(
        run=run_dir, dfn=dfn,
        main=compile_policy_for(MAIN_DEF, run_dir=run_dir, defender_dir=dfn),
        gather=compile_policy_for(T1106.fixture_gather_def(), run_dir=run_dir, defender_dir=dfn))

    for which in ("main", "gather"):
        policy = getattr(env, which)
        for trace in traces:
            assert not permission.decide_read(
                Path(trace), run_dir=env.run, defender_dir=env.dfn, policy=policy).allow
            assert not permission.decide_bash(
                f"cat {trace}", policy=policy, run_dir=env.run, defender_dir=env.dfn).allow
        assert permission.decide_read(
            run_dir / "investigation.md", run_dir=env.run, defender_dir=env.dfn,
            policy=policy).allow, "the positive control failed: nothing reads at all"


