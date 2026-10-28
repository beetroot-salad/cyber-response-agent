"""#1008 — the family judge stops borrowing the questioner's key and claims its own."""
from __future__ import annotations

import dataclasses
import difflib

import pytest

from defender.tests.support.learning.judge import _judge_921 as J
from defender.tests.support.learning.branch import _triplet_947 as T
from defender.tests.support.learning.core import _state1135

JUDGE_ROLE_PROMPT = T.DEFENDER / "learning" / "judge" / "role.md"


@pytest.fixture(autouse=True)
def _tmp_roots(tmp_path, monkeypatch):
    """The learning-state root, pointed at this test's own tree."""
    _state1135.set_state_dir(monkeypatch, tmp_path / "learning-state")


def _role():
    return T.sym("_agent_role", "AgentRole")


def _agents():
    return T.sym("agents", "AGENTS")


def _judge_def():
    return T.sym("learning.judge.run", "JUDGE_DEF")


def _questioner_def():
    return T.sym("learning.branch.questioner", "QUESTIONER_DEF")


def _grant_gate():
    """The #575 grant gate's module — for its `_named_programs` extractor, IMPORTED not copied."""
    return T.mod("tests.runtime.permissions.test_grant_gate_575")


def test_1008_the_family_judge_is_registered_under_its_own_role_key():
    AgentRole = _role()
    AGENTS = _agents()
    JUDGE_DEF = _judge_def()

    assert AgentRole.JUDGE.value == "judge"
    assert AgentRole.JUDGE in AGENTS
    assert AGENTS[AgentRole.JUDGE] is JUDGE_DEF
    assert AGENTS[AgentRole.JUDGE] is not _questioner_def(), (
        "the judge key is registered to the questioner's definition")
    assert JUDGE_DEF.role is AgentRole.JUDGE
    assert JUDGE_DEF.deps_cls.role is AgentRole.JUDGE, (
        "the definition names the judge's role but its deps class does not")


def test_1008_the_real_selection_step_builds_the_judges_agent_with_no_tool_at_all(tmp_path):
    """`build_stage_agent(JudgeDeps, …)`, which looks `type(deps).role` up in `AGENTS`, builds."""
    from pydantic_ai.models.function import FunctionModel

    from defender.learning._pydantic_stage import build_stage_agent
    from defender.learning.core.config import StageWiring, judge_effort, judge_model
    from defender.investigation import observe
    from defender.investigation.agent_definition import ToolSet
    from defender.investigation.driver import build_agent_core
    from defender.providers import BuiltModel

    AgentRole = _role()
    JUDGE_DEF = _judge_def()
    deps_cls = JUDGE_DEF.deps_cls
    assert _agents()[deps_cls.role] is JUDGE_DEF, (
        "the deps class this build selects on does not resolve to the judge's definition, so "
        "what is built below is some other role's agent")
    assert deps_cls.role is AgentRole.JUDGE
    assert JUDGE_ROLE_PROMPT.is_file(), (
        f"the judge's standing prompt {JUDGE_ROLE_PROMPT} is not there")

    seen: list[tuple[str, str | None]] = []

    def make_model(name: str, effort: str | None) -> object:
        seen.append((name, effort))
        return BuiltModel(FunctionModel(lambda messages, info: None), None)

    wiring = StageWiring(prompt_path=JUDGE_ROLE_PROMPT, model=judge_model(),
                         effort=judge_effort(), trace_name="judge_b_0_trace.jsonl",
                         label=f"judge:{T.fixture_world_id('b')}:0")
    logger = observe.RequestLogger(tmp_path / "seam_trace.jsonl")
    try:
        agent = build_stage_agent(deps_cls, wiring, logger, make_model=make_model)
        assert seen == [(wiring.model, wiring.effort)], (
            f"the build never reached the model builder ({seen})")
        registered = sorted(agent._function_toolset.tools)  # noqa: SLF001 — the registration IS the observable
        assert registered == [], (
            f"the judge's agent registered {registered}; this role holds no tool lane at all")

        control = build_agent_core(
            dataclasses.replace(JUDGE_DEF, tools=ToolSet(read=True), model=lambda: wiring.model),
            deps_type=deps_cls, instructions="control", logger=logger,
            agent_id="judge:control", make_model=make_model)
        assert sorted(control._function_toolset.tools) == ["read_file"], (  # noqa: SLF001 — same address as the claim above
            "control: the same builder with `read` on registers nothing either")
    finally:
        logger.close()


def test_1008_every_judge_draw_is_declared_under_the_judges_role(tmp_path):
    """The orchestration half, through the real `grade_episode`."""
    AgentRole = _role()
    ep = J.accepted_episode(tmp_path, ledgers={"b": [J.staged_row("b")], "c": []})
    judge = J.scripted_judge()

    J.grade_at(
        ep, judge=judge, draws=2,
        state=_state1135.env_state())

    assert judge.calls == 6, (
        f"the judge was called {judge.calls} times, not once per draw per graded world plus "
        "one family draw per draw index")
    assert J.draw_files(ep, "b"), "the pass wrote no draw file, so nothing was really graded"
    assert judge.agent_ids == [
        f"judge:{T.fixture_world_id('b')}:0", f"judge:{T.fixture_world_id('b')}:1", f"judge:{T.fixture_world_id('c')}:0", f"judge:{T.fixture_world_id('c')}:1",
        "judge:family:0", "judge:family:1",
    ], f"the `judge:<world>:<n>` / `judge:family:<n>` agent ids changed: {judge.agent_ids}"
    for i, kw in enumerate(judge.kwargs):
        assert kw["role"] is AgentRole.JUDGE, (
            f"draw {i} ({kw['agent_id']}) declared {kw['role']!r}, not the judge's own key")


def test_1008_the_judges_deny_reason_is_its_own_and_names_no_program(tmp_path):
    """The compiled policy carries a refusal in the JUDGE's words."""
    compile_policy_for = T.sym("investigation.permission", "compile_policy_for")
    default_reason = T.sym("investigation.agent_definition", "_DEFAULT_DENY_REASON")
    questioner_reason = T.sym("learning.branch.questioner", "_QUESTIONER_DENY_REASON")
    named_programs = _grant_gate()._named_programs
    JUDGE_DEF = _judge_def()

    policy = compile_policy_for(JUDGE_DEF, run_dir=tmp_path, defender_dir=T.DEFENDER)

    assert policy.deny_reason == JUDGE_DEF.deny_reason, (
        "the compiled policy did not carry the definition's own refusal text")
    for borrowed, whose in ((default_reason, "the runtime default"),
                            (questioner_reason, "the questioner")):
        assert borrowed not in policy.deny_reason, (
            f"the judge's refusal carries {whose}'s text verbatim: {policy.deny_reason!r}")
    assert "judge" in policy.deny_reason.casefold(), (
        f"the judge's refusal never names the judge: {policy.deny_reason!r}")
    # ...and says what the role is, not only which role refuses.
    assert "episode" in policy.deny_reason.casefold(), (
        f"the judge's refusal never names the episode it grades: {policy.deny_reason!r}")

    shape_clause = "bare, not inside a code fence, with nothing before or after it"
    for reason in (questioner_reason, policy.deny_reason):
        assert shape_clause in reason, (
            "the shape clause this guard excludes is not in both reasons")
    own_words = [r.replace(shape_clause, "") for r in (questioner_reason, policy.deny_reason)]
    overlap = difflib.SequenceMatcher(None, own_words[0], own_words[1], autojunk=False)
    longest = overlap.find_longest_match(0, len(own_words[0]), 0, len(own_words[1]))
    shared = own_words[0][longest.a:longest.a + longest.size]
    assert longest.size < 24, (
        f"the judge's refusal shares {longest.size} characters of unbroken text with the "
        f"questioner's ({shared!r})")

    assert named_programs("only the read-only viewers (jq/ls/cat) are permitted") == {
        "jq", "ls", "cat"}, (
        "the extractor found no program names in text that has three")
    spliced = policy.deny_reason + " Filter the archive with `jq` before grading."
    assert named_programs(spliced) == {"jq"}, (
        "the extractor found no program in the judge's reason with one spliced in")

    granted = {g.program for g in policy.bash_allow}
    offenders = named_programs(policy.deny_reason) - granted
    assert offenders == set(), (
        f"the judge's deny reason names {sorted(offenders)}, which its own lane denies")


def test_1008_the_judges_compiled_policy_is_empty_on_every_surface(tmp_path):
    """The judge holds nothing on any surface a definition can open. Its resolved read roots
    still include the defender tree (the gate's default base: `read_confine` is empty), so "no
    read root" is a claim about the definition's field, not about the gate."""
    compile_policy_for = T.sym("investigation.permission", "compile_policy_for")
    JUDGE_DEF = _judge_def()

    assert tuple(JUDGE_DEF.tools) == ()
    assert JUDGE_DEF.verb_grant.entries == ()
    assert JUDGE_DEF.bash_shapes == ()
    assert JUDGE_DEF.write_shapes == ()
    assert JUDGE_DEF.corpus_dirs == ()

    policy = compile_policy_for(JUDGE_DEF, run_dir=tmp_path, defender_dir=T.DEFENDER)
    assert policy.deny_reason == JUDGE_DEF.deny_reason, (
        "positive control: this is not the judge's compiled policy at all")
    assert not policy.bash_allow
    assert not tuple(policy.read_allow)
    assert not policy.read_roots
    assert not policy.write_roots
    assert policy.verb_allow.entries == ()

    files = T.mod("investigation.permission.files")
    resolved = files.resolved_read_roots(policy, tmp_path, T.DEFENDER)
    assert T.DEFENDER.resolve() in resolved, (
        "the judge's resolved read roots no longer include the defender tree")


def test_1008_bind_refuses_the_judges_definition_by_its_deps_type_name(tmp_path):
    """`bind(JUDGE_DEF, …)` REFUSES, and names `JudgeDeps` in the refusal."""
    bind = T.sym("investigation.agent_definition", "bind")
    JUDGE_DEF = _judge_def()
    assert JUDGE_DEF.deps_cls is not None, (
        "the definition names no deps class, so `bind` would refuse for a different reason")

    run_dir = tmp_path / "run"
    run_dir.mkdir()
    with pytest.raises(ValueError, match="not bindable") as caught:
        bind(JUDGE_DEF, run_dir, defender_dir=T.DEFENDER)
    message = str(caught.value)
    assert "JudgeDeps" in message, (
        f"the refusal does not name the deps type it refused: {message}")
    assert "JUDGE_DEF" in message, (
        f"the refusal does not name the definition it refused: {message}")
