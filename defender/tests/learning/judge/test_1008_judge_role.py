"""#1008 — the family judge stops borrowing the questioner's key and claims its own."""
from __future__ import annotations

import ast
import dataclasses
import difflib

import pytest

from defender.tests.support.learning.judge import _judge_921 as J
from defender.tests.support.learning.branch import _triplet_947 as T
from defender.tests.support.learning.core import _state1135

GRANT_KEYWORDS = ("tools", "bash_shapes", "write_shapes", "verb_grant",
                  "read_allow_override", "corpus_dirs")

RUN_STAGE = "defender.learning._pydantic_stage.run_stage"
AGENT_DEFINITION = "defender.runtime.agent_definition.AgentDefinition"
JUDGE_DEPS = "defender.learning.judge.run.JudgeDeps"
QUESTIONER_DEPS = "defender.learning.branch.questioner.QuestionerDeps"
JUDGE_MODEL_ACCESSOR = "defender.learning.core.config.judge_model"
JUDGE_EFFORT_ACCESSOR = "defender.learning.core.config.judge_effort"

JUDGE_RUN = T.DEFENDER / "learning" / "judge" / "run.py"
JUDGE_PKG = T.DEFENDER / "learning" / "judge" / "__init__.py"
JUDGE_ROLE_PROMPT = T.DEFENDER / "learning" / "judge" / "role.md"


@pytest.fixture(autouse=True)
def _tmp_roots(tmp_path, monkeypatch):
    """The three configured roots, pointed at this test's own tree — the #921 fixture verbatim."""
    monkeypatch.setenv(J.RUNS_BASE_ENV, str(tmp_path / "defender-runs"))
    monkeypatch.setenv(J.EPISODES_BASE_ENV, str(tmp_path / "episodes-root"))
    _state1135.set_state_dir(monkeypatch, tmp_path / "learning-state")


def _role():
    return T.sym("runtime.agent_role", "AgentRole")


def _agents():
    return T.sym("agents", "AGENTS")


def _judge_def():
    return T.sym("learning.judge.run", "JUDGE_DEF")


def _questioner_def():
    return T.sym("learning.branch.questioner", "QUESTIONER_DEF")


def _grant_gate():
    """The #575 grant gate's module — for its `_named_programs` extractor, IMPORTED not copied."""
    return T.mod("tests.test_grant_gate_575")


def _astlib():
    """The gates' own scope-aware AST resolver, IMPORTED the way the gates reach it."""
    from defender.tests.support.shared.contracts._by_path import import_lint_lib

    return import_lint_lib("_astlib")


def _function(tree: ast.AST, name: str) -> ast.FunctionDef | None:
    return next((n for n in ast.walk(tree)
                 if isinstance(n, ast.FunctionDef) and n.name == name), None)


def _calls(node: ast.AST, dotted: str, tree: ast.AST | None = None) -> list[ast.Call]:
    """Every call under `node` whose callee RESOLVES to `dotted`, however it is spelled."""
    A = _astlib()
    env = A.module_env(tree if tree is not None else node)
    return [n for n in ast.walk(node)
            if isinstance(n, ast.Call) and A.callee(n, env) == dotted]


def _keywords(call: ast.Call) -> dict[str, str]:
    """The call's NAMED keyword arguments: name -> the unparsed source of its value."""
    return {kw.arg: ast.unparse(kw.value) for kw in call.keywords if kw.arg is not None}


def _splats(call: ast.Call) -> int:
    """How many `**mapping` arguments the call carries — keywords `_keywords` cannot see."""
    return sum(1 for kw in call.keywords if kw.arg is None)


def _origin_of(tree: ast.AST, node: ast.expr) -> str | None:
    """Where the name at `node` actually came from, resolved in ITS OWN scope."""
    A = _astlib()
    return A.origin(node, A.module_env(tree))


def _keyword_node(call: ast.Call, name: str) -> ast.expr | None:
    return next((kw.value for kw in call.keywords if kw.arg == name), None)


def _called_origin(tree: ast.AST, call: ast.Call, keyword: str) -> str | None:
    """The origin of the CLASS or FUNCTION invoked by `call`'s `keyword=` argument."""
    node = _keyword_node(call, keyword)
    if not isinstance(node, ast.Call):
        return None
    return _origin_of(tree, node.func)


def _self_test_the_extractor() -> None:
    """The resolver's own positive control, run at every site that uses it."""
    source = (
        "from a.b import AgentDefinition\n"
        "from a.b import SomeDeps\n"
        "from c.d import OtherDeps as SomeDepsAliased\n"
        "from e.f import run_stage\n"
        "from e.f import run_stage as _rs\n"
        "import e.f as stage_mod\n"
        "def bare():\n"
        "    return run_stage(stage='b', deps=SomeDeps(), tools=T)\n"
        "def attribute():\n"
        "    return stage_mod.run_stage(stage='a', deps=SomeDeps())\n"
        "def aliased():\n"
        "    return _rs(stage='x', deps=SomeDeps())\n"
        "def shadowed():\n"
        "    from g.h import OtherDeps as SomeDeps\n"
        "    return run_stage(stage='s', deps=SomeDeps())\n"
        "def looped():\n"
        "    for SomeDeps in (1, 2):\n"
        "        pass\n"
        "    return run_stage(stage='l', deps=SomeDeps())\n"
        "def defs():\n"
        "    D = AgentDefinition(role=R, model=m, tools=ToolSet(), deps_cls=X)\n"
        "    S = AgentDefinition(role=R, **SURFACES)\n"
        "    return D, S\n"
    )
    tree = ast.parse(source)
    assert _function(tree, "bare") is not None, "the walk cannot find a function by name"

    # 1. THREE SPELLINGS, ONE FUNCTION. A census that reads source text counts one of these
    #    three; the widening call then lives in either of the other two.
    assert len(_calls(tree, "e.f.run_stage")) == 5, (
        "the call census does not resolve every spelling of one callee — bare name, attribute "
        "form and aliased import are the three this file has shipped a miss on")

    # 2. Keyword reading, and the `**mapping` a keyword sweep cannot see.
    defn_call, splatted = _calls(_function(tree, "defs"), "a.b.AgentDefinition", tree)
    assert set(_keywords(defn_call)) == {"role", "model", "tools", "deps_cls"}
    assert "tools" in _keywords(defn_call), "the reader would not report a grant keyword"
    assert _splats(defn_call) == 0
    assert set(_keywords(splatted)) == {"role"}, "the splat leaked into the named keywords"
    assert _splats(splatted) == 1, "the reader cannot see a `**mapping` argument at all"

    resolved = {name: _called_origin(tree, _calls(_function(tree, name), "e.f.run_stage",
                                                  tree)[0], "deps")
                for name in ("bare", "attribute", "aliased", "shadowed", "looped")}
    assert resolved["bare"] == "a.b.SomeDeps"
    assert resolved["attribute"] == "a.b.SomeDeps"
    assert resolved["aliased"] == "a.b.SomeDeps"
    assert resolved["shadowed"] == "g.h.OtherDeps", (
        "a function-local import shadowing the module-level one resolves to the module's "
        "binding — the resolver is not scope-aware, and the seam checks prove nothing")
    assert resolved["looped"] is None, (
        "a `for` target rebinding the name resolves to the import it shadows")

    # And an alias does not HIDE an origin either — the same fact from the other side: a seam
    # that imports the wrong class under the right name answers with the wrong origin.
    assert _origin_of(tree, ast.parse("SomeDepsAliased", mode="eval").body) == "c.d.OtherDeps"


def _assert_sole_unwidened_seam(path, fn_name: str, deps_origin: str) -> None:
    """One production seam drives ONE `run_stage`, with these deps and no call-time widening."""
    _self_test_the_extractor()
    tree = ast.parse(path.read_text(encoding="utf-8"))
    seam = _function(tree, fn_name)
    assert seam is not None, (
        f"{path} declares no `{fn_name}` — the production seam moved, and this check would "
        "otherwise pass by finding nothing")

    module_calls = _calls(tree, RUN_STAGE)
    seam_calls = _calls(seam, RUN_STAGE, tree)
    assert len(module_calls) == 1, (
        f"{path} makes {len(module_calls)} calls that resolve to {RUN_STAGE}; this seam drives "
        "exactly one, and a second is a lane this check does not read")
    moved = (f"the module's one `run_stage` call is not inside `{fn_name}` — the shipped call "
             "moved out of the seam this check inspects")
    assert len(seam_calls) == 1, moved
    assert seam_calls[0] is module_calls[0], moved

    call = module_calls[0]
    spelled = _keywords(call)
    assert _called_origin(tree, call, "deps") == deps_origin, (
        f"{path.name}'s seam builds deps that resolve to "
        f"{_called_origin(tree, call, 'deps')}, not {deps_origin} — the deps class is what "
        f"selects the definition, so this is the line that decides the role. (It is spelled "
        f"{spelled.get('deps')}, which is why the SPELLING is not what is checked.)")
    widened = sorted(set(spelled) & {"tools", "verbs"})
    assert widened == [], (
        f"{path.name}'s seam passes {widened} to `run_stage`, which overrides the registered "
        "definition at call time — a grant handed to a role from outside its own definition")
    assert _splats(call) == 0, (
        f"{path.name}'s seam splats a mapping into `run_stage`, so `tools=`/`verbs=` ride in "
        "unread by the check above")


def test_1008_the_family_judge_is_registered_under_its_own_role_key():
    """The judge's definition is registered under `AgentRole.JUDGE`, and it is NOT the questioner's
    object."""
    AgentRole = _role()
    AGENTS = _agents()
    JUDGE_DEF = _judge_def()

    assert AgentRole.JUDGE.value == "judge"
    assert AgentRole.JUDGE in AGENTS
    assert AGENTS[AgentRole.JUDGE] is JUDGE_DEF
    assert AGENTS[AgentRole.JUDGE] is not _questioner_def(), (
        "the judge key is registered to the QUESTIONER's definition — a second name over one "
        "object, which compiles one policy and refuses in one voice")
    assert JUDGE_DEF.role is AgentRole.JUDGE
    assert JUDGE_DEF.deps_cls.role is AgentRole.JUDGE, (
        "the definition names the judge's role but its deps class does not — and the DEPS "
        "class is what `build_stage_agent` selects on")


def test_1008_the_real_selection_step_builds_the_judges_agent_with_no_tool_at_all(tmp_path):
    """THE SELECTION STEP, driven: `build_stage_agent(JudgeDeps, …)` — the function that turns a
    deps type into an agent by looking `type(deps).role` up in `AGENTS` — builds."""
    from pydantic_ai.models.function import FunctionModel

    from defender.learning._pydantic_stage import build_stage_agent
    from defender.learning.core.config import StageWiring, judge_effort, judge_model
    from defender.runtime import observe
    from defender.runtime.agent_definition import ToolSet
    from defender.runtime.driver import build_agent_core
    from defender.runtime.providers import BuiltModel

    AgentRole = _role()
    JUDGE_DEF = _judge_def()
    deps_cls = JUDGE_DEF.deps_cls
    assert _agents()[deps_cls.role] is JUDGE_DEF, (
        "the deps class this build selects on does not resolve to the judge's definition, so "
        "what is built below is some other role's agent")
    assert deps_cls.role is AgentRole.JUDGE
    assert JUDGE_ROLE_PROMPT.is_file(), (
        f"{JUDGE_ROLE_PROMPT} is not there — the judge has no standing prompt to be built with")

    seen: list[tuple[str, str | None]] = []

    def make_model(name: str, effort: str | None) -> object:
        seen.append((name, effort))
        return BuiltModel(FunctionModel(lambda messages, info: None), None)

    wiring = StageWiring(prompt_path=JUDGE_ROLE_PROMPT, model=judge_model(),
                         effort=judge_effort(), trace_name="judge_b_0_trace.jsonl",
                         label="judge:b:0")
    logger = observe.RequestLogger(tmp_path / "seam_trace.jsonl")
    try:
        agent = build_stage_agent(deps_cls, wiring, logger, make_model=make_model)
        assert seen == [(wiring.model, wiring.effort)], (
            f"the build never reached the model builder ({seen}) — an agent that was not "
            "really constructed registers no tools for reasons of its own")
        registered = sorted(agent._function_toolset.tools)  # noqa: SLF001 — the registration IS the observable
        assert registered == [], (
            f"the judge's agent registered {registered}; this role holds no tool lane at all")

        control = build_agent_core(
            dataclasses.replace(JUDGE_DEF, tools=ToolSet(read=True), model=lambda: wiring.model),
            deps_type=deps_cls, instructions="control", logger=logger,
            agent_id="judge:control", make_model=make_model)
        assert sorted(control._function_toolset.tools) == ["read_file"], (  # noqa: SLF001 — same address as the claim above
            "positive control: the same builder over the same definition with `read` on "
            "registers nothing either, so the emptiness above says nothing about the judge")
    finally:
        logger.close()


def test_1008_every_judge_draw_is_declared_under_the_judges_role(tmp_path):
    """THE ORCHESTRATION HALF, driven through the real `grade_episode`."""
    AgentRole = _role()
    ep = J.accepted_episode(tmp_path, ledgers={"b": [J.staged_row("b")], "c": []})
    judge = J.scripted_judge()

    J.grade_at(
        ep, judge=judge, draws=2,
        state=_state1135.env_state())

    assert judge.calls == 6, (
        f"the judge was called {judge.calls} times, not once per draw per graded world plus "
        "one family draw per draw index (#1007 M5) — with no calls the role assertion below "
        "is vacuous")
    assert J.draw_files(ep, "b"), "the pass wrote no draw file, so nothing was really graded"
    assert judge.agent_ids == [
        "judge:b:0", "judge:b:1", "judge:c:0", "judge:c:1",
        "judge:family:0", "judge:family:1",
    ], f"the `judge:<world>:<n>` / `judge:family:<n>` agent ids changed: {judge.agent_ids}"
    for i, kw in enumerate(judge.kwargs):
        assert kw["role"] is AgentRole.JUDGE, (
            f"draw {i} ({kw['agent_id']}) declared {kw['role']!r} — the family judge no longer "
            "borrows the questioner's key")


def test_1008_the_judges_deny_reason_is_its_own_and_names_no_program(tmp_path):
    """The compiled policy carries a refusal in the JUDGE's words."""
    compile_policy_for = T.sym("runtime.permission", "compile_policy_for")
    default_reason = T.sym("runtime.agent_definition", "_DEFAULT_DENY_REASON")
    questioner_reason = T.sym("learning.branch.questioner", "_QUESTIONER_DENY_REASON")
    named_programs = _grant_gate()._named_programs
    JUDGE_DEF = _judge_def()

    policy = compile_policy_for(JUDGE_DEF, run_dir=tmp_path, defender_dir=T.DEFENDER)

    assert policy.deny_reason == JUDGE_DEF.deny_reason, (
        "the compiled policy did not carry the definition's own refusal text — either the "
        "compile did not run on this definition or the definition declares none")
    for borrowed, whose in ((default_reason, "the runtime default"),
                            (questioner_reason, "the questioner")):
        assert borrowed not in policy.deny_reason, (
            f"the judge's refusal CARRIES {whose}'s text verbatim: {policy.deny_reason!r} — "
            "appending a word to a borrowed refusal is still refusing in a borrowed voice")
    assert "judge" in policy.deny_reason.casefold(), (
        f"the judge's refusal never names the judge: {policy.deny_reason!r} — a refusal in "
        "this role's own words says which role is refusing")
    # ...and it says what this role IS, not merely which role it is. A refusal that names the
    # judge and describes nothing tells the model nothing about why the door is shut.
    assert "episode" in policy.deny_reason.casefold(), (
        f"the judge's refusal never says what it is refusing ABOUT: {policy.deny_reason!r} — "
        "this role grades an archived episode that the host inlined in its prompt, and that is "
        "the fact a refusal has to carry for the model to stop reaching")

    shape_clause = "bare, not inside a code fence, with nothing before or after it"
    for reason in (questioner_reason, policy.deny_reason):
        assert shape_clause in reason, (
            "the shared shape clause this guard excludes is not what both reasons carry — "
            "re-derive the exclusion from the 1018 census before loosening anything here")
    own_words = [r.replace(shape_clause, "") for r in (questioner_reason, policy.deny_reason)]
    overlap = difflib.SequenceMatcher(None, own_words[0], own_words[1], autojunk=False)
    longest = overlap.find_longest_match(0, len(own_words[0]), 0, len(own_words[1]))
    shared = own_words[0][longest.a:longest.a + longest.size]
    assert longest.size < 24, (
        f"the judge's refusal shares {longest.size} characters of unbroken text with the "
        f"questioner's ({shared!r}) — one is a substitution of the other, which is the same "
        "refusal in the only sense that matters, however many single words differ")

    assert named_programs("only the read-only viewers (jq/ls/cat) are permitted") == {
        "jq", "ls", "cat"}, (
        "the g1 extractor found no program names in text that has three — it is blind here, so "
        "the assertion below would prove nothing")
    spliced = policy.deny_reason + " Filter the archive with `jq` before grading."
    assert named_programs(spliced) == {"jq"}, (
        "the extractor finds no program in the judge's own reason even with one spliced in — "
        "the assertion below is then a tautology over this row, not a check")

    granted = {g.program for g in policy.bash_allow}
    offenders = named_programs(policy.deny_reason) - granted
    assert offenders == set(), (
        f"the judge's deny reason names {sorted(offenders)}, which its own lane denies — a "
        "deny reason is PROMPT SURFACE (g1), so a dead program named there is one the model "
        "will spend turns on")


def test_1008_the_judges_compiled_policy_is_empty_on_every_surface(tmp_path):
    """The judge holds nothing on any surface a definition can open: no tool lane, no verb entry, no
    bash grant, no declared read root, no read shape and no write root."""
    compile_policy_for = T.sym("runtime.permission", "compile_policy_for")
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

    files = T.mod("runtime.permission.files")
    resolved = files._resolved_read_roots(policy, tmp_path, T.DEFENDER)
    assert T.DEFENDER.resolve() in resolved, (
        "the judge's resolved read roots no longer include the defender tree — the docstring "
        "above explains why they DO today, and it now describes something else")
    assert not tuple(policy.read_allow), (
        "and there is no shape filter over those roots, which is the other half of why 'no "
        "read root' is a claim about the definition's field and not about the gate")


def test_1008_bind_refuses_the_judges_definition_by_its_deps_type_name(tmp_path):
    """`bind(JUDGE_DEF, …)` REFUSES, and names `JudgeDeps` in the refusal."""
    bind = T.sym("runtime.agent_definition", "bind")
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
