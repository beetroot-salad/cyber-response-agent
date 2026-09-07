"""#1008 — the family judge stops borrowing the questioner's key and claims its own.

THE CHANGE, in one line: `AgentRole.JUDGE` comes back (roles 8 -> 9), bound to the FAMILY
judge (`learning/judge/`), with a zero-field `JudgeDeps`, a `JUDGE_DEF` that grants nothing on
any surface, and a refusal text in the judge's own words.

Until this lands every family-judge draw runs under `AgentRole.QUESTIONER` with
`QuestionerDeps` — so it compiles the questioner's policy and would be refused in the
questioner's words. #922 retired the old pipeline judge and freed the key; this claims it.
The rule the enum states is now per PACKAGE, not per grant: the comparator stays under
QUESTIONER because it is branch-package machinery, and the family judge is its own package.

WHAT DISCRIMINATES, and it is not the seam's `role=` keyword. Every production seam drops that
kwarg (`learning/branch/seams.py:68` carries `noqa: ARG001`; the judge's own `invoke` binds
`role: Any = None` and never reads it). The DEPS CLASS is the mechanism: `build_stage_agent`
reads `type(deps).role` and looks the definition up in `AGENTS` (`_pydantic_stage.py:58`). So
the tests below drive that lookup for real, and treat the recorded kwarg as the secondary
declaration it is.

ONE ORACLE LIMIT, DECLARED RATHER THAN PAPERED OVER. The default seam's own `run_stage` call
cannot be captured: `run_stage` is imported INSIDE `invoke`, so there is no injection point for
it, and reaching it end to end sources a billable provider key. `monkeypatch.setattr` is not
available either (CI ratchets new sites, `scripts/lint/lint_monkeypatch.py`). So the seam's
deps choice — and the fact that it widens nothing with `tools=`/`verbs=` at call time, which
`run_stage` would honour (`_pydantic_stage.py:52-57`) — is discharged by an AST check on
`_default_judge_seam` instead. That check is a source property, and it says so; every OTHER
claim here is driven.

RED against `1fe18daa`: `AgentRole` has no `JUDGE` member, `learning/judge/run.py` declares no
`JUDGE_DEF` and no `JudgeDeps`, `agents.py` registers eight definitions, and the judge's seam
still builds with `QuestionerDeps()`.
"""
from __future__ import annotations

import ast
import dataclasses
import difflib
import re

import pytest

from defender.tests import _judge_921 as J
from defender.tests import _triplet_947 as T

#: The grant surfaces `AgentDefinition` defaults to deny-all on
#: (`runtime/agent_definition.py:63-86`). The whole of O3 is that NONE of them is spelled at
#: the judge's constructor call — an omission over the defaults, not an empty grant line a
#: one-word edit reopens.
#:
#: SIX, not the four that are obviously grants. `read_allow_override` and `corpus_dirs` widen
#: the READ lane and default to deny-all exactly as the other four do, so an empty
#: `read_allow_override=PathShapes()` sitting in the constructor is the same one-word-from-open
#: line the rule forbids — and it compiles to an empty `read_allow`, so the runtime companion
#: assertion below cannot see it either.
GRANT_KEYWORDS = ("tools", "bash_shapes", "write_shapes", "verb_grant",
                  "read_allow_override", "corpus_dirs")

JUDGE_RUN = T.DEFENDER / "learning" / "judge" / "run.py"
JUDGE_PKG = T.DEFENDER / "learning" / "judge" / "__init__.py"
JUDGE_ROLE_PROMPT = T.DEFENDER / "learning" / "judge" / "role.md"


@pytest.fixture(autouse=True)
def _tmp_roots(tmp_path, monkeypatch):
    """The three configured roots, pointed at this test's own tree — the #921 fixture verbatim.

    `monkeypatch.setenv` only: the shipped resolvers already read these off the environment, so
    this is the seam production has rather than a reach into a module.
    """
    monkeypatch.setenv(J.RUNS_BASE_ENV, str(tmp_path / "defender-runs"))
    monkeypatch.setenv(J.EPISODES_BASE_ENV, str(tmp_path / "episodes-root"))
    monkeypatch.setenv(J.STATE_DIR_ENV, str(tmp_path / "learning-state"))


def _role():
    return T.sym("runtime.agent_role", "AgentRole")


def _agents():
    return T.sym("agents", "AGENTS")


def _judge_def():
    return T.sym("learning.judge.run", "JUDGE_DEF")


def _questioner_def():
    return T.sym("learning.branch.questioner", "QUESTIONER_DEF")


def _grant_gate():
    """The #575 grant gate's module — for its `_named_programs` extractor, IMPORTED not copied.

    O2's wording rule is g1's rule (`test_grant_gate_575.py::test_g1_...`): a deny reason is
    prompt surface, so it may not name a program the lane denies. A second extractor here would
    be a second definition of "names a program", and the one that is not the gate's is the one
    that goes stale.
    """
    return T.mod("tests.test_grant_gate_575")


# ---------------------------------------------------------------------------------------
# AST machinery — used where the claim IS about the source (an omitted keyword cannot be
# observed at runtime: a definition that spells `tools=ToolSet()` compiles identically).
# ---------------------------------------------------------------------------------------


def _function(tree: ast.AST, name: str) -> ast.FunctionDef | None:
    return next((n for n in ast.walk(tree)
                 if isinstance(n, ast.FunctionDef) and n.name == name), None)


def _calls(node: ast.AST, callee: str) -> list[ast.Call]:
    """Every `callee(...)` call under `node` — bare name AND attribute form.

    Parsed rather than grepped: a substring scan of a whole file cannot tell a constructor's own
    keyword from the same word in a docstring, in a comment, or at another call — and a check
    that fails when the prose changes is not the check that fails when a grant is added.

    BOTH SPELLINGS, because a census that reads one of them is not a census. Matching only
    `ast.Name` left `_pydantic_stage.run_stage(...)` invisible — and that attribute form is
    how the judge's own module already spells every cross-module call it makes, so a second,
    widening call written the way its neighbours are written would not have been counted.
    """
    return [n for n in ast.walk(node)
            if isinstance(n, ast.Call)
            and ((isinstance(n.func, ast.Name) and n.func.id == callee)
                 or (isinstance(n.func, ast.Attribute) and n.func.attr == callee))]


def _keywords(call: ast.Call) -> dict[str, str]:
    """The call's NAMED keyword arguments: name -> the unparsed source of its value.

    `**mapping` has no `arg` and is dropped here, which is why every caller must also assert
    `_splats(call) == 0`. Reading only what is named is what let a definition carry all four
    grant lines inside a dict and still read as spelling none of them.
    """
    return {kw.arg: ast.unparse(kw.value) for kw in call.keywords if kw.arg is not None}


def _splats(call: ast.Call) -> int:
    """How many `**mapping` arguments the call carries — keywords `_keywords` cannot see."""
    return sum(1 for kw in call.keywords if kw.arg is None)


def _bindings_of(tree: ast.AST, name: str) -> set[tuple[str, str]]:
    """EVERY binding of `name` anywhere in the module, at any scope, as (kind, origin) pairs.

    THE NAME IS NOT THE BINDING, and that gap is the whole reason this exists. A seam whose
    source reads `deps=JudgeDeps()` runs the questioner's deps if the name was bound by
    `from ...questioner import QuestionerDeps as JudgeDeps` — the source check reads exactly
    what it expects and every draw still compiles the wrong definition.

    EVERY binding, not "is there an honest one somewhere", which is the narrower question this
    helper first asked and which is not the same question at all. Python resolves a name at the
    site that uses it, so an honest module-level import satisfies an any() sweep while a
    function-local import of a different class SHADOWS it at the one line that constructs the
    deps. Collecting every binding and demanding they agree makes a rebinding at ANY scope
    visible, without this test having to model Python's scope rules to decide which one wins:
    if they all name the same origin, no site can resolve to anything else.

    An `import a.b.c` (plain, not from-) binds the ROOT name only, so it cannot bind a class
    name and is not collected; anything else that binds the name — an assignment, a def, a
    class, a for target — is reported as its own kind, which is enough to fail the equality.
    """
    found: set[tuple[str, str]] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            for alias in node.names:
                bound = alias.asname or alias.name
                if bound == name:
                    kind = "import" if alias.asname is None else "aliased-import"
                    found.add((kind, f"{node.module}.{alias.name}"))
        elif isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for t in targets:
                if isinstance(t, ast.Name) and t.id == name:
                    found.add(("assignment", ast.unparse(node)))
        elif (isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
              and node.name == name):
            found.add(("definition", node.name))
    return found


def _binds_only(tree: ast.AST, name: str, module: str) -> bool:
    """Whether every binding of `name` in the module is the unaliased import from `module`."""
    return _bindings_of(tree, name) == {("import", f"{module}.{name}")}


def _self_test_the_extractor() -> None:
    """The extractor's own positive control, run at every site that uses it.

    An AST check whose parse silently found NOTHING passes for the wrong reason forever. This
    proves, on synthetic source, that the walk locates a call, reads its keyword names, and
    would REPORT a grant keyword if one were written — so a green result upstream means the
    keyword is absent, not that the checker is blind.
    """
    source = (
        "from a.b import SomeDeps\n"
        "from c.d import OtherDeps as Aliased\n"
        "def helper():\n"
        "    return stage_mod.run_stage(stage='h', deps=SomeDeps(), tools=T)\n"
        "def seam():\n"
        "    from x.y import OtherDeps as Shadowed\n"
        "    D = AgentDefinition(role=R, model=m, tools=ToolSet(), deps_cls=X)\n"
        "    S = AgentDefinition(role=R, **SURFACES)\n"
        "    return run_stage(stage='s', deps=SomeDeps(), tools=T)\n"
    )
    tree = ast.parse(source)
    seam = _function(tree, "seam")
    assert seam is not None, "the extractor cannot find a function it was handed by name"
    defn_call, splatted = _calls(seam, "AgentDefinition")
    assert set(_keywords(defn_call)) == {"role", "model", "tools", "deps_cls"}
    assert "tools" in _keywords(defn_call), "the extractor would not report a grant keyword"
    assert _splats(defn_call) == 0
    (stage_call,) = _calls(seam, "run_stage")
    assert _keywords(stage_call)["deps"] == "SomeDeps()"
    assert "tools" in _keywords(stage_call)

    # The three blind spots every check below has to close, proved on source that HAS them.
    #
    # 1. A splatted mapping carries grant keywords `_keywords` never reports.
    assert set(_keywords(splatted)) == {"role"}, "the splat leaked into the named keywords"
    assert _splats(splatted) == 1, "the extractor cannot see a `**mapping` argument at all"
    # 2. An ATTRIBUTE-form call is a call. The module census must find `helper`'s as well as
    #    the seam's, or a widening call spelled the way its neighbours are is uncounted.
    assert len(_calls(tree, "run_stage")) == 2, (
        "the call census reads only bare-name calls, so an attribute-form one is invisible")
    # 3. A binding sweep that asks "is there an honest import somewhere" passes a module whose
    #    honest module-level import is SHADOWED at the site that uses the name.
    assert _binds_only(tree, "SomeDeps", "a.b")
    assert not _binds_only(tree, "Aliased", "c.d"), (
        "the binding sweep accepts an ALIASED binding — one thing it exists to refuse")
    assert not _binds_only(tree, "SomeDeps", "wrong.module")
    assert _bindings_of(tree, "Shadowed") == {("aliased-import", "x.y.OtherDeps")}, (
        "the binding sweep does not descend into function scope, where a shadowing import "
        "lives — the other thing it exists to refuse")


def _assert_sole_unwidened_seam(path, fn_name: str, deps_call: str, deps_module: str) -> None:
    """One production seam drives ONE `run_stage`, with these deps and no call-time widening.

    ONE HELPER FOR BOTH SEAMS, because the two copies of this check drifted inside a single
    commit: the mirror written for the questioner's seam dropped the widening assertion and the
    call-identity pair that the judge's own copy calls load-bearing. Two seams, one body — then
    a hole closed on one side cannot stay open on the other.

    Each assertion answers a way the shipped call can betray the definition it is supposed to
    run under:
      * the deps class IS the mechanism — `build_stage_agent` reads `type(deps).role`, so a
        seam handing the other role's deps runs every call under the other role's definition,
        whatever the registry says and whatever the `role=` kwarg declares;
      * the NAME is not the binding — an aliased or shadowing import spells the right class and
        constructs the wrong one;
      * ONE call, counted over the whole MODULE — scoped to the function, this reads whichever
        call sits inside it, and a second one in a module-level helper the seam delegates to can
        hand `tools=` to a role that grants nothing while the body reads clean;
      * `run_stage(tools=…, verbs=…)` WIDENS the registered definition at call time
        (`learning/_pydantic_stage.py`), so either keyword is a grant from outside the
        definition — and a `**mapping` is both keywords, unread.
    """
    _self_test_the_extractor()
    tree = ast.parse(path.read_text(encoding="utf-8"))
    seam = _function(tree, fn_name)
    assert seam is not None, (
        f"{path} declares no `{fn_name}` — the production seam moved, and this check would "
        "otherwise pass by finding nothing")

    module_calls = _calls(tree, "run_stage")
    seam_calls = _calls(seam, "run_stage")
    assert len(module_calls) == 1, (
        f"{path} makes {len(module_calls)} `run_stage(` calls; this seam drives exactly one, "
        "and a second is a lane this check does not read")
    moved = (f"the module's one `run_stage(` call is not inside `{fn_name}` — the shipped call "
             "moved out of the seam this check inspects")
    assert len(seam_calls) == 1, moved
    assert seam_calls[0] is module_calls[0], moved

    call = module_calls[0]
    spelled = _keywords(call)
    deps_name = deps_call.removesuffix("()")
    assert spelled.get("deps") == deps_call, (
        f"{path.name}'s seam builds with deps={spelled.get('deps')}, not {deps_call} — the deps "
        "class is what selects the definition, so this is the line that decides the role")
    assert _binds_only(tree, deps_name, deps_module), (
        f"the seam spells `{deps_call}` but the module does not bind `{deps_name}` to "
        f"{deps_module} and nothing else — an aliased import, at module scope or shadowing one "
        f"inside the seam, reads exactly like this line and builds another class entirely. "
        f"Bound by: {sorted(_bindings_of(tree, deps_name))}")
    widened = sorted(set(spelled) & {"tools", "verbs"})
    assert widened == [], (
        f"{path.name}'s seam passes {widened} to `run_stage`, which overrides the registered "
        "definition at call time — a grant handed to a role from outside its own definition")
    assert _splats(call) == 0, (
        f"{path.name}'s seam splats a mapping into `run_stage`, so `tools=`/`verbs=` ride in "
        "unread by the check above")


# ---------------------------------------------------------------------------------------
# O1 — every family-judge draw runs under the judge's own role
# ---------------------------------------------------------------------------------------


def test_1008_the_family_judge_is_registered_under_its_own_role_key():
    """The judge's definition is registered under `AgentRole.JUDGE`, and it is NOT the
    questioner's object.

    Both halves matter. "Registered under JUDGE" alone would be satisfied by registering
    `QUESTIONER_DEF` a second time under a new key — the same compiled policy and the same
    refusal text, with a new name on it — which is the change this issue is not.
    """
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
    """THE SELECTION STEP, driven: `build_stage_agent(JudgeDeps, …)` — the function that turns
    a deps type into an agent by looking `type(deps).role` up in `AGENTS` — builds, and the
    agent it returns has registered ZERO tools.

    THE MODEL BUILDER IS INJECTED. `build_agent_core`'s default is `providers.build_for_effort`,
    which SOURCES A BILLABLE KEY: left to the ambient environment this asserts whether the HOST
    is credentialed (green on a developer's machine, red on CI). A `FunctionModel` behind a
    `BuiltModel` is the idiom `test_947_triplet_launcher.py:296-330` already uses for exactly
    this, and no provider call is made.

    TWO POSITIVE CONTROLS, because "no tools" is the kind of claim a half-built object satisfies
    for free:
      * the injected builder RECORDS the `(model, effort)` it was handed — so the build really
        reached past the registry lookup and constructed a model;
      * the SAME builder, at the SAME address, over the same definition with one read bit
        flipped on, registers `read_file` — so `_function_toolset.tools` is an address that can
        be non-empty, and its emptiness above is a fact about the judge.
    """
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
        # `_function_toolset` is the registration itself, which is what makes it the observable:
        # `register_tools` is the only thing that puts a lane on a built agent (#921's premise 2
        # probed exactly this on `QUESTIONER_DEF`), so an empty one is "the model cannot attempt
        # a tool call at all" rather than a claim about a field.
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
    """THE ORCHESTRATION HALF, driven through the real `grade_episode`: every draw the family
    judge makes declares `AgentRole.JUDGE` at the seam, and the `judge:<world>:<n>` agent id is
    unchanged.

    This is the SECONDARY oracle by design — production seams ignore the kwarg — but it is the
    only one that covers the orchestration's own spelling (`learning/judge/__init__.py:284`),
    which is the line a reader of the wire log meets. The deps class the shipped seam builds
    with is pinned by the AST check below, for the reason the module docstring gives.

    Positive control: four draws actually happened (two graded worlds x two draws) and the pass
    wrote its draw files, so "every recorded role is JUDGE" cannot pass over an empty list.
    """
    AgentRole = _role()
    ep = J.accepted_episode(tmp_path, ledgers={"b": [J.staged_row("b")], "c": []})
    judge = J.FakeJudge(default=J.as_reply_text(J.reply_doc()))

    J.mod("learning.judge").grade_episode(
        ep, judge=judge, runs_base=tmp_path / "defender-runs", draws=2)

    assert judge.calls == 4, (
        f"the judge was called {judge.calls} times, not once per draw per graded world — with "
        "no calls the role assertion below is vacuous")
    assert J.draw_files(ep, "b"), "the pass wrote no draw file, so nothing was really graded"
    assert judge.agent_ids == ["judge:b:0", "judge:b:1", "judge:c:0", "judge:c:1"], (
        f"the `judge:<world>:<n>` agent ids changed: {judge.agent_ids}")
    for i, kw in enumerate(judge.kwargs):
        assert kw["role"] is AgentRole.JUDGE, (
            f"draw {i} ({kw['agent_id']}) declared {kw['role']!r} — the family judge no longer "
            "borrows the questioner's key")


# ---------------------------------------------------------------------------------------
# O2 — the refusal text is the judge's own, and it teaches no dead command
# ---------------------------------------------------------------------------------------


def test_1008_the_judges_deny_reason_is_its_own_and_names_no_program(tmp_path):
    """The compiled policy carries a refusal in the JUDGE's words: not the questioner's string,
    not `AgentDefinition`'s default — and it names no program, so it passes the grant gate's g1
    once `"judge"` is a row in `_all_policies`.

    WHY THE COMPILED POLICY AND NOT THE CONSTANT. `deny_reason` reaches a runtime reader only
    through `compile_policy` (`runtime/agent_definition.py:221` -> `permission/bash.py`), so the
    compiled object is where the claim is true or false; reading the module constant would pass
    over a definition that never carried it.

    Positive control on the compile (the policy is the judge's own, not a default-constructed
    `AgentPolicy`), and on the EXTRACTOR (it finds program names in text that has them), which
    is g1's own `seen >= 3` guard rewritten for a single-policy check.
    """
    compile_policy_for = T.sym("runtime.permission", "compile_policy_for")
    default_reason = T.sym("runtime.agent_definition", "_DEFAULT_DENY_REASON")
    questioner_reason = T.sym("learning.branch.questioner", "_QUESTIONER_DENY_REASON")
    named_programs = _grant_gate()._named_programs
    JUDGE_DEF = _judge_def()

    policy = compile_policy_for(JUDGE_DEF, run_dir=tmp_path, defender_dir=T.DEFENDER)

    assert policy.deny_reason == JUDGE_DEF.deny_reason, (
        "the compiled policy did not carry the definition's own refusal text — either the "
        "compile did not run on this definition or the definition declares none")
    # CONTAINMENT, not inequality. `!=` against the two borrowed texts passes for
    # `_DEFAULT_DENY_REASON + " (judge)"` — the runtime default verbatim with the role name
    # bolted on, which is the whole of the text O2 says the judge must not refuse in, and which
    # also satisfies a bare "names the judge" check.
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

    # NOR A FIND-AND-REPLACE OF THE QUESTIONER'S. Containment catches a borrowed text carried
    # WHOLE; it does not catch the questioner's sentence with three noun phrases swapped and
    # the closing clauses left byte-identical, which is what the first draft of this constant
    # actually was. Two texts that are each other's template share a long contiguous run; two
    # texts written about different roles do not. The judge's and the questioner's share 11
    # characters today, and the substituted draft shared 48.
    overlap = difflib.SequenceMatcher(None, questioner_reason, policy.deny_reason)
    longest = overlap.find_longest_match(
        0, len(questioner_reason), 0, len(policy.deny_reason))
    shared = questioner_reason[longest.a:longest.a + longest.size]
    assert longest.size < 24, (
        f"the judge's refusal shares {longest.size} characters of unbroken text with the "
        f"questioner's ({shared!r}) — one is a substitution of the other, which is the same "
        "refusal in the only sense that matters, however many single words differ")

    assert named_programs("only the read-only viewers (jq/ls/cat) are permitted") == {
        "jq", "ls", "cat"}, (
        "the g1 extractor found no program names in text that has three — it is blind here, so "
        "the assertion below would prove nothing")
    # ...and the control that matters: the extractor fires on THIS text's own shape. g1 sweeps
    # every policy at once and guards itself with a whole-sweep `seen >= 3`, so a row that
    # contributes nothing is invisible there; a reason with no backticks and no slash-group —
    # which the judge's is — makes both that check and the one below `set() - set()`. Splicing
    # a program into the judge's own reason proves the check would fail if there were one.
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


# ---------------------------------------------------------------------------------------
# O3 — it grants nothing, and it grants it BY OMISSION
# ---------------------------------------------------------------------------------------


def test_1008_the_judges_compiled_policy_is_empty_on_every_surface(tmp_path):
    """The judge holds nothing on any surface a definition can open: no tool lane, no verb
    entry, no bash grant, no declared read root, no read shape and no write root.

    `tuple(defn.tools)` rather than a row of booleans: `ToolSet.__iter__` yields only the lanes
    a set GRANTS, so the empty tuple is the whole deny-all claim over every lane that exists now
    or is added later (`runtime/agent_definition.py`'s own note).

    WHAT "NO READ ROOT" DOES AND DOES NOT MEAN, because the short version of that sentence is
    false. `policy.read_roots` is the definition's own FIELD, and it being empty is not the
    gate's answer: `permission/files._resolved_read_roots` computes
    `(run_dir, *(read_confine or (defender_dir,)), *read_roots)`, so an empty confine plus empty
    roots RESOLVES to the run dir and the whole `defender/` tree, with no shape filter over it.
    The judge is safe because it registers no read tool, which is a different property from the
    one the field states — and `requires_confine` is the field that would make the strong
    reading true. That is asserted below as what it is, so a reader is not left believing the
    read lane is bounded when a single `tools=` bit would open it over the lessons corpus.
    (The questioner has the identical shape; this is not a fact about the judge alone.)

    Positive control: the policy carries the judge's own refusal text, so an empty policy here
    is the compile's answer about THIS definition rather than a bare `AgentPolicy()`.
    """
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

    # The resolved read lane, asserted as it IS rather than as the field reads. If this ever
    # becomes bounded (a `read_confine`, or `requires_confine=True`), this assertion is what
    # says so out loud instead of a docstring quietly going stale in the other direction.
    files = T.mod("runtime.permission.files")
    resolved = files._resolved_read_roots(policy, tmp_path, T.DEFENDER)
    assert T.DEFENDER.resolve() in resolved, (
        "the judge's resolved read roots no longer include the defender tree — the docstring "
        "above explains why they DO today, and it now describes something else")
    assert not tuple(policy.read_allow), (
        "and there is no shape filter over those roots, which is the other half of why 'no "
        "read root' is a claim about the definition's field and not about the gate")


def test_1008_the_definition_spells_no_grant_keyword_at_all():
    """The definition grants nothing BY OMISSION: its constructor call spells none of
    `tools=`, `bash_shapes=`, `write_shapes=`, `verb_grant=`.

    WHY THIS IS A SOURCE CHECK AND CANNOT BE ANYTHING ELSE. `AgentDefinition`'s defaults ARE
    deny-all, so `tools=ToolSet()` and no `tools=` at all compile to the identical object — the
    runtime cannot tell them apart, and the difference is the whole point: a role that could
    reach something has to have a grant ADDED in a diff a reviewer sees, where an empty grant
    line makes the same widening a one-word edit (the questioner's module docstring states the
    rule this inherits).

    Parsed with `ast` over the one `AgentDefinition(` call in `learning/judge/run.py`, never a
    substring scan of the file, and the parse asserts it FOUND that call — a refactor that moves
    the definition elsewhere fails here instead of silently passing.
    """
    _self_test_the_extractor()
    tree = ast.parse(JUDGE_RUN.read_text(encoding="utf-8"))
    calls = _calls(tree, "AgentDefinition")
    assert len(calls) == 1, (
        f"{JUDGE_RUN} holds {len(calls)} `AgentDefinition(` calls; the judge's definition is "
        "declared there and exactly once — this check has nothing to inspect otherwise")

    spelled = _keywords(calls[0])
    located = f"the located call is not the judge's definition: {sorted(spelled)}"
    assert "role" in spelled, located
    assert "deps_cls" in spelled, located
    assert "deny_reason" in spelled, located
    assert spelled["role"].endswith("JUDGE"), f"the definition declares role={spelled['role']}"
    assert spelled["deps_cls"] == "JudgeDeps"
    granting = sorted(set(spelled) & set(GRANT_KEYWORDS))
    assert granting == [], (
        f"the judge's definition spells {granting} — every grant surface is an OMISSION over a "
        "deny-all default, so that an empty grant line is never sitting there to be edited open")
    assert _splats(calls[0]) == 0, (
        "the definition splats a mapping into its keywords, so the omission check above reads "
        "nothing: all four grant lines can sit inside that dict, each one word from a grant, "
        "while the constructor call reads as spelling none of them")

    # The knobs, checked here because nothing else can: `StageWiring` overrides model and effort
    # at every call, so a definition carrying the QUESTIONER's accessors is invisible to every
    # driven test — and still live to `scripts/policy_cli.py` and any out-of-band build.
    #
    # THE MODEL BY IDENTITY, THE EFFORT BY SOURCE, and the asymmetry is forced. `model` is a
    # thunk, so the object itself says which accessor it is. `effort` is a plain string field
    # whose accessor ran once at import, so its VALUE is neither discriminating (the judge's
    # and the questioner's defaults are both "medium", so swapping the call changes nothing to
    # compare) nor deterministic (a sibling test that sets JUDGE_EFFORT and imports this module
    # first freezes a different value for the whole session). The spelled call is the only
    # form of this claim that is both.
    config = T.mod("learning.core.config")
    JUDGE_DEF = _judge_def()
    assert JUDGE_DEF.model is config.judge_model, (
        f"the definition's model thunk is {JUDGE_DEF.model!r}, not the judge's own knob reader")
    assert spelled["model"] == "judge_model", (
        f"the definition is built with model={spelled['model']}, not the judge's knob reader")
    assert spelled["effort"] == "judge_effort()", (
        f"the definition is built with effort={spelled['effort']} — the questioner's accessor "
        "has the same default, so nothing at runtime can tell the two apart")


def test_1008_the_default_seam_hands_run_stage_the_judges_deps_and_widens_nothing():
    """The SHIPPED judge seam builds with `JudgeDeps()` and widens nothing at call time.

    Every assertion lives in `_assert_sole_unwidened_seam`, shared with the questioner's mirror
    below — see its docstring for what each one answers.

    A SOURCE CHECK, and the module docstring says why: `run_stage` is imported inside `invoke`
    (deliberately — see `_default_judge_seam`'s own docstring), so there is nothing to inject
    at, driving it end to end sources a billable provider key, and `monkeypatch.setattr` is
    forbidden here. `test_921_judge_call.py` checks the INJECTED seam's kwargs, which is a
    different object entirely.
    """
    _assert_sole_unwidened_seam(
        JUDGE_PKG, "_default_judge_seam", "JudgeDeps()", "defender.learning.judge.run")


# ---------------------------------------------------------------------------------------
# O4 — the registry invariant
# ---------------------------------------------------------------------------------------


def test_1008_the_registry_holds_one_definition_per_role_and_nine_of_them():
    """Nine roles, nine definitions, one per key.

    `set(AGENTS.keys()) == set(AgentRole)` is the invariant the whole roster rests on: an enum
    key with no definition behind it is a compiled grant nothing claims, and a definition with
    no key cannot be reached. The COUNT is stated too, because the four hand-kept censuses
    (`test_947_triplet_questioner.py`, `test_grant_gate_575.py`, `test_bind_sole_seam_551.py`)
    move together and this is the ninth member arriving.
    """
    AgentRole = _role()
    AGENTS = _agents()
    assert len(AgentRole) == 9
    assert len(AGENTS) == 9
    assert set(AGENTS.keys()) == set(AgentRole)
    assert sorted(defn.role.value for defn in AGENTS.values()) == sorted(
        r.value for r in AgentRole)


# ---------------------------------------------------------------------------------------
# O5 — the questioner and the comparator are untouched
# ---------------------------------------------------------------------------------------


def test_1008_the_questioner_keeps_its_definition_deps_and_deny_reason(tmp_path):
    """The questioner's key still resolves to the questioner's own definition, deps class and
    refusal text — the judge took a new key, it did not take the questioner's.

    Asserted against the QUESTIONER's own constant rather than a literal string, and against
    the JUDGE's text for inequality: what could go wrong here is the two collapsing onto one
    object or one voice, not the questioner's wording drifting.
    """
    compile_policy_for = T.sym("runtime.permission", "compile_policy_for")
    AgentRole = _role()
    questioner = T.mod("learning.branch.questioner")
    QUESTIONER_DEF = _questioner_def()

    assert _agents()[AgentRole.QUESTIONER] is QUESTIONER_DEF
    assert QUESTIONER_DEF.deps_cls is questioner.QuestionerDeps
    assert questioner.QuestionerDeps.role is AgentRole.QUESTIONER

    policy = compile_policy_for(QUESTIONER_DEF, run_dir=tmp_path, defender_dir=T.DEFENDER)
    assert policy.deny_reason == questioner._QUESTIONER_DENY_REASON
    assert "questioner" in policy.deny_reason.casefold()
    assert policy.deny_reason != _judge_def().deny_reason, (
        "the two deny-all roles refuse in one voice — then only one of them is refusing in its "
        "own words")


def test_1008_the_comparator_still_judges_under_the_questioners_role(tmp_path):
    """The comparator's judging call STAYS on `AgentRole.QUESTIONER`.

    The rule #1008 settles is one deny-all key per PACKAGE: the comparator is branch-package
    machinery (its only callers are `learning/branch/review.py` and `learning/branch/
    episode.py`), so it shares the branch package's key; the family judge is its own package
    and gets its own. Nothing pinned the comparator's role before this — `test_947_triplet_
    questioner.py:174-185` pins only that the four calls' trace ids are distinct — so a change
    that moved it along with the judge would have been silent.

    Driven through the real `compare` with a recording fake on its own `invoke=` seam, and the
    assertion is against the CAPTURED kwarg, not the canned reply. Positive controls: the
    comparison actually reached the model (a byte-identical pair is settled offline by
    `mechanical` and never calls at all) and its answer came back as the verdict.
    """
    AgentRole = _role()
    comparator = T.mod("learning.branch.comparator")
    agent = T.FakeAgent("mutation")

    verdict = comparator.compare("{}", '{"a": 1}', "an axis", invoke=agent)

    assert agent.calls == 1, (
        "the comparator settled without a model call, so there is no recorded role to assert on")
    assert verdict is comparator.Verdict.MUTATION, (
        f"the fake's reply did not come back as the verdict ({verdict!r})")
    assert agent.kwargs[0]["role"] is AgentRole.QUESTIONER, (
        f"the comparator now judges under {agent.kwargs[0]['role']!r} — it is branch-package "
        "machinery and shares the branch package's key")
    assert agent.kwargs[0]["role"] is not AgentRole.JUDGE
    assert agent.agent_ids[0].startswith(comparator.AGENT_ID_PREFIX), (
        f"the comparator's agent id {agent.agent_ids[0]!r} left the `comparator:` namespace")


def test_1008_the_questioners_own_seam_still_builds_with_the_questioners_deps():
    """The BRANCH package's seam still hands `run_stage` a `QuestionerDeps()` — the mirror of
    the judge's check, on the module that answers for the other four calls.

    `seams.model_seam` is BOTH production questioner users at once: `learning/branch/cli.py`
    builds the family author and the comparator from it. So one line there moves the
    questioner's three authoring calls AND the comparator onto whatever deps class it names —
    and every runtime assertion in this file's O5 tests survives that, because all they read is
    the `role=` kwarg the module docstring calls decorative, and the registry identity, which
    such a change does not touch.

    Through the SAME helper as the judge's seam, deliberately: the first version of this mirror
    was a hand-copy that had already lost two of the judge-side assertions before it was
    committed once.
    """
    _assert_sole_unwidened_seam(
        T.DEFENDER / "learning" / "branch" / "seams.py", "model_seam",
        "QuestionerDeps()", "defender.learning.branch.questioner")


def test_1008_no_shipped_prose_still_says_the_judge_runs_as_the_questioner():
    """Every trusted sentence that DESCRIBES the borrowed key is gone, because each is now
    false — across all THIRTEEN files that carried one.

    A REPLAY OF THE DECK'S #700 SHAPE, which is why it is a test rather than a review note:
    when a change moves what an arrangement IS, every sentence describing the old arrangement
    stays byte-identical and green. Nothing else in this suite can fail on a sentence.

    THIS TEST HAS NOW MISSED TWICE, AND BOTH MISSES ARE DESIGNED OUT HERE.

    * It first listed the four files the design named and shipped green over five more. The
      rows are what reviews of the merged tree actually found, and the two that mattered were
      surfaces no mechanism named: a MODEL-LOADABLE handbook page saying the judge role does
      not exist, and the questioner's own module — what an author adding the next deny-all
      role reads first — still stating the rule this change refutes.
    * Then one row was INERT: a phrase transcribed from a sentence that is LINE-WRAPPED at
      exactly that point, so it matched nothing anywhere and the row could not fail however
      stale the file got. Both sides are whitespace-normalized now, so a wrap cannot hide a
      match — and every row carries its own ANCHOR, a phrase that must still be present in
      the same file, so a mis-transcribed or mis-pathed row raises instead of passing. The
      old version had three anchors for eight paths, which is what let the inert row through.

    Each row is a phrase the shipped tree ASSERTED and this change refutes — not a wording
    preference.
    """
    def flat(text: str) -> str:
        """One line, with the markers that only exist because of WRAPPING taken out.

        A sentence is one sentence whether it fits on a line or not. Collapsing whitespace
        alone is not enough: a wrapped Python comment carries a `#` at each continuation and a
        wrapped Markdown blockquote a `>`, so the flattened text has a marker sitting in the
        middle of the phrase and the match fails for a reason that has nothing to do with what
        the file says. Both are stripped per line before the join.
        """
        lines = [re.sub(r"^\s*[#>]\s?", "", line) for line in text.splitlines()]
        return " ".join(" ".join(lines).split())

    D = T.DEFENDER
    rows = [
        (D / "runtime" / "agent_role.py",
         "a second key would be a second compiled policy over the same empty one",
         "ONE DENY-ALL KEY PER PACKAGE",
         "the judge's key IS a second one over an equally empty policy, and deliberately"),
        (JUDGE_RUN, "runs under `AgentRole.QUESTIONER`'s existing definition",
         "WHAT THE OWN KEY BUYS",
         "it runs under its own, declared in this very file"),
        (JUDGE_RUN, "THE TWO JUDGES SHARE THOSE KNOBS", "WHAT THE OWN KEY BUYS",
         "the other judge was deleted with the pipeline in #922"),
        (D / "agents.py", "until then runs under the questioner's definition",
         "one deny-all key per PACKAGE",
         "'until then' is the past, and this line sits above the registration that ended it"),
        (JUDGE_PKG, "`QuestionerDeps`/`AgentRole.QUESTIONER` key",
         "THE IMPORTS ARE INSIDE `invoke`",
         "the seam below now builds with the judge's own deps"),
        (D / "skills" / "handbook" / "content" / "learning-loop.md",
         "neither do the `actor`, `oracle` and `judge` agent roles",
         "That pipeline is **deleted**.",
         "a MODEL reads this page to ground which roles exist, and `judge` is one of them"),
        (D / "learning" / "branch" / "questioner" / "__init__.py",
         "A second role key would buy a second compiled policy over the same (empty) grant",
         "WHY THREE CALLS SHARE ONE ROLE KEY",
         "this is the rule #1008 refutes, in the file an author adding the next deny-all role "
         "reads first"),
        (D / "runtime" / "agent_definition.py", "The judge was the one such role",
         "no longer any role whose static shape understates it",
         "`AgentRole.JUDGE` names a live role again, and it is not that one"),
        (D / "tests" / "test_922_witnesses.py", "and it is the role #1008 will fork",
         "EVERY deny-all role, DERIVED",
         "future tense of a landed change, on the guard that had to grow to cover it"),
        (D / "docs" / "learning-loop.md", "running under the questioner's definition",
         "## The Judge",
         "`CLAUDE.md` names this doc the FIRST read before changing the judge"),
        (D / "docs" / "agent-definition-single-source.md", "Today's eight are in",
         "Roster note (post-#922, updated #1008)",
         "the roster is nine and `judge` is one of them, so this banner is stale in the "
         "direction that makes the live-looking grant row below read as authoritative"),
        (D / "evals" / "oracle_golden" / "judge.py",
         "two different env vars that happen to rhyme",
         "THE ENV VARS ARE THE SAME TWO NAMES",
         "they are the same two names, and the tree carried the correction and this "
         "refutation of it at once"),
        (D.parent / "experiments" / "judge-context-921" / "run_judge.py",
         "from defender.learning.branch.questioner import QuestionerDeps",
         "deps=JudgeDeps()",
         "the arm the judge's prompt is measured in must compile what production compiles"),
    ]
    for path, phrase, anchor, why in rows:
        text = path.read_text(encoding="utf-8")
        assert flat(anchor) in flat(text), (
            f"positive control: {path.name} does not contain {anchor!r}, which it should — "
            "this row is mis-pathed or mis-transcribed, so its absence check below proves "
            "nothing about the prose")
        assert flat(phrase) not in flat(text), f"{path.name} still says {phrase!r} — {why}"


# ---------------------------------------------------------------------------------------
# O6 — the deps carry nothing but the role
# ---------------------------------------------------------------------------------------


def test_1008_the_judges_deps_carry_nothing_but_the_role():
    """`JudgeDeps` is a frozen, ZERO-FIELD dataclass in the judge's own package whose only
    content is a `role` ClassVar, and it is NOT an `AgentDeps` subtype.

    A field here would be a channel: a run dir, a world label or an episode path reachable from
    inside a deny-all call is exactly the state this role is defined not to have. And `AgentDeps`
    IS the run scope — run dir, compiled policy, box executor, cwd anchor — so inheriting it
    would hand the judge the eleven handles this class exists not to have (`QuestionerDeps`'
    own docstring states the rule this copies).

    Positive control on the subtype check: a role that DOES carry a run scope (the lead author)
    is a subclass at the same address, so `not issubclass(...)` is a discriminating answer
    rather than a broken one.
    """
    AgentDeps = T.sym("runtime.tools", "AgentDeps")
    AgentRole = _role()
    deps_cls = _judge_def().deps_cls

    assert deps_cls.__name__ == "JudgeDeps"
    assert deps_cls.__module__.startswith("defender.learning.judge"), (
        f"{deps_cls.__name__} lives in {deps_cls.__module__} — it belongs beside the definition "
        "it is the deps for, in the judge's own package")
    assert dataclasses.is_dataclass(deps_cls)
    assert deps_cls.__dataclass_params__.frozen
    assert dataclasses.fields(deps_cls) == (), (
        f"the judge's deps gained {[f.name for f in dataclasses.fields(deps_cls)]}, and a field "
        "here is a channel into a call that is supposed to hold nothing")
    assert deps_cls.role is AgentRole.JUDGE

    assert not issubclass(deps_cls, AgentDeps), (
        "the judge's deps inherit the run scope — run dir, policy, box, anchors — that a role "
        "holding no grant exists not to carry")
    assert issubclass(T.sym("agents", "LEAD_AUTHOR_DEF").deps_cls, AgentDeps), (
        "positive control: a role that really does carry a run scope is not an AgentDeps "
        "subtype either, so the check above discriminates nothing")

    # NOT THE QUESTIONER'S DEPS EITHER, by inheritance or by re-export. Every check above is
    # satisfied by `class JudgeDeps(QuestionerDeps)` with the role overridden — zero fields,
    # frozen, not an `AgentDeps` subtype, named right, in the right module — and what ships
    # then is the questioner's deps class wearing the judge's role, which is the "second name
    # over one object" this issue exists not to be.
    QuestionerDeps = T.mod("learning.branch.questioner").QuestionerDeps
    assert deps_cls is not QuestionerDeps
    assert not issubclass(deps_cls, QuestionerDeps), (
        "the judge's deps INHERIT the questioner's — a subclass carries every field and every "
        "future field of the class it is supposed to be independent of")
    assert deps_cls.__mro__[1:] == (object,), (
        f"the judge's deps inherit {[c.__name__ for c in deps_cls.__mro__[1:-1]]} — this class "
        "carries its role and nothing else, which means it derives from nothing else")


def test_1008_bind_refuses_the_judges_definition_by_its_deps_type_name(tmp_path):
    """`bind(JUDGE_DEF, …)` REFUSES, and names `JudgeDeps` in the refusal.

    `bind` is the one production seam that turns a definition plus a run into deps plus a
    policy, and there is no run for a role whose entire input is inlined in one prompt by the
    host. Refusing BY NAME rather than handing back a half-built object is what makes the
    carve-out legible — and it is what puts the judge in the `refused` partition of #922's
    sole-seam census (`test_922_witnesses.py`), beside the questioner, rather than in the
    partition whose modules are held to the no-front-door rule.

    The refusal must be the DEPS-TYPE one, not `bind`'s other refusal for a definition that
    declares no `deps_cls` at all — so that is asserted apart.
    """
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
