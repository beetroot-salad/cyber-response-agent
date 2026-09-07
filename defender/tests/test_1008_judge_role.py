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

import pytest

from defender.tests import _judge_921 as J
from defender.tests import _triplet_947 as T

#: The four grant surfaces `AgentDefinition` defaults to deny-all on
#: (`runtime/agent_definition.py:63-86`). The whole of O3 is that NONE of them is spelled at
#: the judge's constructor call — an omission over the defaults, not an empty grant line a
#: one-word edit reopens.
GRANT_KEYWORDS = ("tools", "bash_shapes", "write_shapes", "verb_grant")

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
    """Every `callee(...)` call under `node`, by the callee's NAME.

    Parsed rather than grepped: a substring scan of a whole file cannot tell a constructor's own
    keyword from the same word in a docstring, in a comment, or at another call — and a check
    that fails when the prose changes is not the check that fails when a grant is added.
    """
    return [n for n in ast.walk(node)
            if isinstance(n, ast.Call)
            and isinstance(n.func, ast.Name) and n.func.id == callee]


def _keywords(call: ast.Call) -> dict[str, str]:
    """The call's keyword arguments: name -> the unparsed source of its value."""
    return {kw.arg: ast.unparse(kw.value) for kw in call.keywords if kw.arg is not None}


def _self_test_the_extractor() -> None:
    """The extractor's own positive control, run at every site that uses it.

    An AST check whose parse silently found NOTHING passes for the wrong reason forever. This
    proves, on synthetic source, that the walk locates a call, reads its keyword names, and
    would REPORT a grant keyword if one were written — so a green result upstream means the
    keyword is absent, not that the checker is blind.
    """
    source = (
        "def seam():\n"
        "    D = AgentDefinition(role=R, model=m, tools=ToolSet(), deps_cls=X)\n"
        "    return run_stage(stage='s', deps=SomeDeps(), tools=T)\n"
    )
    tree = ast.parse(source)
    seam = _function(tree, "seam")
    assert seam is not None, "the extractor cannot find a function it was handed by name"
    (defn_call,) = _calls(seam, "AgentDefinition")
    assert set(_keywords(defn_call)) == {"role", "model", "tools", "deps_cls"}
    assert "tools" in _keywords(defn_call), "the extractor would not report a grant keyword"
    (stage_call,) = _calls(seam, "run_stage")
    assert _keywords(stage_call)["deps"] == "SomeDeps()"
    assert "tools" in _keywords(stage_call)


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
    assert policy.deny_reason not in (default_reason, questioner_reason), (
        "the judge refuses in the runtime default's or the questioner's words")
    assert "judge" in policy.deny_reason.casefold(), (
        f"the judge's refusal never names the judge: {policy.deny_reason!r} — a refusal in "
        "this role's own words says which role is refusing")

    assert named_programs("only the read-only viewers (jq/ls/cat) are permitted") == {
        "jq", "ls", "cat"}, (
        "the g1 extractor found no program names in text that has three — it is blind here, so "
        "the assertion below would prove nothing")
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
    entry, no bash grant, no read root, no read shape and no write root.

    `tuple(defn.tools)` rather than a row of booleans: `ToolSet.__iter__` yields only the lanes
    a set GRANTS, so the empty tuple is the whole deny-all claim over every lane that exists now
    or is added later (`runtime/agent_definition.py`'s own note).

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


def test_1008_the_default_seam_hands_run_stage_the_judges_deps_and_widens_nothing():
    """The SHIPPED seam builds with `JudgeDeps()` and passes neither `tools=` nor `verbs=`.

    Both halves are load-bearing and neither is covered elsewhere:
      * the deps class is the mechanism — `build_stage_agent` reads `type(deps).role`, so a seam
        still handing `QuestionerDeps()` runs every draw under the questioner's definition no
        matter what the registry says or what the `role=` kwarg declares;
      * `run_stage(tools=…, verbs=…)` WIDENS the definition at CALL time
        (`learning/_pydantic_stage.py:52-57`), so a deny-all definition plus a seam that passes
        `tools=` is a grant. `test_921_judge_call.py:433-436` checks the INJECTED seam's kwargs,
        which is a different object entirely.

    A SOURCE CHECK, and the module docstring says why: `run_stage` is imported inside `invoke`
    (deliberately — see `_default_judge_seam`'s own docstring), so there is no seam to inject
    at, driving it end to end sources a billable provider key, and `monkeypatch.setattr` is
    forbidden here. The parse asserts it found the function AND the call inside it.
    """
    _self_test_the_extractor()
    tree = ast.parse(JUDGE_PKG.read_text(encoding="utf-8"))
    seam = _function(tree, "_default_judge_seam")
    assert seam is not None, (
        f"{JUDGE_PKG} declares no `_default_judge_seam` — the production judge seam moved, and "
        "this check would otherwise pass by finding nothing")
    calls = _calls(seam, "run_stage")
    assert len(calls) == 1, (
        f"`_default_judge_seam` makes {len(calls)} `run_stage(` calls; it drives exactly one")

    spelled = _keywords(calls[0])
    assert spelled.get("deps") == "JudgeDeps()", (
        f"the shipped seam builds with deps={spelled.get('deps')} — the deps class is what "
        "selects the definition, so this is the line that decides which role the judge runs as")
    widened = sorted(set(spelled) & {"tools", "verbs"})
    assert widened == [], (
        f"the seam passes {widened} to `run_stage`, which overrides the registered definition "
        "at call time — a grant handed to a deny-all role from outside its own definition")


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
