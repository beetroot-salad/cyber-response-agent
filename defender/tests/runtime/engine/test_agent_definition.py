"""AgentDefinition: toolset registration, policy compilation, roots, model/effort and request-limit wiring.

Grant semantics belong to `test_grant_gate_575.py`; this file stays at the definition layer. Hermetic:
a `FunctionModel` enters through the `make_model` seam under `override_allow_model_requests(False)`."""
from __future__ import annotations

import re

import pytest

pytest.importorskip("pydantic_ai")

from pydantic_ai.exceptions import UsageLimitExceeded  # noqa: E402
from pydantic_ai.messages import ModelResponse, TextPart  # noqa: E402
from pydantic_ai.models import override_allow_model_requests  # noqa: E402
from pydantic_ai.models.function import FunctionModel  # noqa: E402
from pydantic_ai.usage import UsageLimits  # noqa: E402

from defender.configuration._env import FatalConfigError  # noqa: E402
from defender._paths import PATHS  # noqa: E402
from defender.learning.core import config  # noqa: E402
from defender.agents import QUESTIONER_DEF  # noqa: E402
from defender.learning.branch.questioner import QuestionerDeps  # noqa: E402
from defender.investigation import driver, observe, permission  # noqa: E402
from defender import providers  # noqa: E402
from defender._agent_role import AgentRole  # noqa: E402
from defender.providers import BuiltModel  # noqa: E402
from defender.tests.support.runtime.engine._engine_helpers import fake_model as _fake_model  # noqa: E402
from defender.investigation.tools import AgentDeps  # noqa: E402

from defender.investigation.agent_definition import (  # noqa: E402
    AgentDefinition,
    RunScope,
    ToolSet,
    bind,
    build_registry,
    compile_policy,
    compile_policy_for,
    read_allow_of,
    resolve_roots,
)
from defender.investigation.permission import Grant, Route  # noqa: E402
from defender.tests.support.tenancy import _tenants1106 as T1106
from typing import ClassVar  # noqa: E402

from defender._model import model  # noqa: E402


@model(frozen=True)
class _ToolFreeDeps(AgentDeps):
    """A plain run-scoped deps type for the tool-free agent tests below."""

    role: ClassVar[AgentRole] = AgentRole.QUESTIONER
from defender.agents import (  # noqa: E402
    AGENTS,
    MAIN_DEF,
)

_CONFINE_A = config.REPO_ROOT / "defender" / "lessons"
_CONFINE_B = config.REPO_ROOT / "defender" / "skills"

_ORACLE_YAML = 'events:\n  - Computer: "FINANCE-DB"\n    EventID: 4624\n'


def _text_fn(text: str = "ok"):
    return lambda messages, info: ModelResponse(parts=[TextPart(content=text)])


def _capture_make_model(settings=None):
    """A `make_model` fake for the (name, effort) seam: records every call and returns a hermetic
    FunctionModel paired with `settings`. Returns (fake, calls)."""
    calls: list[tuple[str, object]] = []

    def fake(model: str, effort):
        calls.append((model, effort))
        return BuiltModel(FunctionModel(_text_fn()), settings)

    return fake, calls


def _counting_make_model(text: str = "ok", settings=None):
    """A `make_model` fake whose FunctionModel appends to `reqs` on every model request. Returns
    (fake, reqs)."""
    reqs: list[object] = []

    def fn(messages, info):
        reqs.append(info)
        return ModelResponse(parts=[TextPart(content=text)])

    def fake(model: str, effort):
        return BuiltModel(FunctionModel(fn), settings)

    return fake, reqs


@pytest.fixture
def logger(tmp_path):
    lg = observe.RequestLogger(tmp_path / "llm_requests.jsonl")
    try:
        yield lg
    finally:
        lg.close()


def _glm_thunk() -> str:
    return "glm-5.3"


_EMPTY_TOOLSET = ToolSet()


def _defn(
    *, role=AgentRole.MAIN, model=_glm_thunk, effort=None, tools=_EMPTY_TOOLSET,
    corpus_dirs=(), bash_shapes=(), write_shapes=(), deps_cls=None,
):
    """An AgentDefinition for a shape test (model defaults to a glm thunk). `bash_shapes` defaults
    empty: an agent may hold the bash tool and be granted nothing."""
    return AgentDefinition(
        role=role, model=model, effort=effort, tools=tools, corpus_dirs=corpus_dirs,
        bash_shapes=bash_shapes, write_shapes=write_shapes, deps_cls=deps_cls,
    )


def _scope_patterns(policy) -> list[str]:
    """The source strings of the policy's path scope, where the run's roots live (argv shapes carry
    no path). `re.Pattern` compares by identity, so project the strings."""
    return [p.pattern for p in policy.read_allow]


_DEFAULT_SCOPE = RunScope()


def _compile(defn, run_dir, scope=_DEFAULT_SCOPE):
    """Drive the real `resolve_roots` → `compile_policy` composition."""
    return compile_policy(defn, resolve_roots(run_dir, defn.corpus_dirs, scope))


def test_read_surface_is_the_cat_grants_scope(tmp_path):
    """The read surface IS the `cat` grant's scope, the same object, so no second read grammar can
    drift; an agent with no `cat` grant gets an empty `read_allow`, so the identity is not vacuous."""
    assert not hasattr(AgentDefinition(role=AgentRole.QUESTIONER, model=_glm_thunk, effort=None),
                       "read_shapes")
    pol = compile_policy_for(MAIN_DEF, run_dir=tmp_path, defender_dir=PATHS.defender_dir)
    cat_scope = next(g.scope for g in pol.bash_allow if g.program == "cat")
    assert pol.read_allow is cat_scope
    assert pol.read_allow is read_allow_of(pol.bash_allow)
    assert cat_scope
    assert read_allow_of(_compile(_defn(role=AgentRole.QUESTIONER), tmp_path).bash_allow) == ()


def test_build_registers_exact_toolset(logger):
    """`build_agent_core` registers exactly the present tools of `defn.tools`, in a pinned order."""
    defn = _defn(tools=ToolSet(read=True, bash=True, write=True))
    with override_allow_model_requests(False):
        agent = driver.build_agent_core(
            defn, deps_type=AgentDeps, instructions="x", logger=logger,
            agent_id="main", make_model=_fake_model(_text_fn()),
        )
    assert list(agent._function_toolset.tools) == ["bash", "read_file", "write_file", "edit_file"]


def test_registration_order_bash_before_read(logger):
    """Registration order is bash before read_file, not ToolSet's field order (read, bash, write)."""
    defn = _defn(tools=ToolSet(read=True, bash=True))
    with override_allow_model_requests(False):
        agent = driver.build_agent_core(
            defn, deps_type=AgentDeps, instructions="x", logger=logger,
            agent_id="a", make_model=_fake_model(_text_fn()),
        )
    assert list(agent._function_toolset.tools) == ["bash", "read_file"]


def test_toolset_exact_combos(logger):
    """Each (read, bash, write) combination registers exactly its tools."""
    with override_allow_model_requests(False):
        read_only = driver.build_agent_core(
            _defn(tools=ToolSet(read=True, bash=False, write=False)),
            deps_type=AgentDeps, instructions="x", logger=logger,
            agent_id="a", make_model=_fake_model(_text_fn()),
        )
        bash_writer = driver.build_agent_core(
            _defn(tools=ToolSet(read=False, bash=True, write=True)),
            deps_type=AgentDeps, instructions="x", logger=logger,
            agent_id="b", make_model=_fake_model(_text_fn()),
        )
    assert list(read_only._function_toolset.tools) == ["read_file"]
    assert list(bash_writer._function_toolset.tools) == ["bash", "write_file", "edit_file"]


def test_toolset_bash_presence_vs_permission(logger, tmp_path):
    """Holding the bash tool and being granted commands are two facts: `bash=True` with no grants
    registers the tool and compiles an empty `bash_allow`."""
    granted = _defn(tools=ToolSet(read=True, bash=True))
    with override_allow_model_requests(False):
        none_agent = driver.build_agent_core(
            _defn(tools=ToolSet(read=True, bash=False)),
            deps_type=AgentDeps, instructions="x", logger=logger,
            agent_id="a", make_model=_fake_model(_text_fn()),
        )
        bash_agent = driver.build_agent_core(
            granted, deps_type=AgentDeps, instructions="x", logger=logger,
            agent_id="b", make_model=_fake_model(_text_fn()),
        )
    assert "bash" not in list(none_agent._function_toolset.tools)
    assert "bash" in list(bash_agent._function_toolset.tools)
    assert _compile(granted, tmp_path).bash_allow == ()


def test_deny_all_role_empty_toolset(logger):
    """A deny-all role (the questioner) registers no tool at all, so its lack of `read_file` is
    structural, not a runtime gate; main registering `read_file` is the positive control."""
    with override_allow_model_requests(False):
        deny_all = driver.build_agent_core(
            QUESTIONER_DEF, deps_type=QuestionerDeps, instructions="x", logger=logger,
            agent_id="questioner", make_model=_fake_model(_text_fn()),
        )
        main = driver.build_agent_core(
            _defn(tools=ToolSet(read=True, bash=True, write=True)),
            deps_type=AgentDeps, instructions="x", logger=logger,
            agent_id="main", make_model=_fake_model(_text_fn()),
        )
    assert list(deny_all._function_toolset.tools) == []
    assert "read_file" in list(main._function_toolset.tools)


def test_compile_policy_emits_only_declared_grants(tmp_path):
    """`compile_policy` emits no capability the definition did not declare: a def without builders
    projects empty lanes, and main and gather project PLAIN-only bash lanes (data sources go
    through the `query` tool)."""
    no_bash = _compile(_defn(role=AgentRole.MAIN, tools=ToolSet(read=True)), tmp_path)
    assert no_bash.bash_allow == ()
    assert no_bash.read_allow == ()

    def _routes(policy) -> set[Route]:
        return {g.route for g in policy.bash_allow}

    main = _compile(MAIN_DEF, tmp_path)
    gather = _compile(T1106.fixture_gather_def(), tmp_path)
    assert _routes(main) == {Route.PLAIN}
    assert _routes(gather) == {Route.PLAIN}
    assert list(Route) == [Route.PLAIN]
    assert gather.bash_allow
    assert all(isinstance(g, Grant) for g in gather.bash_allow)


def test_gate_bash_parity_read_convergent(tmp_path):
    """`compile_policy_for` (the policy-only half of `bind`) and `bind(MAIN).policy` agree on every
    bash and read probe through the real gate."""
    dfn = PATHS.defender_dir
    bound = bind(MAIN_DEF, tmp_path).policy
    authored = compile_policy_for(MAIN_DEF, run_dir=tmp_path, defender_dir=dfn)
    for cmd in (
        f"cat {tmp_path}/investigation.md",
        "defender-elastic query x",
        "rm -rf /tmp/x",
    ):
        assert (
            permission.decide_bash(cmd, policy=bound, run_dir=tmp_path, defender_dir=dfn).allow
            == permission.decide_bash(cmd, policy=authored, run_dir=tmp_path, defender_dir=dfn).allow
        )
    for p in (tmp_path / "alert.json", tmp_path.parent / "outside.txt"):
        assert (
            permission.decide_read(p, run_dir=tmp_path, defender_dir=dfn, policy=bound).allow
            == permission.decide_read(p, run_dir=tmp_path, defender_dir=dfn, policy=authored).allow
        )
    skill_md = dfn / "SKILL.md"
    assert not permission.decide_read(skill_md, run_dir=tmp_path, defender_dir=dfn, policy=bound).allow
    assert not permission.decide_read(skill_md, run_dir=tmp_path, defender_dir=dfn, policy=authored).allow


def test_resolve_roots_per_run_no_bleed(tmp_path):
    """Roots resolved for two runs do not bleed (as a cache keyed on run_dir would): each run's path
    anchors only its own policy's scope, never an argv shape."""
    run_a, run_b = tmp_path / "runA", tmp_path / "runB"
    run_a.mkdir()
    run_b.mkdir()
    pa = compile_policy(MAIN_DEF, resolve_roots(run_a, MAIN_DEF.corpus_dirs, RunScope()))
    pb = compile_policy(MAIN_DEF, resolve_roots(run_b, MAIN_DEF.corpus_dirs, RunScope()))
    na, nb = re.escape(str(run_a)), re.escape(str(run_b))
    pats_a, pats_b = _scope_patterns(pa), _scope_patterns(pb)
    assert any(na in p for p in pats_a)
    assert not any(na in p for p in pats_b)
    assert any(nb in p for p in pats_b)
    assert not any(na in g.pattern.pattern for g in pa.bash_allow)


def test_resolve_roots_corpus_resolution(tmp_path):
    """`resolve_roots` resolves corpus dirs to absolutes under defender_dir; `corpus_dirs=()` adds none."""
    roots = resolve_roots(tmp_path, ("lessons", "skills"), RunScope())
    assert all(c.is_absolute() for c in roots.corpus_roots)
    assert set(roots.corpus_roots) == {PATHS.defender_dir / "lessons", PATHS.defender_dir / "skills"}
    empty = resolve_roots(tmp_path, (), RunScope())
    assert empty.corpus_roots == ()


def test_corpus_dirs_excludes_gather_summaries(tmp_path):
    """MAIN's corpus dirs exclude `gather_summaries`, a run-root path that stays readable through the
    run-root anchor."""
    assert AGENTS[AgentRole.MAIN].corpus_dirs == ("lessons", "skills", "examples")
    assert "gather_summaries" not in AGENTS[AgentRole.MAIN].corpus_dirs
    pol = bind(MAIN_DEF, tmp_path).policy
    d = permission.decide_read(
        tmp_path / "gather_summaries" / "x.md",
        run_dir=tmp_path, defender_dir=PATHS.defender_dir, policy=pol,
    )
    assert d.allow


def test_agents_registry_covers_every_role():
    """`AGENTS` holds exactly one definition per `AgentRole`, keyed on its own role, so a role with no
    definition fails here."""
    assert set(AGENTS.keys()) == set(AgentRole)
    assert len(AGENTS) == len(AgentRole)
    assert AgentRole.LEAD_AUTHOR in AGENTS
    for role, d in AGENTS.items():
        assert isinstance(d, AgentDefinition)
        assert d.role is role


def test_agents_duplicate_role_raises():
    """Two definitions sharing a role raise instead of the last silently winning; the real defs
    build the registry cleanly."""
    d1 = _defn(role=AgentRole.QUESTIONER)
    d2 = _defn(role=AgentRole.QUESTIONER)
    with pytest.raises(ValueError, match="role"):
        build_registry((d1, d2))
    reg = build_registry(tuple(AGENTS.values()))
    assert set(reg.keys()) == set(AgentRole)


def test_model_thunk_liveness(monkeypatch):
    """`AgentDefinition.model` is a thunk resolved at build time, so a `DEFENDER_MODEL` set after
    import is honored."""
    monkeypatch.delenv("DEFENDER_MODEL", raising=False)
    before = MAIN_DEF.model()
    monkeypatch.setenv("DEFENDER_MODEL", "glm-sentinel-xyz")
    after = MAIN_DEF.model()
    assert after == "glm-sentinel-xyz"
    assert before != after


def test_model_via_env_channel(monkeypatch, logger):
    """`--model` reaches the thunk through `DEFENDER_MODEL`: the build asks `make_model` for the
    sentinel."""
    monkeypatch.setenv("DEFENDER_MODEL", "sentinel-model")
    fake, calls = _capture_make_model()
    with override_allow_model_requests(False):
        driver.build_agent_core(
            MAIN_DEF, deps_type=AgentDeps, instructions="x", logger=logger,
            agent_id="main", make_model=fake,
        )
    assert calls[0][0] == "sentinel-model"


def test_effort_none_vs_None_distinct(monkeypatch, logger):
    """`effort=None` (omit the knob) and `effort='none'` (Fireworks reasoning disabled) give
    different model settings; 'none' is not coerced to None."""
    pytest.importorskip("pydantic_ai.models.openai")
    monkeypatch.setenv("FIREWORKS_API_KEY", "fw-test")
    with override_allow_model_requests(False):
        omit = driver.build_agent_core(
            _defn(role=AgentRole.QUESTIONER, model=lambda: "glm-5.3", effort=None, tools=ToolSet()),
            deps_type=QuestionerDeps, instructions="x", logger=logger, agent_id="o1",
        )
        disabled = driver.build_agent_core(
            _defn(role=AgentRole.QUESTIONER, model=lambda: "kimi-k3", effort="none", tools=ToolSet()),
            deps_type=QuestionerDeps, instructions="x", logger=logger, agent_id="o2",
        )
    assert "extra_body" not in omit.model_settings
    assert disabled.model_settings["extra_body"]["reasoning_effort"] == "none"
    assert omit.model_settings != disabled.model_settings


def test_effort_none_claude_crossing(monkeypatch, logger):
    """`effort='none'` with a claude-* model fails the build even for a tool-free agent (the model
    is built before tools, and Anthropic rejects 'none'); a Fireworks model builds."""
    pytest.importorskip("pydantic_ai.models.anthropic")
    pytest.importorskip("pydantic_ai.models.openai")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    monkeypatch.setenv("FIREWORKS_API_KEY", "fw-test")
    claude_defn = _defn(role=AgentRole.QUESTIONER, model=lambda: "claude-sonnet-4-6",
                        effort="none", tools=ToolSet())
    with pytest.raises((ValueError, FatalConfigError)), override_allow_model_requests(False):
        driver.build_agent_core(
            claude_defn, deps_type=QuestionerDeps, instructions="x", logger=logger,
            agent_id="oracle", make_model=providers.build_for_effort,
        )
    with override_allow_model_requests(False):
        ok = driver.build_agent_core(
            _defn(role=AgentRole.QUESTIONER, model=lambda: "kimi-k3", effort="none", tools=ToolSet()),
            deps_type=QuestionerDeps, instructions="x", logger=logger,
            agent_id="oracle", make_model=providers.build_for_effort,
        )
    assert ok.model_settings["extra_body"]["reasoning_effort"] == "none"
    assert list(ok._function_toolset.tools) == []


def test_effort_live_on_toolfree(logger, tmp_path):
    """A tool-free agent still carries its effort-derived settings, and one request under
    `request_limit=1` completes its prediction."""
    settings = {"extra_body": {"reasoning_effort": "none"}}
    fake, reqs = _counting_make_model(text=_ORACLE_YAML, settings=settings)
    defn = _defn(role=AgentRole.QUESTIONER, model=lambda: "kimi-k3", effort="none", tools=ToolSet(),
                 deps_cls=_ToolFreeDeps)
    with override_allow_model_requests(False):
        agent = driver.build_agent_core(
            defn, deps_type=QuestionerDeps, instructions="x", logger=logger,
            agent_id="oracle", make_model=fake,
        )
        assert list(agent._function_toolset.tools) == []
        assert agent.model_settings == {**settings, "openai_prompt_cache_key": "oracle"}
        assert reqs == []
        result = agent.run_sync("project this lead", deps=bind(defn, tmp_path),
                                usage_limits=UsageLimits(request_limit=1))
    assert result.output == _ORACLE_YAML
    assert len(reqs) == 1


def test_request_limit_reject_below_one(logger, tmp_path):
    """`request_limit=0` starves the single prediction (`UsageLimitExceeded`) while 1 completes it:
    the floor is starvation, not a silent coerce-to-1."""
    fake, _ = _counting_make_model(text=_ORACLE_YAML)
    defn = _defn(role=AgentRole.QUESTIONER, model=lambda: "kimi-k3", effort="none", tools=ToolSet(),
                 deps_cls=_ToolFreeDeps)
    with override_allow_model_requests(False):
        agent = driver.build_agent_core(
            defn, deps_type=QuestionerDeps, instructions="x", logger=logger,
            agent_id="oracle", make_model=fake,
        )
        deps = bind(defn, tmp_path)
        with pytest.raises(UsageLimitExceeded):
            agent.run_sync("project this lead", deps=deps,
                           usage_limits=UsageLimits(request_limit=0))
        result = agent.run_sync("project this lead", deps=deps,
                                usage_limits=UsageLimits(request_limit=1))
    assert result.output == _ORACLE_YAML


def test_main_keeps_tools(logger):
    """Main registers its full generic surface; the general `write_file`/`edit_file` verbs are gone,
    as investigation.md is append-only."""
    with override_allow_model_requests(False):
        agent = driver.build_agent_core(
            MAIN_DEF, deps_type=AgentDeps, instructions="x", logger=logger,
            agent_id="main", make_model=_fake_model(_text_fn()),
        )
    registered = list(agent._function_toolset.tools)
    assert registered == ["bash", "read_file", "append_block", "fix_row"]
    assert "write_file" not in registered
    assert "edit_file" not in registered


def test_guard_corpus_traversal(tmp_path):
    """`resolve_roots` rejects a corpus entry with '..' or an absolute path, whatever tree it
    anchors; a clean name resolves under defender_dir."""
    with pytest.raises(ValueError, match="corpus name .* clean relative path segment"):
        resolve_roots(tmp_path, ("../evil",), RunScope())
    with pytest.raises(ValueError, match="corpus name .* clean relative path segment"):
        resolve_roots(tmp_path, ("/etc",), RunScope())
    roots = resolve_roots(tmp_path, ("lessons",), RunScope())
    assert roots.corpus_roots == (PATHS.defender_dir / "lessons",)
