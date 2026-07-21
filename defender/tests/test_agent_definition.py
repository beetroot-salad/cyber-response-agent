"""The AgentDefinition suite — the consolidation (#538) as re-based on the one containment
model (#575).

#538 collapsed the two capability carriers (the build-time spec + the runtime `AgentPolicy`)
plus the scattered model/effort constants into one per-agent `AgentDefinition` that BOTH the
build site and the permission gate read, and made the pure-prediction stages (oracle +
verify-forward) genuinely tool-free (register NOTHING). #575 then replaced the *containment*
half of that definition: `BashGrammar` (a bag of capability BITS — `adapters` /
`adapter_sql_pipe` / `operand_gated` / `raw_reads` — that a regex machine expanded into an
allowlist with the run's paths BAKED INTO the argv patterns) is gone, and each agent now hangs
its OWN `bash_shapes` grant builder on its OWN def. So these tests pin what SURVIVES that
change, at the REAL entry points:

  - `build_agent_core(defn, …)`  — registers exactly the ToolSet's present tools
  - `bind(defn, run_dir, scope)` — the deps + policy resolution seam
  - `compile_policy(defn, roots)` — the AgentPolicy projection (it now COMPOSES what the def
                                    brings: the grants come from `defn.bash_shapes`, and the
                                    read surface IS the `cat` grant's scope object)
  - `resolve_roots(run_dir, corpus_dirs, scope)` — run-anchored read roots
  - `AGENTS` — the role-keyed registry, now at `defender.agents` (nothing under `runtime/`
                may enumerate agents)

The *grant* semantics themselves (shape ∧ scope, the PROGRAMS table, the resolved-path
matching, the per-agent lanes) are owned by `test_grant_gate_575.py` — the #575 executable
spec. This file stays at the DEFINITION layer: what a def carries, what a build registers,
what a compile projects.

Hermetic: no network, no key — a `FunctionModel` is injected through the `make_model`
DI seam under `override_allow_model_requests(False)`; faults enter through that seam and
`monkeypatch.setenv`, never `monkeypatch.setattr`.
"""
from __future__ import annotations

import dataclasses
import inspect
import re
from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")

from pydantic_ai.exceptions import UsageLimitExceeded  # noqa: E402
from pydantic_ai.messages import ModelResponse, TextPart  # noqa: E402
from pydantic_ai.models import override_allow_model_requests  # noqa: E402
from pydantic_ai.models.function import FunctionModel  # noqa: E402
from pydantic_ai.usage import UsageLimits  # noqa: E402

from defender._env import FatalConfigError  # noqa: E402
from defender._paths import PATHS  # noqa: E402
from defender.learning.core import config  # noqa: E402
from defender.learning.author.verify_forward.engine import (  # noqa: E402
    VERIFY_REQUEST_LIMIT,
    VerifierDeps,
)
from defender.learning.pipeline.actor_engine import ActorDeps  # noqa: E402
from defender.learning.pipeline.judge.engine_pydantic import JudgeDeps  # noqa: E402
from defender.learning.pipeline.oracle_engine import (  # noqa: E402
    ORACLE_REQUEST_LIMIT,
    OracleDeps,
)
from defender.runtime import driver, observe, permission, providers  # noqa: E402
from defender.runtime.agent_role import AgentRole  # noqa: E402
from defender.runtime.providers import BuiltModel  # noqa: E402
from defender.tests._engine_helpers import fake_model as _fake_model  # noqa: E402
from defender.runtime.tools import AgentDeps, GatherDeps  # noqa: E402

from defender.runtime.agent_definition import (  # noqa: E402
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
from defender.runtime.permission import Grant, Route  # noqa: E402
from defender.agents import (  # noqa: E402
    ACTOR_DEF,
    AGENTS,
    GATHER_DEF,
    MAIN_DEF,
    ORACLE_DEF,
    VERIFY_DEF,
)

_ENV_RETRIEVE = config.LESSONS_ENV_RETRIEVE_SCRIPT
_ACTOR_INDEX = config.LESSONS_ACTOR_INDEX_SCRIPT
_ACTOR_DIR = config.LESSONS_ACTOR_DIR
_ENV_DIR = config.LESSONS_ENVIRONMENT_DIR

_ORACLE_YAML = 'events:\n  - Computer: "FINANCE-DB"\n    EventID: 4624\n'



def _text_fn(text: str = "ok"):
    return lambda messages, info: ModelResponse(parts=[TextPart(content=text)])




def _capture_make_model(settings=None):
    """A `make_model` fake for the (name, effort) seam: records every call and returns a
    hermetic FunctionModel paired with `settings`. Returns (fake, calls)."""
    calls: list[tuple[str, object]] = []

    def fake(model: str, effort):
        calls.append((model, effort))
        return BuiltModel(FunctionModel(_text_fn()), settings)

    return fake, calls


def _counting_make_model(text: str = "ok", settings=None):
    """A `make_model` fake whose FunctionModel appends to `reqs` on every model request —
    so the caller can count how many requests a run issued. Returns (fake, reqs)."""
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
    return "glm-5.2"


_EMPTY_TOOLSET = ToolSet()


def _defn(
    *, role=AgentRole.MAIN, model=_glm_thunk, effort=None, tools=_EMPTY_TOOLSET,
    corpus_dirs=(), bash_shapes=(), write_shapes=(), deps_cls=None,
):
    """Build an AgentDefinition for a shape test (model defaults to a glm thunk). `bash_shapes`
    is the #575 per-agent grant builder tuple — an agent may hold the bash TOOL and be granted
    nothing (presence and permission are two facts), so it defaults empty. `deps_cls` is only
    needed by a def a test actually `bind`s."""
    return AgentDefinition(
        role=role, model=model, effort=effort, tools=tools, corpus_dirs=corpus_dirs,
        bash_shapes=bash_shapes, write_shapes=write_shapes, deps_cls=deps_cls,
    )


def _scope_patterns(policy) -> list[str]:
    """The SOURCE strings of the policy's path scope — the paths half of the containment model
    (#575: the run's roots live in the grants' SCOPE, never interpolated into an argv shape; the
    shapes carry no path at all). re.Pattern compares by identity, so project the strings."""
    return [p.pattern for p in policy.read_allow]


_DEFAULT_SCOPE = RunScope()


def _compile(defn, run_dir, scope=_DEFAULT_SCOPE):
    """Drive the real resolve_roots → compile_policy composition. Since #575 `compile_policy`
    takes the DEFINITION itself (not a projection of its fields): the grants come from the def's
    own `bash_shapes` builders, so there is nothing left for the caller to unpack."""
    return compile_policy(defn, resolve_roots(run_dir, defn.corpus_dirs, scope))



def test_agentdefinition_shape():
    """AgentDefinition is a frozen dataclass carrying role/model(thunk)/effort/tools/
    corpus_dirs/bash_shapes/write_shapes/deps_cls/deny_reason; the tail fields default
    (ToolSet() / () / None / str)."""
    defn = AgentDefinition(role=AgentRole.MAIN, model=lambda: "glm-5.2", effort="low")
    assert dataclasses.is_dataclass(defn)
    assert defn.role is AgentRole.MAIN
    assert callable(defn.model)
    assert defn.model() == "glm-5.2"
    assert defn.effort == "low"
    assert isinstance(defn.tools, ToolSet)
    assert defn.corpus_dirs == ()
    assert defn.bash_shapes == ()
    assert defn.write_shapes == ()
    assert defn.deps_cls is None
    assert isinstance(defn.deny_reason, str)


def test_agentdefinition_frozen():
    """AgentDefinition is frozen: mutating .tools/.role/.model raises FrozenInstanceError,
    so bind/build cannot corrupt a shared definition."""
    defn = AgentDefinition(role=AgentRole.MAIN, model=lambda: "m", effort=None)
    with pytest.raises(dataclasses.FrozenInstanceError):
        defn.tools = ToolSet(read=True)  # type: ignore[misc]
    with pytest.raises(dataclasses.FrozenInstanceError):
        defn.role = AgentRole.GATHER  # type: ignore[misc]


def test_toolset_shape():
    """ToolSet is a frozen dataclass of PRESENCE bits, every one defaulting off (the no-tool
    safe default). `bash` is a plain bool since #575 — it says whether the agent HOLDS the bash
    tool; WHAT it may run is its def's `bash_shapes` grants, a separate fact."""
    ts = ToolSet()
    assert dataclasses.is_dataclass(ts)
    assert ts.read is False
    assert ts.bash is False
    assert ts.write is False
    with pytest.raises(dataclasses.FrozenInstanceError):
        ts.read = True  # type: ignore[misc]


def test_read_surface_is_the_cat_grants_scope(tmp_path):
    """There is no `read_shapes` FIELD on a definition any more (#575): the read surface IS the
    `cat` grant's scope — the same tuple OBJECT, since `cat` is the one program that opens a path
    on the bash lane, so the set of paths an agent may `cat` IS the set it may read. Parity is
    identity, not a second grammar kept in sync (#545's two grammars drifted).

    NEGATIVE: an agent with NO `cat` grant (the tool-free oracle) gets an EMPTY read_allow — no
    shape filter — so the identity is not vacuously satisfied by "everything is ()"."""
    assert not hasattr(AgentDefinition(role=AgentRole.ORACLE, model=_glm_thunk, effort=None),
                       "read_shapes")
    pol = compile_policy_for(MAIN_DEF, run_dir=tmp_path, defender_dir=PATHS.defender_dir)
    cat_scope = next(g.scope for g in pol.bash_allow if g.program == "cat")
    assert pol.read_allow is cat_scope
    assert pol.read_allow is read_allow_of(pol.bash_allow)
    assert cat_scope
    assert read_allow_of(_compile(_defn(role=AgentRole.ORACLE), tmp_path).bash_allow) == ()



def test_bind_gather_isinstance_preserved(tmp_path):
    """bind(GATHER_DEF, run_dir) returns an object for which isinstance(x, GatherDeps) is
    True and x.role is AgentRole.GATHER, so the adapter-capture narrow at tools.py:195
    stays live (the rejected bare-AgentDeps return would break it)."""
    deps = bind(GATHER_DEF, tmp_path)
    assert isinstance(deps, GatherDeps)
    assert deps.role is AgentRole.GATHER


def test_bind_actor_read_confine(tmp_path):
    """bind(ACTOR_DEF, run_dir, scope=<confine>) returns an ActorDeps carrying the required
    read_confine (matching the scope's confine) — bind supplies the subtype's extra required
    field, so a confined actor never falls back to the whole defender_dir corpus."""
    confine = (_ACTOR_DIR, _ENV_DIR)
    deps = bind(ACTOR_DEF, tmp_path, scope=RunScope(scripts=(_ENV_RETRIEVE, _ACTOR_INDEX), read_confine=confine))
    assert isinstance(deps, ActorDeps)
    assert deps.policy.read_confine == confine
    assert deps.policy.read_confine != ()


def test_bind_gather_lead_id_channel(tmp_path):
    """bind stays per-run and has NO lead param: gather's per-dispatch lead_id/query_id enter
    via a thin wrapper over bind, not via bind's signature (the rejected lead_id param would
    conflate per-run and per-dispatch scopes)."""
    params = set(inspect.signature(bind).parameters)
    assert "lead_id" not in params
    assert "query_id" not in params
    assert params == {"defn", "run_dir", "scope", "salt", "defender_dir", "box"}
    deps = bind(GATHER_DEF, tmp_path)
    assert isinstance(deps, GatherDeps)
    assert getattr(deps, "lead_id", None) is None



def test_build_registers_exact_toolset(logger):
    """build_agent_core(defn) registers EXACTLY the present tools in defn.tools and nothing
    else (the always-on register_tools bash+read_file branch is deleted). A read+bash+write
    agent registers ['bash','read_file','write_file','edit_file'] in that order."""
    defn = _defn(tools=ToolSet(read=True, bash=True, write=True))
    with override_allow_model_requests(False):
        agent = driver.build_agent_core(
            defn, deps_type=AgentDeps, instructions="x", logger=logger,
            agent_id="main", make_model=_fake_model(_text_fn()),
        )
    assert list(agent._function_toolset.tools) == ["bash", "read_file", "write_file", "edit_file"]


def test_registration_order_bash_before_read(logger):
    """Registered order is bash BEFORE read_file (the current pinned order), NOT ToolSet's
    dataclass field order (read, bash, write): a read+bash agent pins ['bash','read_file']."""
    defn = _defn(tools=ToolSet(read=True, bash=True))
    with override_allow_model_requests(False):
        agent = driver.build_agent_core(
            defn, deps_type=AgentDeps, instructions="x", logger=logger,
            agent_id="a", make_model=_fake_model(_text_fn()),
        )
    assert list(agent._function_toolset.tools) == ["bash", "read_file"]


def test_toolset_exact_combos(logger):
    """Each (read,bash,write) combination maps to exactly its tools:
    ToolSet(read=True, bash=False, write=False) -> ['read_file'];
    ToolSet(read=False, bash=True, write=True) -> ['bash','write_file','edit_file']."""
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
    """Tool PRESENCE and PERMISSION are two facts (#575, which split them into two fields —
    they used to be one nullable `bash` grammar, so "holds the tool" and "may run something"
    could not be spelled apart). bash=False registers NO bash tool; bash=True DOES register it
    even when the def declares NO grants at all — and that agent's compiled policy then has an
    EMPTY bash_allow, i.e. it holds the tool and the gate denies every command."""
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



def test_oracle_empty_toolset(logger):
    """build_agent_core(ORACLE_DEF) with tools=ToolSet() registers NOTHING: the tool list is
    [] (no read_file, no bash, no write_file/edit_file — all four covered by list-empty).
    POSITIVE CONTROL: main (read=True) registers read_file, proving the registration
    mechanism fired and the empty list is not vacuous."""
    with override_allow_model_requests(False):
        oracle = driver.build_agent_core(
            ORACLE_DEF, deps_type=OracleDeps, instructions="x", logger=logger,
            agent_id="oracle", make_model=_fake_model(_text_fn()),
        )
        main = driver.build_agent_core(
            _defn(tools=ToolSet(read=True, bash=True, write=True)),
            deps_type=AgentDeps, instructions="x", logger=logger,
            agent_id="main", make_model=_fake_model(_text_fn()),
        )
    assert list(oracle._function_toolset.tools) == []
    assert "read_file" in list(main._function_toolset.tools)


def test_verify_empty_toolset(logger):
    """build_agent_core(VERIFY_DEF) with tools=ToolSet() registers NOTHING: tools == [].
    POSITIVE CONTROL: a judge-shaped agent (read=True) registers read_file."""
    with override_allow_model_requests(False):
        verify = driver.build_agent_core(
            VERIFY_DEF, deps_type=VerifierDeps, instructions="x", logger=logger,
            agent_id="verify", make_model=_fake_model(_text_fn()),
        )
        judge = driver.build_agent_core(
            _defn(role=AgentRole.JUDGE, tools=ToolSet(read=True, bash=True)),
            deps_type=JudgeDeps, instructions="x", logger=logger,
            agent_id="judge", make_model=_fake_model(_text_fn()),
        )
    assert list(verify._function_toolset.tools) == []
    assert "read_file" in list(judge._function_toolset.tools)


def test_oracle_no_escape_hatch(logger, tmp_path):
    """The oracle built via ToolSet() has NO read_file even when its run_dir holds answer-
    bearing source (source_refs.yaml) — absence is STRUCTURAL (build-time), not a runtime
    gate. POSITIVE CONTROL: an agent with read=True over the same run_dir DOES register
    read_file, so the missing read_file is structural, not incidental to the run_dir."""
    (tmp_path / "source_refs.yaml").write_text("normalized_disposition: malicious\n")
    with override_allow_model_requests(False):
        oracle = driver.build_agent_core(
            ORACLE_DEF, deps_type=OracleDeps, instructions="x", logger=logger,
            agent_id="oracle", make_model=_fake_model(_text_fn()),
        )
        reader = driver.build_agent_core(
            _defn(tools=ToolSet(read=True)),
            deps_type=AgentDeps, instructions="x", logger=logger,
            agent_id="reader", make_model=_fake_model(_text_fn()),
        )
    assert "read_file" not in list(oracle._function_toolset.tools)
    assert "read_file" in list(reader._function_toolset.tools)



def test_compile_policy_emits_only_declared_grants(tmp_path):
    """SAFE-BY-CONSTRUCTION: compile_policy emits no capability the DEFINITION did not declare.
    It is a pure composition of the def's own `bash_shapes` builders — there is no capability
    inference left, which is the point of #575: the capability BITS
    (`adapters`/`adapter_sql_pipe`/`operand_gated`/`raw_reads`) are gone, and each was a place a
    declared value could disagree with the lane that enforced it. A capability is now an ADDRESS
    in the grant list, so "main may not run an adapter" is the absence of that grant.

    A def declaring no builders projects an empty lane (bash_allow == (), and — since the read
    surface IS the cat grant's scope — an empty read_allow too). Since #611 a data source is
    reached through the `query` TOOL, not from bash: no builder emits an adapter route any more, so
    every grant on every lane is `Route.PLAIN` (the enum has one member). Gather's data capability
    now lives in `ToolSet.query`, not in a bash grant — asserted by the query-tool spec
    (`tests/e2e/test_query_tool_611.py`), not here. This test's surviving claim is that main and
    gather both project a PLAIN-only bash lane and nothing infers a route."""
    no_bash = _compile(_defn(role=AgentRole.MAIN, tools=ToolSet(read=True)), tmp_path)
    assert no_bash.bash_allow == ()
    assert no_bash.read_allow == ()

    def _routes(policy) -> set[Route]:
        return {g.route for g in policy.bash_allow}

    main = _compile(MAIN_DEF, tmp_path)
    gather = _compile(GATHER_DEF, tmp_path)
    assert _routes(main) == {Route.PLAIN}
    assert _routes(gather) == {Route.PLAIN}
    assert list(Route) == [Route.PLAIN]
    assert gather.bash_allow
    assert all(isinstance(g, Grant) for g in gather.bash_allow)


def test_gate_bash_parity_read_convergent(tmp_path):
    """#551: `compile_policy_for` (the policy-only half of `bind`) and `bind(MAIN).policy` AGREE
    on every probe — BASH and READ alike, including the path-shape filter. `bind` is
    `compile_policy_for` + the deps mint, so the two are the SAME projection; this pins that they
    never diverge, verified through the REAL gate. (The read↔bash agreement WITHIN one policy is
    structural since #575 — one scope object serves both surfaces, pinned by d4/d5 in
    test_grant_gate_575.py; what is pinned HERE is that the two COMPILE seams agree.)"""
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
    """resolve_roots(run_A, …) then resolve_roots(run_B, …) yield run-anchored roots with NO
    cross-run bleed (guards the #497/#534-family @cache-on-run_dir hazard): observed through
    the main policy the roots compile to — run_A's own path is anchored in run_A's path SCOPE
    (where #575 moved the run's roots: out of the argv shapes, into the grants' scope) and is
    ABSENT from run_B's, and vice-versa."""
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
    """resolve_roots resolves corpus_dirs to absolutes under defender_dir; corpus_dirs=()
    yields only the run-derived roots (no corpus dirs added)."""
    roots = resolve_roots(tmp_path, ("lessons", "skills"), RunScope())
    assert all(c.is_absolute() for c in roots.corpus_roots)
    assert set(roots.corpus_roots) == {PATHS.defender_dir / "lessons", PATHS.defender_dir / "skills"}
    empty = resolve_roots(tmp_path, (), RunScope())
    assert empty.corpus_roots == ()


def test_corpus_dirs_excludes_gather_summaries(tmp_path):
    """AGENTS[MAIN].corpus_dirs == ('lessons','skills','examples') and does NOT contain
    'gather_summaries' (a run-root path, not a defender_dir corpus dir). POSITIVE CONTROL: a
    {run_dir}/gather_summaries/x.md read stays allowed via the run-root anchor."""
    assert AGENTS[AgentRole.MAIN].corpus_dirs == ("lessons", "skills", "examples")
    assert "gather_summaries" not in AGENTS[AgentRole.MAIN].corpus_dirs
    pol = bind(MAIN_DEF, tmp_path).policy
    d = permission.decide_read(
        tmp_path / "gather_summaries" / "x.md",
        run_dir=tmp_path, defender_dir=PATHS.defender_dir, policy=pol,
    )
    assert d.allow



def test_agents_registry_covers_every_role():
    """AGENTS covers EXACTLY the AgentRole members (one AgentDefinition each, keyed on its own
    role — no silent last-wins drop). The roster GROWS (6 at #538, LEAD_AUTHOR at #543,
    CORPUS_AUTHOR at #556), so the invariant is `set(AGENTS.keys()) == set(AgentRole)` — the count
    tracks the enum rather than a hardcoded number, and a new role that never registers a
    definition fails here."""
    assert set(AGENTS.keys()) == set(AgentRole)
    assert len(AGENTS) == len(AgentRole)
    assert AgentRole.LEAD_AUTHOR in AGENTS
    for role, d in AGENTS.items():
        assert isinstance(d, AgentDefinition)
        assert d.role is role


def test_agents_duplicate_role_raises():
    """GUARD: building the registry from a tuple with two AgentDefinitions sharing a role
    RAISES (vs the dict-comp's silent last-wins overwrite). POSITIVE CONTROL: the real, distinct
    defs build the registry successfully."""
    d1 = _defn(role=AgentRole.ORACLE)
    d2 = _defn(role=AgentRole.ORACLE)
    with pytest.raises(ValueError, match="role"):
        build_registry((d1, d2))
    reg = build_registry(tuple(AGENTS.values()))
    assert set(reg.keys()) == set(AgentRole)



def test_model_thunk_liveness(monkeypatch):
    """AgentDefinition.model is a zero-arg thunk called at build time: setting DEFENDER_MODEL
    AFTER the definition is constructed changes what MAIN_DEF.model() returns (late
    resolution), so a --model/env override is honored. An eager str would freeze at import."""
    monkeypatch.delenv("DEFENDER_MODEL", raising=False)
    before = MAIN_DEF.model()
    monkeypatch.setenv("DEFENDER_MODEL", "glm-sentinel-xyz")
    after = MAIN_DEF.model()
    assert after == "glm-sentinel-xyz"
    assert before != after


def test_model_via_env_channel(monkeypatch, logger):
    """The explicit --model CLI arg reaches the zero-arg thunk by being routed through
    DEFENDER_MODEL: with DEFENDER_MODEL set to a sentinel, build resolves the main model to
    the sentinel (captured at the make_model seam)."""
    monkeypatch.setenv("DEFENDER_MODEL", "sentinel-model")
    fake, calls = _capture_make_model()
    with override_allow_model_requests(False):
        driver.build_agent_core(
            MAIN_DEF, deps_type=AgentDeps, instructions="x", logger=logger,
            agent_id="main", make_model=fake,
        )
    assert calls[0][0] == "sentinel-model"


def test_effort_none_vs_None_distinct(monkeypatch, logger):
    """effort=None (omit the reasoning knob) and effort='none' (Fireworks reasoning DISABLED)
    are distinct: they produce DIFFERENT model_settings; 'none' is not coerced to None. Built
    through the REAL make_model (a fake key keeps it hermetic — the settings make no call)."""
    pytest.importorskip("pydantic_ai.models.openai")
    monkeypatch.setenv("FIREWORKS_API_KEY", "fw-test")
    with override_allow_model_requests(False):
        omit = driver.build_agent_core(
            _defn(role=AgentRole.ORACLE, model=lambda: "glm-5.2", effort=None, tools=ToolSet()),
            deps_type=OracleDeps, instructions="x", logger=logger, agent_id="o1",
        )
        disabled = driver.build_agent_core(
            _defn(role=AgentRole.ORACLE, model=lambda: "glm-5.2", effort="none", tools=ToolSet()),
            deps_type=OracleDeps, instructions="x", logger=logger, agent_id="o2",
        )
    assert omit.model_settings is None
    assert disabled.model_settings["extra_body"]["reasoning_effort"] == "none"
    assert omit.model_settings != disabled.model_settings


def test_effort_none_claude_crossing(monkeypatch, logger):
    """#527 crossing, NOT defused by tool-freeness: oracle's definition with effort='none' + a
    claude-* model thunk builds the model BEFORE tool registration, so build_for_effort raises
    (settings_for_effort rejects 'none' on Anthropic — a config fault -> exit 2). POSITIVE
    CONTROL: effort='none' + a fireworks/glm model builds fine."""
    pytest.importorskip("pydantic_ai.models.anthropic")
    pytest.importorskip("pydantic_ai.models.openai")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    monkeypatch.setenv("FIREWORKS_API_KEY", "fw-test")
    claude_defn = _defn(role=AgentRole.ORACLE, model=lambda: "claude-sonnet-4-6",
                        effort="none", tools=ToolSet())
    with pytest.raises((ValueError, FatalConfigError)), override_allow_model_requests(False):
        driver.build_agent_core(
            claude_defn, deps_type=OracleDeps, instructions="x", logger=logger,
            agent_id="oracle", make_model=providers.build_for_effort,
        )
    with override_allow_model_requests(False):
        ok = driver.build_agent_core(
            _defn(role=AgentRole.ORACLE, model=lambda: "glm-5.2", effort="none", tools=ToolSet()),
            deps_type=OracleDeps, instructions="x", logger=logger,
            agent_id="oracle", make_model=providers.build_for_effort,
        )
    assert ok.model_settings["extra_body"]["reasoning_effort"] == "none"
    assert list(ok._function_toolset.tools) == []


def test_effort_live_on_toolfree(logger, tmp_path):
    """Even with ToolSet() (nothing registered), the tool-free agent still carries the
    effort-derived model_settings AND issues exactly one model request — effort is consumed at
    build regardless of the empty toolset (F-BUILD-ORDER: the model is built before, and
    independent of, tool registration)."""
    settings = {"extra_body": {"reasoning_effort": "none"}}
    fake, reqs = _counting_make_model(text=_ORACLE_YAML, settings=settings)
    defn = _defn(role=AgentRole.ORACLE, model=lambda: "glm-5.2", effort="none", tools=ToolSet(),
                 deps_cls=OracleDeps)
    with override_allow_model_requests(False):
        agent = driver.build_agent_core(
            defn, deps_type=OracleDeps, instructions="x", logger=logger,
            agent_id="oracle", make_model=fake,
        )
        assert list(agent._function_toolset.tools) == []
        assert agent.model_settings == settings
        assert reqs == []
        result = agent.run_sync("project this lead", deps=bind(defn, tmp_path),
                                usage_limits=UsageLimits(request_limit=1))
    assert result.output == _ORACLE_YAML
    assert len(reqs) == 1



def test_request_limit_one():
    """ORACLE_REQUEST_LIMIT == 1 and VERIFY_REQUEST_LIMIT == 1 (down from 6): no tool is
    callable, so no headroom above 1 is needed."""
    assert ORACLE_REQUEST_LIMIT == 1
    assert VERIFY_REQUEST_LIMIT == 1


def test_request_limit_one_sufficient(logger, tmp_path):
    """Driving the tool-free oracle build with a single-turn replay COMPLETES under
    request_limit=1 — 1 request is SUFFICIENT (not merely non-crashing): the tool-free
    predictor makes exactly one model request and returns its output."""
    fake, reqs = _counting_make_model(text=_ORACLE_YAML)
    defn = _defn(role=AgentRole.ORACLE, model=lambda: "glm-5.2", effort="none", tools=ToolSet(),
                 deps_cls=OracleDeps)
    with override_allow_model_requests(False):
        agent = driver.build_agent_core(
            defn, deps_type=OracleDeps, instructions="x", logger=logger,
            agent_id="oracle", make_model=fake,
        )
        result = agent.run_sync("project this lead", deps=bind(defn, tmp_path),
                                usage_limits=UsageLimits(request_limit=1))
    assert result.output == _ORACLE_YAML
    assert len(reqs) == 1


def test_request_limit_reject_below_one(logger, tmp_path):
    """GUARD: a request_limit of 0 (the falsy member) STARVES the single prediction — the run
    cannot complete (UsageLimitExceeded). POSITIVE CONTROL: request_limit==1 runs the one
    prediction to completion (so 0 is rejected specifically for starving, not a build fault).
    spec-assumption: the <1 floor is realized as usage-limit starvation through the real run,
    not a silent coerce-to-1."""
    fake, _ = _counting_make_model(text=_ORACLE_YAML)
    defn = _defn(role=AgentRole.ORACLE, model=lambda: "glm-5.2", effort="none", tools=ToolSet(),
                 deps_cls=OracleDeps)
    with override_allow_model_requests(False):
        agent = driver.build_agent_core(
            defn, deps_type=OracleDeps, instructions="x", logger=logger,
            agent_id="oracle", make_model=fake,
        )
        deps = bind(defn, tmp_path)
        with pytest.raises(UsageLimitExceeded):
            agent.run_sync("project this lead", deps=deps,
                           usage_limits=UsageLimits(request_limit=0))
        result = agent.run_sync("project this lead", deps=deps,
                                usage_limits=UsageLimits(request_limit=1))
    assert result.output == _ORACLE_YAML



def test_agentspec_removed_migrated():
    """AgentSpec is removed: no residual construction site under defender/ (production + tests
    migrated); build_agent_core accepts an AgentDefinition and derives writers from tools.write,
    so its former callers still build their agents. Observed by walking the SOURCE tree — the
    installed venv is skipped: `defender/.venv/**/site-packages` is third-party code, and
    pydantic_ai ships its OWN unrelated `AgentSpec` (`pydantic_ai/agent/spec.py`), so scanning it
    would false-positive on CI (where `.venv` sits under `defender/`); it is not our source, the
    same reason `__pycache__` is skipped."""
    needle = "AgentSpec" "("
    this = Path(__file__).resolve()
    hits = []
    for py in PATHS.defender_dir.rglob("*.py"):
        if py.resolve() == this or "__pycache__" in py.parts or ".venv" in py.parts:
            continue
        if needle in py.read_text(encoding="utf-8", errors="ignore"):
            hits.append(str(py))
    assert hits == [], f"residual AgentSpec construction sites: {hits}"


def test_main_keeps_tools(logger):
    """Landing oracle/verify ToolSet() does not squeeze main: main's ToolSet(read=True,
    bash=True, write=True) still registers all four tools — the operator agent is unchanged."""
    with override_allow_model_requests(False):
        agent = driver.build_agent_core(
            MAIN_DEF, deps_type=AgentDeps, instructions="x", logger=logger,
            agent_id="main", make_model=_fake_model(_text_fn()),
        )
    assert list(agent._function_toolset.tools) == ["bash", "read_file", "write_file", "edit_file"]



def test_guard_corpus_traversal(tmp_path):
    """GUARD: resolve_roots raises if a corpus_dirs entry contains '..' or is an absolute path
    (path-traversal defense on the confinement primitive). POSITIVE CONTROL: a clean relative
    name like 'lessons' resolves to a real absolute under defender_dir (not silently
    dropped/normalized)."""
    with pytest.raises(ValueError, match="corpus"):
        resolve_roots(tmp_path, ("../evil",), RunScope())
    with pytest.raises(ValueError, match="corpus"):
        resolve_roots(tmp_path, ("/etc",), RunScope())
    roots = resolve_roots(tmp_path, ("lessons",), RunScope())
    assert roots.corpus_roots == (PATHS.defender_dir / "lessons",)
