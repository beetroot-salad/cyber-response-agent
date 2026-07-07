"""Executable spec (written BEFORE the code) for design #538 — the AgentDefinition
consolidation + tool-free predictors.

#538 collapses the two capability carriers (the build-time spec + the runtime
`AgentPolicy`) plus the scattered model/effort constants into one per-agent
`AgentDefinition` that BOTH the build site and the permission gate read, and it makes
the pure-prediction stages (oracle + verify-forward) genuinely tool-free (register
NOTHING). These tests pin the observable behavior at the REAL entry points:

  - `build_agent_core(defn, …)`  — registers exactly the ToolSet's present tools
  - `bind(defn, run_dir, scope)` — the deps + policy resolution seam (replaces the six
                                   `_xxx_policy` factories + `for_scope`/`for_run`)
  - `compile_policy(tools, read_shapes, roots, deny_reason)` — the AgentPolicy projection
  - `resolve_roots(run_dir, corpus_dirs, scope)` — run-anchored read roots
  - `AGENTS` — the role-keyed registry

The targets do NOT exist yet: importing `defender.runtime.agent_definition` /
`defender.runtime.agents` is the EXPECTED red at collection. Every OTHER import
resolves against real source, so the sole collection error is the two missing #538
modules.

Hermetic: no network, no key — a `FunctionModel` is injected through the `make_model`
DI seam under `override_allow_model_requests(False)`; faults enter through that seam and
`monkeypatch.setenv`, never `monkeypatch.setattr`.

Deferred (spec waivers, NOT exercised here — #535 end-state):
  - r3_parity_535: the read_file/bash "one roots set, two surfaces" parity is the #535
    end state; at step one main/gather intentionally diverge (bash lane tight-to-corpus,
    decide_read broad because read_roots==()). Preserved implicitly by the per-agent
    compile_policy characterization + gate_decisions_unchanged.
  - read_shapes_semantics: the ReadShape filename-grammar FILTERING is #535-dependent;
    only the read_shapes FIELD's existence/type is pinned (read_shapes_field).

spec-assumption (seams the design leaves ambiguous — write-code-from-spec reconciles):
  - `RunScope` is the unified per-invocation carriage (superset of the judge's
    `_ToolScope` and the actor's `_ActorScope`): fields `add_dirs` (judge comparison
    roots → read_roots), `read_confine` (actor gray-box confine), `scripts` (actor
    pinned lesson scripts → one bash_allow pattern each), `ticket_cli` (benign judge).
    All default empty. `resolve_roots` folds it against the run.
  - `resolve_roots(run_dir, corpus_dirs, scope)` returns a rich `roots` value carrying
    the run anchor + defender_dir + resolved corpus absolutes (`.corpus_roots`) + the
    scope-derived extras, which `compile_policy` projects into an `AgentPolicy`.
  - `build_registry(defs)` is the guarded collector that fans the six definitions into
    `AGENTS`, raising on a duplicate role (vs the dict-comp's silent last-wins).
  - `build_agent_core` keeps its current keyword args (deps_type / instructions /
    logger / agent_id / make_model) but takes an `AgentDefinition` positionally in place
    of the old spec, deriving the writers bit from `tools.write` and the model/effort
    from `defn.model()` / `defn.effort`.
"""
from __future__ import annotations

import dataclasses
import inspect
import re
from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")  # CI installs the runtime extra; skip otherwise

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
    _VERIFY_POLICY,
)
from defender.learning.pipeline.actor_engine import ActorDeps, _actor_policy  # noqa: E402
from defender.learning.pipeline.judge.engine_pydantic import (  # noqa: E402
    JudgeDeps,
    _judge_policy,
)
from defender.learning.pipeline.oracle_engine import (  # noqa: E402
    ORACLE_REQUEST_LIMIT,
    OracleDeps,
    _ORACLE_POLICY,
)
from defender.runtime import driver, observe, permission, providers  # noqa: E402
from defender.runtime.agent_role import AgentRole  # noqa: E402
from defender.runtime.permission.policies._common import reader_patterns  # noqa: E402
from defender.runtime.providers import BuiltModel  # noqa: E402
from defender.runtime.tools import AgentDeps, GatherDeps  # noqa: E402

# ── THE NOT-YET-WRITTEN #538 TARGETS — this is the expected collection-time red ──────
# spec-assumption: `build_registry` (the guarded collector) lives in the definition
# primitive layer alongside AgentDefinition; the mandated symbols are otherwise verbatim
# from the spec's assumed layout.
from defender.runtime.agent_definition import (  # noqa: E402
    AgentDefinition,
    BashGrammar,
    RunScope,
    ToolSet,
    bind,
    build_registry,
    compile_policy,
    resolve_roots,
)
from defender.runtime.agents import (  # noqa: E402
    ACTOR_DEF,
    AGENTS,
    GATHER_DEF,
    JUDGE_DEF,
    MAIN_DEF,
    ORACLE_DEF,
    VERIFY_DEF,
)

# Real repo-relative script/confine paths — `_actor_policy`'s `_script_pattern` does
# `script.resolve().relative_to(REPO_ROOT)`, so synthetic paths outside the repo raise.
_ENV_RETRIEVE = config.LESSONS_ENV_RETRIEVE_SCRIPT
_ACTOR_INDEX = config.LESSONS_ACTOR_INDEX_SCRIPT
_ACTOR_DIR = config.LESSONS_ACTOR_DIR
_ENV_DIR = config.LESSONS_ENVIRONMENT_DIR

# A minimal, well-formed per-lead oracle reply — the shape the run tests replay.
_ORACLE_YAML = 'events:\n  - Computer: "FINANCE-DB"\n    EventID: 4624\n'


# ============================================================================
# Test machinery (mirrors test_harness_b_construction / test_oracle_pydantic_engine)
# ============================================================================

def _text_fn(text: str = "ok"):
    return lambda messages, info: ModelResponse(parts=[TextPart(content=text)])


def _fake_model(fn):
    # settings=None — a FunctionModel needs no provider settings (mirrors _replay_harness).
    return lambda model, effort: BuiltModel(FunctionModel(fn), None)


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


# ToolSet() is frozen/immutable, so one shared module-level singleton is a safe default
# (the endorsed `repo_root: Path = REPO_ROOT` shape — no in-body re-defaulting the lint
# gate flags, and no call-in-argument-default the B008 gate flags).
_EMPTY_TOOLSET = ToolSet()


def _defn(*, role=AgentRole.MAIN, model=_glm_thunk, effort=None, tools=_EMPTY_TOOLSET, corpus_dirs=()):
    """Build an AgentDefinition for a shape test (model defaults to a glm thunk)."""
    return AgentDefinition(
        role=role, model=model, effort=effort, tools=tools, corpus_dirs=corpus_dirs,
    )


def _patterns(policy) -> list[str]:
    """re.Pattern compares by identity — project the SOURCE strings for comparison."""
    return [p.pattern for p in policy.bash_allow]


def _policy_fields(p) -> tuple:
    """Stable, cache-independent projection of an AgentPolicy for field-for-field parity
    (bash_allow's compiled Patterns → their source strings)."""
    return (
        tuple(pat.pattern for pat in p.bash_allow),
        p.jq_operand_gated, p.adapters, p.adapter_sql_pipe,
        p.raw_reads, tuple(p.read_roots), tuple(p.read_confine), p.deny_reason,
    )


# RunScope() is frozen, so one shared module-level singleton is a safe default anchored
# in the signature (satisfies both the unanchored-default and the B008 gates).
_DEFAULT_SCOPE = RunScope()


def _compile(defn, run_dir, scope=_DEFAULT_SCOPE):
    """Drive the real resolve_roots → compile_policy composition (the design snippet:
    `compile_policy(defn.tools, defn.read_shapes, roots, defn.deny_reason)`)."""
    roots = resolve_roots(run_dir, defn.corpus_dirs, scope)
    return compile_policy(defn.tools, defn.read_shapes, roots, defn.deny_reason)


# ============================================================================
# Type / seam shapes — AgentDefinition, ToolSet, BashGrammar
# ============================================================================

def test_agentdefinition_shape():
    """AgentDefinition is a frozen dataclass carrying role/model(thunk)/effort/tools/
    corpus_dirs/read_shapes/deny_reason; the tail fields default (ToolSet() / () / str)."""
    defn = AgentDefinition(role=AgentRole.MAIN, model=lambda: "glm-5.2", effort="low")
    assert dataclasses.is_dataclass(defn)
    assert defn.role is AgentRole.MAIN
    assert callable(defn.model)               # model is a zero-arg thunk
    assert defn.model() == "glm-5.2"
    assert defn.effort == "low"
    assert isinstance(defn.tools, ToolSet)     # defaults to ToolSet()
    assert defn.corpus_dirs == ()
    assert defn.read_shapes == ()
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
    """ToolSet is a frozen dataclass: read=False, bash=None, write=False (read-only/no-tool
    safe default)."""
    ts = ToolSet()
    assert dataclasses.is_dataclass(ts)
    assert ts.read is False
    assert ts.bash is None
    assert ts.write is False
    with pytest.raises(dataclasses.FrozenInstanceError):
        ts.read = True  # type: ignore[misc]


def test_bashgrammar_shape():
    """BashGrammar is a frozen dataclass: shims/viewers default to (); adapters/
    adapter_sql_pipe/jq_operand_gated default to False."""
    bg = BashGrammar()
    assert dataclasses.is_dataclass(bg)
    assert bg.shims == ()
    assert bg.viewers == ()
    assert bg.adapters is False
    assert bg.adapter_sql_pipe is False
    assert bg.jq_operand_gated is False
    with pytest.raises(dataclasses.FrozenInstanceError):
        bg.adapters = True  # type: ignore[misc]


def test_read_shapes_field():
    """AgentDefinition carries a read_shapes tuple field (default ()); the FIELD exists and
    is a tuple. Its filtering SEMANTICS are #535-deferred (read_shapes_semantics waiver)."""
    defn = AgentDefinition(role=AgentRole.ORACLE, model=lambda: "m", effort=None)
    assert defn.read_shapes == ()
    assert isinstance(defn.read_shapes, tuple)


# ============================================================================
# #0 return contract — bind dispatches on defn.role to the AgentDeps subtype
# ============================================================================

def test_bind_returns_role_subtype(tmp_path):
    """bind(defn, run_dir, scope=RunScope()) returns the AgentDeps subtype for defn.role
    (main->AgentDeps, gather->GatherDeps, judge->JudgeDeps, actor->ActorDeps,
    oracle->OracleDeps, verify->VerifierDeps), each with defender_dir==PATHS.defender_dir,
    run_id==run_dir.name, a fresh 32-hex salt, and policy==compile_policy(...)."""
    main = bind(MAIN_DEF, tmp_path)
    assert type(main) is AgentDeps            # bare base for MAIN (not a subtype)
    assert main.role is AgentRole.MAIN
    assert isinstance(bind(GATHER_DEF, tmp_path), GatherDeps)
    assert bind(GATHER_DEF, tmp_path).role is AgentRole.GATHER
    judge = bind(JUDGE_DEF, tmp_path, scope=RunScope(add_dirs=(tmp_path / "cmp",)))
    assert isinstance(judge, JudgeDeps)
    assert judge.role is AgentRole.JUDGE
    actor = bind(ACTOR_DEF, tmp_path, scope=RunScope(scripts=(_ENV_RETRIEVE,), read_confine=(_ENV_DIR,)))
    assert isinstance(actor, ActorDeps)
    assert actor.role is AgentRole.ACTOR
    assert isinstance(bind(ORACLE_DEF, tmp_path), OracleDeps)
    assert isinstance(bind(VERIFY_DEF, tmp_path), VerifierDeps)
    # shared identity + policy contract (checked on MAIN)
    assert main.defender_dir == PATHS.defender_dir
    assert main.run_id == tmp_path.name
    assert len(main.salt) == 32               # a fresh uuid4 hex
    assert all(c in "0123456789abcdef" for c in main.salt)
    assert _policy_fields(main.policy) == _policy_fields(_compile(MAIN_DEF, tmp_path))


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
    assert deps.policy.read_confine == confine     # non-empty confine carried verbatim
    assert deps.policy.read_confine != ()          # the gray-box wall is set


def test_bind_gather_lead_id_channel(tmp_path):
    """bind stays per-run and has NO lead param: gather's per-dispatch lead_id/query_id enter
    via a thin wrapper over bind, not via bind's signature (the rejected lead_id param would
    conflate per-run and per-dispatch scopes)."""
    params = set(inspect.signature(bind).parameters)
    assert "lead_id" not in params
    assert "query_id" not in params
    # spec-assumption: bind's parameters are exactly {defn, run_dir, scope}.
    assert params == {"defn", "run_dir", "scope"}
    # bind itself leaves the per-dispatch lead_id unset; the wrapper stamps it post-bind.
    deps = bind(GATHER_DEF, tmp_path)
    assert isinstance(deps, GatherDeps)
    assert getattr(deps, "lead_id", None) is None


# ============================================================================
# build_agent_core — exact tool registration derived from the ToolSet
# ============================================================================

def test_build_registers_exact_toolset(logger):
    """build_agent_core(defn) registers EXACTLY the present tools in defn.tools and nothing
    else (the always-on register_tools bash+read_file branch is deleted). A read+bash+write
    agent registers ['bash','read_file','write_file','edit_file'] in that order."""
    defn = _defn(tools=ToolSet(read=True, bash=BashGrammar(), write=True))
    with override_allow_model_requests(False):
        agent = driver.build_agent_core(
            defn, deps_type=AgentDeps, instructions="x", logger=logger,
            agent_id="main", make_model=_fake_model(_text_fn()),
        )
    assert list(agent._function_toolset.tools) == ["bash", "read_file", "write_file", "edit_file"]


def test_registration_order_bash_before_read(logger):
    """Registered order is bash BEFORE read_file (the current pinned order), NOT ToolSet's
    dataclass field order (read, bash, write): a read+bash agent pins ['bash','read_file']."""
    defn = _defn(tools=ToolSet(read=True, bash=BashGrammar()))
    with override_allow_model_requests(False):
        agent = driver.build_agent_core(
            defn, deps_type=AgentDeps, instructions="x", logger=logger,
            agent_id="a", make_model=_fake_model(_text_fn()),
        )
    assert list(agent._function_toolset.tools) == ["bash", "read_file"]


def test_toolset_exact_combos(logger):
    """Each (read,bash,write) combination maps to exactly its tools:
    ToolSet(read=True, bash=None, write=False) -> ['read_file'];
    ToolSet(read=False, bash=BashGrammar(), write=True) -> ['bash','write_file','edit_file']."""
    with override_allow_model_requests(False):
        read_only = driver.build_agent_core(
            _defn(tools=ToolSet(read=True, bash=None, write=False)),
            deps_type=AgentDeps, instructions="x", logger=logger,
            agent_id="a", make_model=_fake_model(_text_fn()),
        )
        bash_writer = driver.build_agent_core(
            _defn(tools=ToolSet(read=False, bash=BashGrammar(), write=True)),
            deps_type=AgentDeps, instructions="x", logger=logger,
            agent_id="b", make_model=_fake_model(_text_fn()),
        )
    assert list(read_only._function_toolset.tools) == ["read_file"]
    assert list(bash_writer._function_toolset.tools) == ["bash", "write_file", "edit_file"]


def test_toolset_bash_none_vs_empty(logger):
    """bash=None registers NO bash tool ('bash' absent); bash=BashGrammar() (empty grammar)
    DOES register it — absence vs present-but-empty are observably distinct."""
    with override_allow_model_requests(False):
        none_agent = driver.build_agent_core(
            _defn(tools=ToolSet(read=True, bash=None)),
            deps_type=AgentDeps, instructions="x", logger=logger,
            agent_id="a", make_model=_fake_model(_text_fn()),
        )
        empty_agent = driver.build_agent_core(
            _defn(tools=ToolSet(read=True, bash=BashGrammar())),
            deps_type=AgentDeps, instructions="x", logger=logger,
            agent_id="b", make_model=_fake_model(_text_fn()),
        )
    assert "bash" not in list(none_agent._function_toolset.tools)   # None → unregistered
    assert "bash" in list(empty_agent._function_toolset.tools)      # BashGrammar() → registered


# ============================================================================
# Tool-free predictors (negatives, each with a positive control)
# ============================================================================

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
            _defn(tools=ToolSet(read=True, bash=BashGrammar(), write=True)),
            deps_type=AgentDeps, instructions="x", logger=logger,
            agent_id="main", make_model=_fake_model(_text_fn()),
        )
    assert list(oracle._function_toolset.tools) == []
    assert "read_file" in list(main._function_toolset.tools)   # positive control


def test_verify_empty_toolset(logger):
    """build_agent_core(VERIFY_DEF) with tools=ToolSet() registers NOTHING: tools == [].
    POSITIVE CONTROL: a judge-shaped agent (read=True) registers read_file."""
    with override_allow_model_requests(False):
        verify = driver.build_agent_core(
            VERIFY_DEF, deps_type=VerifierDeps, instructions="x", logger=logger,
            agent_id="verify", make_model=_fake_model(_text_fn()),
        )
        judge = driver.build_agent_core(
            _defn(role=AgentRole.JUDGE, tools=ToolSet(read=True, bash=BashGrammar(jq_operand_gated=True))),
            deps_type=JudgeDeps, instructions="x", logger=logger,
            agent_id="judge", make_model=_fake_model(_text_fn()),
        )
    assert list(verify._function_toolset.tools) == []
    assert "read_file" in list(judge._function_toolset.tools)   # positive control


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
    assert "read_file" in list(reader._function_toolset.tools)   # positive control


# ============================================================================
# compile_policy — step-one characterization (decide_bash/decide_read UNCHANGED)
# ============================================================================

def test_compile_policy_oracle_verify_denyall(tmp_path):
    """compile_policy(ToolSet(), (), roots, deny_reason) for oracle/verify projects a deny-all
    AgentPolicy: bash_allow==(), all capability bools False, read_roots==(), read_confine==(),
    deny_reason set — field-for-field equal to today's _ORACLE_POLICY / _VERIFY_POLICY."""
    for defn, authored in ((ORACLE_DEF, _ORACLE_POLICY), (VERIFY_DEF, _VERIFY_POLICY)):
        pol = _compile(defn, tmp_path)
        assert pol.bash_allow == ()
        assert pol.jq_operand_gated is False
        assert pol.adapters is False
        assert pol.adapter_sql_pipe is False
        assert pol.raw_reads is False
        assert pol.read_roots == ()
        assert pol.read_confine == ()
        assert pol.deny_reason                                   # a real deny message
        assert _policy_fields(pol) == _policy_fields(authored)   # equal to today's deny-all


def test_compile_policy_main(tmp_path):
    """STEP-ONE CHARACTERIZATION ANCHOR: compile_policy(main.tools, …, roots) reproduces
    today's main policy — [p.pattern for p in bash_allow] == the reader_patterns(run,dfn)
    strings; adapters/adapter_sql_pipe/raw_reads/jq_operand_gated all False; read_roots==()
    (step one — the bash lane confines via the anchored allowlist, decide_read stays broad)."""
    pol = _compile(MAIN_DEF, tmp_path)
    expected = reader_patterns(tmp_path, PATHS.defender_dir)
    assert _patterns(pol) == [p.pattern for p in expected]
    assert pol.adapters is False
    assert pol.adapter_sql_pipe is False
    assert pol.raw_reads is False
    assert pol.jq_operand_gated is False
    assert pol.read_roots == ()   # step-one
    # full field-for-field parity against the authored per-run main policy
    authored = permission.policy_for("main", run_dir=tmp_path, defender_dir=PATHS.defender_dir)
    assert _policy_fields(pol) == _policy_fields(authored)


def test_compile_policy_gather(tmp_path):
    """compile_policy(gather.tools=ToolSet(read=True, bash=BashGrammar(adapters=True,
    adapter_sql_pipe=True))) reproduces today's gather policy: bash_allow patterns ==
    reader_patterns(run,dfn); adapters==True, adapter_sql_pipe==True, raw_reads==True,
    read_roots==() (step one)."""
    pol = _compile(GATHER_DEF, tmp_path)
    expected = reader_patterns(tmp_path, PATHS.defender_dir)
    assert _patterns(pol) == [p.pattern for p in expected]
    assert pol.adapters is True
    assert pol.adapter_sql_pipe is True
    assert pol.raw_reads is True
    assert pol.read_roots == ()   # step-one
    authored = permission.policy_for("gather", run_dir=tmp_path, defender_dir=PATHS.defender_dir)
    assert _policy_fields(pol) == _policy_fields(authored)


def test_compile_policy_judge(tmp_path):
    """compile_policy(judge.tools=ToolSet(read=True, bash=BashGrammar(jq_operand_gated=True)),
    roots carrying scope.add_dirs) reproduces _judge_policy: jq_operand_gated==True,
    raw_reads==True, read_confine==(), read_roots==the scope add-dirs, adapters==False,
    adapter_sql_pipe==False, and '^jq(?: .*)?$' is among the bash_allow patterns."""
    cmp1, cmp2 = tmp_path / "cmp", tmp_path / "raw"
    pol = _compile(JUDGE_DEF, tmp_path, RunScope(add_dirs=(cmp1, cmp2)))
    assert pol.jq_operand_gated is True
    assert pol.raw_reads is True
    assert pol.read_confine == ()
    assert pol.read_roots == (cmp1, cmp2)
    assert pol.adapters is False
    assert pol.adapter_sql_pipe is False
    assert "^jq(?: .*)?$" in _patterns(pol)
    # parity with the established builder for the same roots (no ticket = adversarial leg)
    authored = _judge_policy(read_roots=(cmp1, cmp2), ticket_cli=None)
    assert _policy_fields(pol) == _policy_fields(authored)


def test_compile_policy_actor(tmp_path):
    """compile_policy(actor.tools=ToolSet(read=True, bash=BashGrammar()), scope=<scripts,
    confine>) reproduces _actor_policy: bash_allow == one anchored 'python3 <script> …'
    pattern per pinned script, raw_reads==False, read_confine==the per-leg lesson dirs,
    adapters==False, read_roots==()."""
    scripts = (_ENV_RETRIEVE, _ACTOR_INDEX)
    confine = (_ACTOR_DIR, _ENV_DIR)
    pol = _compile(ACTOR_DEF, tmp_path, RunScope(scripts=scripts, read_confine=confine))
    assert pol.raw_reads is False
    assert pol.read_confine == confine
    assert len(pol.bash_allow) == len(scripts)      # one anchored pattern per pinned script
    assert pol.adapters is False
    assert pol.read_roots == ()
    for pat in _patterns(pol):
        assert "python3" in pat                     # each is a python3 <script> matcher
    authored = _actor_policy(scripts, read_confine=confine)
    assert _policy_fields(pol) == _policy_fields(authored)


def test_compile_policy_projects_only_toolset_bits(tmp_path):
    """SAFE-BY-CONSTRUCTION: compile_policy emits no capability the ToolSet did not declare.
    ToolSet(read=True, bash=None) -> bash_allow==() and adapters==False; a bit is set only
    when its ToolSet/BashGrammar source bit is set (positive control: BashGrammar(adapters=
    True) DOES set adapters, proving the projection fires, not that it always denies)."""
    no_bash = _compile(_defn(role=AgentRole.MAIN, tools=ToolSet(read=True, bash=None)), tmp_path)
    assert no_bash.bash_allow == ()          # no grammar → no bash allowlist
    assert no_bash.adapters is False
    assert no_bash.adapter_sql_pipe is False
    assert no_bash.jq_operand_gated is False
    # positive control: the source bit set -> the projected bit set
    with_adapters = _compile(
        _defn(role=AgentRole.GATHER, tools=ToolSet(read=True, bash=BashGrammar(adapters=True))),
        tmp_path,
    )
    assert with_adapters.adapters is True


def test_gate_decisions_unchanged(tmp_path):
    """SURVIVAL ANCHOR: for representative probes, decide_bash/decide_read fed the
    bind(defn,run).policy return the SAME Decision they return fed today's authored policy —
    'the gate does not change in step one', verified through the REAL gate."""
    dfn = PATHS.defender_dir
    bound = bind(MAIN_DEF, tmp_path).policy
    authored = permission.policy_for("main", run_dir=tmp_path, defender_dir=dfn)
    for cmd in (
        f"cat {tmp_path}/investigation.md",       # anchored viewer under run_dir
        "defender-elastic query x --raw",         # a data-source adapter (main may not)
        "rm -rf /tmp/x",                           # arbitrary shell
    ):
        assert (
            permission.decide_bash(cmd, policy=bound, run_dir=tmp_path, defender_dir=dfn).allow
            == permission.decide_bash(cmd, policy=authored, run_dir=tmp_path, defender_dir=dfn).allow
        )
    for p in (tmp_path / "alert.json", dfn / "SKILL.md", tmp_path.parent / "outside.txt"):
        assert (
            permission.decide_read(p, run_dir=tmp_path, defender_dir=dfn, policy=bound).allow
            == permission.decide_read(p, run_dir=tmp_path, defender_dir=dfn, policy=authored).allow
        )


# ============================================================================
# resolve_roots — per-run, corpus resolution, no cross-run bleed
# ============================================================================

def test_resolve_roots_per_run_no_bleed(tmp_path):
    """resolve_roots(run_A, …) then resolve_roots(run_B, …) yield run-anchored roots with NO
    cross-run bleed (guards the #497/#534-family @cache-on-run_dir hazard): observed through
    the main policy the roots compile to — run_A's own path is baked into run_A's anchored
    bash_allow and is ABSENT from run_B's, and vice-versa."""
    run_a, run_b = tmp_path / "runA", tmp_path / "runB"
    run_a.mkdir()
    run_b.mkdir()
    pa = compile_policy(MAIN_DEF.tools, MAIN_DEF.read_shapes,
                        resolve_roots(run_a, MAIN_DEF.corpus_dirs, RunScope()), MAIN_DEF.deny_reason)
    pb = compile_policy(MAIN_DEF.tools, MAIN_DEF.read_shapes,
                        resolve_roots(run_b, MAIN_DEF.corpus_dirs, RunScope()), MAIN_DEF.deny_reason)
    na, nb = re.escape(str(run_a)), re.escape(str(run_b))
    pats_a, pats_b = _patterns(pa), _patterns(pb)
    assert any(na in p for p in pats_a)          # run_A anchored to itself
    assert not any(na in p for p in pats_b)      # …and does NOT bleed into run_B's policy
    assert any(nb in p for p in pats_b)          # run_B correctly anchored to itself


def test_resolve_roots_corpus_resolution(tmp_path):
    """resolve_roots resolves corpus_dirs to absolutes under defender_dir; corpus_dirs=()
    yields only the run-derived roots (no corpus dirs added)."""
    # spec-assumption: the resolved roots expose the corpus absolutes as `.corpus_roots`.
    roots = resolve_roots(tmp_path, ("lessons", "skills"), RunScope())
    assert all(c.is_absolute() for c in roots.corpus_roots)
    assert set(roots.corpus_roots) == {PATHS.defender_dir / "lessons", PATHS.defender_dir / "skills"}
    empty = resolve_roots(tmp_path, (), RunScope())
    assert empty.corpus_roots == ()              # no corpus names -> no corpus dirs


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
    assert d.allow                               # readable via the run-root anchor, not corpus


# ============================================================================
# AGENTS registry (R2) + duplicate-role guard
# ============================================================================

def test_agents_registry_covers_every_role():
    """AGENTS covers EXACTLY the AgentRole members (one AgentDefinition each, keyed on its own
    role — no silent last-wins drop). The spec forked at 6 roles; the #543 merge added a 7th,
    AgentRole.LEAD_AUTHOR (the loop's first writer), which is folded into the registry — so the
    invariant is `set(AGENTS.keys()) == set(AgentRole)`, and the count tracks the enum rather than
    a hardcoded 6."""
    assert set(AGENTS.keys()) == set(AgentRole)
    assert len(AGENTS) == len(AgentRole)
    assert AgentRole.LEAD_AUTHOR in AGENTS      # the #543 writer, brought into the AgentDefinition framework
    for role, d in AGENTS.items():
        assert isinstance(d, AgentDefinition)
        assert d.role is role


def test_agents_duplicate_role_raises():
    """GUARD: building the registry from a tuple with two AgentDefinitions sharing a role
    RAISES (vs the dict-comp's silent last-wins overwrite). POSITIVE CONTROL: the 6 distinct
    defs build the registry successfully."""
    d1 = _defn(role=AgentRole.ORACLE)
    d2 = _defn(role=AgentRole.ORACLE)            # same role — the collision
    # spec-assumption: the duplicate-role error names the offending "role".
    with pytest.raises(ValueError, match="role"):
        build_registry((d1, d2))
    # positive control: the six distinct defs collect cleanly
    reg = build_registry(tuple(AGENTS.values()))
    assert set(reg.keys()) == set(AgentRole)


# ============================================================================
# model thunk + effort (R4)
# ============================================================================

def test_model_thunk_liveness(monkeypatch):
    """AgentDefinition.model is a zero-arg thunk called at build time: setting DEFENDER_MODEL
    AFTER the definition is constructed changes what MAIN_DEF.model() returns (late
    resolution), so a --model/env override is honored. An eager str would freeze at import."""
    monkeypatch.delenv("DEFENDER_MODEL", raising=False)
    before = MAIN_DEF.model()
    monkeypatch.setenv("DEFENDER_MODEL", "glm-sentinel-xyz")
    after = MAIN_DEF.model()
    assert after == "glm-sentinel-xyz"           # re-read live from the env
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
    assert calls[0][0] == "sentinel-model"       # the thunk fed the --model override to build


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
    assert omit.model_settings is None                                          # None -> omit
    assert disabled.model_settings["extra_body"]["reasoning_effort"] == "none"  # 'none' -> set
    assert omit.model_settings != disabled.model_settings


def test_effort_none_claude_crossing(monkeypatch, logger):
    """#527 crossing, NOT defused by tool-freeness: oracle's definition with effort='none' + a
    claude-* model thunk builds the model BEFORE tool registration, so build_for_effort raises
    (settings_for_effort rejects 'none' on Anthropic — a config fault -> exit 2). POSITIVE
    CONTROL: effort='none' + a fireworks/glm model builds fine."""
    pytest.importorskip("pydantic_ai.models.anthropic")
    pytest.importorskip("pydantic_ai.models.openai")
    # Fake keys keep both hermetic — the ValueError comes from settings_for_effort, not a call.
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    monkeypatch.setenv("FIREWORKS_API_KEY", "fw-test")
    claude_defn = _defn(role=AgentRole.ORACLE, model=lambda: "claude-sonnet-4-6",
                        effort="none", tools=ToolSet())
    with pytest.raises((ValueError, FatalConfigError)), override_allow_model_requests(False):
        driver.build_agent_core(
            claude_defn, deps_type=OracleDeps, instructions="x", logger=logger,
            agent_id="oracle", make_model=providers.build_for_effort,
        )
    # positive control: effort='none' + glm builds fine (Fireworks reasoning DISABLED)
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
    settings = {"extra_body": {"reasoning_effort": "none"}}   # stands for the effort-derived settings
    fake, reqs = _counting_make_model(text=_ORACLE_YAML, settings=settings)
    defn = _defn(role=AgentRole.ORACLE, model=lambda: "glm-5.2", effort="none", tools=ToolSet())
    with override_allow_model_requests(False):
        agent = driver.build_agent_core(
            defn, deps_type=OracleDeps, instructions="x", logger=logger,
            agent_id="oracle", make_model=fake,
        )
        assert list(agent._function_toolset.tools) == []   # empty toolset
        assert agent.model_settings == settings            # effort-derived settings survive
        assert reqs == []                                  # not yet run
        result = agent.run_sync("project this lead", deps=bind(defn, tmp_path),
                                usage_limits=UsageLimits(request_limit=1))
    assert result.output == _ORACLE_YAML                   # completes
    assert len(reqs) == 1                                  # exactly one model request


# ============================================================================
# Request limits (R4) + floor guard
# ============================================================================

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
    defn = _defn(role=AgentRole.ORACLE, model=lambda: "glm-5.2", effort="none", tools=ToolSet())
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
    defn = _defn(role=AgentRole.ORACLE, model=lambda: "glm-5.2", effort="none", tools=ToolSet())
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
    assert result.output == _ORACLE_YAML   # positive control


# ============================================================================
# R5 subtraction / survival
# ============================================================================

def test_agentspec_removed_migrated():
    """AgentSpec is removed: no residual construction site under defender/ (production + tests
    migrated); build_agent_core accepts an AgentDefinition and derives writers from tools.write,
    so its former callers still build their agents. Observed by walking the SOURCE tree — the
    installed venv is skipped: `defender/.venv/**/site-packages` is third-party code, and
    pydantic_ai ships its OWN unrelated `AgentSpec` (`pydantic_ai/agent/spec.py`), so scanning it
    would false-positive on CI (where `.venv` sits under `defender/`); it is not our source, the
    same reason `__pycache__` is skipped."""
    needle = "AgentSpec" "("   # split so this test file itself never matches
    this = Path(__file__).resolve()
    hits = []
    for py in PATHS.defender_dir.rglob("*.py"):
        if py.resolve() == this or "__pycache__" in py.parts or ".venv" in py.parts:
            continue
        if needle in py.read_text(encoding="utf-8", errors="ignore"):
            hits.append(str(py))
    assert hits == [], f"residual AgentSpec construction sites: {hits}"


def test_factories_replaced_by_bind(tmp_path):
    """The six per-agent policy factories + for_scope/for_run/policy_for are replaced by bind:
    bind(AGENTS[role], run_dir) produces deps whose policy equals today's factory output
    (main/gather via policy_for), and every deps-construction site obtains an equivalent
    AgentDeps subtype via bind."""
    for role_name, defn in (("main", MAIN_DEF), ("gather", GATHER_DEF)):
        bound = bind(defn, tmp_path).policy
        authored = permission.policy_for(role_name, run_dir=tmp_path, defender_dir=PATHS.defender_dir)
        assert _policy_fields(bound) == _policy_fields(authored)
    # a current deps-construction site (gather dispatch) obtains its subtype via bind
    assert isinstance(bind(GATHER_DEF, tmp_path), GatherDeps)


def test_main_keeps_tools(logger):
    """Landing oracle/verify ToolSet() does not squeeze main: main's ToolSet(read=True,
    bash=BashGrammar(shims,viewers), write=True) still registers all four tools — the
    operator agent is unchanged."""
    with override_allow_model_requests(False):
        agent = driver.build_agent_core(
            MAIN_DEF, deps_type=AgentDeps, instructions="x", logger=logger,
            agent_id="main", make_model=_fake_model(_text_fn()),
        )
    assert list(agent._function_toolset.tools) == ["bash", "read_file", "write_file", "edit_file"]


# ============================================================================
# Guard — corpus traversal on the confinement primitive
# ============================================================================

def test_guard_corpus_traversal(tmp_path):
    """GUARD: resolve_roots raises if a corpus_dirs entry contains '..' or is an absolute path
    (path-traversal defense on the confinement primitive). POSITIVE CONTROL: a clean relative
    name like 'lessons' resolves to a real absolute under defender_dir (not silently
    dropped/normalized)."""
    # spec-assumption: the traversal error names the offending "corpus" entry.
    with pytest.raises(ValueError, match="corpus"):
        resolve_roots(tmp_path, ("../evil",), RunScope())        # a '..' traversal
    with pytest.raises(ValueError, match="corpus"):
        resolve_roots(tmp_path, ("/etc",), RunScope())           # an absolute path
    # positive control: a clean relative name resolves under defender_dir
    roots = resolve_roots(tmp_path, ("lessons",), RunScope())
    assert roots.corpus_roots == (PATHS.defender_dir / "lessons",)
