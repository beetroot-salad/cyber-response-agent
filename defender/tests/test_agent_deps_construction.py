"""Executable spec for #498 — `AgentDeps` (renamed from `RunDeps`) requires its
`policy`, and the learning-loop stages build their deps through a `for_scope` factory.

The gate keys on `deps.policy` (capability as DATA), so this refactor removes the
inheritable `_MAIN_POLICY` default from the deps base: a security-critical subtype can
no longer be born in the MAIN-shaped (fail-open) state by omitting `policy`. This suite
pins the CONSTRUCTION contract:

  - requiredness / safe-by-construction — `AgentDeps` and its subtypes (`JudgeDeps`,
    `ActorDeps`, and — since #535 — `GatherDeps`) RAISE when constructed without `policy`
    (kw-only); the unsafe MAIN state is unconstructable, not silently inherited,
  - GatherDeps is per-run since #535 — its bash reader lane is anchored to the run's
    roots, so it no longer carries a static default (it inherits the base's required
    kw-only policy, built via `policy_for('gather', run_dir, defender_dir)` at its site),
  - the `for_scope(scope, run_dir)` factory — identity fields (defender_dir via the
    `PATHS` primitive, run_id == run_dir.name), the scope→policy input surface, and
    PARITY: the factory-built policy equals the shipped builder's output field-for-field,
  - guarded negatives — a factory-built policy is NOT `_MAIN_POLICY`-shaped, each paired
    with a positive control proving the unsafe shape is real and different.

Explicitly OUT OF SCOPE (pinned elsewhere): policy ENFORCEMENT (decide_read/decide_bash
allow/deny — test_read_confine*.py) and the pydantic run loop. Capabilities are unchanged;
this only moves WHERE policy is supplied.

Against HEAD this is RED where the refactor is new (the `AgentDeps` name, required policy,
`for_scope`) and GREEN where it preserves behavior (gather's static default) — the mixed
state of a behavior-preserving refactor spec.
"""
from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")

from defender._paths import PATHS  # noqa: E402
from defender.learning.core import config  # noqa: E402
from defender.learning.pipeline import actor_engine  # noqa: E402
from defender.learning.pipeline.actor_engine import ActorDeps, _ActorScope  # noqa: E402
from defender.learning.pipeline.judge import engine_pydantic  # noqa: E402
from defender.learning.pipeline.judge.engine_pydantic import JudgeDeps  # noqa: E402
from defender.learning.pipeline.judge.run import _ToolScope  # noqa: E402
from defender.runtime import permission, tools  # noqa: E402
from defender.runtime.agent_role import AgentRole  # noqa: E402
from defender.runtime.permission import AgentPolicy  # noqa: E402

# Representative per-run main/gather policies for the construction tests. Since #535
# there is no module-level tools._MAIN_POLICY/_GATHER_POLICY — a runtime-agent policy
# is built PER-RUN via `policy_for(run_dir, defender_dir)` (the reader lane is anchored
# to the run's roots). These synthetic absolute roots only anchor the bash lane, which
# these CONSTRUCTION tests don't exercise (enforcement is pinned in
# test_read_confine_bash.py); their capability SHAPE (read_confine/raw_reads) is what
# the guarded negatives below assert.
_MAIN_POLICY = permission.policy_for("main", run_dir=Path("/run"), defender_dir=Path("/dfn"))
_GATHER_POLICY = permission.policy_for("gather", run_dir=Path("/run"), defender_dir=Path("/dfn"))

# Real repo-relative script/confine paths — `_actor_policy`'s `_script_pattern` does
# `script.resolve().relative_to(REPO_ROOT)`, so synthetic paths outside the repo raise.
_ENV_RETRIEVE = config.LESSONS_ENV_RETRIEVE_SCRIPT
_ACTOR_INDEX = config.LESSONS_ACTOR_INDEX_SCRIPT
_ACTOR_DIR = config.LESSONS_ACTOR_DIR
_ENV_DIR = config.LESSONS_ENVIRONMENT_DIR


def _ident(run_dir: Path) -> dict:
    """The four identity kwargs every deps construction shares."""
    return dict(run_dir=run_dir, defender_dir=PATHS.defender_dir, run_id=run_dir.name, salt="s")


def _policy_fields(p: AgentPolicy) -> tuple:
    """Stable, cache-independent projection of an AgentPolicy for parity comparison.
    `bash_allow` / `write_allow` hold compiled `re.Pattern`s whose `==` is identity (True
    across builds only via CPython's re-cache) — compare their SOURCE strings instead.
    INCLUDES write_allow (#545 footgun B) so a write-scope divergence projects unequal; the
    additive read_shapes (the intended #545 delta) stays out of this parity projection."""
    return (
        tuple(pat.pattern for pat in p.bash_allow),
        p.jq_operand_gated, p.adapters, p.adapter_sql_pipe,
        p.raw_reads, tuple(p.read_roots), tuple(p.read_confine),
        tuple(pat.pattern for pat in p.write_allow), p.deny_reason,
    )


# ============================================================================
# A. Requiredness / safe-by-construction — the unsafe MAIN state is unconstructable
# ============================================================================

def test_agent_deps_requires_policy(tmp_path):
    """AgentDeps(run_dir, defender_dir, run_id, salt) with NO policy= -> TypeError
    (the base has no inheritable default to go silently MAIN-shaped)."""
    # rejected: constructs, silently inheriting _MAIN_POLICY (today's RunDeps behavior)
    with pytest.raises(TypeError):
        tools.AgentDeps(run_dir=tmp_path, defender_dir=PATHS.defender_dir, run_id="r", salt="s")


def test_agent_deps_accepts_explicit_policy(tmp_path):
    """POSITIVE CONTROL for the requiredness negatives: AgentDeps(..., policy=_MAIN_POLICY)
    constructs, .policy is _MAIN_POLICY, role is MAIN — so the TypeError above is specifically
    about the MISSING policy, not some unrelated construction failure."""
    deps = tools.AgentDeps(**_ident(tmp_path), policy=_MAIN_POLICY)
    assert deps.policy is _MAIN_POLICY
    assert deps.role is AgentRole.MAIN


def test_judge_deps_requires_policy(tmp_path):
    """JudgeDeps inherits the base requiredness: JudgeDeps(4 identity fields) with no policy=
    -> TypeError (a mis-built judge cannot silently get MAIN and lose its grounding roots)."""
    # rejected: inherits _MAIN_POLICY (raw_reads=False, read_roots=()) -> evidence-starved judge
    with pytest.raises(TypeError):
        JudgeDeps(run_dir=tmp_path, defender_dir=PATHS.defender_dir, run_id="r", salt="s")


def test_actor_deps_requires_policy(tmp_path):
    """ActorDeps inherits the base requiredness: ActorDeps(4 identity fields) with no policy=
    -> TypeError. This is the fail-OPEN case: MAIN's empty read_confine would re-expose the
    judge rubric under defender/ (#512) — so the MAIN-shaped actor must be unconstructable."""
    # rejected: inherits _MAIN_POLICY (read_confine=()) -> gray-box rubric leak
    with pytest.raises(TypeError):
        ActorDeps(run_dir=tmp_path, defender_dir=PATHS.defender_dir, run_id="r", salt="s")


def test_policy_is_keyword_only(tmp_path):
    """policy is keyword-only: passing it as the 5th POSITIONAL arg -> TypeError. Pins the
    `field(kw_only=True)` shape (matches the _ActorToolScope.read_confine precedent)."""
    # rejected: required-positional policy (would let AgentDeps(rd, dd, rid, salt, pol) succeed)
    with pytest.raises(TypeError):
        tools.AgentDeps(tmp_path, PATHS.defender_dir, "r", "s", _MAIN_POLICY)


# ============================================================================
# B. GatherDeps — per-run since #535: policy REQUIRED (no static default), like the judge
# ============================================================================

def test_gather_deps_requires_policy(tmp_path):
    """#535: GatherDeps(4 identity fields) with NO policy= now RAISES. The gather reader lane is
    anchored PER-RUN, so gather no longer carries a static default — it inherits the base's required
    kw-only policy (exactly like the per-scope judge/actor), and the unconfined state is
    unconstructable rather than silently inherited."""
    # rejected: keep a static _GATHER_POLICY default (a run-less, unanchored gather policy)
    with pytest.raises(TypeError):
        tools.GatherDeps(**_ident(tmp_path))


def test_gather_deps_prod_construction_with_explicit_policy(tmp_path):
    """Orphaned-consumer pin (tools_gather.py:315): the prod gather construction now passes an
    explicit per-run policy (`policy_for('gather', run_dir, defender_dir)`) — .policy is that
    policy, role is GATHER, lead_id is carried."""
    deps = tools.GatherDeps(**_ident(tmp_path), lead_id="l-001", policy=_GATHER_POLICY)
    assert deps.policy is _GATHER_POLICY
    assert deps.role is AgentRole.GATHER
    assert deps.lead_id == "l-001"


# ============================================================================
# C. Orphaned consumers — main-loop construction + the rename
# ============================================================================

def test_main_loop_constructs_with_explicit_main_policy(tmp_path):
    """Orphaned-consumer pin (driver.py:436, which builds deps with no policy today): the
    post-refactor main construction AgentDeps(4 identity fields, policy=_MAIN_POLICY)
    succeeds, role is MAIN, .policy is _MAIN_POLICY — main is not special-cased away."""
    deps = tools.AgentDeps(**_ident(tmp_path), policy=_MAIN_POLICY)
    assert deps.role is AgentRole.MAIN
    assert deps.policy is _MAIN_POLICY


def test_rename_agent_deps_is_base_of_subtypes():
    """The rename RunDeps->AgentDeps: `AgentDeps` is the exported base of the deps subtypes."""
    assert issubclass(tools.GatherDeps, tools.AgentDeps)
    assert issubclass(JudgeDeps, tools.AgentDeps)
    assert issubclass(ActorDeps, tools.AgentDeps)


# ============================================================================
# D. for_scope factory — identity fields + return shape
# ============================================================================

def test_judge_for_scope_returns_judge_deps_with_identity_fields(tmp_path):
    """JudgeDeps.for_scope(scope, run_dir) -> a JudgeDeps whose identity fields the factory
    wires: run_dir==arg, defender_dir==PATHS.defender_dir (the primitive, not a REPO_ROOT dup),
    run_id==run_dir.name, role==JUDGE, salt a non-empty 32-char hex string."""
    scope = _ToolScope(add_dir=[tmp_path / "cmp"], ticket_cli=None)
    deps = JudgeDeps.for_scope(scope, tmp_path)
    assert isinstance(deps, JudgeDeps)
    assert deps.run_dir == tmp_path
    assert deps.defender_dir == PATHS.defender_dir
    assert deps.run_id == tmp_path.name
    assert deps.role is AgentRole.JUDGE
    assert len(deps.salt) == 32
    assert all(c in "0123456789abcdef" for c in deps.salt)


def test_actor_for_scope_returns_actor_deps_with_identity_fields(tmp_path):
    """ActorDeps.for_scope(scope, run_dir) -> an ActorDeps with the same identity wiring
    (defender_dir==PATHS.defender_dir, run_id==run_dir.name, role==ACTOR)."""
    scope = _ActorScope((_ENV_RETRIEVE,), read_confine=(_ENV_DIR,))
    deps = ActorDeps.for_scope(scope, tmp_path)
    assert isinstance(deps, ActorDeps)
    assert deps.defender_dir == PATHS.defender_dir
    assert deps.run_id == tmp_path.name
    assert deps.role is AgentRole.ACTOR


def test_for_scope_run_id_is_basename_of_nested_run_dir():
    """run_id is derived as run_dir.name: a nested run_dir -> run_id is its basename only."""
    scope = _ToolScope(add_dir=None, ticket_cli=None)
    deps = JudgeDeps.for_scope(scope, Path("/tmp/learn-runs/2026-07-05/run-1"))
    assert deps.run_id == "run-1"


# ============================================================================
# E. for_scope input surface — scope -> read_roots / bash_allow
# ============================================================================

def test_judge_for_scope_add_dir_list_populates_read_roots(tmp_path):
    """add_dir = a populated list -> policy.read_roots == tuple(that list)."""
    d1, d2 = tmp_path / "cmp", tmp_path / "raw"
    deps = JudgeDeps.for_scope(_ToolScope(add_dir=[d1, d2], ticket_cli=None), tmp_path)
    assert deps.policy.read_roots == (d1, d2)


def test_judge_for_scope_add_dir_none_yields_empty_read_roots(tmp_path):
    """add_dir = None -> policy.read_roots == () (the direct-unit-call empty-roots case)."""
    deps = JudgeDeps.for_scope(_ToolScope(add_dir=None, ticket_cli=None), tmp_path)
    assert deps.policy.read_roots == ()


def test_judge_for_scope_add_dir_empty_list_yields_empty_read_roots(tmp_path):
    """add_dir = [] -> policy.read_roots == () (tuple([]) is the empty tuple)."""
    deps = JudgeDeps.for_scope(_ToolScope(add_dir=[], ticket_cli=None), tmp_path)
    assert deps.policy.read_roots == ()


def test_judge_for_scope_single_path_add_dir_yields_empty_read_roots(tmp_path):
    """add_dir = a SINGLE Path (not a list) -> policy.read_roots == () — the non-list `else ()`
    branch is PRESERVED (behavior-preserving refactor; prod always passes a list, run.py:184)."""
    # rejected: coerce a single Path to (path,) — would CHANGE current behavior (out of #498 scope)
    deps = JudgeDeps.for_scope(_ToolScope(add_dir=tmp_path / "solo", ticket_cli=None), tmp_path)
    assert deps.policy.read_roots == ()


def test_judge_for_scope_ticket_present_adds_ticket_matcher(tmp_path):
    """ticket_cli = (py, path) (the benign leg) -> bash_allow length 2 (jq + closed-ticket)."""
    scope = _ToolScope(add_dir=[tmp_path / "cmp"], ticket_cli=("python3", tmp_path / "ticket_cli.py"))
    deps = JudgeDeps.for_scope(scope, tmp_path)
    assert len(deps.policy.bash_allow) == 2


def test_judge_for_scope_ticket_absent_is_jq_only(tmp_path):
    """ticket_cli = None (the adversarial leg) -> bash_allow length 1 (jq only, no ticket
    matcher — the adversarial judge can never reach the ticket store)."""
    deps = JudgeDeps.for_scope(_ToolScope(add_dir=[tmp_path / "cmp"], ticket_cli=None), tmp_path)
    assert len(deps.policy.bash_allow) == 1


def test_actor_for_scope_bash_allow_is_one_pattern_per_script(tmp_path):
    """scripts -> exactly one bash_allow pattern per pinned script (0, 1, and 2 scripts)."""
    assert len(ActorDeps.for_scope(_ActorScope((), read_confine=(_ENV_DIR,)), tmp_path).policy.bash_allow) == 0
    assert len(ActorDeps.for_scope(_ActorScope((_ENV_RETRIEVE,), read_confine=(_ENV_DIR,)), tmp_path).policy.bash_allow) == 1
    two = ActorDeps.for_scope(_ActorScope((_ENV_RETRIEVE, _ACTOR_INDEX), read_confine=(_ACTOR_DIR, _ENV_DIR)), tmp_path)
    assert len(two.policy.bash_allow) == 2


def test_actor_for_scope_read_confine_preserved(tmp_path):
    """read_confine from the scope is carried onto the built policy verbatim."""
    deps = ActorDeps.for_scope(_ActorScope((_ENV_RETRIEVE,), read_confine=(_ACTOR_DIR, _ENV_DIR)), tmp_path)
    assert deps.policy.read_confine == (_ACTOR_DIR, _ENV_DIR)


# ============================================================================
# F. Parity — the factory-built policy == the shipped builder's, field-for-field
# ============================================================================

def test_judge_for_scope_policy_parity_with_builder(tmp_path):
    """PARITY (cross-surface): JudgeDeps.for_scope's policy is field-for-field identical to
    the established `_judge_policy` builder for the same roots + ticket — the factory drops
    or rewires nothing (raw_reads, read_roots, jq_operand_gated, adapters, bash_allow, deny)."""
    roots = [tmp_path / "cmp", tmp_path / "raw"]
    ticket = ("python3", tmp_path / "ticket_cli.py")
    got = JudgeDeps.for_scope(_ToolScope(add_dir=roots, ticket_cli=ticket), tmp_path).policy
    expected = engine_pydantic._judge_policy(read_roots=tuple(roots), ticket_cli=ticket)
    assert _policy_fields(got) == _policy_fields(expected)


def test_actor_for_scope_policy_parity_with_builder(tmp_path):
    """PARITY (cross-surface): ActorDeps.for_scope's policy is field-for-field identical to
    the established `_actor_policy` builder for the same scripts + confine."""
    scripts = (_ENV_RETRIEVE, _ACTOR_INDEX)
    confine = (_ACTOR_DIR, _ENV_DIR)
    got = ActorDeps.for_scope(_ActorScope(scripts, read_confine=confine), tmp_path).policy
    expected = actor_engine._actor_policy(scripts, read_confine=confine)
    assert _policy_fields(got) == _policy_fields(expected)


# ============================================================================
# G. Guarded negatives (not MAIN-shaped) + lifecycle
# ============================================================================

def test_actor_for_scope_policy_is_not_main_shaped(tmp_path):
    """GUARDED NEGATIVE: a factory-built actor policy is NOT the fail-open MAIN shape — its
    read_confine is non-empty (the gray-box wall is set). POSITIVE CONTROL: _MAIN_POLICY's
    read_confine IS () (the unsafe shape is real, and empty == full-defender_dir read)."""
    deps = ActorDeps.for_scope(_ActorScope((_ENV_RETRIEVE,), read_confine=(_ENV_DIR,)), tmp_path)
    assert deps.policy.read_confine != ()      # negative: the confined shape, not MAIN
    assert _MAIN_POLICY.read_confine == ()     # positive control: the unsafe shape differs


def test_judge_for_scope_policy_is_not_main_shaped(tmp_path):
    """GUARDED NEGATIVE: a factory-built judge policy is NOT MAIN-shaped — raw_reads is True
    (it may read gather_raw). POSITIVE CONTROL: _MAIN_POLICY.raw_reads is False."""
    deps = JudgeDeps.for_scope(_ToolScope(add_dir=[tmp_path / "cmp"], ticket_cli=None), tmp_path)
    assert deps.policy.raw_reads is True        # negative: judge shape, not MAIN
    assert _MAIN_POLICY.raw_reads is False       # positive control: the MAIN shape differs


def test_for_scope_salt_unique_but_policy_deterministic(tmp_path):
    """Two for_scope(same scope, same run_dir) calls -> DISTINCT salts (a per-invocation
    uniqueness axis) but field-EQUAL policies (the factory is otherwise deterministic)."""
    scope = _ToolScope(add_dir=[tmp_path / "cmp"], ticket_cli=None)
    a = JudgeDeps.for_scope(scope, tmp_path)
    b = JudgeDeps.for_scope(scope, tmp_path)
    assert a.salt != b.salt
    assert _policy_fields(a.policy) == _policy_fields(b.policy)
