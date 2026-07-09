"""Executable spec for #498 — `AgentDeps` (renamed from `RunDeps`) REQUIRES its `policy`.

The gate keys on `deps.policy` (capability as DATA), so this refactor removes the
inheritable `_MAIN_POLICY` default from the deps base: a security-critical subtype can
no longer be born in the MAIN-shaped (fail-open) state by omitting `policy`. This suite
pins the CONSTRUCTION contract:

  - requiredness / safe-by-construction — `AgentDeps` and its subtypes (`JudgeDeps`,
    `ActorDeps`, and — since #535 — `GatherDeps`) RAISE when constructed without `policy`
    (kw-only); the unsafe MAIN state is unconstructable, not silently inherited,
  - GatherDeps is per-run since #535 — its bash reader lane is anchored to the run's
    roots, so it no longer carries a static default (it inherits the base's required
    kw-only policy, built via `bind(GATHER_DEF, run_dir, defender_dir=…)` at its site).

The per-stage `for_scope`/`for_run` DEPS FACTORIES this suite once pinned were RETIRED by
#551 — every production deps site now obtains its `AgentDeps` via the single `bind` seam, so
the factory identity/parity/guarded-negative sections moved to `test_bind_sole_seam_551.py`
(the `d1_*_via_bind` + `d4_*` demands). What remains here is the durable base contract:
`policy` is required, never silently MAIN-inherited.

Explicitly OUT OF SCOPE (pinned elsewhere): policy ENFORCEMENT (decide_read/decide_bash
allow/deny — test_read_confine*.py) and the pydantic run loop. Capabilities are unchanged;
this only moves WHERE policy is supplied.
"""
from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")

from defender._paths import PATHS  # noqa: E402
from defender.learning.pipeline.actor_engine import ActorDeps  # noqa: E402
from defender.learning.pipeline.judge.engine_pydantic import JudgeDeps  # noqa: E402
from defender.runtime import tools  # noqa: E402
from defender.runtime.agent_definition import compile_policy_for  # noqa: E402
from defender.runtime.agent_role import AgentRole  # noqa: E402
from defender.runtime.driver import GATHER_DEF, MAIN_DEF  # noqa: E402

# Representative per-run main/gather policies for the construction tests. Since #535
# there is no module-level tools._MAIN_POLICY/_GATHER_POLICY — a runtime-agent policy
# is compiled PER-RUN via `compile_policy_for(<DEF>, run_dir, defender_dir=…)` (the reader lane is
# anchored to the run's roots — the policy-only half of `bind`). These synthetic absolute
# roots only anchor the bash lane, which these CONSTRUCTION tests don't exercise (enforcement
# is pinned in test_read_confine_bash.py); their capability SHAPE (read_confine/raw_reads) is
# what the guarded negatives below assert.
_MAIN_POLICY = compile_policy_for(MAIN_DEF, run_dir=Path("/run"), defender_dir=Path("/dfn"))
_GATHER_POLICY = compile_policy_for(GATHER_DEF, run_dir=Path("/run"), defender_dir=Path("/dfn"))


def _ident(run_dir: Path) -> dict:
    """The four identity kwargs every deps construction shares."""
    return dict(run_dir=run_dir, defender_dir=PATHS.defender_dir, run_id=run_dir.name, salt="s")


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
    explicit per-run policy (`compile_policy_for(GATHER_DEF, run_dir, defender_dir=…)`) — .policy is that
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
