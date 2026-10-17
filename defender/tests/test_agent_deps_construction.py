"""AgentDeps and subtypes cannot be constructed without an explicit policy and cwd anchor."""
from __future__ import annotations

import functools
from pathlib import Path

import pytest
from pydantic import ValidationError

pytest.importorskip("pydantic_ai")

from defender._paths import PATHS  # noqa: E402
from defender.runtime import tools  # noqa: E402
from defender.runtime.agent_definition import compile_policy_for  # noqa: E402
from defender.runtime.agent_role import AgentRole  # noqa: E402
from defender.runtime.driver import MAIN_DEF  # noqa: E402
from defender.tests import _tenants1106 as T1106  # noqa: E402

_MAIN_POLICY = compile_policy_for(MAIN_DEF, run_dir=Path("/run"), defender_dir=Path("/dfn"))


@functools.cache
def _gather_policy():
    """Gather's policy, compiled with a RUN's grant (#1106 M4: `GATHER_DEF` carries none) — lazily, so the module..."""
    return compile_policy_for(
        T1106.fixture_gather_def(), run_dir=Path("/run"), defender_dir=Path("/dfn"))


def _ident(run_dir: Path) -> dict:
    """The identity and cwd kwargs every valid deps construction shares."""
    return dict(run_dir=run_dir, defender_dir=PATHS.defender_dir, run_id=run_dir.name,
                cwd_anchor=run_dir)


def test_agent_deps_requires_policy(tmp_path):
    """AgentDeps(run_dir, defender_dir, run_id, salt) with NO policy= -> ValidationError (the base has no..."""
    with pytest.raises(ValidationError):  # 1067: a required/kw-only miss is pydantic's ValidationError, never stdlib's TypeError
        tools.AgentDeps(run_dir=tmp_path, defender_dir=PATHS.defender_dir, run_id="r",
                        cwd_anchor=tmp_path)


def test_agent_deps_accepts_explicit_policy(tmp_path):
    """POSITIVE CONTROL for the requiredness negatives: AgentDeps(..., policy=_MAIN_POLICY) constructs, .policy..."""
    deps = tools.AgentDeps(**_ident(tmp_path), policy=_MAIN_POLICY)
    assert deps.policy is _MAIN_POLICY
    assert deps.role is AgentRole.MAIN
    assert deps.cwd_anchor == tmp_path


def test_agent_deps_requires_cwd_anchor(tmp_path):
    """AgentDeps cannot silently resolve relative paths against the ambient process cwd."""
    with pytest.raises(ValidationError):  # 1067: a required/kw-only miss is pydantic's ValidationError, never stdlib's TypeError
        tools.AgentDeps(
            run_dir=tmp_path, defender_dir=PATHS.defender_dir, run_id="r",
            policy=_MAIN_POLICY,
        )


def test_gather_deps_requires_policy(tmp_path):
    """#535: GatherDeps(4 identity fields) with NO policy= now RAISES. The gather reader lane is anchored..."""
    with pytest.raises(ValidationError):  # 1067: a required/kw-only miss is pydantic's ValidationError, never stdlib's TypeError
        tools.GatherDeps(**_ident(tmp_path))


def test_gather_deps_prod_construction_with_explicit_policy(tmp_path):
    """Orphaned-consumer pin (tools_gather.py:315): the prod gather construction now passes an explicit per-run..."""
    gather_policy = _gather_policy()
    deps = tools.GatherDeps(**_ident(tmp_path), lead_id="l-001", policy=gather_policy)
    assert deps.policy is gather_policy
    assert deps.role is AgentRole.GATHER
    assert deps.lead_id == "l-001"


