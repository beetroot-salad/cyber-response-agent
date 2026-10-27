"""AgentDeps and subtypes cannot be constructed without an explicit policy and cwd anchor.

A missing required field raises pydantic's `ValidationError`, never stdlib's `TypeError` (#1067)."""
from __future__ import annotations

import functools
from pathlib import Path

import pytest
from pydantic import ValidationError

pytest.importorskip("pydantic_ai")

from defender._paths import PATHS  # noqa: E402
from defender.investigation import tools  # noqa: E402
from defender.investigation.agent_definition import compile_policy_for  # noqa: E402
from defender._agent_role import AgentRole  # noqa: E402
from defender.investigation.driver import MAIN_DEF  # noqa: E402
from defender.tests.support.tenancy import _tenants1106 as T1106

_MAIN_POLICY = compile_policy_for(MAIN_DEF, run_dir=Path("/run"), defender_dir=Path("/dfn"))


@functools.cache
def _gather_policy():
    """Gather's policy, compiled with a run's grant (`GATHER_DEF` carries none), lazily so the module
    collects before the tenant folder exists."""
    return compile_policy_for(
        T1106.fixture_gather_def(), run_dir=Path("/run"), defender_dir=Path("/dfn"))


def _ident(run_dir: Path) -> dict:
    """The identity and cwd kwargs every valid deps construction shares."""
    return dict(run_dir=run_dir, defender_dir=PATHS.defender_dir, run_id=run_dir.name,
                cwd_anchor=run_dir)


def test_agent_deps_requires_policy(tmp_path):
    """`AgentDeps` without `policy=` raises: the base has no default to fall back to MAIN-shaped."""
    with pytest.raises(ValidationError):
        tools.AgentDeps(run_dir=tmp_path, defender_dir=PATHS.defender_dir, run_id="r",
                        cwd_anchor=tmp_path)


def test_agent_deps_accepts_explicit_policy(tmp_path):
    """Positive control for the requiredness negatives: with `policy=` given, construction succeeds."""
    deps = tools.AgentDeps(**_ident(tmp_path), policy=_MAIN_POLICY)
    assert deps.policy is _MAIN_POLICY
    assert deps.role is AgentRole.MAIN
    assert deps.cwd_anchor == tmp_path


def test_agent_deps_requires_cwd_anchor(tmp_path):
    """AgentDeps cannot silently resolve relative paths against the ambient process cwd."""
    with pytest.raises(ValidationError):
        tools.AgentDeps(
            run_dir=tmp_path, defender_dir=PATHS.defender_dir, run_id="r",
            policy=_MAIN_POLICY,
        )


def test_gather_deps_requires_policy(tmp_path):
    """`GatherDeps` without `policy=` raises too: its reader lane is anchored per run, so there is no
    static default."""
    with pytest.raises(ValidationError):
        tools.GatherDeps(**_ident(tmp_path))


def test_gather_deps_prod_construction_with_explicit_policy(tmp_path):
    """Gather's production construction with an explicit per-run policy carries that policy, the
    GATHER role and the lead id."""
    gather_policy = _gather_policy()
    deps = tools.GatherDeps(**_ident(tmp_path), lead_id="l-001", policy=gather_policy)
    assert deps.policy is gather_policy
    assert deps.role is AgentRole.GATHER
    assert deps.lead_id == "l-001"


