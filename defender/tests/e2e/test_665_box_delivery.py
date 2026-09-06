"""#665 — box delivery + the two creation sites, as the binding suite (part 1 of 3).

This file pins DELIVERY (box= threaded to every bash-enabled learning role) and the two
COMPOSITION frames that create a box — `run_one` (the run-cycle box shared by the actor and
judge legs) and `_run_worktree_batch` (the drain box over its worktree leaf). Geography /
mount rendering, the gate-vs-mount reasoning, and the return contract live in
`test_665_box_geography.py`; the live mechanism confirmations in `test_665_box_live.py`.

RED AGAINST HEAD BY CONSTRUCTION. The target does not exist: `box=` is not yet a param on
the Subagents/invoke seams or `CuratorDeps.for_run`; `run_one` / `_run_worktree_batch` do not
yet create, deliver, or tear down a box (run_one ends in a bare `raise`, no try/finally). Every
test drives the REAL (future) entry point and asserts an observable — a recorded box delivery,
a raised error, a teardown order. Fakes enter through injection seams (a `box=` param, an
injected `start_box`/`stop_box`/`agents`/`branch`/docker), never a monkeypatch. See
`spec_graph_665-box-learning-roles.yaml` for the demand↔test map.
"""
from __future__ import annotations

from defender.tests.e2e._box665 import DEFENDER  # noqa: E402


import pytest


pytest.importorskip("pydantic_ai")

from defender import agents as agents_registry  # noqa: E402
from defender.runtime import box as box_mod
from defender.runtime.agent_definition import RunScope, bind  # noqa: E402
from defender.runtime.agent_role import AgentRole  # noqa: E402

pytestmark = pytest.mark.e2e

SALT = "s665"




def _curator_for_run(tmp_path, *, box):
    """Build a curator's deps through the REAL production wrapper CuratorDeps.for_run with
    the future required `box=`. TypeError at HEAD. Sets up a real worktree defender tree so
    the wrapped bind() actually resolves (the future green path)."""
    from defender.learning.author.curator_engine import (
        SHIPPED_LESSON_CORPORA,
        CuratorDeps,
        ForwardCheckConfig,
    )
    from defender.learning.author.verify_forward.checks import ForwardCheck

    repo = tmp_path / "repo"
    dtree = repo / "defender"
    for name in SHIPPED_LESSON_CORPORA:
        (dtree / name).mkdir(parents=True, exist_ok=True)
    run_dir = tmp_path / "lrd"
    run_dir.mkdir(exist_ok=True)  # both curator helpers may run against one tmp_path
    check = ForwardCheck(error_prefix="spec", prompt_path=None, run=lambda ctx: "")
    return CuratorDeps.for_run(
        run_dir,
        repo,
        dtree / "lessons",
        cfg=ForwardCheckConfig(check=check, runs_dir=tmp_path / "runs", pending=tmp_path / "pending.jsonl", queued_ids=frozenset()),
        box=box,
    )


# Delivery / census (O1/O6/M10) — the box reaches every bash-enabled role
def test_census_observes_box_attachment_on_production_path(tmp_path):
    """census_observes_attachment — every bash-enabled learning role runs in a box, and
    that is observed as ATTACHMENT on the PRODUCTION construction seam, not `isinstance`
    over a test-local `bind` (the retired census could only see the field exists). The
    registry's bash roles are how the subject is PICKED; the assertion drives one through
    its real construction wrapper (CuratorDeps.for_run) with the delivered box and reads it
    back off the built deps."""
    bash_roles = [d for d in agents_registry.AGENTS.values() if d.tools.bash]
    assert bash_roles, "the registry reports no bash-enabled role — the census cannot be empty"
    assert AgentRole.CORPUS_AUTHOR in {d.role for d in bash_roles}

    delivered = box_mod.BoxExecutor(name="run-cycle-box")
    deps = _curator_for_run(tmp_path, box=delivered)
    assert deps.box is delivered, "the delivered box did not attach on the production seam"


def test_box_delivery_absence_does_not_silently_re_dead_the_lane(tmp_path):
    """test_box_delivery_absence_does_not_silently_re_dead_the_lane (F1 → R1) — box= is a
    REQUIRED parameter on the production construction wrapper: omitting it is a LOUD
    TypeError at construction, never a silent inert `BoxExecutor()` fallback (which would
    re-create the exact dead-lane defect this issue fixes). Positive control on the same
    seam: supplying the box attaches it."""
    with pytest.raises(TypeError):
        _curator_for_run_no_box(tmp_path)

    delivered = box_mod.BoxExecutor(name="box")
    assert _curator_for_run(tmp_path, box=delivered).box is delivered


def _curator_for_run_no_box(tmp_path):
    from defender.learning.author.curator_engine import (
        SHIPPED_LESSON_CORPORA,
        CuratorDeps,
        ForwardCheckConfig,
    )
    from defender.learning.author.verify_forward.checks import ForwardCheck

    repo = tmp_path / "repo"
    dtree = repo / "defender"
    for name in SHIPPED_LESSON_CORPORA:
        (dtree / name).mkdir(parents=True, exist_ok=True)
    run_dir = tmp_path / "lrd"
    run_dir.mkdir(exist_ok=True)  # both curator helpers may run against one tmp_path
    check = ForwardCheck(error_prefix="spec", prompt_path=None, run=lambda ctx: "")
    return CuratorDeps.for_run(
        run_dir,
        repo,
        dtree / "lessons",
        cfg=ForwardCheckConfig(check=check, runs_dir=tmp_path / "runs", pending=tmp_path / "pending.jsonl", queued_ids=frozenset()),
    )


def test_fifth_bash_enabled_role_outside_the_four_named_construction_paths(tmp_path):
    """test_fifth_bash_enabled_role_outside_the_four_named_construction_paths (F11 → R1) —
    a future fifth bash-enabled role reached through none of the four named delivery paths
    is a RECORDED residual (N7-style), not a mechanism built now. The census is keyed on the
    production construction seams; a role built through a raw `bind` off those seams keeps
    N5's still-constructible inert default (bash enabled + box absent is not made
    unbuildable). This pins the accepted residual: raw bind stays constructible with an
    inert box."""
    # N5: a raw bind off the four named seams remains constructible with the inert default.
    deps = bind(agents_registry.AGENTS[AgentRole.ACTOR], tmp_path / "run",
                defender_dir=DEFENDER, scope=RunScope(read_confine=(tmp_path / "run",),
                                                      scripts=()))
    assert isinstance(deps.box, box_mod.BoxExecutor)
    # …and that off-path instance's lane is DEAD (inert transport raises) — the recorded
    # capability loss O2 names, which the role-keyed census over the production seams cannot see.
    with pytest.raises(box_mod.BoxFault):
        deps.box.run_parsed([], command="true", cwd=tmp_path / "run", timeout=1.0)










def test_curator_for_run_threads_box_to_bind(tmp_path):
    """curator_for_run_box_passthrough — the curator's `CuratorDeps.for_run` wrapper (M9)
    threads the per-call box through to its inner `bind`, so the built CuratorDeps carries
    it. TypeError at HEAD (for_run has no box=)."""
    delivered = box_mod.BoxExecutor(name="drain-box")
    deps = _curator_for_run(tmp_path, box=delivered)
    assert deps.box is delivered






def test_role_keyed_census_blind_to_caller_constructed_boxless_instance(tmp_path):
    """test_role_keyed_census_blind_to_caller_constructed_boxless_instance (N7) — the eval
    harness constructs a bash role directly, off all production creation sites, with no box;
    once the production seams require box, that off-path instance keeps N5's inert default
    and its bash lane stays dead. Nothing observes it — an accepted, RECORDED non-obligation
    (O2's capability loss the O6 role-keyed census structurally cannot see), not a defect
    this design fixes."""
    off_path = bind(agents_registry.AGENTS[AgentRole.ACTOR], tmp_path / "run",
                    defender_dir=DEFENDER,
                    scope=RunScope(read_confine=(tmp_path / "run",), scripts=()))
    assert off_path.box.transport is box_mod._unattached, \
        "an off-path bind should keep N5's inert (unattached) default, not a live box"
    with pytest.raises(box_mod.BoxFault):
        off_path.box.run_parsed([], command="true", cwd=tmp_path / "run", timeout=1.0)






































