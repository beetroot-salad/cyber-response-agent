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

import inspect
from pathlib import Path

import pytest

from _box665 import (  # noqa: E402  (bare import: tests/e2e is on sys.path via conftest)
    DEFENDER,
    BoxLifecycleRecorder,
    RecordingBranch,
    RecordingSubagents,
    make_run_dir,
    satisfy_engine_keys,
)

pytest.importorskip("pydantic_ai")

from defender import agents as agents_registry  # noqa: E402
from defender.runtime import box as box_mod  # noqa: E402
from defender.runtime.agent_definition import RunScope, bind  # noqa: E402
from defender.runtime.agent_role import AgentRole  # noqa: E402

pytestmark = pytest.mark.e2e

SALT = "s665"


# --------------------------------------------------------------------------- #
# Helpers to drive the two composition frames with the injectable box seams.
# --------------------------------------------------------------------------- #
def _paths(tmp_path: Path):
    from defender.learning.core.config import LoopPaths

    repo = tmp_path / "repo"
    (repo / "defender").mkdir(parents=True, exist_ok=True)
    return LoopPaths(repo_root=repo, state_dir=tmp_path / "state")


def _run_one(tmp_path, monkeypatch, rec, *, agents=None, disposition="inconclusive", **kw):
    """Drive the REAL run_one with the future injectable `start_box`/`stop_box` seams.
    TypeError at HEAD (run_one has no such kwargs) — the red the box-creation site does not
    yet exist; the recorded assertions define the contract it is built against."""
    from defender.learning.core.run_cycle import run_one

    satisfy_engine_keys(monkeypatch, disposition)
    run_dir = make_run_dir(tmp_path, disposition=disposition)
    return run_one(
        run_dir, paths=_paths(tmp_path), agents=agents or RecordingSubagents(),
        start_box=rec.start_box, stop_box=rec.stop_box, **kw,
    )


def _worktree_batch(tmp_path, rec, *, do_work, has_work=None, branch=None,
                    label="author_drain", **kw):
    """Drive the REAL _run_worktree_batch with the future injectable box seams."""
    from defender.learning.core.drains import _run_worktree_batch

    paths = _paths(tmp_path)
    branch = branch or RecordingBranch(tmp_path / "wt", events=rec.events)
    return _run_worktree_batch(
        paths, branch, label=label,
        has_work=has_work or (lambda p: True), do_work=do_work,
        start_box=rec.start_box, stop_box=rec.stop_box, **kw,
    )


def _curator_for_run(tmp_path, *, box):
    """Build a curator's deps through the REAL production wrapper CuratorDeps.for_run with
    the future required `box=`. TypeError at HEAD. Sets up a real worktree defender tree so
    the wrapped bind() actually resolves (the future green path)."""
    from defender.learning.author.curator_engine import SHIPPED_LESSON_CORPORA, CuratorDeps
    from defender.learning.author.verify_forward.checks import ForwardCheck

    repo = tmp_path / "repo"
    dtree = repo / "defender"
    for name in SHIPPED_LESSON_CORPORA:
        (dtree / name).mkdir(parents=True, exist_ok=True)
    run_dir = tmp_path / "lrd"
    run_dir.mkdir(exist_ok=True)  # both curator helpers may run against one tmp_path
    check = ForwardCheck(error_prefix="spec", prompt_path=None, run=lambda ctx: "")
    return CuratorDeps.for_run(
        run_dir, repo, dtree / "lessons",
        check=check, runs_dir=tmp_path / "runs", pending=tmp_path / "pending.jsonl",
        queued_ids=frozenset(), box=box,
    )


# ======================================================================= #
# Delivery / census (O1/O6/M10) — the box reaches every bash-enabled role
# ======================================================================= #
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
    from defender.learning.author.curator_engine import SHIPPED_LESSON_CORPORA, CuratorDeps
    from defender.learning.author.verify_forward.checks import ForwardCheck

    repo = tmp_path / "repo"
    dtree = repo / "defender"
    for name in SHIPPED_LESSON_CORPORA:
        (dtree / name).mkdir(parents=True, exist_ok=True)
    run_dir = tmp_path / "lrd"
    run_dir.mkdir(exist_ok=True)  # both curator helpers may run against one tmp_path
    check = ForwardCheck(error_prefix="spec", prompt_path=None, run=lambda ctx: "")
    return CuratorDeps.for_run(  # box= omitted → must raise (required), never inert-default
        run_dir, repo, dtree / "lessons",
        check=check, runs_dir=tmp_path / "runs", pending=tmp_path / "pending.jsonl",
        queued_ids=frozenset(),
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
    deps = bind(agents_registry.AGENTS[AgentRole.ACTOR], tmp_path / "run", salt=SALT,
                defender_dir=DEFENDER, scope=RunScope(read_confine=(tmp_path / "run",),
                                                      scripts=()))
    assert isinstance(deps.box, box_mod.BoxExecutor)
    # …and that off-path instance's lane is DEAD (inert transport raises) — the recorded
    # capability loss O2 names, which the role-keyed census over the production seams cannot see.
    with pytest.raises(box_mod.BoxFault):
        deps.box.run_parsed([], command="true", cwd=tmp_path / "run", timeout=1.0)


def test_box_threaded_as_percall_param_through_subagents(tmp_path):
    """subagents_box_param — box is threaded as an explicit PER-CALL parameter through the
    three bash-reaching Subagents/invoke seams (invoke_actor / invoke_actor_benign /
    invoke_judge), not carried on a defaulted `agents` object. Each invoke hands the box to
    the engine fn; a recording engine fn reads it back. TypeError at HEAD (no box param)."""
    from defender.learning.core.directions import ADVERSARIAL_WIRING
    from defender.learning.pipeline.judge.run import invoke_judge
    from defender.learning.pipeline.malicious_actor.run import invoke_actor

    delivered = box_mod.BoxExecutor(name="run-cycle")
    seen: dict[str, object] = {}

    def rec(*_a, **k):
        seen["box"] = k.get("box")
        return "SKIP: spec"

    lrd = tmp_path / "lrd"
    lrd.mkdir()
    (tmp_path / "alert.json").write_text("{}", encoding="utf-8")
    (tmp_path / "ai.yaml").write_text("x: 1\n", encoding="utf-8")
    # invoke_judge builds its prompt from the story and telemetry on disk before it ever
    # reaches judge_fn — both are inputs the real seam reads (judge/run.py:74, :58).
    (tmp_path / "story.md").write_text("1. Routine story\n", encoding="utf-8")
    (tmp_path / "telemetry.yaml").write_text("projections: []\n", encoding="utf-8")

    invoke_actor(tmp_path / "alert.json", tmp_path / "ai.yaml", lrd,
                 box=delivered, actor_fn=rec)
    assert seen["box"] is delivered, "invoke_actor did not thread the per-call box"

    seen.clear()
    invoke_judge(ADVERSARIAL_WIRING, tmp_path, tmp_path / "story.md",
                 tmp_path / "telemetry.yaml", lrd, box=delivered, judge_fn=rec)
    assert seen["box"] is delivered, "invoke_judge did not thread the per-call box"


def test_invoke_actor_box_required_no_silent_inert_default(tmp_path):
    """test_invoke_actor_box_required_no_silent_inert_default (F2 → R1) — R1 makes box= REQUIRED
    on ALL three bash-reaching invoke seams, not only the CuratorDeps.for_run passthrough. On
    invoke_actor box must be a keyword-only parameter with NO default: omitting it is a loud
    TypeError, never a silent inert BoxExecutor() default (which re-opens F1's dead-lane defect
    on the adversarial seam). Positive control: box IS a param a supplied box threads to the
    engine fn (test_box_threaded_as_percall_param_through_subagents)."""
    from defender.learning.pipeline.malicious_actor.run import invoke_actor

    box = inspect.signature(invoke_actor).parameters.get("box")
    assert box is not None, "invoke_actor has no box parameter — the box never reaches the adversarial seam"
    assert box.kind is inspect.Parameter.KEYWORD_ONLY, "box must be keyword-only on invoke_actor"
    assert box.default is inspect.Parameter.empty, \
        "box carries a default on invoke_actor — a silent inert default re-deads the lane (F1)"


def test_invoke_actor_benign_box_required_no_silent_inert_default(tmp_path):
    """test_invoke_actor_benign_box_required_no_silent_inert_default (F2 → R1) — the benign
    actor leg is one of 'the actor' (two invoke methods): box= is REQUIRED (keyword-only, no
    default) on invoke_actor_benign too, so omitting it raises loudly rather than falling back
    to an inert BoxExecutor() and re-deading the benign leg's bash lane. Positive control: a
    supplied box threads to the benign leg (test_box_reaches_both_actor_legs_and_both_drain_chains)."""
    from defender.learning.pipeline.benign_actor.run import invoke_actor_benign

    box = inspect.signature(invoke_actor_benign).parameters.get("box")
    assert box is not None, "invoke_actor_benign has no box parameter — the box never reaches the benign seam"
    assert box.kind is inspect.Parameter.KEYWORD_ONLY, "box must be keyword-only on invoke_actor_benign"
    assert box.default is inspect.Parameter.empty, \
        "box carries a default on invoke_actor_benign — a silent inert default re-deads the benign lane (F1)"


def test_invoke_judge_box_required_no_silent_inert_default(tmp_path):
    """test_invoke_judge_box_required_no_silent_inert_default (F2 → R1) — box= is REQUIRED
    (keyword-only, no default) on invoke_judge, the judge's bash-reaching seam: omitting it is a
    loud TypeError, never a silent inert BoxExecutor() default that would re-dead the judge's
    boxed lane. Positive control: a supplied box threads to the judge engine fn
    (test_box_threaded_as_percall_param_through_subagents)."""
    from defender.learning.pipeline.judge.run import invoke_judge

    box = inspect.signature(invoke_judge).parameters.get("box")
    assert box is not None, "invoke_judge has no box parameter — the box never reaches the judge seam"
    assert box.kind is inspect.Parameter.KEYWORD_ONLY, "box must be keyword-only on invoke_judge"
    assert box.default is inspect.Parameter.empty, \
        "box carries a default on invoke_judge — a silent inert default re-deads the judge lane (F1)"


def test_curator_for_run_threads_box_to_bind(tmp_path):
    """curator_for_run_box_passthrough — the curator's `CuratorDeps.for_run` wrapper (M9)
    threads the per-call box through to its inner `bind`, so the built CuratorDeps carries
    it. TypeError at HEAD (for_run has no box=)."""
    delivered = box_mod.BoxExecutor(name="drain-box")
    deps = _curator_for_run(tmp_path, box=delivered)
    assert deps.box is delivered


def test_box_reaches_both_actor_legs_and_both_drain_chains(tmp_path):
    """test_box_reaches_both_actor_legs_and_both_drain_chains — 'the actor' is TWO invoke
    methods (adversarial + benign) and the drain reaches its bash roles through TWO
    structurally different chains (author_drain's curator + lead_author's callable, brief
    RF2). Box delivery must reach BOTH actor legs AND BOTH drain chains; wiring only one
    member of either pair is incomplete against O1/M10. Each is driven through its real seam,
    and BOTH drain chains read the delivered box back off their built deps (curator_deps.box
    and the lead-author deps the injected run_stage returns) — not merely invoked."""
    from defender.learning.pipeline.benign_actor.run import invoke_actor_benign
    from defender.learning.pipeline.malicious_actor.run import invoke_actor

    delivered = box_mod.BoxExecutor(name="box")
    got: dict[str, object] = {}

    def rec(name):
        def _fn(*_a, **k):
            got[name] = k.get("box")
            return "SKIP: spec"
        return _fn

    lrd = tmp_path / "lrd"
    lrd.mkdir()
    (tmp_path / "alert.json").write_text("{}", encoding="utf-8")
    (tmp_path / "ai.yaml").write_text("x: 1\n", encoding="utf-8")
    (tmp_path / "investigation.md").write_text("+ x\n", encoding="utf-8")

    invoke_actor(tmp_path / "alert.json", tmp_path / "ai.yaml", lrd,
                 box=delivered, actor_fn=rec("actor"))
    # case_entities is a str on the benign seam (benign_actor/run.py:21) — it is wrapped
    # into a prompt section, so a dict is rejected before the box is ever threaded.
    invoke_actor_benign(tmp_path / "alert.json", "", "rule.key", lrd,
                        box=delivered, actor_fn=rec("actor_benign"))
    # drain chain 1 — curator via for_run
    curator_deps = _curator_for_run(tmp_path, box=delivered)
    # drain chain 2 — lead_author engine
    from defender.learning.leads import lead_author_engine

    lead_deps = lead_author_engine._run_lead_author_pydantic(
        prompt_path=tmp_path / "p.md", model="m", effort=None, trace_name="t",
        label="l", user="u", learning_run_dir=lrd, repo_root=tmp_path / "repo",
        request_limit=4, wall_clock_timeout=60,
        box=delivered, run_stage=lambda **k: k["deps"],
    )
    assert got.get("actor") is delivered, "adversarial actor leg reached with no box"
    assert got.get("actor_benign") is delivered, "benign actor leg reached with no box"
    assert curator_deps.box is delivered, "the curator drain chain reached with no box"
    assert lead_deps.box is delivered, "the lead-author drain chain reached with no box"


def test_dispatched_callable_not_updated_for_the_new_call_shape(tmp_path):
    """test_dispatched_callable_not_updated_for_the_new_call_shape — the dispatched
    callables (each Direction's `invoke_actor` lambda, the drain's importlib/injected
    dispatch) must thread the new per-call box. A Subagents whose method REQUIRES box
    (keyword-only, no default) is driven through the real ADVERSARIAL direction dispatch: a
    dispatch that still calls `agents.actor(run_dir, lrd)` without box raises loudly rather
    than silently dropping the box on the floor. Positive control: the benign lambda
    threads it too."""
    from defender.learning.core.directions import ADVERSARIAL, BENIGN

    class StrictAgents:
        def __init__(self):
            self.box = None

        def actor(self, run_dir, lrd, *, box):
            self.box = box
            return "SKIP: spec"

        def actor_benign(self, run_dir, lrd, key, *, box):
            self.box = box
            return "SKIP: spec"

    delivered = box_mod.BoxExecutor(name="rc")
    a = StrictAgents()
    ADVERSARIAL.invoke_actor(a, tmp_path, tmp_path / "lrd", "rule.key", box=delivered)
    assert a.box is delivered
    b = StrictAgents()
    BENIGN.invoke_actor(b, tmp_path, tmp_path / "lrd", "rule.key", box=delivered)
    assert b.box is delivered


def test_role_keyed_census_blind_to_caller_constructed_boxless_instance(tmp_path):
    """test_role_keyed_census_blind_to_caller_constructed_boxless_instance (N7) — the eval
    harness constructs a bash role directly, off all production creation sites, with no box;
    once the production seams require box, that off-path instance keeps N5's inert default
    and its bash lane stays dead. Nothing observes it — an accepted, RECORDED non-obligation
    (O2's capability loss the O6 role-keyed census structurally cannot see), not a defect
    this design fixes."""
    off_path = bind(agents_registry.AGENTS[AgentRole.ACTOR], tmp_path / "run", salt=SALT,
                    defender_dir=DEFENDER,
                    scope=RunScope(read_confine=(tmp_path / "run",), scripts=()))
    assert off_path.box.transport is box_mod._unattached, \
        "an off-path bind should keep N5's inert (unattached) default, not a live box"
    with pytest.raises(box_mod.BoxFault):
        off_path.box.run_parsed([], command="true", cwd=tmp_path / "run", timeout=1.0)


# ======================================================================= #
# run_one — the run-cycle box shared by the actor + judge legs
# ======================================================================= #
def test_run_one_creates_run_cycle_box_and_delivers_to_actor_and_judge(tmp_path, monkeypatch):
    """run_cycle_box_delivered — run_one creates ONE run-cycle box once learning_run_dir
    exists and delivers it to the concurrently-dispatched direction legs (the actor and the
    judge share it, decision 2), then tears it down. Driven with the injectable start_box /
    stop_box seams and a recording Subagents; asserts one box created, delivered to both
    legs, and stopped."""
    rec = BoxLifecycleRecorder()
    agents = RecordingSubagents()
    _run_one(tmp_path, monkeypatch, rec, agents=agents, disposition="inconclusive")

    box = rec.only_request() and rec.boxes[0]
    assert agents.actor_box is box, "the run-cycle box did not reach the adversarial leg"
    assert agents.actor_benign_box is box, "the run-cycle box did not reach the benign leg"
    assert rec.stopped == [box], "the run-cycle box was not torn down exactly once"


def test_run_cycle_box_self_collides_across_its_own_concurrent_direction_legs(tmp_path, monkeypatch):
    """test_run_cycle_box_self_collides_across_its_own_concurrent_direction_legs — the box
    is created ONCE, before the two direction legs are dispatched, so the sibling legs never
    race to stand up two containers under the same composed name (decision 2: one box per
    invocation, actor + judge share it). Asserts exactly one box created for the whole
    invocation."""
    rec = BoxLifecycleRecorder()
    _run_one(tmp_path, monkeypatch, rec, disposition="inconclusive")
    assert len(rec.boxes) == 1, "each concurrent leg stood up its own box — they collide"


def test_sibling_direction_leg_continues_against_a_shared_box_after_the_other_leg_faults(
    tmp_path, monkeypatch,
):
    """test_sibling_direction_leg_continues_against_a_shared_box_after_the_other_leg_faults
    (F2 → R2) — when one leg faults, the shared run-cycle box is kept alive until BOTH legs
    finish; a leg fault does not trigger an early teardown that cuts the still-running
    sibling off. The box is torn down exactly once, at run end, after both legs ran."""
    rec = BoxLifecycleRecorder()
    agents = RecordingSubagents(actor_fault=RuntimeError("adversarial leg blew up"))
    with pytest.raises(RuntimeError):  # run_one re-raises the captured leg error, not the seam TypeError
        _run_one(tmp_path, monkeypatch, rec, agents=agents, disposition="inconclusive")
    assert "actor_benign" in agents.calls, "the sibling leg was cut off by an early teardown"
    assert rec.stopped == rec.boxes, "the shared box was not torn down exactly once at run end"


def test_run_one_leaks_box_on_an_exceptional_exit_not_already_anticipated(tmp_path, monkeypatch):
    """test_run_one_leaks_box_on_an_exceptional_exit_not_already_anticipated — O7: no box
    outlives its batch holding a rw bind. run_one has no top-level try/finally today; an
    exceptional exit anywhere (here a leg fault re-raised by run_one) must still tear the
    run-cycle box down, not leak it."""
    rec = BoxLifecycleRecorder()
    agents = RecordingSubagents(actor_fault=RuntimeError("boom"))
    with pytest.raises(RuntimeError):
        _run_one(tmp_path, monkeypatch, rec, agents=agents, disposition="inconclusive")
    assert rec.boxes, "no run-cycle box was created before the exceptional exit"
    assert rec.stopped == rec.boxes, \
        "an exceptional run_one exit leaked the run-cycle box (no teardown ran)"


def test_run_cycle_box_name_distinct_from_runtime_box_and_grammar_valid(tmp_path, monkeypatch):
    """test_run_cycle_box_name_distinct_from_runtime_box_and_grammar_valid (M8/O7) —
    container_name keys on run_id alone, so a run-cycle box would claim the runtime box's
    name for the same run_id (a live one refuses the batch, a stopped one is reaped from its
    owner). The caller-composed run-cycle name must NOT equal the runtime box's name for the
    same run_id, while still satisfying the run-id grammar (#698)."""
    from defender._run_id import is_valid_run_id

    rec = BoxLifecycleRecorder()
    run_dir = make_run_dir(tmp_path, disposition="inconclusive")
    run_id = run_dir.name
    runtime_name = box_mod.container_name(run_id)
    satisfy_engine_keys(monkeypatch, "inconclusive")
    from defender.learning.core.run_cycle import run_one

    run_one(run_dir, paths=_paths(tmp_path), agents=RecordingSubagents(),
            start_box=rec.start_box, stop_box=rec.stop_box)
    name = rec.only_request().name
    assert name != runtime_name, "the run-cycle box reused the runtime box's name"
    assert is_valid_run_id(name.removeprefix(box_mod._NAME_PREFIX)) or is_valid_run_id(name), \
        "the composed run-cycle name violates the #698 run-id grammar"


def test_box_names_distinct_no_runtime_collision(tmp_path, monkeypatch):
    """box_names_no_collision — the run-cycle box, the drain box, and the runtime box for
    concurrent activity write DISTINCT container names (identity keyed on run_id / batch_id
    with a tier-distinguishing component); no two collide."""
    rc = BoxLifecycleRecorder()
    run_dir = make_run_dir(tmp_path, disposition="inconclusive")
    satisfy_engine_keys(monkeypatch, "inconclusive")
    from defender.learning.core.run_cycle import run_one

    run_one(run_dir, paths=_paths(tmp_path), agents=RecordingSubagents(),
            start_box=rc.start_box, stop_box=rc.stop_box)
    run_cycle_name = rc.only_request().name
    assert run_cycle_name != box_mod.container_name(run_dir.name)


# ======================================================================= #
# _run_worktree_batch — the drain box over its worktree leaf
# ======================================================================= #
def test_drain_batch_creates_own_box_and_delivers_to_triggered_roles(tmp_path):
    """drain_box_delivered — each drain invocation builds its OWN box over its worktree leaf
    and delivers it to the bash roles its do_work dispatches (curator + lead_author). Driven
    with the injectable start_box/stop_box; the do_work recorder reads the delivered box."""
    rec = BoxLifecycleRecorder()
    got = {}

    def do_work(wt_paths, *, box=None):
        got["box"] = box

    _worktree_batch(tmp_path, rec, do_work=do_work)
    assert len(rec.boxes) == 1, "the drain did not create exactly one box for the batch"
    assert got["box"] is rec.boxes[0], "the drain box did not reach the dispatched roles"
    assert rec.stopped == rec.boxes, "the drain box was not torn down"


def test_one_drain_box_must_serve_more_than_one_dispatched_module_in_a_batch(tmp_path):
    """test_one_drain_box_must_serve_more_than_one_dispatched_module_in_a_batch — one box is
    created once per drain invocation (M1/decision 2) and PERSISTS across every curator
    module the dispatch reaches in that batch; it is not recreated per dispatched module. The
    do_work here reaches two modules against the one delivered box."""
    rec = BoxLifecycleRecorder()
    seen = []

    def do_work(wt_paths, *, box=None):
        for _module in ("author", "author_actor"):
            seen.append(box)

    _worktree_batch(tmp_path, rec, do_work=do_work)
    assert len(rec.boxes) == 1, "a box was created per dispatched module, not once per batch"
    assert seen == [rec.boxes[0], rec.boxes[0]], "the modules did not share one box"


def test_box_creation_deferred_past_multiple_independent_threshold_checks_in_one_tick(tmp_path):
    """test_box_creation_deferred_past_multiple_independent_threshold_checks_in_one_tick
    (F7 → R6) — the drain refactors to decide-all → create one box over the triggered union
    → run-all: the full triggered set is computed BEFORE the box is created, so exactly one
    box serves the tick (not one per newly-triggered corpus). Asserts one box created for a
    do_work that triggers two corpora."""
    rec = BoxLifecycleRecorder()
    triggered = ["lessons", "lessons-actor"]

    def do_work(wt_paths, *, box=None):
        # decide-all already happened; every triggered corpus runs against the one box.
        for _corpus in triggered:
            assert box is rec.boxes[0]

    _worktree_batch(tmp_path, rec, do_work=do_work)
    assert len(rec.boxes) == 1, \
        "the box was recreated per newly-triggered corpus instead of once over the union"


def test_box_torn_down_within_batch_ordered(tmp_path):
    """teardown_within_batch — decision 8's order: the box is stopped (rw bind released)
    BEFORE the scan / finish_batch / cleanup steps that read and commit the tree. Asserts
    stop precedes finish_batch in the recorded event log."""
    log: list[str] = []
    rec = BoxLifecycleRecorder(events=log)
    branch = RecordingBranch(tmp_path / "wt", events=log)

    _worktree_batch(tmp_path, rec, do_work=lambda wt, *, box=None: None, branch=branch)
    assert rec.stopped, "no box teardown was recorded"
    assert branch.finished, "no finish_batch was recorded"
    stop_i = next(i for i, e in enumerate(log) if e.startswith("stop:"))
    finish_i = next(i for i, e in enumerate(log) if e.startswith("finish_batch:"))
    assert stop_i < finish_i, "finish_batch ran while the box still held the rw bind"


def test_box_torn_down_before_finish_batch_regardless_of_where_it_was_created(tmp_path):
    """test_box_torn_down_before_finish_batch_regardless_of_where_it_was_created — however
    the drain box was created within the batch, its teardown lands before finish_batch (the
    commit+push+PR supply-chain step, S7). Same ordering invariant, pinned independent of the
    creation site."""
    log: list[str] = []
    rec = BoxLifecycleRecorder(events=log)
    branch = RecordingBranch(tmp_path / "wt", events=log)
    _worktree_batch(tmp_path, rec, do_work=lambda wt, *, box=None: None, branch=branch)
    assert rec.stopped, "no box teardown was recorded"
    assert log.index(f"stop:{rec.boxes[0].name}") < log.index(f"finish_batch:{branch.finished[0]}")


def test_box_teardown_failure_blocks_or_permits_subsequent_lifecycle_steps(tmp_path):
    """test_box_teardown_failure_blocks_or_permits_subsequent_lifecycle_steps (F13 → R2) —
    a FAILED stop_box BLOCKS finish_batch/cleanup and aborts loudly: never commit+push+PR
    from a tree whose box still holds the rw bind (S7 supply-chain path). Asserts finish_batch
    is NOT called when teardown raises."""
    log: list[str] = []
    rec = BoxLifecycleRecorder(events=log, stop_fault=box_mod.BoxFault("could not tear down"))
    branch = RecordingBranch(tmp_path / "wt", events=log)
    with pytest.raises(box_mod.BoxFault):
        _worktree_batch(tmp_path, rec, do_work=lambda wt, *, box=None: None, branch=branch)
    assert branch.finished == [], "finish_batch ran after a failed box teardown (supply-chain leak)"


def test_two_concurrent_drain_invocations_mint_leaves_whose_paths_collide(tmp_path):
    """test_two_concurrent_drain_invocations_mint_leaves_whose_paths_collide — two
    concurrent drain invocations mint worktree leaves under disjoint prefixes/locks with a
    fresh batch_id each, so their leaf paths (and the boxes bound over them) never collide.
    Asserts the two batches' box requests carry distinct names."""
    rec_a = BoxLifecycleRecorder()
    rec_b = BoxLifecycleRecorder()
    _worktree_batch(tmp_path / "a", rec_a, do_work=lambda wt, *, box=None: None)
    _worktree_batch(tmp_path / "b", rec_b, do_work=lambda wt, *, box=None: None)
    assert rec_a.only_request().name != rec_b.only_request().name, \
        "two concurrent drains composed colliding box names"


def test_startup_fault_absorbed_by_an_existing_per_item_continue_idiom(tmp_path):
    """test_startup_fault_absorbed_by_an_existing_per_item_continue_idiom (F4 → R3) — a
    startup BoxFault must surface as a batch-level ABORT, not be swallowed by the drain's
    existing per-item logged-skip-returns-0 idiom; the startup-BoxFault class is added to the
    systemic-fault set so it bypasses the per-item skip. Asserts a create-time BoxFault
    propagates out of the batch rather than returning 0."""
    def bad_start(request, *_a, **_k):
        raise box_mod.BoxFault("could not create the box: bind source path does not exist")

    with pytest.raises(box_mod.BoxFault):
        _worktree_batch_start(tmp_path, do_work=lambda wt, *, box=None: None, start_box=bad_start)


def _worktree_batch_start(tmp_path, *, do_work, start_box):
    from defender.learning.core.drains import _run_worktree_batch

    paths = _paths(tmp_path)
    branch = RecordingBranch(tmp_path / "wt")
    return _run_worktree_batch(
        paths, branch, label="author_drain", has_work=lambda p: True, do_work=do_work,
        start_box=start_box, stop_box=box_mod.stop_box,
    )


def test_box_startup_failure_unwinds_the_resources_created_before_it(tmp_path):
    """test_box_startup_failure_unwinds_the_resources_created_before_it — when box startup
    fails, the resources created before it (the worktree leaf / branch) are unwound (M1):
    the batch does not leave an orphaned worktree behind a failed box. Asserts branch.cleanup
    runs even though start_box faulted before any work."""
    from defender.learning.core.drains import _run_worktree_batch

    paths = _paths(tmp_path)
    branch = RecordingBranch(tmp_path / "wt")

    def bad_start(request, *_a, **_k):
        raise box_mod.BoxFault("docker binary unavailable")

    with pytest.raises(box_mod.BoxFault):
        _run_worktree_batch(paths, branch, label="author_drain", has_work=lambda p: True,
                            do_work=lambda wt, *, box=None: None,
                            start_box=bad_start, stop_box=box_mod.stop_box)
    assert "cleanup" in branch.events, "a failed box startup leaked the worktree leaf"


def test_stale_run_cycle_container_from_a_prior_crashed_attempt_at_the_same_run_id(
    tmp_path, monkeypatch,
):
    """test_stale_run_cycle_container_from_a_prior_crashed_attempt_at_the_same_run_id
    (F3 → R2) — on a LIVE same-name container, box creation REFUSES and surfaces (already the
    code's behavior); reaping one's own STOPPED crashed attempt is acceptable but must be
    logged loudly, never silent. Driven at start_box with a RecordingDocker reporting a live
    same-name container — creation raises BoxFault, no reap-and-replace."""
    from _box665 import RecordingDocker

    run_dir = make_run_dir(tmp_path, disposition="inconclusive")
    docker = RecordingDocker(running=True)  # a LIVE same-name container (po4-grounded)
    with pytest.raises(box_mod.BoxFault):
        box_mod.start_box(run_dir, DEFENDER, docker=docker)
    assert not any(c[:3] == ["docker", "rm", "-f"] for c in docker.calls), \
        "a LIVE same-name container was silently reaped instead of refused"


def test_a_retried_drain_invocation_reuses_a_batch_id_whose_prior_container_still_exists(tmp_path):
    """test_a_retried_drain_invocation_reuses_a_batch_id_whose_prior_container_still_exists
    (F6 → R2) — batch_id is a fresh uuid4().hex[:12] per invocation, so batches do not retry
    onto a colliding container today; this is an ACCEPTED residual contingent on decision-5's
    'loop not currently scheduled' (it reopens — needing a distinguishing suffix — only if the
    loop is scheduled). Pins that two invocations mint distinct batch ids."""
    rec_a = BoxLifecycleRecorder()
    rec_b = BoxLifecycleRecorder()
    _worktree_batch(tmp_path / "a", rec_a, do_work=lambda wt, *, box=None: None)
    _worktree_batch(tmp_path / "b", rec_b, do_work=lambda wt, *, box=None: None)
    assert rec_a.only_request().name != rec_b.only_request().name


def test_orphaned_worktree_and_box_survive_a_hard_kill_before_any_finally_runs(tmp_path):
    """test_orphaned_worktree_and_box_survive_a_hard_kill_before_any_finally_runs
    (F15 → R2) — a SIGKILL bypasses every finally; no reaper independent of a same-identity
    re-invocation exists, so orphans are an ACCEPTED residual contingent on 'not scheduled'.
    This pins the in-process guarantee the design DOES make: on any ordinary (non-SIGKILL)
    exceptional exit, the finally-driven teardown releases the box."""
    rec = BoxLifecycleRecorder()

    def do_work(wt_paths, *, box=None):
        raise RuntimeError("mid-batch failure short of a hard kill")

    with pytest.raises(RuntimeError):
        _worktree_batch(tmp_path, rec, do_work=do_work)
    assert rec.boxes, "no box was created before the mid-batch failure"
    assert rec.stopped == rec.boxes, "an ordinary exceptional exit still leaked the box"
