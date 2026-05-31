"""logic.py + represent.py — control-flow view, noise collapse, representation.

Zero live calls: the representer is injected. Golden assertions run against the
real learning loop and double as drift detectors.
"""
from __future__ import annotations

import pytest

from flowmap.logic import (
    NOISE_NAMES,
    agent_table,
    build_control_flow,
    collapse_noise,
    render_logic_mermaid,
)
from flowmap.represent import (
    apply_representation,
    collect_requests,
    represent_logic,
)
from flowmap.resolve import resolve_module_dispatch
from flowmap.seed import seed_python_module


def _cg(synth_pkg):
    g = seed_python_module(synth_pkg["module"], synth_pkg["root"], entry="entry")
    resolve_module_dispatch(g, synth_pkg["module"], synth_pkg["root"])
    return g


# --------------------------------------------------------------------------- #
# CFG structure (synthetic)
# --------------------------------------------------------------------------- #


def test_cfg_has_sequence_and_terminals(synth_pkg):
    cg = _cg(synth_pkg)
    cfg = build_control_flow(cg, synth_pkg["module"], synth_pkg["root"], "entry")
    kinds = [n.kind for n in cfg.nodes.values()]
    assert "terminal" in kinds            # start/end
    labels = {n.label for n in cfg.nodes.values()}
    assert "entry" in labels              # start node named for the function
    assert "invoke_actor" in labels       # a tracked call appears as a step


def test_cfg_marks_agent_dispatcher(synth_pkg):
    cg = _cg(synth_pkg)
    cfg = build_control_flow(cg, synth_pkg["module"], synth_pkg["root"], "entry")
    # invoke_actor dispatches actor.md -> rendered as an `agent` node
    agents = [n.label for n in cfg.nodes.values() if n.kind == "agent"]
    assert "invoke_actor" in agents


def test_cfg_branch_has_decision(synth_pkg):
    cg = _cg(synth_pkg)
    cfg = build_control_flow(cg, synth_pkg["module"], synth_pkg["root"], "_local_helper")
    # _local_helper has `if x: return 1`
    assert any(n.kind == "decision" for n in cfg.nodes.values())
    assert any(n.kind == "terminal" and n.label == "return"
               for n in cfg.nodes.values())


def test_cfg_unknown_entry_raises(synth_pkg):
    cg = _cg(synth_pkg)
    with pytest.raises(ValueError):
        build_control_flow(cg, synth_pkg["module"], synth_pkg["root"], "nope")


# --------------------------------------------------------------------------- #
# noise collapse (render-only)
# --------------------------------------------------------------------------- #


def test_collapse_removes_logging_nodes(synth_pkg):
    cg = _cg(synth_pkg)
    cfg = build_control_flow(cg, synth_pkg["module"], synth_pkg["root"], "entry")
    # inject a synthetic logging node into the graph to prove splice keeps flow
    before = len([n for n in cfg.nodes.values() if n.label in NOISE_NAMES])
    collapsed = collapse_noise(cfg)
    after = len([n for n in collapsed.nodes.values() if n.label in NOISE_NAMES])
    assert after == 0
    # collapse must not strand nodes: every non-terminal kept node still on a path
    assert len(collapsed.nodes) <= len(cfg.nodes)
    # collapse is render-only: original untouched
    assert len([n for n in cfg.nodes.values() if n.label in NOISE_NAMES]) == before


def test_collapse_preserves_branch_label_on_splice():
    """A logging node sitting on a 'yes' branch must not drop the 'yes' label."""
    from flowmap.model import Edge, Graph, Node
    g = Graph()
    g.nodes["d"] = Node(id="d", kind="decision", label="cond")
    g.nodes["lg"] = Node(id="lg", kind="code", label="_log")
    g.nodes["k"] = Node(id="k", kind="code", label="real_step")
    g.add_edge(Edge("d", "lg", "flow", label="yes"))
    g.add_edge(Edge("lg", "k", "flow", label=""))
    out = collapse_noise(g)
    assert "lg" not in out.nodes
    spliced = [e for e in out.edges if e.src == "d" and e.dst == "k"]
    assert spliced and spliced[0].label == "yes"


# --------------------------------------------------------------------------- #
# representation layer (injected representer — zero live calls)
# --------------------------------------------------------------------------- #


def test_collect_requests_covers_branches_and_agents(synth_pkg):
    cg = _cg(synth_pkg)
    cfg = build_control_flow(cg, synth_pkg["module"], synth_pkg["root"], "entry")
    reqs = collect_requests(cfg, cg, synth_pkg["root"])
    kinds = {r["kind"] for r in reqs}
    assert "agent" in kinds  # invoke_actor
    # every request id is a real node
    for r in reqs:
        assert r["id"] in cfg.nodes


def test_represent_applies_only_valid_ids(synth_pkg):
    cg = _cg(synth_pkg)
    cfg = build_control_flow(cg, synth_pkg["module"], synth_pkg["root"], "entry")

    def rep(requests):
        out = {r["id"]: f"REPHRASED:{r['kind']}" for r in requests}
        out["ghost-id-not-in-graph"] = "should be dropped"  # structural gate
        return out

    summary = represent_logic(cfg, cg, synth_pkg["root"], representer=rep)
    assert summary["applied"] == summary["requested"]
    # the ghost id never landed
    assert all("ghost" not in nid for nid in cfg.nodes)
    # an agent node now carries a goal; a branch node got a new label
    agent = next(n for n in cfg.nodes.values() if n.kind == "agent")
    assert agent.signals.get("goal", "").startswith("REPHRASED:agent")


def test_partial_representation_degrades_to_raw(synth_pkg):
    """A representer that returns nothing leaves the verifiable raw labels intact."""
    cg = _cg(synth_pkg)
    cfg = build_control_flow(cg, synth_pkg["module"], synth_pkg["root"], "_local_helper")
    raw_labels = {n.label for n in cfg.nodes.values() if n.kind == "decision"}
    summary = represent_logic(cfg, cg, synth_pkg["root"], representer=lambda reqs: {})
    assert summary["applied"] == 0
    still = {n.label for n in cfg.nodes.values() if n.kind == "decision"}
    assert still == raw_labels  # unchanged, not blanked


def test_render_has_readable_classdefs(synth_pkg):
    cg = _cg(synth_pkg)
    cfg = build_control_flow(cg, synth_pkg["module"], synth_pkg["root"], "entry")
    out = render_logic_mermaid(collapse_noise(cfg), title="entry")
    assert "classDef agent" in out and "color:#" in out
    assert ":::agent" in out or ":::code" in out


# --------------------------------------------------------------------------- #
# golden: real learning loop
# --------------------------------------------------------------------------- #


def test_golden_run_one_cfg_shows_direction_branch(defender_root, loop_module):
    cg = seed_python_module(loop_module, defender_root, entry="run_one")
    resolve_module_dispatch(cg, loop_module, defender_root)
    cfg = build_control_flow(cg, loop_module, defender_root, "run_one")
    cfg = collapse_noise(cfg)
    # the disposition fan-out: a `for direction in directions` loop + an
    # `direction == 'adversarial'` decision selecting the two directions
    labels = [n.label for n in cfg.nodes.values()]
    assert any("direction" in lab for lab in labels)
    assert any(n.kind == "loop" for n in cfg.nodes.values())
    # _log collapsed away
    assert "_log" not in labels


def test_golden_adversarial_agents_in_table(defender_root, loop_module):
    cg = seed_python_module(loop_module, defender_root, entry="run_one")
    resolve_module_dispatch(cg, loop_module, defender_root)
    cfg = build_control_flow(cg, loop_module, defender_root, "_run_adversarial")
    table = agent_table(cfg, cg, loop_module, defender_root)
    assert "invoke_actor" in table and "invoke_judge" in table
    assert "input context" in table
    assert "actor_input" in table  # context tag extracted from dispatch f-string


def test_golden_agent_goal_from_representation_wins(defender_root, loop_module):
    cg = seed_python_module(loop_module, defender_root, entry="run_one")
    resolve_module_dispatch(cg, loop_module, defender_root)
    cfg = build_control_flow(cg, loop_module, defender_root, "_run_adversarial")
    represent_logic(cfg, cg, defender_root,
                    representer=lambda reqs: {r["id"]: "GOAL-X" for r in reqs
                                             if r["kind"] == "agent"})
    table = agent_table(cfg, cg, loop_module, defender_root)
    assert "GOAL-X" in table  # represented goal used, not the raw first line
