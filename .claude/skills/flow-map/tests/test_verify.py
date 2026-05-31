"""verify.py — differential verifier. ZERO live calls (tracers injected).

Proves: structural gate hard-blocks and short-circuits the (paid) differential;
view construction is deterministic; agreement passes; disagreement is reported
as a surrogate-fidelity gap (never a silent pass); the structural backstop runs
regardless of tracer behaviour.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from flowmap.model import Edge
from flowmap.resolve import resolve_module_dispatch
from flowmap.seed import seed_python_module
from flowmap.verify import (
    SubflowSpec,
    compare_traces,
    differential_verify,
    expected_steps_from_graph,
    graph_view,
    select_load_bearing_subflows,
    source_view,
)


def _build(synth_pkg):
    g = seed_python_module(synth_pkg["module"], synth_pkg["root"], entry="entry")
    resolve_module_dispatch(g, synth_pkg["module"], synth_pkg["root"])
    return g


# --------------------------------------------------------------------------- #
# Deterministic views + comparison (no model)
# --------------------------------------------------------------------------- #


def test_source_view_returns_function_body(synth_pkg):
    src = source_view(synth_pkg["module"], "entry")
    assert "def entry" in src
    assert "invoke_actor()" in src


def test_source_view_unknown_func_raises(synth_pkg):
    with pytest.raises(ValueError):
        source_view(synth_pkg["module"], "nope")


def test_graph_view_lists_seed_out_edges(synth_pkg):
    g = _build(synth_pkg)
    view = graph_view(g, "learn/main.py", "entry")
    # entry -> _local_helper, invoke_actor, run_script, trigger, helper.assist
    assert "invoke_actor" in view
    assert "assist" in view  # cross-module edge surfaces in the view


def test_compare_traces_symmetric_diff():
    only_r, only_g = compare_traces(["a", "b", "c"], ["b", "c", "d"])
    assert only_r == ["a"]
    assert only_g == ["d"]


def test_compare_traces_normalizes_case_and_space():
    only_r, only_g = compare_traces(["Invoke_Actor", " run_script "], ["invoke_actor", "run_script"])
    assert only_r == [] and only_g == []


def test_expected_steps_from_graph_matches_edges(synth_pkg):
    g = _build(synth_pkg)
    steps = expected_steps_from_graph(g, "learn/main.py", "entry")
    assert "invoke_actor" in steps
    assert "assist" in steps


# --------------------------------------------------------------------------- #
# Orchestration with injected tracers
# --------------------------------------------------------------------------- #


def test_structural_gate_short_circuits_differential(synth_pkg):
    g = _build(synth_pkg)
    # corrupt a ref so structural fails
    g.nodes["py:learn/main.py::entry"].ref = "learn/main.py:99999"

    calls = []
    def tracer(artifact, question):
        calls.append(artifact)
        return []

    res = differential_verify(g, synth_pkg["module"], synth_pkg["root"],
                              [SubflowSpec("entry")], tracer=tracer,
                              run_differential=True)
    assert res.structural          # structural errors present
    assert res.differentials == []  # differential never ran
    assert calls == []              # tracer (the paid part) never called
    assert not res.ok


def test_agreement_passes_clean(synth_pkg):
    g = _build(synth_pkg)
    # both tracers return the same step set -> faithful surrogate
    def tracer(artifact, question):
        return ["invoke_actor", "run_script", "assist"]

    res = differential_verify(g, synth_pkg["module"], synth_pkg["root"],
                              [SubflowSpec("entry")], tracer=tracer,
                              run_differential=True)
    assert res.structural == []
    assert len(res.differentials) == 1
    assert res.differentials[0].agree
    assert res.gaps == []
    assert res.ok


def test_disagreement_reported_as_gap(synth_pkg):
    g = _build(synth_pkg)
    # graph-side tracer is missing 'assist' that the code-side tracer found
    def tracer(artifact, question):
        if "out-edges" in artifact:           # graph view
            return ["invoke_actor", "run_script"]
        return ["invoke_actor", "run_script", "assist"]  # source view

    res = differential_verify(g, synth_pkg["module"], synth_pkg["root"],
                              [SubflowSpec("entry")], tracer=tracer,
                              run_differential=True)
    d = res.differentials[0]
    assert not d.agree
    assert d.only_in_raw == ["assist"]
    assert any(gp.kind == "surrogate-fidelity" for gp in res.gaps)
    # the gap is also recorded on the graph itself (surfaced to the user)
    assert any(gp.kind == "surrogate-fidelity" for gp in g.gaps)
    assert not res.ok


def test_run_differential_false_does_structural_only(synth_pkg):
    g = _build(synth_pkg)
    def boom(artifact, question):
        raise AssertionError("tracer must not run when run_differential=False")
    res = differential_verify(g, synth_pkg["module"], synth_pkg["root"],
                              [SubflowSpec("entry")], tracer=boom,
                              run_differential=False)
    assert res.structural == []
    assert res.differentials == []
    assert res.ok


def test_differential_off_by_default_no_env(synth_pkg, monkeypatch):
    """With no env var and no explicit flag, the paid tier does NOT run."""
    monkeypatch.delenv("FLOWMAP_DIFFERENTIAL", raising=False)
    def boom(artifact, question):
        raise AssertionError("differential ran without opt-in")
    res = differential_verify(g := _build(synth_pkg), synth_pkg["module"],
                              synth_pkg["root"], [SubflowSpec("entry")], tracer=boom)
    assert res.differentials == []
    assert res.ok


def test_env_var_enables_differential(synth_pkg, monkeypatch):
    """FLOWMAP_DIFFERENTIAL=1 turns the differential on without an explicit flag."""
    monkeypatch.setenv("FLOWMAP_DIFFERENTIAL", "1")
    ran = []
    def tracer(artifact, question):
        ran.append(1)
        return ["invoke_actor", "run_script", "assist"]
    res = differential_verify(_build(synth_pkg), synth_pkg["module"],
                              synth_pkg["root"], [SubflowSpec("entry")], tracer=tracer)
    assert ran                       # tracer was invoked
    assert len(res.differentials) == 1


def test_explicit_flag_overrides_env(synth_pkg, monkeypatch):
    """An explicit run_differential=False beats FLOWMAP_DIFFERENTIAL=1."""
    monkeypatch.setenv("FLOWMAP_DIFFERENTIAL", "1")
    def boom(artifact, question):
        raise AssertionError("explicit False must override env opt-in")
    res = differential_verify(_build(synth_pkg), synth_pkg["module"],
                              synth_pkg["root"], [SubflowSpec("entry")],
                              tracer=boom, run_differential=False)
    assert res.differentials == []


# --------------------------------------------------------------------------- #
# Sub-flow selection (deterministic, drives `build`)
# --------------------------------------------------------------------------- #


def test_selector_includes_entry_first(synth_pkg):
    g = _build(synth_pkg)
    specs = select_load_bearing_subflows(g, "learn/main.py", "entry", k=2)
    assert specs[0].seed_func == "entry"


def test_selector_prefers_dispatch_bearing_funcs(synth_pkg):
    g = _build(synth_pkg)
    specs = select_load_bearing_subflows(g, "learn/main.py", "entry", k=3)
    names = [s.seed_func for s in specs]
    # invoke_actor dispatches actor.md; run_script runs a subprocess -> both
    # are load-bearing and should be chosen over plain helpers
    assert "invoke_actor" in names or "run_script" in names
    assert "_local_helper" not in names  # no dispatch/subprocess -> not picked


def test_selector_respects_k(synth_pkg):
    g = _build(synth_pkg)
    assert len(select_load_bearing_subflows(g, "learn/main.py", "entry", k=1)) == 1


def test_selector_is_deterministic(synth_pkg):
    g = _build(synth_pkg)
    a = [s.seed_func for s in select_load_bearing_subflows(g, "learn/main.py", "entry", k=3)]
    b = [s.seed_func for s in select_load_bearing_subflows(g, "learn/main.py", "entry", k=3)]
    assert a == b


def test_two_specs_both_traced(synth_pkg):
    g = _build(synth_pkg)
    seen = []
    def tracer(artifact, question):
        seen.append(artifact[:20])
        return ["invoke_actor", "run_script", "assist"] if "out-edges" not in artifact \
            else ["invoke_actor", "run_script", "assist"]
    specs = [SubflowSpec("entry"), SubflowSpec("invoke_actor")]
    res = differential_verify(g, synth_pkg["module"], synth_pkg["root"],
                              specs, tracer=tracer, run_differential=True)
    assert len(res.differentials) == 2
    assert len(seen) == 4  # 2 specs x (source + graph)


# --------------------------------------------------------------------------- #
# Golden: the load-bearing learning-loop sub-flow, traces injected from the
# graph's own ground truth (no model) — proves the wiring end-to-end on real code
# --------------------------------------------------------------------------- #


def test_golden_adversarial_subflow_self_consistent(defender_root, loop_module):
    g = seed_python_module(loop_module, defender_root, entry="run_one")
    resolve_module_dispatch(g, loop_module, defender_root)
    rel = "defender/learning/loop.py"

    # A faithful tracer = the graph's own out-edge names. Feeding the same oracle
    # to both sides must agree (sanity: the comparison + gap logic don't false-fire
    # on real data).
    truth = expected_steps_from_graph(g, rel, "_run_adversarial")
    res = differential_verify(g, loop_module, defender_root,
                              [SubflowSpec("_run_adversarial")],
                              tracer=lambda a, q: truth, run_differential=True)
    assert res.structural == []
    assert res.differentials[0].agree
    assert res.ok
    # the oracle includes the load-bearing dispatch + persistence steps
    assert "invoke_actor" in truth
    assert "persist_run" in truth
