"""seed.py — deterministic call + dispatch extraction.

Tier 1 (synth): tool logic on a controlled module.
Tier 2 (golden): the real loop.py facts that double as drift detectors.
"""
from __future__ import annotations

import ast

from flowmap.seed import ConstResolver, seed_python_module


# --------------------------------------------------------------------------- #
# Tier 1 — synthetic
# --------------------------------------------------------------------------- #


def test_const_resolver_resolves_path_chains(synth_pkg):
    module = synth_pkg["module"]
    tree = ast.parse(module.read_text())
    cr = ConstResolver(module)
    cr.load(tree)
    # ROOT = parents[1] of learn/main.py == tmp_path
    assert cr.values["ROOT"] == synth_pkg["root"]
    assert cr.values["ACTOR_PROMPT"] == synth_pkg["root"] / "pkg" / "actor.md"
    assert cr.values["PROJECT_SCRIPT"] == synth_pkg["root"] / "tools" / "do_thing.py"


def test_seed_local_calls(synth_pkg):
    g = seed_python_module(synth_pkg["module"], synth_pkg["root"], entry="entry")
    rel = "learn/main.py"
    have = {(e.src, e.dst) for e in g.edges if e.kind == "calls"}
    assert (f"py:{rel}::entry", f"py:{rel}::_local_helper") in have
    assert (f"py:{rel}::entry", f"py:{rel}::invoke_actor") in have


def test_seed_dispatch_edge_resolves_to_md(synth_pkg):
    g = seed_python_module(synth_pkg["module"], synth_pkg["root"], entry="entry")
    disp = [e for e in g.edges if e.kind == "dispatches"]
    assert len(disp) == 1
    assert disp[0].dst == "agent-prompt:pkg/actor.md"
    assert disp[0].via == "run_claude"
    assert disp[0].confidence == "deterministic"


def test_seed_subprocess_edge_resolves_to_py(synth_pkg):
    g = seed_python_module(synth_pkg["module"], synth_pkg["root"], entry="entry")
    runs = [e for e in g.edges if e.kind == "runs_command"]
    assert any(e.dst == "script:tools/do_thing.py" for e in runs)


def test_seed_reports_dynamic_import_gap(synth_pkg):
    g = seed_python_module(synth_pkg["module"], synth_pkg["root"], entry="entry")
    assert any(gp.kind == "dynamic-dispatch" and "__import__" in gp.detail
               for gp in g.gaps)


def test_seed_harvests_docstring_label(synth_pkg):
    g = seed_python_module(synth_pkg["module"], synth_pkg["root"], entry="entry")
    node = g.nodes["py:learn/main.py::entry"]
    assert node.label == "Top-level entry point."
    assert node.label_source == "harvested"


def test_seed_records_decision_density(synth_pkg):
    g = seed_python_module(synth_pkg["module"], synth_pkg["root"], entry="entry")
    # _local_helper has one `if`
    assert g.nodes["py:learn/main.py::_local_helper"].signals["decision_density"] == 1


def test_seed_unknown_entry_raises(synth_pkg):
    import pytest
    with pytest.raises(SystemExit):
        seed_python_module(synth_pkg["module"], synth_pkg["root"], entry="nope")


# --------------------------------------------------------------------------- #
# Tier 2 — golden (real loop.py)
# --------------------------------------------------------------------------- #

REL = "defender/learning/loop.py"

EXPECTED_DISPATCHES = {
    "invoke_actor": "agent-prompt:defender/learning/actor.md",
    "invoke_oracle": "agent-prompt:defender/learning/oracle.md",
    "invoke_judge": "agent-prompt:defender/learning/judge.md",
    "invoke_actor_benign": "agent-prompt:defender/learning/actor_benign.md",
    "invoke_judge_benign": "agent-prompt:defender/learning/judge_benign.md",
}


def test_golden_all_five_prompt_dispatches(defender_root, loop_module):
    g = seed_python_module(loop_module, defender_root, entry="run_one")
    by_src = {}
    for e in g.edges:
        if e.kind == "dispatches":
            by_src[e.src] = e.dst
    for fn, want in EXPECTED_DISPATCHES.items():
        assert by_src.get(f"py:{REL}::{fn}") == want


def test_golden_subprocess_to_project_lead_sequence(defender_root, loop_module):
    g = seed_python_module(loop_module, defender_root, entry="run_one")
    assert any(
        e.kind == "runs_command"
        and e.dst == "script:defender/scripts/project_lead_sequence.py"
        for e in g.edges
    )


def test_golden_import_gap_present_before_resolution(defender_root, loop_module):
    g = seed_python_module(loop_module, defender_root, entry="run_one")
    assert any("__import__" in gp.detail for gp in g.gaps)
