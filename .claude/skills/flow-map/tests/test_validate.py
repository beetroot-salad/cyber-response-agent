"""validate.py — the trust lock. These tests prove it both PASSES on a faithful
graph AND FAILS on a tampered one. A validator that never fails is worthless, so
the tampering tests are the load-bearing ones.
"""
from __future__ import annotations

from flowmap.model import Edge, Node
from flowmap.resolve import resolve_module_dispatch
from flowmap.seed import seed_python_module
from flowmap.validate import (
    check_call_consistency,
    check_edges,
    check_refs,
    validate,
)


def _build(defender_root, loop_module, *, resolve: bool):
    g = seed_python_module(loop_module, defender_root, entry="run_one")
    if resolve:
        resolve_module_dispatch(g, loop_module, defender_root)
    return g


# --------------------------------------------------------------------------- #
# PASS: faithful graphs validate clean (both modes)
# --------------------------------------------------------------------------- #


def test_resolved_graph_validates_clean(defender_root, loop_module):
    g = _build(defender_root, loop_module, resolve=True)
    assert validate(g, loop_module, defender_root) == []


def test_unresolved_graph_validates_clean(defender_root, loop_module):
    g = _build(defender_root, loop_module, resolve=False)
    assert validate(g, loop_module, defender_root) == []


# --------------------------------------------------------------------------- #
# FAIL: each check must catch its own class of tampering
# --------------------------------------------------------------------------- #


def test_ref_check_catches_bad_line(defender_root, loop_module):
    g = _build(defender_root, loop_module, resolve=False)
    g.nodes["py:defender/learning/loop.py::run_one"].ref = "defender/learning/loop.py:99999"
    errs = check_refs(g, defender_root)
    assert any(e.startswith("[R]") for e in errs)


def test_ref_check_catches_nonexistent_file(defender_root, loop_module):
    g = _build(defender_root, loop_module, resolve=False)
    g.nodes["py:defender/learning/loop.py::run_one"].ref = "defender/nope.py:1"
    assert any(e.startswith("[R]") for e in check_refs(g, defender_root))


def test_edge_check_catches_dangling_endpoint(defender_root, loop_module):
    g = _build(defender_root, loop_module, resolve=False)
    g.add_edge(Edge("py:defender/learning/loop.py::run_one",
                    "py:defender/learning/loop.py::ghost", "calls"))
    assert any(e.startswith("[E]") for e in check_edges(g))


def test_consistency_catches_invented_local_call(defender_root, loop_module):
    g = _build(defender_root, loop_module, resolve=False)
    # invent a calls edge between two real funcs that don't actually call
    src = "py:defender/learning/loop.py::run_one"
    dst = "py:defender/learning/loop.py::_slugify"  # real func, not called by run_one
    g.add_edge(Edge(src, dst, "calls", via="ast"))
    errs = check_call_consistency(g, loop_module, defender_root)
    assert any("invented" in e for e in errs)


def test_consistency_catches_missing_local_call(defender_root, loop_module):
    g = _build(defender_root, loop_module, resolve=False)
    # drop a real edge run_one -> normalize_disposition
    src = "py:defender/learning/loop.py::run_one"
    dst = "py:defender/learning/loop.py::normalize_disposition"
    g.edges = [e for e in g.edges if not (e.src == src and e.dst == dst)]
    errs = check_call_consistency(g, loop_module, defender_root)
    assert any("missing" in e for e in errs)


def test_golden_catches_removed_dispatch(defender_root, loop_module):
    g = _build(defender_root, loop_module, resolve=False)
    # strip the actor dispatch — golden must notice the load-bearing edge is gone
    g.edges = [e for e in g.edges if not (e.kind == "dispatches"
                                          and e.dst.endswith("actor.md"))]
    errs = validate(g, loop_module, defender_root)
    assert any(e.startswith("[G]") for e in errs)


def test_cross_module_edges_do_not_trip_consistency(defender_root, loop_module):
    """Resolver-added cross-module calls must NOT be flagged as invented."""
    g = _build(defender_root, loop_module, resolve=True)
    errs = check_call_consistency(g, loop_module, defender_root)
    assert errs == []
