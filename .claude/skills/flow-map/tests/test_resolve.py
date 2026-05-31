"""resolve.py — deterministic gap-closure (cross-module dispatch)."""
from __future__ import annotations

from flowmap.resolve import resolve_module_dispatch
from flowmap.seed import seed_python_module


# --------------------------------------------------------------------------- #
# Tier 1 — synthetic
# --------------------------------------------------------------------------- #


def test_resolve_closes_dynamic_import(synth_pkg):
    g = seed_python_module(synth_pkg["module"], synth_pkg["root"], entry="entry")
    assert any(gp.kind == "dynamic-dispatch" for gp in g.gaps)  # precondition

    summary = resolve_module_dispatch(g, synth_pkg["module"], synth_pkg["root"])

    assert summary["gaps_dropped"] == 1
    assert not any(gp.kind == "dynamic-dispatch" for gp in g.gaps)
    # trigger("worker") -> worker.run_batch, recovered from the literal call-site arg
    assert any(
        e.src == "py:learn/main.py::trigger"
        and e.dst == "py:learn/worker.py::run_batch"
        and e.via == "dynamic-import"
        for e in g.edges
    )


def test_resolve_closes_static_cross_module_call(synth_pkg):
    g = seed_python_module(synth_pkg["module"], synth_pkg["root"], entry="entry")
    resolve_module_dispatch(g, synth_pkg["module"], synth_pkg["root"])
    # helper.assist() — silently dropped by the per-expression seed, recovered here
    assert any(
        e.src == "py:learn/main.py::entry"
        and e.dst == "py:learn/helper.py::assist"
        and e.via == "module-attr"
        for e in g.edges
    )


def test_resolve_label_names_resolved_module(synth_pkg):
    g = seed_python_module(synth_pkg["module"], synth_pkg["root"], entry="entry")
    resolve_module_dispatch(g, synth_pkg["module"], synth_pkg["root"])
    edge = next(e for e in g.edges if e.via == "dynamic-import")
    assert edge.label == "worker.run_batch"


def test_resolve_skips_nonexistent_sibling(synth_pkg):
    # rewrite trigger() to import a module with no sibling file on disk
    mod = synth_pkg["module"]
    src = mod.read_text().replace('trigger("worker")', 'trigger("ghost")')
    mod.write_text(src)
    g = seed_python_module(mod, synth_pkg["root"], entry="entry")
    summary = resolve_module_dispatch(g, mod, synth_pkg["root"])
    # no sibling ghost.py -> no edge, gap NOT dropped (honest: still unresolved)
    assert not any(e.dst.endswith("ghost.py::run_batch") for e in g.edges)
    assert summary["gaps_dropped"] == 0
    assert any(gp.kind == "dynamic-dispatch" for gp in g.gaps)


def test_resolved_edges_are_deterministic(synth_pkg):
    g = seed_python_module(synth_pkg["module"], synth_pkg["root"], entry="entry")
    resolve_module_dispatch(g, synth_pkg["module"], synth_pkg["root"])
    for e in g.edges:
        if e.via in ("dynamic-import", "module-attr"):
            assert e.confidence == "deterministic"
            assert e.resolved_by == "seed"


# --------------------------------------------------------------------------- #
# Tier 2 — golden (real loop.py): the three curators + silent-drop recoveries
# --------------------------------------------------------------------------- #

REL = "defender/learning/loop.py"

EXPECTED_CURATORS = {
    "py:defender/learning/author.py::run_batch",
    "py:defender/learning/author_actor.py::run_batch",
    "py:defender/learning/author_actor_benign.py::run_batch",
}


def test_golden_curators_resolved(defender_root, loop_module):
    g = seed_python_module(loop_module, defender_root, entry="run_one")
    resolve_module_dispatch(g, loop_module, defender_root)
    trig = f"py:{REL}::_maybe_trigger_author"
    got = {e.dst for e in g.edges if e.src == trig and e.via == "dynamic-import"}
    assert got == EXPECTED_CURATORS


def test_golden_import_gap_closed(defender_root, loop_module):
    g = seed_python_module(loop_module, defender_root, entry="run_one")
    resolve_module_dispatch(g, loop_module, defender_root)
    assert not any("__import__" in gp.detail for gp in g.gaps)


def test_golden_silent_drops_recovered(defender_root, loop_module):
    g = seed_python_module(loop_module, defender_root, entry="run_one")
    resolve_module_dispatch(g, loop_module, defender_root)
    dsts = {e.dst for e in g.edges if e.via == "module-attr"}
    assert "py:defender/learning/lead_author.py::run" in dsts
    assert "py:defender/learning/mitre_corpus.py::sample_menu" in dsts


def test_golden_resolved_targets_exist_in_source(defender_root, loop_module):
    """Every resolved cross-module edge points at a real FunctionDef."""
    import ast
    g = seed_python_module(loop_module, defender_root, entry="run_one")
    resolve_module_dispatch(g, loop_module, defender_root)
    for e in g.edges:
        if e.via not in ("dynamic-import", "module-attr"):
            continue
        relpath, _, fn = e.dst[len("py:"):].partition("::")
        path = defender_root / relpath
        assert path.is_file(), f"{e.dst}: file missing"
        tree = ast.parse(path.read_text())
        assert any(
            isinstance(d, (ast.FunctionDef, ast.AsyncFunctionDef)) and d.name == fn
            for d in ast.walk(tree)
        ), f"{e.dst}: no def {fn}"
