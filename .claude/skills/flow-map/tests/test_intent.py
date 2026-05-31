"""intent.py — NL → resolved seed. Parser injected; zero live calls.

The deterministic core (resolve_seed, validate_intent, resolve_question wiring)
is exercised exhaustively; the haiku parser is replaced by a stub so the
classifier's job (pick mode/target) is simulated without a model.
"""
from __future__ import annotations

import pytest

from flowmap.intent import (
    Intent,
    IntentError,
    catalog,
    resolve_question,
    resolve_seed,
    validate_intent,
)
from flowmap.resolve import resolve_module_dispatch
from flowmap.seed import seed_python_module


def _build(synth_pkg):
    g = seed_python_module(synth_pkg["module"], synth_pkg["root"], entry="entry")
    resolve_module_dispatch(g, synth_pkg["module"], synth_pkg["root"])
    return g


# --------------------------------------------------------------------------- #
# deterministic seed resolution — scripts own identity
# --------------------------------------------------------------------------- #


def test_catalog_lists_bare_names(synth_pkg):
    g = _build(synth_pkg)
    names = catalog(g)
    assert "entry" in names and "invoke_actor" in names and "actor.md" in names


def test_resolve_exact_name(synth_pkg):
    g = _build(synth_pkg)
    assert resolve_seed(g, "invoke_actor") == "py:learn/main.py::invoke_actor"


def test_resolve_substring_when_unique(synth_pkg):
    g = _build(synth_pkg)
    # "actor.md" only appears in the agent-prompt node
    assert resolve_seed(g, "actor.md") == "agent-prompt:pkg/actor.md"


def test_resolve_absent_raises(synth_pkg):
    g = _build(synth_pkg)
    with pytest.raises(IntentError):
        resolve_seed(g, "does_not_exist")


def test_resolve_ambiguous_substring_raises(synth_pkg):
    g = _build(synth_pkg)
    # "run" substring hits run_script, run_batch (worker), _run_claude ...
    with pytest.raises(IntentError):
        resolve_seed(g, "run")


def test_resolve_never_invents(synth_pkg):
    """Every resolved id is a real node — the NL path cannot fabricate one."""
    g = _build(synth_pkg)
    for name in catalog(g):
        rid = resolve_seed(g, name) if len([n for n in g.nodes
                                            if n.split("::")[-1].split("/")[-1] == name]) == 1 \
            else None
        if rid is not None:
            assert rid in g.nodes


def test_validate_intent_rejects_bad_mode():
    with pytest.raises(IntentError):
        validate_intent(Intent("flowchart", "x"))


def test_validate_intent_rejects_empty_target():
    with pytest.raises(IntentError):
        validate_intent(Intent("component-card", "   "))


# --------------------------------------------------------------------------- #
# resolve_question wiring with an injected parser (the LLM seam)
# --------------------------------------------------------------------------- #


def _parser(mode, target):
    return lambda question, names: Intent(mode, target)


def test_component_question_resolves_seed(synth_pkg):
    g = _build(synth_pkg)
    intent, seed_id = resolve_question(
        g, "how does invoke_actor work?",
        parser=_parser("component-card", "invoke_actor"))
    assert intent.mode == "component-card"
    assert seed_id == "py:learn/main.py::invoke_actor"


def test_subsystem_question_resolves_driver(synth_pkg):
    g = _build(synth_pkg)
    intent, seed_id = resolve_question(
        g, "how does the entry flow work?",
        parser=_parser("subsystem-map", "entry"))
    assert intent.mode == "subsystem-map"
    assert seed_id == "py:learn/main.py::entry"


def test_parser_picking_fake_target_is_rejected(synth_pkg):
    """If the LLM returns a name not in the graph, resolution fails loudly."""
    g = _build(synth_pkg)
    with pytest.raises(IntentError):
        resolve_question(g, "q", parser=_parser("component-card", "imaginary_fn"))


def test_parser_seen_catalog_is_real(synth_pkg):
    """The parser is handed the real catalog (so it can only pick real names)."""
    g = _build(synth_pkg)
    seen = {}
    def spy(question, names):
        seen["names"] = names
        return Intent("component-card", "entry")
    resolve_question(g, "q", parser=spy)
    assert set(seen["names"]) == set(catalog(g))


# --------------------------------------------------------------------------- #
# golden: real question against the learning loop
# --------------------------------------------------------------------------- #


def test_golden_learning_loop_resolves_run_one(defender_root, loop_module):
    g = seed_python_module(loop_module, defender_root, entry="run_one")
    resolve_module_dispatch(g, loop_module, defender_root)
    intent, seed_id = resolve_question(
        g, "how does the learning loop work?",
        parser=_parser("subsystem-map", "run_one"))
    assert intent.mode == "subsystem-map"
    assert seed_id == "py:defender/learning/loop.py::run_one"
