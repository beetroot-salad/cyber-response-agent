"""scope.py — deterministic component card. No LLM."""
from __future__ import annotations

import pytest

from flowmap.resolve import resolve_module_dispatch
from flowmap.scope import (
    component_card,
    render_card_markdown,
)
from flowmap.seed import seed_python_module


def _build(synth_pkg):
    g = seed_python_module(synth_pkg["module"], synth_pkg["root"], entry="entry")
    resolve_module_dispatch(g, synth_pkg["module"], synth_pkg["root"])
    return g


# --------------------------------------------------------------------------- #
# component card
# --------------------------------------------------------------------------- #


def test_component_card_keeps_focus_callers_targets(synth_pkg):
    g = _build(synth_pkg)
    res = component_card(g, "py:learn/main.py::invoke_actor")
    ids = set(res.graph.nodes)
    assert "py:learn/main.py::invoke_actor" in ids        # focus
    assert "py:learn/main.py::entry" in ids               # caller
    assert "agent-prompt:pkg/actor.md" in ids             # dispatch target
    assert res.mode == "component-card"


def test_card_markdown_is_source_faithful(synth_pkg):
    g = _build(synth_pkg)
    md = render_card_markdown(g, "py:learn/main.py::invoke_actor")
    assert "invoke_actor" in md
    assert "called by" in md and "entry" in md
    assert "dispatches" in md and "actor.md" in md
    assert "learn/main.py:" in md  # ref present


def test_component_card_unknown_raises(synth_pkg):
    g = _build(synth_pkg)
    with pytest.raises(ValueError):
        component_card(g, "py:learn/main.py::ghost")


def test_card_keeps_callers_and_targets(synth_pkg):
    g = _build(synth_pkg)
    res = component_card(g, "py:learn/main.py::entry")
    ids = set(res.graph.nodes)
    assert "py:learn/main.py::entry" in ids                # focus
    assert "py:learn/main.py::invoke_actor" in ids         # an outbound call
    assert res.collapsed == 0
