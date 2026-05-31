"""CLI — the `build` command makes verification integral.

These assert the contract the user cares about: a built graph is verified as
part of producing it. Structural always gates; the differential is env/flag
gated and never runs unless opted in. Run via the in-process entrypoint with a
monkeypatched tracer so there are zero live calls.
"""
from __future__ import annotations

import json
from pathlib import Path

import flowmap.verify as verify
from flowmap import __doc__ as _pkgdoc  # noqa: F401  (ensure package importable)

import importlib.util

# load the top-level flowmap.py CLI module (not the package) by path
_CLI_PATH = Path(__file__).resolve().parents[1] / "flowmap.py"
_spec = importlib.util.spec_from_file_location("flowmap_cli", _CLI_PATH)
cli = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cli)


def test_build_runs_structural_and_writes_graph(defender_root, loop_module, tmp_path):
    out = tmp_path / "graph.json"
    rc = cli.main([
        "build", str(loop_module), "--root", str(defender_root),
        "--entry", "run_one", "--out", str(out),
    ])
    assert rc == 0                      # structural passed, no differential
    doc = json.loads(out.read_text())
    assert doc["schema_version"] == 1
    assert any(e["kind"] == "dispatches" for e in doc["edges"])


def test_build_fails_on_structural_error(defender_root, loop_module, tmp_path, monkeypatch):
    # _cmd_build delegates structural checking to differential_verify, which
    # calls `validate` as imported into the verify module — patch it THERE, not
    # on the cli module (where build never looks it up).
    monkeypatch.setattr(verify, "validate", lambda g, m, r: ["[R] injected error"])
    rc = cli.main([
        "build", str(loop_module), "--root", str(defender_root), "--entry", "run_one",
    ])
    assert rc == 1


def test_build_differential_off_by_default(defender_root, loop_module, monkeypatch):
    monkeypatch.delenv("FLOWMAP_DIFFERENTIAL", raising=False)
    def boom(artifact, question):
        raise AssertionError("differential ran without opt-in")
    monkeypatch.setattr(verify, "_default_tracer", boom)
    rc = cli.main([
        "build", str(loop_module), "--root", str(defender_root), "--entry", "run_one",
    ])
    assert rc == 0  # clean build, differential never invoked


def test_build_differential_runs_when_forced(defender_root, loop_module, monkeypatch):
    # inject a faithful tracer = the graph's own out-edges, so it agrees
    from flowmap.verify import expected_steps_from_graph

    captured = {}

    def fake_diff(g, module, root, specs, *, tracer=None, run_differential=None):
        captured["ran"] = True
        captured["specs"] = [s.seed_func for s in specs]
        from flowmap.verify import VerifyResult
        return VerifyResult(structural=[], differentials=[], gaps=[])

    monkeypatch.setattr(cli, "differential_verify", fake_diff)
    rc = cli.main([
        "build", str(loop_module), "--root", str(defender_root),
        "--entry", "run_one", "--differential",
    ])
    assert rc == 0
    assert captured["ran"]
    assert "run_one" in captured["specs"]  # entry always verified


def test_map_component_card(defender_root, loop_module, monkeypatch):
    """`map` routes a component question to a card + mermaid, no live call."""
    from flowmap.intent import Intent
    # patch the resolve step (the LLM seam) to a fixed intent + real seed id;
    # component-card rendering is fully deterministic, so no live call follows.
    monkeypatch.setattr(
        cli, "resolve_question",
        lambda g, q: (Intent("component-card", "invoke_actor"),
                      "py:defender/learning/loop.py::invoke_actor"))
    rc = cli.main([
        "map", "how does invoke_actor work?", str(loop_module),
        "--root", str(defender_root), "--entry", "run_one",
    ])
    assert rc == 0


def test_map_subsystem(defender_root, loop_module, monkeypatch):
    """`map` routes a subsystem question to the logic view. The intent seam and
    the representation seam are both injected, so there are zero live calls."""
    from flowmap.intent import Intent
    from flowmap.logic import render_logic_view as real_view

    monkeypatch.setattr(
        cli, "resolve_question",
        lambda g, q: (Intent("subsystem-map", "run_one"),
                      "py:defender/learning/loop.py::run_one"))
    # inject a no-op representer (degrade to raw labels) -> no haiku call
    monkeypatch.setattr(
        cli, "render_logic_view",
        lambda cg, m, r, fn, **k: real_view(cg, m, r, fn, representer=lambda reqs: {}))
    rc = cli.main([
        "map", "how does the learning loop work?", str(loop_module),
        "--root", str(defender_root), "--entry", "run_one",
    ])
    assert rc == 0


def test_map_unresolvable_target_fails_cleanly(defender_root, loop_module, monkeypatch):
    from flowmap.intent import IntentError

    def boom(g, q):
        raise IntentError("no node matches 'imaginary_xyz'")
    monkeypatch.setattr(cli, "resolve_question", boom)
    rc = cli.main([
        "map", "how does imaginary_xyz work?", str(loop_module),
        "--root", str(defender_root), "--entry", "run_one",
    ])
    assert rc == 1  # actionable failure, not a crash


def test_map_subsystem_rejects_non_function_target(defender_root, loop_module, monkeypatch):
    """A subsystem-map whose target resolves to a prompt/script (not a function)
    fails cleanly rather than crashing in the CFG builder."""
    from flowmap.intent import Intent
    monkeypatch.setattr(
        cli, "resolve_question",
        lambda g, q: (Intent("subsystem-map", "actor.md"),
                      "agent-prompt:defender/learning/prompts/actor.md"))
    rc = cli.main([
        "map", "how does actor.md work?", str(loop_module),
        "--root", str(defender_root), "--entry", "run_one",
    ])
    assert rc == 1


def test_seed_command_does_not_verify(defender_root, loop_module, monkeypatch):
    """`seed` is extraction-only — it must not invoke verification."""
    def boom(*a, **k):
        raise AssertionError("seed must not verify")
    monkeypatch.setattr(cli, "differential_verify", boom)
    rc = cli.main([
        "seed", str(loop_module), "--root", str(defender_root), "--entry", "run_one",
    ])
    assert rc == 0
