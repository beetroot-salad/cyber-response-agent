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


def test_seed_command_does_not_verify(defender_root, loop_module, monkeypatch):
    """`seed` is extraction-only — it must not invoke verification."""
    def boom(*a, **k):
        raise AssertionError("seed must not verify")
    monkeypatch.setattr(cli, "differential_verify", boom)
    rc = cli.main([
        "seed", str(loop_module), "--root", str(defender_root), "--entry", "run_one",
    ])
    assert rc == 0
