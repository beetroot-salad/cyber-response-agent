"""The ratchet half of lint_unguarded_tree_write (#771 M3): a baselined site must say why."""
from __future__ import annotations

import json
from pathlib import Path

from _by_path import load_lint_gate

_GATE = load_lint_gate("lint_unguarded_tree_write")

_WRITE = "def stage(dst):\n    dst.mkdir(parents=True, exist_ok=True)\n"


def _run(tmp_path: Path, reason: str) -> int:
    scope = tmp_path / "scope"
    scope.mkdir()
    (scope / "stage_1191.py").write_text(_WRITE, encoding="utf-8")
    baseline = tmp_path / "baseline.json"
    baseline.write_text(json.dumps({"entries": {"stage_1191.py:stage": reason}}), encoding="utf-8")
    return _GATE.main([], scope=scope, baseline_path=baseline)


def test_a_baselined_site_with_a_reason_passes(tmp_path):
    assert _run(tmp_path, "false positive: writes a tmp dir no box can reach") == 0


def test_a_baselined_site_with_an_empty_reason_fails(tmp_path):
    """An empty reason means nobody looked. Without `require_reasons`, any change could bury a
    new unguarded write with `--update-baseline` and leave the reason blank."""
    assert _run(tmp_path, "") == 1
