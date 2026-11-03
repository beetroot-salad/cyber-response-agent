"""Tests for the lint_adapter_replay_blind gate (#1385 L1): no adapter, nor the adapter kit's
interface, reads the branch point, the run state or the run clock; host-state stamps no time."""
from __future__ import annotations

from pathlib import Path

import pytest

from _by_path import load_lint_gate

_GATE = load_lint_gate("lint_adapter_replay_blind")

#: An adapter as #1385 leaves one: its context's env, and (tacit-knowledge's interim) today's date.
_CLEAN_ADAPTER = ("import datetime as dt\n"
                  "def query(ctx, *, q):\n"
                  "    day = dt.datetime.now(dt.UTC).date()\n"
                  "    return {'q': q, 'base': ctx.env.get('BASE'), 'day': str(day)}\n")
_KIT = ("from typing import Protocol\n"
        "class VerbContext(Protocol):\n"
        "    @property\n"
        "    def env(self): ...\n")


def _tree(tmp_path: Path, files: dict[str, str]) -> Path:
    root = tmp_path / "defender"
    for rel, text in {"kit/verbs.py": _KIT, **files}.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root


def test_the_real_tree_is_clean():
    """The checkout's adapters and kit carry no replay input (L1)."""
    assert _GATE.main([]) == 0


def test_a_clean_adapter_and_tests_reading_the_cut_have_no_findings(tmp_path):
    """Positive control: a replay-blind adapter, and a test stub reading `as_of`, pass (L1)."""
    stub = "def query(ctx):\n    return getattr(ctx, 'as_of', None)\n"
    files = {"integrations/x_adapter.py": _CLEAN_ADAPTER, "tests/t_adapter.py": stub}
    assert _GATE.scan(_tree(tmp_path, files)) == []


@pytest.mark.parametrize("line", [
    "    at = getattr(ctx, 'as_of', None)",
    "    at = ctx.as_of",
    "    at = getattr(ctx, 'run_state', None)",
    "    at = ctx.run_state.now()",
])
def test_an_adapter_reading_the_branch_point_or_run_state_is_found(tmp_path, line):
    """Each spelling #1385 removed from the adapters is a finding at its line (L1)."""
    src = f"def query(ctx, *, q):\n{line}\n    return {{'q': q}}\n"
    found = _GATE.scan(_tree(tmp_path, {"integrations/x_adapter.py": src}))
    assert found, found
    assert all("integrations/x_adapter.py:2" in f for f in found), found


@pytest.mark.parametrize("name", ["as_of", "run_state"])
def test_the_kit_interface_offering_a_replay_input_is_found(tmp_path, name):
    """The adapter kit's protocol declaring `as_of` or `run_state` is a finding (L1)."""
    kit = f"{_KIT}    @property\n    def {name}(self): ...\n"
    found = _GATE.scan(_tree(tmp_path, {"kit/verbs.py": kit}))
    assert len(found) == 1 and "kit/verbs.py" in found[0] and name in found[0], found


def test_host_state_stamping_its_own_time_is_found(tmp_path):
    """Host-state reading a clock to stamp a capture is a finding; another adapter's is not (L1)."""
    found = _GATE.scan(_tree(tmp_path, {"integrations/host_state_adapter.py": _CLEAN_ADAPTER,
                                        "integrations/x_adapter.py": _CLEAN_ADAPTER}))
    assert len(found) == 1 and "integrations/host_state_adapter.py:3" in found[0], found
