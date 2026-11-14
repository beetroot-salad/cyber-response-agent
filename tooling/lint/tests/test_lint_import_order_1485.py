"""#1485 P1: the learning store is its own top-level package, `learning_store`, placed directly below `learning`, so the
import-order fence keeps every import of `defender.learning` out of it (function-level ones included)."""
from __future__ import annotations

from pathlib import Path

import pytest

from _by_path import load_lint_gate

_GATE = load_lint_gate("lint_import_order")
_DEFENDER = Path(__file__).resolve().parents[3] / "defender"
_BELOW = ("knowledge", "jobs", "database", "tenancy", "records", "_flat")
_ABOVE = ("run_common", "lifecycle", "cli", "api")


def _tree(tmp_path: Path, files: dict[str, str]) -> Path:
    root = tmp_path / "defender"
    for rel, text in {"learning/__init__.py": "", "learning/core.py": "", "learning_store/__init__.py": "",
                      "jobs/__init__.py": "", "knowledge/__init__.py": "", **files}.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root


def test_p1_learning_store_sits_directly_below_learning_above_the_layers_it_uses():
    """`learning_store` is in `ORDER` one place before `learning`, above knowledge, jobs, database, tenancy and
    records, below run_common, lifecycle, cli and api. (P1, Names)"""
    order = list(_GATE.ORDER)
    assert "learning_store" in order
    at = order.index("learning_store")
    assert order[at + 1] == "learning"
    assert all(order.index(n) < at for n in _BELOW)
    assert all(order.index(n) > at for n in _ABOVE)


@pytest.mark.parametrize("src", [
    "from defender.learning import core\n",
    "def f():\n    from defender.learning import core\n",
    "from typing import TYPE_CHECKING\nif TYPE_CHECKING:\n    from defender.learning import core\n",
    "import defender.learning.core\n",
    "from ..learning import core\n",
])
def test_p1_any_import_of_learning_inside_the_store_is_a_finding_however_spelled(tmp_path, src):
    """An import of `defender.learning` in `learning_store/`, at module level, in a function, under TYPE_CHECKING, dotted
    or relative, is reported as pointing up. (P1)"""
    root = _tree(tmp_path, {"learning_store/_store.py": src})
    assert sorted(f.fingerprint for f in _GATE.scan(root)) == ["learning_store/_store.py:defender.learning.core"]


def test_p1_the_downward_imports_of_the_store_and_of_learning_are_clean(tmp_path):
    """Control for the cases above: learning imports the store, and the store imports jobs and knowledge, with no
    finding. (P1)"""
    root = _tree(tmp_path, {
        "learning/store_user.py": "from defender.learning_store import LearningStore\n",
        "learning_store/_store.py": "from defender.jobs import x\nfrom defender.knowledge import y\n",
        "jobs/x.py": "", "knowledge/y.py": "",
    })
    assert _GATE.scan(root) == []


def test_p1_nothing_in_the_real_learning_store_imports_up_and_the_baseline_excuses_none():
    """In this checkout `defender/learning_store/` exists, `learning/store/` is gone, no file of the store imports
    up the order, and no baseline entry names the store. (P1, Names)"""
    assert (_DEFENDER / "learning_store" / "__init__.py").is_file(), "the lifted package is missing"
    assert not (_DEFENDER / "learning" / "store").exists(), "no shim: the old package is gone"
    assert [f.display for f in _GATE.scan(_DEFENDER) if "learning_store/" in f.fingerprint] == []
    excused = [k for k in _GATE._load_entries(_GATE.BASELINE) if k.startswith("learning_store/") or "learning_store" in k.split(":")[-1]]
    assert excused == []
