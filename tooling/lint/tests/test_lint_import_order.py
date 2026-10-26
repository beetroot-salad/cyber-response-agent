"""Tests for the lint_import_order gate (#1080): one declared order over `defender/`'s top-level
packages, the two adapter rules, and a baseline that only shrinks and names an owner."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from _by_path import load_lint_gate

_GATE = load_lint_gate("lint_import_order")


def _tree(tmp_path: Path, files: dict[str, str]) -> Path:
    root = tmp_path / "defender"
    for rel, text in {"kit/__init__.py": "", "records/__init__.py": "",
                      "runtime/__init__.py": "", **files}.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root


def _prints(found) -> list[str]:
    return sorted(f.fingerprint for f in found)


def test_downward_imports_are_clean(tmp_path):
    root = _tree(tmp_path, {
        "runtime/engine.py": "from defender.records import store\nfrom defender.kit import faults\n",
        "records/store.py": "from defender import _io\n",
        "_io.py": "",
        "kit/faults.py": "",
    })
    assert _GATE.scan(root) == []


@pytest.mark.parametrize("src", [
    "from defender.runtime import engine\n",
    "def f():\n    from defender.runtime import engine\n",
    "from typing import TYPE_CHECKING\nif TYPE_CHECKING:\n    from defender.runtime import engine\n",
    "from typing import TYPE_CHECKING\nif not TYPE_CHECKING:\n    from defender.runtime import engine\n",
    "import defender.runtime.engine\n",
    "from ..runtime import engine\n",
])
def test_an_upward_import_is_found_however_it_is_spelled(tmp_path, src):
    root = _tree(tmp_path, {"records/store.py": src, "runtime/engine.py": ""})
    assert _prints(_GATE.scan(root)) == ["records/store.py:defender.runtime.engine"]


def test_the_fingerprint_is_the_resolved_module_not_the_package(tmp_path):
    root = _tree(tmp_path, {
        "records/store.py": "from defender.runtime import engine, CONSTANT\n",
        "runtime/engine.py": "",
    })
    assert _prints(_GATE.scan(root)) == [
        "records/store.py:defender.runtime", "records/store.py:defender.runtime.engine"]


def test_flat_modules_are_one_node_and_entry_modules_their_own(tmp_path):
    root = _tree(tmp_path, {
        "_io.py": "from defender import _paths\n",
        "_paths.py": "from defender import run_common\n",
        "run_common.py": "",
    })
    assert _prints(_GATE.scan(root)) == ["_paths.py:defender.run_common"]


def test_a_folder_without_an_entry_file_is_its_own_node(tmp_path):
    root = _tree(tmp_path, {"_filesystem/bound.py": "from defender._filesystem import write\n",
                            "_filesystem/write.py": ""})
    assert _GATE.scan(root) == []


def test_an_unplaced_package_fails_without_a_baseline(tmp_path, capsys):
    root = _tree(tmp_path, {"newthing/__init__.py": ""})
    with pytest.raises(_GATE.Unplaced):
        _GATE.scan(root)
    assert _GATE.main(["--root", str(root), "--baseline", str(tmp_path / "b.json")]) == 1
    assert "newthing" in capsys.readouterr().out


def test_an_adapter_imports_only_the_kit_flat_tier_and_knowledge(tmp_path):
    root = _tree(tmp_path, {
        "integrations/a_adapter.py": "from defender.kit import faults\nfrom defender import _io\n"
                                     "from defender.knowledge import x\nfrom . import _transport\n"
                                     "from defender.records import store\n",
        "integrations/_transport.py": "",
        "knowledge/x.py": "", "_io.py": "", "kit/faults.py": "", "records/store.py": "",
    })
    assert _prints(_GATE.scan(root)) == [
        "adapter-imports:integrations/a_adapter.py:defender.records.store"]


def test_any_import_of_adapter_code_from_outside_is_found(tmp_path):
    root = _tree(tmp_path, {
        "integrations/_transport.py": "",
        "integrations/a_adapter.py": "from defender.integrations import _transport\n",
        "cli/tacit_cli.py": "def f():\n    from defender.integrations import _transport\n",
    })
    assert _prints(_GATE.scan(root)) == [
        "imports-adapters:cli/tacit_cli.py:defender.integrations._transport"]


def test_importing_a_folder_package_by_name_is_judged(tmp_path):
    root = _tree(tmp_path, {"records/store.py": "from defender import learning\n",
                            "learning/core.py": ""})
    assert _prints(_GATE.scan(root)) == ["records/store.py:defender.learning"]


@pytest.mark.parametrize("src", [
    "from defender._gone import y\n",
    "from defender import _gone\n",
    "def f():\n    from defender.tests.support import helper\n",
    "try:\n    from defender.optional_thing import x\nexcept ImportError:\n    x = None\n",
])
def test_an_import_of_anything_not_scanned_is_outside_the_order(tmp_path, src):
    root = _tree(tmp_path, {"records/store.py": src, "tests/support/helper.py": ""})
    assert _GATE.scan(root) == []


def _write_baseline(path: Path, entries: dict[str, str]) -> Path:
    path.write_text(json.dumps({"//": "", "entries": entries}), encoding="utf-8")
    return path


def _upward(tmp_path: Path) -> Path:
    return _tree(tmp_path, {"records/store.py": "from defender.runtime import engine\n",
                            "runtime/engine.py": ""})


def test_a_listed_upward_import_with_an_owner_passes(tmp_path):
    root = _upward(tmp_path)
    baseline = _write_baseline(tmp_path / "b.json",
                               {"records/store.py:defender.runtime.engine": "#1309 (a): why"})
    assert _GATE.main(["--root", str(root), "--baseline", str(baseline)]) == 0


def test_an_unlisted_upward_import_fails(tmp_path):
    root = _upward(tmp_path)
    baseline = _write_baseline(tmp_path / "b.json", {})
    assert _GATE.main(["--root", str(root), "--baseline", str(baseline)]) == 1


def test_an_entry_without_an_owner_issue_fails(tmp_path, capsys):
    root = _upward(tmp_path)
    baseline = _write_baseline(tmp_path / "b.json",
                               {"records/store.py:defender.runtime.engine": "accepted for now"})
    assert _GATE.main(["--root", str(root), "--baseline", str(baseline)]) == 1
    assert "ownerless" in capsys.readouterr().out


def test_a_stale_entry_fails(tmp_path, capsys):
    root = _tree(tmp_path, {"runtime/engine.py": ""})
    baseline = _write_baseline(tmp_path / "b.json",
                               {"records/store.py:defender.runtime.engine": "#1309 (a): why"})
    assert _GATE.main(["--root", str(root), "--baseline", str(baseline)]) == 1
    assert "stale" in capsys.readouterr().out


def test_an_unparseable_file_cannot_be_cleared(tmp_path):
    root = _tree(tmp_path, {"records/store.py": "def (:\n"})
    assert _GATE.main(["--root", str(root), "--baseline", str(tmp_path / "b.json")]) == 2


def test_the_order_names_every_package_of_this_checkout():
    rels = _GATE._files(_GATE.DEFENDER).values()
    assert {_GATE.node_of(rel) for rel in rels} <= set(_GATE.ORDER)
