"""The shared baseline ratchet (#1364 O5): a baseline it cannot read unambiguously fails its lint
as scan-blind (exit 2, naming the file), in check and `--update-baseline` mode alike, and is
never rewritten. A missing baseline is still an empty one."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from _by_path import import_lint_lib, load_lint_gate

_baseline = import_lint_lib("_baseline")

_FINDING = _baseline.Finding("defender/a.py:token", "defender/a.py:3: token")

_DUPLICATE = ('{"//": "h", "entries": {"defender/a.py:token": "first reason",\n'
              '"defender/a.py:token": "second reason"}}\n')
_UNREADABLE = {
    "duplicate entry": (_DUPLICATE, "defender/a.py:token"),
    "duplicate top-level key": ('{"//": "h", "//": "h2", "entries": {}}\n', "//"),
    "not JSON": ('{"entries": {"defender/a.py:token": ""\n<<<<<<< HEAD\n', "not valid JSON"),
    "entries not an object": ('{"entries": ["defender/a.py:token"]}\n', "entries"),
    "a reason that is not text": ('{"entries": {"defender/a.py:token": 3}}\n', "defender/a.py:token"),
    "not an object": ('["defender/a.py:token"]\n', "object"),
}


def _gate(path: Path, *, update: bool = False, require_reasons: bool = False) -> int:
    return _baseline.gate([_FINDING], path, ["--update-baseline"] if update else [],
                          label="lint_x", header="h", require_reasons=require_reasons)


@pytest.mark.parametrize("update", [False, True], ids=["check", "update"])
@pytest.mark.parametrize("case", sorted(_UNREADABLE))
def test_an_unreadable_baseline_is_scan_blind_and_left_as_it_is(tmp_path, capsys, case, update):
    text, named = _UNREADABLE[case]
    path = tmp_path / "lint_x_baseline.json"
    path.write_text(text, encoding="utf-8")
    assert _gate(path, update=update) == 2
    out = capsys.readouterr()
    said = out.out + out.err
    assert "[lint_x]" in said and path.name in said and named in said, said
    assert path.read_text(encoding="utf-8") == text


def test_the_unreadable_cases_are_all_exercised():
    assert len(_UNREADABLE) == 6


def test_a_missing_baseline_is_empty(tmp_path):
    path = tmp_path / "lint_x_baseline.json"
    assert _gate(path) == 1
    assert _gate(path, update=True) == 0
    assert json.loads(path.read_text(encoding="utf-8"))["entries"] == {"defender/a.py:token": ""}


def test_a_well_formed_baseline_still_gates(tmp_path):
    path = tmp_path / "lint_x_baseline.json"
    path.write_text(json.dumps({"//": "h", "entries": {"defender/a.py:token": "why"}}),
                    encoding="utf-8")
    assert _gate(path, require_reasons=True) == 0


def test_the_import_order_lint_refuses_a_duplicate_baseline(tmp_path, capsys):
    lint = load_lint_gate("lint_import_order")
    root = tmp_path / "defender"
    (root / "kit").mkdir(parents=True)
    (root / "kit" / "__init__.py").write_text("", encoding="utf-8")
    path = tmp_path / "b.json"
    path.write_text(_DUPLICATE, encoding="utf-8")
    assert lint.main(["--root", str(root), "--baseline", str(path)]) == 2
    said = capsys.readouterr()
    assert path.name in said.out + said.err
