"""Lint gates exit 2 (never clean) when a file in scope cannot be read or parsed."""
from __future__ import annotations

import importlib
import sys
from pathlib import Path

import pytest

LINT_DIR = Path(__file__).resolve().parents[1]

DI_GATES = ["lint_unpinned_text_io", "lint_unsafe_jsonl_io", "lint_hand_rolled_frontmatter"]


@pytest.fixture(autouse=True)
def _lint_dir_on_path():
    if str(LINT_DIR) not in sys.path:
        sys.path.insert(0, str(LINT_DIR))


@pytest.fixture
def tree(tmp_path):
    """A minimal clean scan scope plus its baseline."""
    (tmp_path / "fine.py").write_text("x = 1\n", encoding="utf-8")
    baseline = tmp_path / "baseline.json"
    baseline.write_text('{"entries": {}}', encoding="utf-8")
    return tmp_path, baseline


@pytest.mark.parametrize("mod_name", DI_GATES)
def test_unparseable_file_in_scope_exits_2_not_0(mod_name, tree, capsys):
    scope, baseline = tree
    (scope / "broken.py").write_text("def (:\n", encoding="utf-8")
    mod = importlib.import_module(mod_name)
    assert mod.main([], scope=scope, baseline_path=baseline) == 2
    assert "broken.py" in capsys.readouterr().err


@pytest.mark.parametrize("mod_name", DI_GATES)
def test_control_same_tree_without_the_broken_file_is_clean(mod_name, tree):
    """The control for the test above: identical scope, no unparseable file, exit 0. Without
    this, the exit-2 test would also pass against a gate that returned 2 unconditionally."""
    scope, baseline = tree
    mod = importlib.import_module(mod_name)
    assert mod.main([], scope=scope, baseline_path=baseline) == 0


@pytest.mark.parametrize("mod_name", DI_GATES)
def test_unreadable_file_in_scope_exits_2(mod_name, tree, capsys):
    """The OSError twin of the parse case — a file in scope that cannot be read at all."""
    scope, baseline = tree
    victim = scope / "denied.py"
    victim.write_text("x = 1\n", encoding="utf-8")
    victim.chmod(0o000)
    try:
        mod = importlib.import_module(mod_name)
        if mod.main([], scope=scope, baseline_path=baseline) == 0:
            pytest.skip("running as root: chmod 000 does not deny the read")
        assert "denied.py" in capsys.readouterr().err
    finally:
        victim.chmod(0o644)


def test_read_and_parse_raises_scanblind_on_syntax_error(tmp_path):
    import _astlib

    p = tmp_path / "b.py"
    p.write_text("def (:\n", encoding="utf-8")
    with pytest.raises(_astlib.ScanBlind) as exc:
        _astlib.read_and_parse(p, "b.py")
    assert "b.py" in str(exc.value)


def test_read_and_parse_returns_text_and_tree_on_a_good_file(tmp_path):
    import ast

    import _astlib

    p = tmp_path / "g.py"
    p.write_text("x = 1\n", encoding="utf-8")
    text, tree = _astlib.read_and_parse(p, "g.py")
    assert text == "x = 1\n"
    assert isinstance(tree, ast.Module)


def test_read_and_parse_still_replaces_undecodable_bytes(tmp_path):
    import _astlib

    p = tmp_path / "l.py"
    p.write_bytes(b'x = "caf\xe9"\n')
    text, _ = _astlib.read_and_parse(p, "l.py")
    assert "�" in text
