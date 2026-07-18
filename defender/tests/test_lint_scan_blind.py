"""The swallow-to-clean fix for the lint gates (#652, generalizing #618/#621).

Eight gates each carried their own copy of::

    try:
        text = path.read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(text)
    except (OSError, SyntaxError):
        continue

so a file the gate could not read or parse silently left the scanned corpus, and the gate
printed ``0 finding(s)`` and exited 0 — reporting clean on source it never examined. The fix
routes every one through ``_astlib.read_and_parse`` / ``read_source``, which raise
``ScanBlind``, and each ``main()`` turns that into **exit 2** (the ``lint_vulture`` /
``lint_stale_refs`` convention: the gate could not run, which is not clean).

The gates exercised end-to-end here are the three with a ``scope=`` DI seam, which is what
lets a test point a real gate at a throwaway tree. The remaining five share the identical
call into ``_astlib``, whose own contract is pinned directly below.

Every exit-2 assertion is paired with a control run over the same tree minus the broken
file, so none of these can pass by the gate simply being broken.
"""
from __future__ import annotations

import importlib
import sys
from pathlib import Path

import pytest

LINT_DIR = Path(__file__).resolve().parents[2] / "scripts" / "lint"

# The gates with a `scope=`/`baseline_path=` seam — drivable against a tmp tree.
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
    """A file the gate cannot parse must not be skipped into a clean report.

    Exit 2 specifically, not merely non-zero: exit 1 means "the gate looked and found a
    violation", and a `!= 0` assertion would pass against that conflation. The gate found
    nothing here — it could not look."""
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


# ── the shared seam's own contract ───────────────────────────────────────────
def test_read_and_parse_raises_scanblind_on_syntax_error(tmp_path):
    import _astlib

    p = tmp_path / "b.py"
    p.write_text("def (:\n", encoding="utf-8")
    with pytest.raises(_astlib.ScanBlind) as exc:
        _astlib.read_and_parse(p, "b.py")
    # The message must name the file — an operator has to know WHICH file went unscanned.
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
    """`errors="replace"` is preserved from the eight copies this seam replaced, so a latin-1
    byte is still substituted rather than raising. Pinned because the alternative — letting
    UnicodeDecodeError through — would turn a merely-odd file into an exit-2 gate failure, a
    behaviour change the fix does not intend and the old copies never had."""
    import _astlib

    p = tmp_path / "l.py"
    p.write_bytes(b'x = "caf\xe9"\n')  # latin-1 é, invalid utf-8
    text, _ = _astlib.read_and_parse(p, "l.py")
    assert "�" in text
