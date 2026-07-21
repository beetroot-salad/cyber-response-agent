"""The lint gate that keeps the fold from regressing: lint_hand_rolled_frontmatter
(spec_graph_591 d0_lint_gate + d_lint_*).

The gate (fork L1: pytest coverage, departing from the no-lint-tests house
convention) AST-scans defender/ for NEW hand-rolled fence-parse call sites and
runs the shared _baseline.gate ratchet. These tests are RED against HEAD: the
module does not exist yet (each test fails loading it — "missing module"), and
the real-tree-clean run additionally depends on the five sites having landed.

The gate is driven through its TESTABILITY SEAM, which the spec defines and the
implementation must conform to:
  - main(argv=None, *, scope=None, baseline_path=None): keyword overrides default
    to the module constants;
  - _scan(root) -> list[Finding]: per-file findings under ``root``.
The gate lives at repo-root scripts/lint/ (not under defender/), so its path is
derived from this file, never hardcoded to /workspace.
"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

WORKTREE = Path(__file__).resolve().parents[2]
LINT_DIR = WORKTREE / "scripts" / "lint"
LINT_PATH = LINT_DIR / "lint_hand_rolled_frontmatter.py"


def _load_gate():
    if str(LINT_DIR) not in sys.path:
        sys.path.insert(0, str(LINT_DIR))
    spec = importlib.util.spec_from_file_location("lint_hand_rolled_frontmatter", LINT_PATH)
    assert spec is not None
    assert spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_FIND = 'def f_find(t):\n    return t.find("\\n---", 4)\n'
_SPLIT = 'def f_split(t):\n    return t.split("---", 2)\n'
_STARTS = 'def f_starts(t):\n    return t.startswith("---")\n'
_REGEX = 'import re\n\ndef f_regex(t):\n    return re.search(r"^---\\s*\\n", t)\n'


def _pyfile(tree: Path, rel: str, src: str) -> Path:
    p = tree / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(src, encoding="utf-8")
    return p


def _by_function(findings) -> dict[str, list]:
    out: dict[str, list] = {}
    for f in findings:
        parts = f.fingerprint.split(":")
        func = parts[-2] if len(parts) >= 2 else "?"
        out.setdefault(func, []).append(f)
    return out


def _write_baseline(path: Path, fingerprints: list[str]) -> None:
    path.write_text(
        json.dumps({"//": "test", "entries": {fp: "" for fp in fingerprints}}) + "\n",
        encoding="utf-8",
    )


def test_d0_lint_gate(tmp_path):
    gate = _load_gate()
    tree = tmp_path / "scope"
    _pyfile(tree, "prod.py", _FIND)
    _pyfile(tree, "test_prod.py", _FIND)
    _pyfile(tree, "_frontmatter.py", _FIND)

    findings = gate._scan(tree)
    assert findings, "the production idiom must be flagged"
    assert all("prod.py" in f.fingerprint for f in findings)
    assert not any("test_prod" in f.fingerprint for f in findings)
    assert not any("_frontmatter" in f.fingerprint for f in findings)

    empty_baseline = tmp_path / "empty.json"
    assert gate.main([], scope=tree, baseline_path=empty_baseline) == 1
    bp = tmp_path / "bp.json"
    _write_baseline(bp, [f.fingerprint for f in findings])
    assert gate.main([], scope=tree, baseline_path=bp) == 0
    assert gate.main([], scope=tmp_path / "does-not-exist") == 2


def test_d_lint_flags_each_idiom(tmp_path):
    gate = _load_gate()
    tree = tmp_path / "scope"
    _pyfile(tree, "idioms.py", _FIND + "\n" + _SPLIT + "\n" + _STARTS + "\n" + _REGEX)

    findings = gate._scan(tree)
    assert all("idioms.py" in f.fingerprint for f in findings)
    flagged_funcs = set(_by_function(findings))
    for func in ("f_find", "f_split", "f_starts", "f_regex"):
        assert func in flagged_funcs, f"{func} idiom must be flagged"
    assert gate.main([], scope=tree, baseline_path=tmp_path / "empty.json") == 1


def test_d_lint_writer_fstrings_clean(tmp_path):
    gate = _load_gate()
    tree = tmp_path / "scope"
    clean = (
        '"""A module docstring mentioning --- and \\n--- fences."""\n'
        "def emit(y, text):\n"
        '    frag = f"---\\nid: {y}\\n---\\n"      # JoinedStr writer, not a parse\n'
        '    sep = "--- stdout ---"                # plain Constant separator\n'
        '    if "\\n---" in text:                  # in-containment Compare (waived)\n'
        "        pass\n"
        "    return frag + sep\n"
    )
    _pyfile(tree, "writer.py", clean)
    assert gate._scan(tree) == [], "writers/constants/in-checks must not be flagged"

    _pyfile(tree, "reader.py", _FIND)
    findings = gate._scan(tree)
    assert findings
    assert all("reader.py" in f.fingerprint for f in findings)


def test_d_lint_tests_excluded(tmp_path):
    gate = _load_gate()
    tree = tmp_path / "scope"
    _pyfile(tree, "test_reader.py", _FIND)
    assert gate._scan(tree) == []
    _pyfile(tree, "reader.py", _FIND)
    assert any("reader.py" in f.fingerprint for f in gate._scan(tree))


def test_d_lint_canonical_exempt(tmp_path):
    gate = _load_gate()
    tree = tmp_path / "scope"
    _pyfile(tree, "_frontmatter.py", _FIND)
    assert gate._scan(tree) == []
    _pyfile(tree, "other.py", _FIND)
    assert any("other.py" in f.fingerprint for f in gate._scan(tree))


def test_d_lint_suppression(tmp_path):
    gate = _load_gate()
    on = tmp_path / "on"
    _pyfile(on, "s.py", 'def f(t):\n    return t.find("\\n---", 4)  # lint-frontmatter: ok — canonical-ish\n')
    assert gate._scan(on) == []
    off = tmp_path / "off"
    _pyfile(off, "s.py",
            "# lint-frontmatter: ok — far above\n"
            "def f(t):\n"
            "    x = 1\n"
            "    y = 2\n"
            '    return t.find("\\n---", 4)\n')
    assert gate._scan(off), "a marker outside the node span must not suppress"
    bare = tmp_path / "bare"
    _pyfile(bare, "s.py", 'def f(t):\n    return t.find("\\n---", 4)  # lint-frontmatter: ok\n')
    assert gate._scan(bare) == []


def test_d_lint_real_tree_clean():
    gate = _load_gate()
    assert gate.main([]) == 0


def test_d_lint_baseline_lifecycle(tmp_path):
    gate = _load_gate()
    tree = tmp_path / "scope"
    _pyfile(tree, "prod.py", _FIND)
    bp = tmp_path / "bp.json"

    assert gate.main(["--update-baseline"], scope=tree, baseline_path=bp) == 0
    assert bp.exists()
    assert gate.main([], scope=tree, baseline_path=bp) == 0
    data = json.loads(bp.read_text(encoding="utf-8"))
    data.setdefault("entries", {})["defender/ghost.py:ghost:find"] = ""
    bp.write_text(json.dumps(data) + "\n", encoding="utf-8")
    assert gate.main([], scope=tree, baseline_path=bp) == 0
    assert gate.main([], scope=tree, baseline_path=tmp_path / "gone.json") == 1


def test_d_lint_exit2_scope_missing(tmp_path):
    gate = _load_gate()
    assert gate.main([], scope=tmp_path / "not-a-dir") == 2


def test_d_lint_syntax_error_is_not_clean(tmp_path):
    import _astlib

    gate = _load_gate()
    tree = tmp_path / "scope"
    _pyfile(tree, "broken.py", "def f(:\n    this is not python\n")
    _pyfile(tree, "ok.py", _FIND)
    with pytest.raises(_astlib.ScanBlind) as exc:
        gate._scan(tree)
    assert "broken.py" in str(exc.value)


def test_d_lint_clean_tree_still_scans(tmp_path):
    """The control: the same tree minus the unparseable file scans normally and finds the
    real site. Without this, the raises-test above would also pass against a gate that
    raised unconditionally."""
    gate = _load_gate()
    tree = tmp_path / "scope"
    _pyfile(tree, "ok.py", _FIND)
    assert any("ok.py" in f.fingerprint for f in gate._scan(tree))


def test_d_lint_fingerprint_dedup(tmp_path):
    gate = _load_gate()
    tree = tmp_path / "scope"
    src = (
        "def same(t):\n"
        '    a = t.find("\\n---", 4)\n'
        '    b = t.find("\\n---", 8)\n'
        "    return a, b\n"
        "\n"
        "def two(t):\n"
        '    a = t.find("\\n---", 4)\n'
        '    b = t.split("---", 2)\n'
        "    return a, b\n"
    )
    _pyfile(tree, "dedup.py", src)
    by_func = _by_function(gate._scan(tree))
    assert len(by_func.get("same", [])) == 1
    assert len(by_func.get("two", [])) == 2


def test_aliased_re_import_is_flagged(tmp_path):
    gate = _load_gate()
    tree = tmp_path / "scope"
    _pyfile(tree, "prod.py", (
        "import re as regex\n\n"
        'def f(t):\n    return regex.compile(r"\\A---\\n")\n'
    ))
    assert gate._scan(tree)


def test_from_import_re_is_flagged(tmp_path):
    gate = _load_gate()
    tree = tmp_path / "scope"
    _pyfile(tree, "prod.py", (
        "from re import search\n\n"
        'def f(t):\n    return search(r"^---\\n(.*?)\\n---", t)\n'
    ))
    assert gate._scan(tree)
