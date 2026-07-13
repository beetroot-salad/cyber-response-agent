"""Characterization + intent tests for the lint_unsafe_jsonl_io gate (#602).

Same two-block shape as test_lint_unpinned_text_io.py: the first block pins what
the detector does (the net under the resolver refactor), the second is the bugs
the resolver fixed — each written as an `xfail(strict=True)` first, so the fix
announced itself as an XPASS and the deleted marker is the proof.

The bug here was narrow and total: `_is_json_call` required
`call.func.value.id == "json"`, i.e. the callee must be SPELLED `json.loads`. An
alias (`import json as j`) or a from-import (`from json import loads`) makes the
whole gate blind, and the shape it exists to stop — a hand-rolled per-line
json.loads reader that crashes on a torn append (#446) — walks straight through.

Driven through the DI seam added in the parent commit:
  - main(argv=None, *, scope=None, baseline_path=None) -> exit code
  - _scan(root) -> list[Finding]
"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

WORKTREE = Path(__file__).resolve().parents[2]
LINT_DIR = WORKTREE / "scripts" / "lint"
LINT_PATH = LINT_DIR / "lint_unsafe_jsonl_io.py"


def _load_gate():
    # scripts/lint is on the gate's own import path (it does `from _baseline import ...`)
    if str(LINT_DIR) not in sys.path:
        sys.path.insert(0, str(LINT_DIR))
    spec = importlib.util.spec_from_file_location("lint_unsafe_jsonl_io", LINT_PATH)
    assert spec is not None
    assert spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _pyfile(tree: Path, rel: str, src: str) -> Path:
    p = tree / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(src, encoding="utf-8")
    return p


def _write_baseline(path: Path, fingerprints: list[str]) -> None:
    path.write_text(
        json.dumps({"//": "test", "entries": {fp: "" for fp in fingerprints}}) + "\n",
        encoding="utf-8",
    )


def _flags(tmp_path: Path, src: str) -> bool:
    tree = tmp_path / "scope"
    _pyfile(tree, "prod.py", src)
    return bool(_load_gate()._scan(tree))


# --- the two banned idioms, as source templates -----------------------------
def _reader(imp: str, call: str) -> str:
    """A hand-rolled per-line JSON reader — the #446 torn-line crash shape."""
    return (
        f"{imp}\n"
        "def read(p):\n"
        "    rows = []\n"
        "    with open(p) as fh:\n"
        "        for line in fh:\n"
        f"            rows.append({call}(line))\n"
        "    return rows\n"
    )


def _appender(imp: str, call: str) -> str:
    """A hand-rolled JSONL append — json.dumps + a newline onto an append handle."""
    return (
        f"{imp}\n"
        "def append(p, row):\n"
        '    with open(p, "a") as fh:\n'
        f'        fh.write({call}(row) + "\\n")\n'
    )


# ===========================================================================
# Characterization — the detector as it stands. Must stay green.
# ===========================================================================
def test_scan_and_ratchet_contract(tmp_path):
    gate = _load_gate()
    tree = tmp_path / "scope"
    _pyfile(tree, "prod.py", _reader("import json", "json.loads"))

    findings = gate._scan(tree)
    assert findings, "a hand-rolled per-line json.loads reader must be flagged"
    assert all("prod.py" in f.fingerprint for f in findings)

    empty = tmp_path / "empty.json"
    assert gate.main([], scope=tree, baseline_path=empty) == 1        # a new finding
    bp = tmp_path / "bp.json"
    _write_baseline(bp, [f.fingerprint for f in findings])
    assert gate.main([], scope=tree, baseline_path=bp) == 0           # all baselined
    assert gate.main([], scope=tmp_path / "nope") == 2                # scope missing


def test_flags_the_spelled_reader(tmp_path):
    assert _flags(tmp_path, _reader("import json", "json.loads"))


def test_flags_the_spelled_appender(tmp_path):
    tree = tmp_path / "scope"
    _pyfile(tree, "prod.py", _appender("import json", "json.dumps"))
    assert any(f.fingerprint.endswith(":append") for f in _load_gate()._scan(tree))


def test_splitlines_on_a_plain_value_is_clean(tmp_path):
    """A subprocess stdout string has no torn-file failure mode — deliberately
    NOT matched, and the refactor must not widen into it."""
    assert not _flags(tmp_path, (
        "import json\n"
        "def read(out):\n"
        "    return [json.loads(x) for x in out.splitlines()]\n"
    ))


def test_suppression(tmp_path):
    assert not _flags(tmp_path, (
        "import json\n"
        "def read(p):\n"
        "    rows = []\n"
        "    with open(p) as fh:\n"
        "        for line in fh:  # lint-jsonl-io: ok — deliberate\n"
        "            rows.append(json.loads(line))\n"
        "    return rows\n"
    ))


def test_syntax_error_file_is_skipped(tmp_path):
    tree = tmp_path / "scope"
    _pyfile(tree, "broken.py", "def f(:\n")
    _pyfile(tree, "prod.py", _reader("import json", "json.loads"))
    assert all("prod.py" in f.fingerprint for f in _load_gate()._scan(tree))


def test_real_tree_clean():
    """The regression check: the shipped baseline is EMPTY, so the real tree must
    scan clean. Any new finding here is a live site the refactor introduced."""
    assert _load_gate().main([]) == 0


# ===========================================================================
# The bugs, now fixed. Each of these was an xfail(strict=True) in the parent
# commit — the executable statement of a bug — and landing the resolver flipped
# every one to XPASS. The deleted markers ARE the proof; these are plain
# regression tests from here on.
# ===========================================================================
def test_aliased_json_reader_is_flagged(tmp_path):
    assert _flags(tmp_path, _reader("import json as j", "j.loads"))


def test_from_import_json_reader_is_flagged(tmp_path):
    assert _flags(tmp_path, _reader("from json import loads", "loads"))


def test_aliased_json_appender_is_flagged(tmp_path):
    tree = tmp_path / "scope"
    _pyfile(tree, "prod.py", _appender("import json as j", "j.dumps"))
    assert any(f.fingerprint.endswith(":append") for f in _load_gate()._scan(tree))
