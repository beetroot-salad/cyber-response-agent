"""Tests for the lint_unpinned_text_io gate (#594/#602)."""
from __future__ import annotations

import json

from pathlib import Path

import pytest

from _by_path import load_lint_gate

_GATE = load_lint_gate("lint_unpinned_text_io")


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


def _kinds(tree: Path) -> set[str]:
    """The set of `file:function:kind` fingerprints found under `tree`."""
    return {f.fingerprint for f in _GATE._scan(tree)}


def _flags(tmp_path: Path, src: str) -> bool:
    """True if the gate flags anything in `src`. One source, one scan."""
    tree = tmp_path / "scope"
    _pyfile(tree, "prod.py", src)
    return bool(_GATE._scan(tree))


def test_scan_and_ratchet_contract(tmp_path):
    gate = _GATE
    tree = tmp_path / "scope"
    _pyfile(tree, "prod.py", "def f(p):\n    return p.read_text()\n")
    _pyfile(tree, "test_prod.py", "def f(p):\n    return p.read_text()\n")

    findings = gate._scan(tree)
    assert findings, "an unpinned read_text must be flagged"
    assert all("prod.py" in f.fingerprint for f in findings)
    assert not any("test_prod" in f.fingerprint for f in findings), "test modules excluded"

    empty = tmp_path / "empty.json"
    assert gate.main([], scope=tree, baseline_path=empty) == 1
    bp = tmp_path / "bp.json"
    _write_baseline(bp, [f.fingerprint for f in findings])
    assert gate.main([], scope=tree, baseline_path=bp) == 0
    assert gate.main([], scope=tmp_path / "nope") == 2


def test_flags_each_idiom(tmp_path):
    tree = tmp_path / "scope"
    _pyfile(tree, "prod.py", (
        "import subprocess\n"
        "def f_read(p):    return p.read_text()\n"
        "def f_write(p,s): return p.write_text(s)\n"
        "def f_open(p):    return open(p)\n"
        "def f_proc(cmd):  return subprocess.run(cmd, text=True)\n"
    ))
    kinds = {fp.split(":")[-1] for fp in _kinds(tree)}
    assert kinds == {"read", "write", "open", "subprocess"}


def test_fingerprint_dedups_within_a_function(tmp_path):
    tree = tmp_path / "scope"
    _pyfile(tree, "prod.py", "def f(p, q):\n    return p.read_text(), q.read_text()\n")
    assert len(_kinds(tree)) == 1, "same file+function+kind is one fingerprint"


def test_multiple_scopes_are_prefixed_and_cannot_collide(tmp_path):
    gate = _GATE
    a, b = tmp_path / "treeA", tmp_path / "treeB"
    _pyfile(a, "_config.py", "def f(p):\n    return p.read_text()\n")
    _pyfile(b, "_config.py", "def f(p):\n    return p.read_text()\n")
    fa = gate._prefixed_scan(a, "defender/")
    fb = gate._prefixed_scan(b, "tooling/")
    assert [f.fingerprint for f in fa] == ["defender/_config.py:f:read"]
    assert [f.fingerprint for f in fb] == ["tooling/_config.py:f:read"]
    assert not ({f.fingerprint for f in fa} & {f.fingerprint for f in fb})
    assert gate._prefixed_scan(a, "") == gate._scan(a)


@pytest.mark.parametrize(("src", "flagged"), [
    pytest.param(
        "import subprocess\n"
        "def f_read(p):    return p.read_text(encoding='utf-8')\n"
        "def f_write(p,s): return p.write_text(s, encoding='utf-8')\n"
        "def f_open(p):    return open(p, encoding='utf-8')\n"
        "def f_bin(p):     return open(p, 'rb')\n"
        "def f_proc(cmd):  return subprocess.run(cmd, text=True, encoding='utf-8')\n"
        "def f_bytes(cmd): return subprocess.run(cmd)\n",
        False, id="pinned_and_binary_are_clean"),
    pytest.param('def f(p):\n    return p.open("r")\n', True,
                 id="duck_typed_path_open_is_flagged"),
    pytest.param("def f(p):\n    return p.open()\n", True,
                 id="duck_typed_path_open_default_mode_is_flagged"),
    # Genuinely encoding-less openers: `os.open` returns an fd (its third arg is the PERMISSION
    # bits, not a text mode); `tarfile.open` has no `encoding` param.
    pytest.param(
        "import os, tarfile\n"
        "def f_fd(p):  return os.open(p, os.O_RDONLY)\n"
        "def f_tar(p): return tarfile.open(p)\n",
        False, id="os_and_tarfile_open_are_clean"),
    pytest.param("def f(p):\n    return p.read_text()  # lint-text-io: ok — deliberate\n", False,
                 id="suppression"),
    pytest.param("from subprocess import run\ndef f(cmd):\n    return run(cmd, text=True)\n", True,
                 id="from_import_subprocess_is_flagged"),
    # The other half of that bug: matching ANY `.run(..., text=True)` makes a local wrapper
    # that has nothing to do with subprocess a false positive.
    pytest.param("def f(runner, cmd):\n    return runner.run(cmd, text=True)\n", False,
                 id="local_run_wrapper_is_not_flagged"),
    pytest.param('import codecs\ndef f(p):\n    return codecs.open(p, "r")\n', True,
                 id="codecs_open_text_is_flagged"),
    pytest.param("import io\ndef f(p):\n    return io.open(p)\n", True, id="io_open_is_flagged"),
    pytest.param('import gzip\ndef f(p):\n    return gzip.open(p, "rt")\n', True,
                 id="gzip_open_text_mode_is_flagged"),
    pytest.param("import gzip\ndef f(p):\n    return gzip.open(p)\n", False,
                 id="gzip_open_binary_default_is_clean"),
    pytest.param('import codecs\ndef f():\n    return codecs.open("data.txt", "rb")\n', False,
                 id="codecs_open_binary_literal_is_not_flagged_for_the_right_reason"),
    pytest.param('import tempfile\ndef f():\n    return tempfile.NamedTemporaryFile(mode="w")\n',
                 True, id="tempfile_text_mode_is_flagged"),
    pytest.param('MODE = "r"\ndef f(p):\n    return open(p, MODE)\n', True,
                 id="hoisted_mode_constant_is_resolved"),
    pytest.param('import tempfile\ndef f():\n    return tempfile.SpooledTemporaryFile(1024, "w")\n',
                 True, id="spooled_tempfile_text_mode_is_flagged"),
    pytest.param(
        'import tempfile\ndef f():\n    return tempfile.SpooledTemporaryFile(1024, mode="w")\n',
        True, id="spooled_tempfile_text_mode_keyword_is_flagged"),
    pytest.param(
        'import tempfile\ndef f():\n    return tempfile.SpooledTemporaryFile(1024, "w+b")\n',
        False, id="spooled_tempfile_binary_is_clean"),
    pytest.param("from defender._paths import PATHS\ndef f():\n    return PATHS.lessons_dir.open()\n",
                 True, id="open_on_an_imported_object_is_flagged"),
    pytest.param("import subprocess as sp\ndef f(cmd):\n    return sp.run(cmd, text=True)\n", True,
                 id="aliased_subprocess_is_flagged"),
])
def test_each_spelling(tmp_path, src, flagged):
    assert _flags(tmp_path, src) is flagged
