"""Tests for the lint_unpinned_text_io gate (#594/#602)."""
from __future__ import annotations

import json

from pathlib import Path


from defender.tests._by_path import load_lint_gate

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


def test_pinned_and_binary_are_clean(tmp_path):
    assert not _flags(tmp_path, (
        "import subprocess\n"
        "def f_read(p):    return p.read_text(encoding='utf-8')\n"
        "def f_write(p,s): return p.write_text(s, encoding='utf-8')\n"
        "def f_open(p):    return open(p, encoding='utf-8')\n"
        "def f_bin(p):     return open(p, 'rb')\n"
        "def f_proc(cmd):  return subprocess.run(cmd, text=True, encoding='utf-8')\n"
        "def f_bytes(cmd): return subprocess.run(cmd)\n"
    ))


def test_duck_typed_path_open_is_flagged(tmp_path):
    assert _flags(tmp_path, 'def f(p):\n    return p.open("r")\n')
    assert _flags(tmp_path, "def f(p):\n    return p.open()\n")


def test_os_and_tarfile_open_are_clean(tmp_path):
    """Genuinely encoding-less openers. `os.open` returns an fd (its third arg is
    the PERMISSION bits, not a text mode); `tarfile.open` has no `encoding` param."""
    assert not _flags(tmp_path, (
        "import os, tarfile\n"
        "def f_fd(p):  return os.open(p, os.O_RDONLY)\n"
        "def f_tar(p): return tarfile.open(p)\n"
    ))


def test_suppression(tmp_path):
    assert not _flags(
        tmp_path,
        "def f(p):\n    return p.read_text()  # lint-text-io: ok — deliberate\n",
    )


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
    fb = gate._prefixed_scan(b, "spec-flow/scripts/")
    assert [f.fingerprint for f in fa] == ["defender/_config.py:f:read"]
    assert [f.fingerprint for f in fb] == ["spec-flow/scripts/_config.py:f:read"]
    assert not ({f.fingerprint for f in fa} & {f.fingerprint for f in fb})
    assert gate._prefixed_scan(a, "") == gate._scan(a)


def test_from_import_subprocess_is_flagged(tmp_path):
    assert _flags(tmp_path, (
        "from subprocess import run\n"
        "def f(cmd):\n    return run(cmd, text=True)\n"
    ))


def test_local_run_wrapper_is_not_flagged(tmp_path):
    """The other half of the same bug: the gate matches ANY `.run(..., text=True)`,
    so a local wrapper that has nothing to do with subprocess is a false positive."""
    assert not _flags(tmp_path, (
        "def f(runner, cmd):\n    return runner.run(cmd, text=True)\n"
    ))


def test_codecs_open_text_is_flagged(tmp_path):
    assert _flags(tmp_path, (
        "import codecs\n"
        'def f(p):\n    return codecs.open(p, "r")\n'
    ))


def test_io_open_is_flagged(tmp_path):
    assert _flags(tmp_path, "import io\ndef f(p):\n    return io.open(p)\n")


def test_gzip_open_text_mode_is_flagged(tmp_path):
    assert _flags(tmp_path, (
        "import gzip\n"
        'def f(p):\n    return gzip.open(p, "rt")\n'
    ))


def test_gzip_open_binary_default_is_clean(tmp_path):
    assert not _flags(tmp_path, "import gzip\ndef f(p):\n    return gzip.open(p)\n")


def test_codecs_open_binary_literal_is_not_flagged_for_the_right_reason(tmp_path):
    assert not _flags(tmp_path, (
        "import codecs\n"
        'def f():\n    return codecs.open("data.txt", "rb")\n'
    ))


def test_tempfile_text_mode_is_flagged(tmp_path):
    assert _flags(tmp_path, (
        "import tempfile\n"
        'def f():\n    return tempfile.NamedTemporaryFile(mode="w")\n'
    ))


def test_hoisted_mode_constant_is_resolved(tmp_path):
    assert _flags(tmp_path, 'MODE = "r"\ndef f(p):\n    return open(p, MODE)\n')


def test_spooled_tempfile_text_mode_is_flagged(tmp_path):
    assert _flags(tmp_path, (
        "import tempfile\n"
        'def f():\n    return tempfile.SpooledTemporaryFile(1024, "w")\n'
    ))
    assert _flags(tmp_path, (
        "import tempfile\n"
        'def f():\n    return tempfile.SpooledTemporaryFile(1024, mode="w")\n'
    ))


def test_spooled_tempfile_binary_is_clean(tmp_path):
    assert not _flags(tmp_path, (
        "import tempfile\n"
        'def f():\n    return tempfile.SpooledTemporaryFile(1024, "w+b")\n'
    ))


def test_open_on_an_imported_object_is_flagged(tmp_path):
    assert _flags(tmp_path, (
        "from defender._paths import PATHS\n"
        "def f():\n    return PATHS.lessons_dir.open()\n"
    ))


def test_aliased_subprocess_is_flagged(tmp_path):
    assert _flags(tmp_path, (
        "import subprocess as sp\n"
        "def f(cmd):\n    return sp.run(cmd, text=True)\n"
    ))
