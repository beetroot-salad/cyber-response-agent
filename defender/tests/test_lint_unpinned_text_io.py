"""Characterization + intent tests for the lint_unpinned_text_io gate (#594/#602).

Two kinds of test live here, and the difference is the point:

- **Characterization** — what the gate does TODAY. These are green against the
  detector as it stands and must stay green through the resolver refactor. They
  are the net under a rewrite of a gate that had no tests at all.
- **`xfail(strict=True)`** — what the gate SHOULD do. Each one is the executable
  statement of a known bug: it asserts the intended behavior and fails today, on
  purpose. Deleting the marker is the proof the bug is fixed. No prose, no issue
  comment — the suite itself carries the claim.

The bugs, all rooted in ONE mistake: ``_open_mode`` reads ``call.args[0]`` as the
mode for any ``<x>.open(...)``. That is right for ``Path.open(mode)`` and wrong for
every module-level opener, which is path-first — ``codecs.open(file, mode)``,
``io.open(file, mode)``, ``gzip.open(file, mode)``. So the gate reads the FILE PATH
as the mode string, and every verdict on that family turns on whether the path is a
literal and whether it happens to contain the letter ``b``.

The gate is driven through its DI seam (added in the parent commit):
  - main(argv=None, *, scope=None, baseline_path=None) -> exit code
  - _scan(root) -> list[Finding]
"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

WORKTREE = Path(__file__).resolve().parents[2]
LINT_DIR = WORKTREE / "scripts" / "lint"
LINT_PATH = LINT_DIR / "lint_unpinned_text_io.py"


def _load_gate():
    # scripts/lint is on the gate's own import path (it does `from _baseline import ...`)
    if str(LINT_DIR) not in sys.path:
        sys.path.insert(0, str(LINT_DIR))
    spec = importlib.util.spec_from_file_location("lint_unpinned_text_io", LINT_PATH)
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


def _kinds(tree: Path) -> set[str]:
    """The set of `file:function:kind` fingerprints found under `tree`."""
    return {f.fingerprint for f in _load_gate()._scan(tree)}


def _flags(tmp_path: Path, src: str) -> bool:
    """True if the gate flags anything in `src`. One source, one scan."""
    tree = tmp_path / "scope"
    _pyfile(tree, "prod.py", src)
    return bool(_load_gate()._scan(tree))


# ===========================================================================
# Characterization — the detector as it stands. Must stay green.
# ===========================================================================
def test_scan_and_ratchet_contract(tmp_path):
    gate = _load_gate()
    tree = tmp_path / "scope"
    _pyfile(tree, "prod.py", "def f(p):\n    return p.read_text()\n")
    _pyfile(tree, "test_prod.py", "def f(p):\n    return p.read_text()\n")

    findings = gate._scan(tree)
    assert findings, "an unpinned read_text must be flagged"
    assert all("prod.py" in f.fingerprint for f in findings)
    assert not any("test_prod" in f.fingerprint for f in findings), "test modules excluded"

    empty = tmp_path / "empty.json"
    assert gate.main([], scope=tree, baseline_path=empty) == 1        # a new finding
    bp = tmp_path / "bp.json"
    _write_baseline(bp, [f.fingerprint for f in findings])
    assert gate.main([], scope=tree, baseline_path=bp) == 0           # all baselined
    assert gate.main([], scope=tmp_path / "nope") == 2                # scope missing


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
    """The crux of the refactor: `p.open("r")` has an UNRESOLVABLE callee — the
    receiver is a value, not a module. It must stay flagged. A resolver that
    treats "unresolvable" as "skip" would silently gut this gate, and the empty
    baseline would not notice."""
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


def test_syntax_error_file_is_skipped(tmp_path):
    tree = tmp_path / "scope"
    _pyfile(tree, "broken.py", "def f(:\n")
    _pyfile(tree, "prod.py", "def f(p):\n    return p.read_text()\n")
    assert all("prod.py" in fp for fp in _kinds(tree))


def test_fingerprint_dedups_within_a_function(tmp_path):
    tree = tmp_path / "scope"
    _pyfile(tree, "prod.py", "def f(p, q):\n    return p.read_text(), q.read_text()\n")
    assert len(_kinds(tree)) == 1, "same file+function+kind is one fingerprint"


def test_real_tree_clean():
    """The regression check: the shipped baseline is EMPTY, so the real tree must
    scan clean. Any new finding here is a live site the refactor introduced."""
    assert _load_gate().main([]) == 0


def test_binary_tempfile_in_the_real_tree_stays_clean(tmp_path):
    """Guard rail. defender/runtime/bash_exec.py:242 is the ONLY tempfile opener
    under defender/, and it is BINARY (`mode="w+b"`). It must stay clean — it is
    the one site that turns the real tree red if the tempfile branch ignores the
    mode and flags on the callee alone."""
    assert not _flags(tmp_path, (
        "import tempfile\n"
        'def f():\n    return tempfile.TemporaryFile(mode="w+b")\n'
    ))


# ===========================================================================
# Intent — each xfail is a known bug. Deleting the marker proves the fix.
# ===========================================================================
@pytest.mark.xfail(strict=True, reason="#594: from-import evades the spelled `subprocess.` check")
def test_from_import_subprocess_is_flagged(tmp_path):
    assert _flags(tmp_path, (
        "from subprocess import run\n"
        "def f(cmd):\n    return run(cmd, text=True)\n"
    ))


@pytest.mark.xfail(strict=True, reason="#602: `attr in _SUBPROCESS_FUNCS` has NO receiver check")
def test_local_run_wrapper_is_not_flagged(tmp_path):
    """The other half of the same bug: the gate matches ANY `.run(..., text=True)`,
    so a local wrapper that has nothing to do with subprocess is a false positive."""
    assert not _flags(tmp_path, (
        "def f(runner, cmd):\n    return runner.run(cmd, text=True)\n"
    ))


@pytest.mark.xfail(strict=True, reason="#594: _open_mode reads the PATH as the mode")
def test_codecs_open_text_is_flagged(tmp_path):
    assert _flags(tmp_path, (
        "import codecs\n"
        'def f(p):\n    return codecs.open(p, "r")\n'
    ))


@pytest.mark.xfail(strict=True, reason="#594: `io` is skipped, but io.open IS the builtin open")
def test_io_open_is_flagged(tmp_path):
    assert _flags(tmp_path, "import io\ndef f(p):\n    return io.open(p)\n")


@pytest.mark.xfail(strict=True, reason="#602: gzip.open takes encoding= in text mode")
def test_gzip_open_text_mode_is_flagged(tmp_path):
    assert _flags(tmp_path, (
        "import gzip\n"
        'def f(p):\n    return gzip.open(p, "rt")\n'
    ))


def test_gzip_open_binary_default_is_clean(tmp_path):
    """gzip.open defaults to "rb" — the mode DEFAULT is a property of the callee,
    which is exactly what only a resolver can know. Green today (for the wrong
    reason: `gzip` is in the skip-list) and must stay green after."""
    assert not _flags(tmp_path, "import gzip\ndef f(p):\n    return gzip.open(p)\n")


@pytest.mark.xfail(strict=True, reason="#602: 'clean' only because the letter b is in 'f.bin'")
def test_codecs_open_binary_literal_is_not_flagged_for_the_right_reason(tmp_path):
    """`codecs.open("f.bin", "rb")` is clean today because _open_mode returns the
    FILENAME "f.bin", which contains a "b". Rename the file and it flags. This
    test pins the intent: binary is clean because the MODE says so."""
    assert not _flags(tmp_path, (
        "import codecs\n"
        'def f():\n    return codecs.open("data.txt", "rb")\n'
    ))


@pytest.mark.xfail(strict=True, reason="#594: tempfile text-mode openers unhandled")
def test_tempfile_text_mode_is_flagged(tmp_path):
    assert _flags(tmp_path, (
        "import tempfile\n"
        'def f():\n    return tempfile.NamedTemporaryFile(mode="w")\n'
    ))


@pytest.mark.xfail(strict=True, reason="#602: a hoisted mode constant defeats the inline-literal read")
def test_hoisted_mode_constant_is_resolved(tmp_path):
    assert _flags(tmp_path, 'MODE = "r"\ndef f(p):\n    return open(p, MODE)\n')


def test_aliased_subprocess_is_flagged(tmp_path):
    """Green today, but ONLY by accident: the subprocess check has no receiver test
    at all, so `sp.run` matches on the bare attribute `run`. It is the same defect
    that produces the `runner.run` false positive above. After the resolver it is
    green for the right reason — `sp` resolves to `subprocess`."""
    assert _flags(tmp_path, (
        "import subprocess as sp\n"
        "def f(cmd):\n    return sp.run(cmd, text=True)\n"
    ))
