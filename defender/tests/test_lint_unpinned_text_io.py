"""Tests for the lint_unpinned_text_io gate (#594/#602).

The first block characterizes the detector — the net under a gate that had no
tests at all. The second block is the bugs the resolver fixed; each was an
``xfail(strict=True)`` when it was written, so the fix announced itself as an
XPASS and the deleted marker is the proof.

Every one of those bugs came from ONE mistake. The old ``_open_mode`` read
``call.args[0]`` as the mode of any ``<x>.open(...)`` — right for
``Path.open(mode)``, wrong for every module-level opener, which is path-FIRST
(``codecs.open(file, mode)``, ``io.open(file, mode)``, ``gzip.open(file, mode)``).
So the gate read the FILE PATH as the mode string, and every verdict on that
family turned on whether the path was a literal containing the letter ``b``:
``codecs.open("f.bin", "rb")`` scanned clean because of the ``b`` in ``"f.bin"``.
The mode's slot and default are properties of the CALLEE — which is why resolving
the callee is what makes this gate correct, not merely alias-proof.

The gate is driven through its DI seam:
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


def test_syntax_error_file_is_not_silently_skipped(tmp_path):
    """INVERTED by #652 (was `test_syntax_error_file_is_skipped`).

    The old assertion pinned the swallow — `broken.py` left the corpus and the scan carried
    on, so an unpinned `read_text()` sitting in an unparseable file was reported as clean.
    A gate that cannot look must not report clean (#618/#621), so the gate now raises
    ScanBlind, which `main()` surfaces as exit 2."""
    import _astlib

    tree = tmp_path / "scope"
    _pyfile(tree, "broken.py", "def f(:\n")
    _pyfile(tree, "prod.py", "def f(p):\n    return p.read_text()\n")
    with pytest.raises(_astlib.ScanBlind) as exc:
        _kinds(tree)
    assert "broken.py" in str(exc.value)


def test_clean_tree_still_scans(tmp_path):
    """Control for the above: without the unparseable file the scan works normally, so the
    raises-test cannot pass against a gate that raises unconditionally."""
    tree = tmp_path / "scope"
    _pyfile(tree, "prod.py", "def f(p):\n    return p.read_text()\n")
    assert all("prod.py" in fp for fp in _kinds(tree))


def test_fingerprint_dedups_within_a_function(tmp_path):
    tree = tmp_path / "scope"
    _pyfile(tree, "prod.py", "def f(p, q):\n    return p.read_text(), q.read_text()\n")
    assert len(_kinds(tree)) == 1, "same file+function+kind is one fingerprint"


def test_real_tree_clean():
    """The regression check: the shipped baseline is EMPTY, so the real trees must
    scan clean. `main([])` scans BOTH scopes (defender/ + spec-flow/scripts/), so any
    new unpinned site in either tree turns this — and CI — red."""
    assert _load_gate().main([]) == 0


def test_spec_flow_scripts_is_in_scope():
    """#655: the spec-graph tooling was dark to this gate (SCOPE was defender/ only),
    which let check_actors' unpinned reads land — the #643 false-clean. Pin that the
    tree is now a scanned scope so a future refactor can't silently drop it again."""
    gate = _load_gate()
    assert gate.REPO_ROOT / "spec-flow" / "scripts" in gate.SCOPES


def test_multiple_scopes_are_prefixed_and_cannot_collide(tmp_path):
    """The real run scans several roots; a finding is prefixed with its tree-relative path so a
    same-file:function:kind site in two trees yields two DISTINCT fingerprints — otherwise one
    baseline entry would silence a real site in the other tree. Exercises the prefix seam directly
    (no monkeypatch), with the empty prefix returning `_scan` untouched (the single-scope path)."""
    gate = _load_gate()
    a, b = tmp_path / "treeA", tmp_path / "treeB"
    _pyfile(a, "_config.py", "def f(p):\n    return p.read_text()\n")
    _pyfile(b, "_config.py", "def f(p):\n    return p.read_text()\n")
    fa = gate._prefixed_scan(a, "defender/")
    fb = gate._prefixed_scan(b, "spec-flow/scripts/")
    assert [f.fingerprint for f in fa] == ["defender/_config.py:f:read"]
    assert [f.fingerprint for f in fb] == ["spec-flow/scripts/_config.py:f:read"]
    assert not ({f.fingerprint for f in fa} & {f.fingerprint for f in fb})
    assert gate._prefixed_scan(a, "") == gate._scan(a)


def test_binary_tempfile_in_the_real_tree_stays_clean(tmp_path):
    """Guard rail. defender/runtime/bash_exec.py:242 is the ONLY tempfile opener
    under defender/, and it is BINARY (`mode="w+b"`). It must stay clean — it is
    the one site that turns the real tree red if the tempfile branch ignores the
    mode and flags on the callee alone."""
    assert not _flags(tmp_path, (
        "import tempfile\n"
        'def f():\n    return tempfile.TemporaryFile(mode="w+b")\n'
    ))


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
    """gzip.open defaults to "rb" — the mode DEFAULT is a property of the callee,
    which is exactly what only a resolver can know. Green today (for the wrong
    reason: `gzip` is in the skip-list) and must stay green after."""
    assert not _flags(tmp_path, "import gzip\ndef f(p):\n    return gzip.open(p)\n")


def test_codecs_open_binary_literal_is_not_flagged_for_the_right_reason(tmp_path):
    """`codecs.open("f.bin", "rb")` is clean today because _open_mode returns the
    FILENAME "f.bin", which contains a "b". Rename the file and it flags. This
    test pins the intent: binary is clean because the MODE says so."""
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
    """`SpooledTemporaryFile(max_size, mode)` — max_size comes FIRST, so the mode sits at
    slot 1, not slot 0 like its `NamedTemporaryFile`/`TemporaryFile` siblings. Pinning it
    at 0 read the max_size INT as the mode string, so a genuine text-mode spooled file went
    unflagged — the very slot-guessing bug the resolver exists to end, in the one table
    entry never checked against inspect.signature."""
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
    """A receiver rooted at an IMPORTED name is not necessarily a MODULE. `PATHS` is a
    module-level Path-holder object, so `PATHS.lessons_dir.open()` resolves to a non-None
    origin — and a gate that reads "it resolved" as "not a duck-typed opener" drops a real
    unpinned text open on the floor while its empty baseline stays green."""
    assert _flags(tmp_path, (
        "from defender._paths import PATHS\n"
        "def f():\n    return PATHS.lessons_dir.open()\n"
    ))


def test_open_on_a_local_colliding_with_an_import_is_flagged(tmp_path):
    """The live shape (#607): `_astlib.module_env` collects imports from the WHOLE tree, so
    a function-local `from x import parser as p` binds `p` module-wide. An unrelated local
    `p` — an actual Path — then resolves to that module origin. This is not hypothetical:
    defender/learning/pipeline/judge/compare.py does exactly this. Skips must therefore come
    from a positive table, never from "the origin resolved"."""
    assert _flags(tmp_path, (
        "def _invlang():\n"
        "    from defender.skills.invlang import parser as p\n"
        "    return p\n"
        "\n"
        "def write(out_dir):\n"
        "    p = out_dir / 'x.md'\n"
        "    with p.open('w') as fh:\n"
        "        fh.write('hi')\n"
    ))


def test_aliased_subprocess_is_flagged(tmp_path):
    """Green today, but ONLY by accident: the subprocess check has no receiver test
    at all, so `sp.run` matches on the bare attribute `run`. It is the same defect
    that produces the `runner.run` false positive above. After the resolver it is
    green for the right reason — `sp` resolves to `subprocess`."""
    assert _flags(tmp_path, (
        "import subprocess as sp\n"
        "def f(cmd):\n    return sp.run(cmd, text=True)\n"
    ))
