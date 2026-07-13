"""Unit tests for scripts/lint/_astlib.py — the shared callee/arg resolver the three
AST lint gates run on (#602/#594).

The gates' own suites prove the end-to-end behavior; this file pins the resolver's
contract directly, because two of its properties are load-bearing and silent if wrong:

  - ``callee() is None`` means "the receiver is a VALUE, not a module" (duck-typed).
    A gate that reads None as "skip" would turn every resolvable receiver into a false
    negative and still show a green empty baseline.
  - ``origin()`` must NOT walk through a Call. ``zipfile.ZipFile(p).open`` is a value's
    method, not ``zipfile.open``.
"""
from __future__ import annotations

import ast
import importlib.util
import sys
from pathlib import Path

import pytest

WORKTREE = Path(__file__).resolve().parents[2]
LINT_DIR = WORKTREE / "scripts" / "lint"


def _load():
    if str(LINT_DIR) not in sys.path:
        sys.path.insert(0, str(LINT_DIR))
    spec = importlib.util.spec_from_file_location("_astlib", LINT_DIR / "_astlib.py")
    assert spec is not None
    assert spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    # Register BEFORE exec: @dataclass resolves its class's module out of sys.modules,
    # and module_from_spec does not put it there.
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def _first_call(src: str):
    """(the module's first Call node, its ModuleEnv)."""
    astlib = _load()
    tree = ast.parse(src)
    env = astlib.module_env(tree)
    call = next(n for n in ast.walk(tree) if isinstance(n, ast.Call))
    return call, env, astlib


# --- callee(): every spelling of the same origin -----------------------------
@pytest.mark.parametrize(
    ("src", "expected"),
    [
        ("import re\nre.search(p, t)\n", "re.search"),
        ("import re as regex\nregex.search(p, t)\n", "re.search"),
        ("from re import search\nsearch(p, t)\n", "re.search"),
        ("from re import search as s\ns(p, t)\n", "re.search"),
        ("import json\njson.loads(x)\n", "json.loads"),
        ("import json as j\nj.loads(x)\n", "json.loads"),
        ("from json import loads\nloads(x)\n", "json.loads"),
        ("import subprocess\nsubprocess.run(c)\n", "subprocess.run"),
        ("import subprocess as sp\nsp.run(c)\n", "subprocess.run"),
        ("from subprocess import run\nrun(c)\n", "subprocess.run"),
        # `import a.b` binds only `a`
        ("import os.path\nos.path.join(a, b)\n", "os.path.join"),
        ("import os.path as osp\nosp.join(a, b)\n", "os.path.join"),
        # the builtin, when nothing shadows it
        ("open(p)\n", "builtins.open"),
    ],
)
def test_callee_resolves_every_spelling(src, expected):
    call, env, astlib = _first_call(src)
    assert astlib.callee(call, env) == expected


# --- callee(): None is a signal, not a failure -------------------------------
@pytest.mark.parametrize(
    "src",
    [
        "def f(p):\n    return p.open('r')\n",        # Path-like: receiver is a value
        "def f(p):\n    return p.read_text()\n",
        "def f(zf, n):\n    return zf.open(n)\n",     # a bound handle — same shape
        "def f(self):\n    return self.run(c)\n",     # a method on a local wrapper
    ],
)
def test_callee_is_none_for_a_value_receiver(src):
    call, env, astlib = _first_call(src)
    assert astlib.callee(call, env) is None


def test_origin_does_not_walk_through_a_call():
    """`zipfile.ZipFile(p).open(n)` is a VALUE's method. Resolving it to `zipfile.open`
    would confuse the value with its constructor and silently skip a real text open."""
    astlib = _load()
    tree = ast.parse("import zipfile\nzipfile.ZipFile(p).open(n)\n")
    env = astlib.module_env(tree)
    outer = next(
        n for n in ast.walk(tree)
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "open"
    )
    assert astlib.callee(outer, env) is None


def test_a_local_def_shadows_the_builtin():
    """A module that defines its own `open` must not resolve to `builtins.open`."""
    astlib = _load()
    tree = ast.parse("def open(p):\n    return p\n\nopen(x)\n")
    env = astlib.module_env(tree)
    call = next(
        n for n in ast.walk(tree)
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "open"
    )
    assert astlib.callee(call, env) is None


def test_relative_import_never_collides_with_a_stdlib_origin():
    call, env, astlib = _first_call("from .re import search\nsearch(p, t)\n")
    got = astlib.callee(call, env)
    assert got != "re.search"
    assert got.startswith(".")


def test_function_local_import_is_seen():
    """A resolver that only read module-level imports would reproduce the exact blind
    spot it exists to close."""
    call, env, astlib = _first_call(
        "def f(t):\n    import re as regex\n    return regex.search(p, t)\n"
    )
    assert astlib.callee(call, env) == "re.search"


# --- args ---------------------------------------------------------------------
def test_str_args_reads_positional_keyword_tuple_and_consts():
    astlib = _load()
    tree = ast.parse(
        'FENCE = "---\\n"\n'
        "def f(t):\n"
        "    a = t.startswith(FENCE)\n"                 # module const
        '    b = t.startswith(("---", "+++"))\n'        # tuple, flattened
        '    c = t.split(sep="---")\n'                  # keyword
        "    return a, b, c\n"
    )
    env = astlib.module_env(tree)
    found = [
        astlib.str_args(n, env)
        for n in ast.walk(tree) if isinstance(n, ast.Call)
    ]
    assert ["---\n"] in found
    assert ["---", "+++"] in found
    assert ["---"] in found


def test_arg_at_takes_the_positional_slot_the_caller_resolved():
    """The mode's slot is a property of the callee: builtins.open(file, mode) puts it at
    1, Path.open(mode) at 0. arg_at must not guess."""
    astlib = _load()
    tree = ast.parse('open(p, "rb")\np.open("rb")\nopen(p, mode="rb")\n')
    env = astlib.module_env(tree)
    calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call)]
    builtin_open, path_open, kw_open = calls[0], calls[1], calls[2]
    assert astlib.str_value(astlib.arg_at(builtin_open, 1, "mode"), env) == "rb"
    assert astlib.str_value(astlib.arg_at(path_open, 0, "mode"), env) == "rb"
    assert astlib.str_value(astlib.arg_at(kw_open, 1, "mode"), env) == "rb"


def test_str_value_resolves_a_hoisted_mode_constant():
    astlib = _load()
    tree = ast.parse('MODE = "r"\nopen(p, MODE)\n')
    env = astlib.module_env(tree)
    call = next(n for n in ast.walk(tree) if isinstance(n, ast.Call))
    assert astlib.str_value(astlib.arg_at(call, 1, "mode"), env) == "r"


# --- the opener table -----------------------------------------------------------
def test_opener_table_matches_the_real_signatures():
    """The slot and default in OPENERS are claims about the stdlib. Check them against the
    stdlib rather than against a hand-written table — `tempfile.SpooledTemporaryFile` was
    tabled at slot 0 like its siblings when max_size actually comes first, so the gate read
    an int as the mode string."""
    import bz2
    import codecs
    import gzip
    import inspect
    import io
    import lzma
    import os
    import tempfile

    astlib = _load()
    live = {
        "builtins.open": open,
        "io.open": io.open,
        "codecs.open": codecs.open,
        "os.fdopen": os.fdopen,
        "gzip.open": gzip.open,
        "bz2.open": bz2.open,
        "lzma.open": lzma.open,
        "tempfile.NamedTemporaryFile": tempfile.NamedTemporaryFile,
        "tempfile.TemporaryFile": tempfile.TemporaryFile,
        "tempfile.SpooledTemporaryFile": tempfile.SpooledTemporaryFile,
    }
    assert set(astlib.OPENERS) == set(live), "table and fixture must cover the same openers"
    for origin, fn in live.items():
        params = list(inspect.signature(fn).parameters)
        slot, default = astlib.OPENERS[origin]
        assert params.index("mode") == slot, f"{origin}: mode is not at slot {slot}"
        assert inspect.signature(fn).parameters["mode"].default == default, origin
        assert "encoding" in params, f"{origin} must actually take encoding="


def test_opener_slot_never_skips_merely_because_the_origin_resolved():
    """`callee() is not None` does NOT mean "the receiver is a module". It may be an
    imported OBJECT, or a local colliding with an import elsewhere in the file. Reading a
    resolved origin as "not an opener" drops the Path-like open the gates exist for."""
    astlib = _load()
    for src in (
        "from defender._paths import PATHS\nPATHS.lessons_dir.open()\n",
        "from x import parser as p\ndef w(d):\n    p = d / 'f'\n    return p.open('w')\n",
    ):
        tree = ast.parse(src)
        env = astlib.module_env(tree)
        call = next(
            n for n in ast.walk(tree)
            if isinstance(n, ast.Call)
            and isinstance(n.func, ast.Attribute)
            and n.func.attr == "open"
        )
        assert astlib.callee(call, env) is not None, "precondition: the origin resolves"
        assert astlib.opener_slot(call, env) == astlib.DUCK_OPENER


def test_open_mode_falls_back_to_the_callees_own_default():
    astlib = _load()
    cases = [
        ("import gzip\ngzip.open(p)\n", "rb"),          # binary by default
        ("open(p)\n", "r"),                             # text by default
        ("import tempfile\ntempfile.TemporaryFile()\n", "w+b"),
        ('open(p, "a")\n', "a"),                        # explicit wins
    ]
    for src, expected in cases:
        tree = ast.parse(src)
        env = astlib.module_env(tree)
        call = next(n for n in ast.walk(tree) if isinstance(n, ast.Call))
        assert astlib.open_mode(call, env) == expected, src


def test_root_name_walks_through_calls_unlike_origin():
    astlib = _load()
    tree = ast.parse("line.strip().lower()\n")
    call = next(n for n in ast.walk(tree) if isinstance(n, ast.Call))
    assert astlib.root_name(call.func) == "line"
