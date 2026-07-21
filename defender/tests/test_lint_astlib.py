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
        ("import os.path\nos.path.join(a, b)\n", "os.path.join"),
        ("import os.path as osp\nosp.join(a, b)\n", "os.path.join"),
        ("open(p)\n", "builtins.open"),
    ],
)
def test_callee_resolves_every_spelling(src, expected):
    call, env, astlib = _first_call(src)
    assert astlib.callee(call, env) == expected


@pytest.mark.parametrize(
    "src",
    [
        "def f(p):\n    return p.open('r')\n",
        "def f(p):\n    return p.read_text()\n",
        "def f(zf, n):\n    return zf.open(n)\n",
        "def f(self):\n    return self.run(c)\n",
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


def test_a_function_local_import_does_not_leak_into_a_sibling_function():
    """The other half of #607. Collecting a local import must not BIND it module-wide —
    in a sibling function that name is whatever that function makes it."""
    astlib = _load()
    tree = ast.parse(
        "def a():\n"
        "    import json as j\n"
        "    return j.loads('{}')\n"
        "\n"
        "def b(j):\n"
        "    return j.loads('{}')\n"
    )
    env = astlib.module_env(tree)
    calls = [
        n for n in ast.walk(tree)
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
    ]
    inside, sibling = calls[0], calls[1]
    assert astlib.callee(inside, env) == "json.loads"
    assert astlib.callee(sibling, env) is None


def test_a_parameter_shadows_a_module_import():
    call, env, astlib = _first_call(
        "import json\ndef f(json):\n    return json.loads(x)\n"
    )
    assert astlib.callee(call, env) is None


def test_a_parameter_cannot_fabricate_a_builtin_origin():
    """`defines` now carries params and locals, so a parameter named `open` shadows the
    builtin the way Python does."""
    call, env, astlib = _first_call("def f(open, p):\n    return open(p)\n")
    assert astlib.callee(call, env) is None


def test_a_module_import_still_reaches_into_every_function():
    """The load-bearing non-regression: scoping must not make the jsonl/frontmatter gates
    BLIND. For those two, an unresolvable callee means SKIP — so a module-level import
    failing to reach a nested call would silently switch the gate off."""
    astlib = _load()
    tree = ast.parse(
        "import json\n"
        "class C:\n"
        "    def m(self, line):\n"
        "        def inner(s):\n"
        "            return json.loads(s)\n"
        "        return inner(line)\n"
    )
    env = astlib.module_env(tree)
    call = next(
        n for n in ast.walk(tree)
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
    )
    assert astlib.callee(call, env) == "json.loads"


def test_a_local_const_rebind_does_not_carry_the_module_value():
    """`consts` is scoped the same way: a function that rebinds FENCE to something the
    gate cannot read must not keep resolving it to the module's literal."""
    astlib = _load()
    tree = ast.parse(
        'FENCE = "---\\n"\n'
        "def keeps(t):\n"
        "    return t.startswith(FENCE)\n"
        "def rebinds(t, sep):\n"
        "    FENCE = sep\n"
        "    return t.startswith(FENCE)\n"
    )
    env = astlib.module_env(tree)
    calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call)]
    assert astlib.str_args(calls[0], env) == ["---\n"]
    assert astlib.str_args(calls[1], env) == []


def test_str_args_reads_positional_keyword_tuple_and_consts():
    astlib = _load()
    tree = ast.parse(
        'FENCE = "---\\n"\n'
        "def f(t):\n"
        "    a = t.startswith(FENCE)\n"
        '    b = t.startswith(("---", "+++"))\n'
        '    c = t.split(sep="---")\n'
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


def _open_call(src: str):
    astlib = _load()
    tree = ast.parse(src)
    env = astlib.module_env(tree)
    call = next(
        n for n in ast.walk(tree)
        if isinstance(n, ast.Call)
        and isinstance(n.func, ast.Attribute)
        and n.func.attr == "open"
    )
    return call, env, astlib


def test_opener_slot_never_skips_merely_because_the_origin_resolved():
    """`callee() is not None` does NOT mean "the receiver is a module" — it may be an
    imported OBJECT. `PATHS` is a module-level Path-holder, so `PATHS.lessons_dir.open()`
    resolves; reading "it resolved" as "not an opener" would drop a real text open.

    Scoping (#607) does NOT close this one — `PATHS` is never rebound, so it still
    resolves — which is why opener_slot's positive-table rule stays load-bearing."""
    call, env, astlib = _open_call(
        "from defender._paths import PATHS\nPATHS.lessons_dir.open()\n"
    )
    assert astlib.callee(call, env) is not None, "precondition: the origin resolves"
    assert astlib.opener_slot(call, env) == astlib.DUCK_OPENER


def test_a_local_shadows_an_import_bound_in_another_function():
    """#607. `module_env` collects function-local imports (a local `import re as regex` is
    a plausible evasion), but binds them to THEIR OWN SCOPE. Before scoping, the `p` bound
    by one function's import made every other function's local `p` resolve to that module —
    live in judge/compare.py, and it turned a real `Path.open` into a missed violation."""
    call, env, astlib = _open_call(
        "def _invlang():\n"
        "    from defender.skills.invlang import parser as p\n"
        "    return p\n"
        "\n"
        "def w(d):\n"
        "    p = d / 'f'\n"
        "    return p.open('w')\n"
    )
    assert astlib.callee(call, env) is None, "the local `p` is a Path, not the module"
    assert astlib.opener_slot(call, env) == astlib.DUCK_OPENER


def test_open_mode_falls_back_to_the_callees_own_default():
    astlib = _load()
    cases = [
        ("import gzip\ngzip.open(p)\n", "rb"),
        ("open(p)\n", "r"),
        ("import tempfile\ntempfile.TemporaryFile()\n", "w+b"),
        ('open(p, "a")\n', "a"),
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
