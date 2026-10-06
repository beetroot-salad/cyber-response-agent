"""Spec for the lint_unbounded_whole_read gate (#1188 M4, as amended by design amendment 2).

A whole-file read by path in ``defender/`` production code must not land silently. The gate
flags any use of an attribute named ``read_text`` / ``read_bytes``, called or not, matched by
name whatever the receiver: ``p.read_text()``, the class-qualified ``Path.read_text(p)`` (and
``pathlib.Path.read_bytes(p)``, an aliased ``P.read_text(p)``), and a method reference handed on
(``map(Path.read_text, ps)``, ``partial(Path.read_bytes, p)``, ``r = p.read_text``). Outside the
root ``_io.py`` and outside tests. The remedy is ``_io.read_text_utf8`` / ``read_bytes_capped``;
``getattr(p, "read_text")`` is not matched (recorded non-obligation).

The rare exception is the house convention: ``# lint-whole-read: ok — <reason>`` on the read's
line span, with a reason (not just dashes). The baseline ships EMPTY. ``_io``'s own readers need no marker and
no checking: their cap only lowers (#1188 D1, pinned in ``test_1174_bounded_read.py``).

Fingerprint: ``<rel>:<func>:<kind>``; ``<func>`` is the innermost enclosing ``def`` (``<module>``
at top level). The gate is driven through its seams:
  - ``_scan(root, *, honor_markers=True) -> list[Finding]`` — fingerprints relative to ``root``;
    ``honor_markers=False`` reports marked reads too (the real-tree census uses it);
  - ``main(argv=None, *, scope=None, baseline_path=None) -> int`` — 0 clean, 1 new finding, 2 blind.
"""
from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

from defender.tests._by_path import DEFENDER, LINT_DIR, import_lint_lib, load_lint_gate

_ASTLIB = import_lint_lib("_astlib")
_GATE = load_lint_gate("lint_unbounded_whole_read")

REAL_BASELINE = LINT_DIR / "lint_unbounded_whole_read_baseline.json"
MARK = "# lint-whole-read: ok — operator-only fixture"


def _pyfile(tree: Path, rel: str, src: str) -> Path:
    p = tree / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(src, encoding="utf-8")
    return p


def _tree(tmp_path: Path, files: dict[str, str]) -> Path:
    """A scan root holding a root ``_io.py`` that itself reads whole files (it must be skipped)
    plus ``files`` (rel -> source)."""
    tree = tmp_path / "scope"
    _pyfile(tree, "_io.py", "def read_plain(path):\n    return path.read_bytes()\n")
    for rel, src in files.items():
        _pyfile(tree, rel, src)
    return tree


def _fps(tree: Path, **kw: bool) -> set[str]:
    return {f.fingerprint for f in _GATE._scan(tree, **kw)}


# --------------------------------------------------------------------------------------------
# what is a whole read
# --------------------------------------------------------------------------------------------

def test_attribute_reads_fire_whatever_the_receiver(tmp_path):
    """Pinned encoding or not: this gate is about SIZE, not text-io's locale."""
    tree = _tree(tmp_path, {"prod.py": (
        "class Store:\n"
        "    def load(self):\n"
        "        return self.path.read_text(encoding='utf-8')\n"
        "\n"
        "def f(p, q, base):\n"
        "    return p.read_text(), q.read_bytes(), (base / 'x.json').read_text()\n"
    )})
    assert _fps(tree) == {
        "prod.py:load:read_text",
        "prod.py:f:read_text",
        "prod.py:f:read_bytes",
    }


def test_class_qualified_forms_fire(tmp_path):
    tree = _tree(tmp_path, {"prod.py": (
        "import pathlib\n"
        "import pathlib as pl\n"
        "from pathlib import Path\n"
        "from pathlib import Path as P\n"
        "\n"
        "def direct(a):\n"
        "    return Path.read_text(a)\n"
        "\n"
        "def qualified(b):\n"
        "    return pathlib.Path.read_bytes(b)\n"
        "\n"
        "def aliased(c):\n"
        "    return P.read_text(c, encoding='utf-8')\n"
        "\n"
        "def aliased_module(d):\n"
        "    return pl.Path.read_bytes(d)\n"
    )})
    assert _fps(tree) == {
        "prod.py:direct:read_text",
        "prod.py:qualified:read_bytes",
        "prod.py:aliased:read_text",
        "prod.py:aliased_module:read_bytes",
    }


def test_method_references_fire(tmp_path):
    """A reference to the method reads a whole file when it is later called: flagged where it
    is named. Control (`ctl`): an unrelated attribute of the same receiver is not."""
    tree = _tree(tmp_path, {"prod.py": (
        "from functools import partial\n"
        "from pathlib import Path\n"
        "\n"
        "def mapped(ps):\n"
        "    return list(map(Path.read_text, ps))\n"
        "\n"
        "def partial_bytes(p):\n"
        "    return partial(Path.read_bytes, p)()\n"
        "\n"
        "def stored(p):\n"
        "    r = p.read_text\n"
        "    return r()\n"
        "\n"
        "def ctl(p):\n"
        "    return p.name, p.read_link\n"
    )})
    assert _fps(tree) == {
        "prod.py:mapped:read_text",
        "prod.py:partial_bytes:read_bytes",
        "prod.py:stored:read_text",
    }


def test_function_naming(tmp_path):
    """Innermost def (scoped, not sticky), async alike, `<module>` at top level."""
    tree = _tree(tmp_path, {"prod.py": (
        "from pathlib import Path\n"
        "CSS = (Path(__file__).parent / 'styles.css').read_text(encoding='utf-8')\n"
        "\n"
        "def outer(p, q):\n"
        "    def inner(r):\n"
        "        return r.read_text()\n"
        "    return inner(q), p.read_bytes()\n"
        "\n"
        "async def fetch(s):\n"
        "    return s.read_bytes()\n"
    )})
    assert _fps(tree) == {
        "prod.py:<module>:read_text",
        "prod.py:inner:read_text",
        "prod.py:outer:read_bytes",
        "prod.py:fetch:read_bytes",
    }


def test_handle_and_stdin_reads_are_not_flagged(tmp_path):
    """Recorded non-obligation: reads through an open handle, `sys.stdin`, sized reads. `ctl.py`
    is the positive control in the same tree."""
    tree = _tree(tmp_path, {
        "handles.py": (
            "import json\n"
            "import sys\n"
            "\n"
            "def a(p):\n"
            "    with open(p, encoding='utf-8') as f:\n"
            "        return f.read(), json.load(f), f.readlines(), f.read(4096)\n"
            "\n"
            "def b(p):\n"
            "    return open(p, 'rb').read(), p.open(encoding='utf-8').read()\n"
            "\n"
            "def c():\n"
            "    return sys.stdin.read(), sys.stdin.buffer.read()\n"
        ),
        "ctl.py": "def f(p):\n    return p.read_text()\n",
    })
    assert _fps(tree) == {"ctl.py:f:read_text"}


def test_tests_venv_cache_and_only_the_root_io_py_are_excluded(tmp_path):
    """The same source fires in `prod.py` and in `sub/_io.py` (the exclusion is the ROOT `_io.py`
    only, not a basename), and nowhere else."""
    src = "def f(p):\n    return p.read_text()\n"
    tree = _tree(tmp_path, {
        "prod.py": src,
        "latest.py": src,
        "attest_report.py": src,
        "sub/_io.py": src,
        "tests/helper.py": src,
        "pkg/tests/deep.py": src,
        "test_prod.py": src,
        "prod_test.py": src,
        "conftest.py": src,
        ".venv/lib/site.py": src,
        "__pycache__/cached.py": src,
    })
    assert _fps(tree) == {
        "prod.py:f:read_text", "latest.py:f:read_text", "attest_report.py:f:read_text",
        "sub/_io.py:f:read_text",
    }


def test_same_fingerprint_twice_is_one_finding(tmp_path):
    tree = _tree(tmp_path, {"prod.py": (
        "def twice(p, q):\n"
        "    return p.read_text(), q.read_text()\n"
    )})
    assert [f.fingerprint for f in _GATE._scan(tree)] == ["prod.py:twice:read_text"]


# --------------------------------------------------------------------------------------------
# the marker
# --------------------------------------------------------------------------------------------

def test_a_reasoned_marker_on_the_call_line_suppresses(tmp_path):
    tree = _tree(tmp_path, {"prod.py": (
        "def marked(p):\n"
        f"    return p.read_text()  {MARK}\n"
        "\n"
        "def unmarked(p):\n"
        "    return p.read_text()\n"
    )})
    assert _fps(tree) == {"prod.py:unmarked:read_text"}
    assert _fps(tree, honor_markers=False) == {
        "prod.py:marked:read_text", "prod.py:unmarked:read_text"}


@pytest.mark.parametrize("dash", ["—", "-", "--"])
def test_the_reason_dash_may_be_spelled_plainly(tmp_path, dash):
    tree = _tree(tmp_path, {"prod.py": (
        "def f(p):\n"
        f"    return p.read_text()  # lint-whole-read: ok {dash} repo-shipped prompt\n"
    )})
    assert _fps(tree) == set()


@pytest.mark.parametrize("comment", [
    "# lint-whole-read: ok",
    "# lint-whole-read: ok —",
    "# lint-whole-read: ok —   ",
    "# lint-whole-read: ok -",
    "# lint-whole-read: ok --",
    "# lint-whole-read: ok ——",
    "# lint-whole-read: ok - -",
    "# lint-whole-read: ok —-",
    "# lint-text-io: ok — another gate's marker",
    "# noqa",
    "# ok — trusted",
    "# lint-whole-read — repo-shipped (no `: ok`)",
])
def test_a_marker_without_a_reason_or_another_gates_marker_does_not_suppress(tmp_path, comment):
    """Control: the reasoned marker on the same line suppresses (the test above)."""
    tree = _tree(tmp_path, {"prod.py": f"def f(p):\n    return p.read_text()  {comment}\n"})
    assert _fps(tree) == {"prod.py:f:read_text"}


def test_the_marker_covers_the_calls_own_line_span_only(tmp_path):
    """Any line of a multi-line call counts; the line above or below it does not."""
    tree = _tree(tmp_path, {"prod.py": (
        "def spanned(p):\n"
        "    return p.read_text(\n"
        f"        encoding='utf-8',  {MARK}\n"
        "    )\n"
        "\n"
        "def above(p):\n"
        f"    {MARK}\n"
        "    return p.read_text()\n"
        "\n"
        "def below(p):\n"
        "    x = p.read_text()\n"
        f"    {MARK}\n"
        "    return x\n"
    )})
    assert _fps(tree) == {"prod.py:above:read_text", "prod.py:below:read_text"}


def test_one_marked_read_does_not_cover_another_in_the_same_function(tmp_path):
    """The mark covers its own call: the unmarked read beside it, same kind, same def, fires."""
    tree = _tree(tmp_path, {"prod.py": (
        "def f(p, q):\n"
        f"    a = p.read_text()  {MARK}\n"
        "    b = q.read_text()\n"
        "    return a, b\n"
    )})
    assert _fps(tree) == {"prod.py:f:read_text"}
    assert _GATE.main([], scope=tree, baseline_path=tmp_path / "absent.json") == 1


def test_one_marked_read_does_not_cover_another_in_a_same_named_method(tmp_path):
    """The marker is per call, not per fingerprint: class B's `load` reads unmarked beside class
    A's marked `load`, and the gate fails on it (the empty baseline holds nothing)."""
    tree = _tree(tmp_path, {"prod.py": (
        "class A:\n"
        "    def load(self):\n"
        f"        return self.path.read_text()  {MARK}\n"
        "\n"
        "class B:\n"
        "    def load(self):\n"
        "        return self.path.read_text()\n"
    )})
    empty = tmp_path / "absent.json"
    assert _fps(tree) == {"prod.py:load:read_text"}
    assert _GATE.main([], scope=tree, baseline_path=empty) == 1
    _pyfile(tree, "prod.py", (tree / "prod.py").read_text(encoding="utf-8").replace(
        "        return self.path.read_text()\n",
        f"        return self.path.read_text()  {MARK}\n"))
    assert _GATE.main([], scope=tree, baseline_path=empty) == 0


# --------------------------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------------------------

def test_main_fails_on_an_unmarked_read_and_passes_once_marked(tmp_path):
    tree = _tree(tmp_path, {"prod.py": "def f(p):\n    return p.read_text()\n"})
    empty = tmp_path / "absent.json"
    assert _GATE.main([], scope=tree, baseline_path=empty) == 1
    _pyfile(tree, "prod.py", f"def f(p):\n    return p.read_text()  {MARK}\n")
    assert _GATE.main([], scope=tree, baseline_path=empty) == 0


def test_main_is_blind_when_the_scope_is_missing(tmp_path):
    assert _GATE.main([], scope=tmp_path / "nope", baseline_path=tmp_path / "absent.json") == 2


def test_unparseable_file_is_blind_and_its_control_scans(tmp_path):
    good = _tree(tmp_path / "good", {"prod.py": f"def f(p):\n    return p.read_text()  {MARK}\n"})
    broken = _tree(tmp_path / "broken", {"prod.py": "def f(:\n"})
    empty = tmp_path / "absent.json"
    assert _GATE.main([], scope=good, baseline_path=empty) == 0
    with pytest.raises(_ASTLIB.ScanBlind) as exc:
        _GATE._scan(broken)
    assert "prod.py" in str(exc.value)
    assert _GATE.main([], scope=broken, baseline_path=empty) == 2


def test_cli_exits_with_the_gate_status():
    """CI reads only the process status."""
    src = (LINT_DIR / "lint_unbounded_whole_read.py").read_text(encoding="utf-8")
    guards = [n for n in ast.parse(src).body if isinstance(n, ast.If)
              and "__main__" in ast.unparse(n.test)]
    assert [ast.unparse(s) for g in guards for s in g.body] == ["sys.exit(main())"]


# --------------------------------------------------------------------------------------------
# the real tree (`gate`: CI's lint job runs these; the test job deselects them)
# --------------------------------------------------------------------------------------------

def _independent_census(root: Path) -> list[str]:
    """Written apart from the gate: every attribute named `read_text`/`read_bytes` in `root`'s
    production code (tests, `.venv`, `__pycache__`, the root `_io.py` out), as `rel:line`."""
    found: list[str] = []
    for path in sorted(root.rglob("*.py")):
        rel = path.relative_to(root).as_posix()
        parts = Path(rel).parts
        if (rel == "_io.py" or "tests" in parts or ".venv" in parts or "__pycache__" in parts
                or path.name == "conftest.py" or path.name.startswith("test_")
                or path.name.endswith("_test.py")):
            continue
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Attribute) and node.attr in ("read_text", "read_bytes"):
                found.append(f"{rel}:{node.lineno}")
    return found


def test_the_independent_census_sees_reads(tmp_path):
    """Control for the real-tree census below: it is not empty because it is blind."""
    tree = _tree(tmp_path, {"prod.py": "def f(p):\n    return p.read_text(), p.read_bytes\n"})
    assert _independent_census(tree) == ["prod.py:2", "prod.py:2"]


#: The production whole reads outside `_io`, each in a stdlib-only module run without `defender`
#: on `sys.path`, so `_io` is out of its reach: `_image.py` (`box_image.py` loads it by path on
#: a bare `python3`) and two eval scripts run by path.
_REAL_EXCEPTIONS = {
    "runtime/box/_image.py",
    "evals/oracle_golden/migrate_esql_encoding.py",
    "evals/oracle_golden/story_from_run.py",
}


@pytest.mark.gate
def test_real_tree_has_no_direct_whole_read():
    """Every production whole-file read goes through `_io`'s capped readers (#1188 amendment 3)
    but the stdlib-only image module's, and the baseline holds nothing."""
    found = _independent_census(DEFENDER)
    assert {hit.split(":")[0] for hit in found} == _REAL_EXCEPTIONS, found
    assert len(found) == len(_REAL_EXCEPTIONS), found
    entries = json.loads(REAL_BASELINE.read_text(encoding="utf-8"))["entries"]
    assert entries == {}


def test_the_shipped_baseline_header_is_the_gates():
    """An `--update-baseline` run must not churn the header: the shipped one is the gate's."""
    assert json.loads(REAL_BASELINE.read_text(encoding="utf-8"))["//"] == _GATE.HEADER


@pytest.mark.gate
def test_real_run_scans_the_real_tree_and_reports(capsys):
    """The real path runs the ratchet over the real tree: its summary is printed, with no
    finding. A real run that returned 0 without scanning prints nothing."""
    assert _GATE.main([]) == 0
    out = capsys.readouterr().out
    assert "[lint_unbounded_whole_read] 0 finding(s): 0 baselined, 0 new" in out


@pytest.mark.parametrize("rel", sorted(_REAL_EXCEPTIONS))
def test_each_exception_module_imports_only_the_standard_library(rel):
    """Why these reads are the exceptions: each module runs where `defender` cannot be imported
    (a bare CI `python3`, or a script run by path), so any non-stdlib import there (an `_io`
    reader included) breaks it. The dev venv imports `defender` anyway, so only this check
    sees it."""
    import sys

    tree = ast.parse((DEFENDER / rel).read_text(encoding="utf-8"))
    tops = {alias.name.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.Import)
            for alias in n.names}
    tops |= {n.module.split(".")[0] for n in ast.walk(tree)
             if isinstance(n, ast.ImportFrom) and n.module and n.level == 0}
    assert tops, "the census must see the module's imports"
    assert tops <= set(sys.stdlib_module_names) | {"__future__"}, sorted(tops)
