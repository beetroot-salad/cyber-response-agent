"""Spec for the lint_unbounded_whole_read gate (#1188, M4).

A whole-file read by path with no size limit, in ``defender/`` production code, must not land
silently. Two shapes count:

- ``read_text`` / ``read_bytes`` — a direct ``<x>.read_text(...)`` / ``<x>.read_bytes()``
  outside ``_io.py``, or the class-qualified ``Path.read_text(p)`` form (resolved through
  ``_astlib.callee``, so ``pathlib.Path.read_bytes(p)`` and an aliased ``P.read_text(p)`` count).
- ``uncapped`` — a call to one of ``_io``'s limit-taking readers that turns the cap off or
  passes one the lint cannot check. The reader set and the cap's value are both DERIVED from
  the scanned root's ``_io.py``, not hand-listed.

Fingerprint: ``<rel>:<func>:<kind>:<detail>``. ``<func>`` is the innermost enclosing ``def``
(``<module>`` at top level). ``<detail>`` is ``ast.unparse`` of the receiver for the attribute
form, of the first argument for the class-qualified form, and the reader's short name for
``uncapped``. Same fingerprint twice in one function is one finding (a known blind spot).

The gate is driven through its seams only:
  - ``_scan(root) -> list[Finding]`` — fingerprints relative to ``root``, no prefix; raises
    ``_astlib.ScanBlind`` when ``<root>/_io.py`` is absent (it cannot see the reader set).
  - ``main(argv=None, *, scope=None, baseline_path=None) -> int`` — 0 clean, 1 new finding /
    un-reasoned entry / ``_io`` default drift, 2 blind.
  - ``_drifted_defaults(io_path) -> list[str]`` — ``_io`` readers whose ``limit`` default is
    not the bare name ``READ_LIMIT`` (drift is not baselinable: it uncaps every caller).

Every tmp tree carries a minimal ``_io.py`` (`_io_py`) that itself contains flaggable reads, so
every exact-set assertion below also checks that the root ``_io.py`` is excluded.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from defender.tests._by_path import DEFENDER, LINT_DIR, import_lint_lib, load_lint_gate

_ASTLIB = import_lint_lib("_astlib")
_GATE = load_lint_gate("lint_unbounded_whole_read")

REAL_BASELINE = LINT_DIR / "lint_unbounded_whole_read_baseline.json"

#: `READ_LIMIT = 64 * 1024 * 1024` in the default stub, evaluated.
_CAP = 64 * 1024 * 1024


# --------------------------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------------------------

def _pyfile(tree: Path, rel: str, src: str) -> Path:
    p = tree / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(src, encoding="utf-8")
    return p


def _io_py(
    tree: Path,
    *,
    read_limit: str = "64 * 1024 * 1024",
    jsonl_default: str = "READ_LIMIT",
    extra: str = "",
) -> Path:
    """A minimal stand-in for ``defender/_io.py`` at ``<tree>/_io.py``.

    Readers: public ``read_jsonl_rows`` (default ``jsonl_default``) and ``read_text_utf8``
    (default ``READ_LIMIT``); private ``_read_followed`` with a REQUIRED ``limit`` (no default,
    as the real one has); ``read_plain`` with no ``limit`` at all. Each body does a
    ``read_text``/``read_bytes`` of its own, which the gate must not report from the root
    ``_io.py``.
    """
    return _pyfile(tree, "_io.py", (
        "from pathlib import Path\n"
        "\n"
        f"READ_LIMIT = {read_limit}\n"
        "\n"
        "\n"
        f"def read_jsonl_rows(path: Path, *, limit: int | None = {jsonl_default}) -> list:\n"
        "    return path.read_text(encoding='utf-8').splitlines()\n"
        "\n"
        "\n"
        "def read_text_utf8(path: Path, *, limit: int | None = READ_LIMIT) -> str:\n"
        "    return path.read_text(encoding='utf-8')\n"
        "\n"
        "\n"
        "def _read_followed(path: Path, *, limit: int | None, errors: str) -> str:\n"
        "    return path.read_text(encoding='utf-8', errors=errors)\n"
        "\n"
        "\n"
        "def read_plain(path: Path) -> bytes:\n"
        "    return path.read_bytes()\n"
        + extra
    ))


def _tree(tmp_path: Path, files: dict[str, str], **io_kw: str) -> Path:
    """A scan root holding the stub ``_io.py`` plus ``files`` (rel -> source)."""
    tree = tmp_path / "scope"
    _io_py(tree, **io_kw)
    for rel, src in files.items():
        _pyfile(tree, rel, src)
    return tree


def _fps(tree: Path) -> set[str]:
    return {f.fingerprint for f in _GATE._scan(tree)}


def _write_baseline(path: Path, entries: dict[str, str]) -> Path:
    path.write_text(json.dumps({"//": "test", "entries": entries}) + "\n", encoding="utf-8")
    return path


# --------------------------------------------------------------------------------------------
# read_text / read_bytes
# --------------------------------------------------------------------------------------------

def test_attribute_reads_fire_with_the_receiver_as_detail(tmp_path):
    """Any receiver, pinned encoding or not: this gate is about SIZE, not text-io's locale.
    The detail is `ast.unparse` of the receiver, so two reads in one function on different
    paths are two fingerprints."""
    tree = _tree(tmp_path, {"prod.py": (
        "class Store:\n"
        "    def load(self):\n"
        "        return self.path.read_text(encoding='utf-8')\n"
        "\n"
        "def f(p, q, base):\n"
        "    a = p.read_text(encoding='utf-8')\n"
        "    b = q.read_bytes()\n"
        "    c = (base / 'x.json').read_text()\n"
        "    return a, b, c\n"
    )})
    assert _fps(tree) == {
        "prod.py:load:read_text:self.path",
        "prod.py:f:read_text:p",
        "prod.py:f:read_bytes:q",
        "prod.py:f:read_text:base / 'x.json'",
    }


def test_class_qualified_forms_take_the_first_argument_as_detail(tmp_path):
    """`Path.read_text(p)` reads `p`; its receiver is the class. A receiver-only detail would
    give `Path` / `pathlib.Path` / `P` — every class-qualified read in a function collapsing to
    one fingerprint, and the alias spelling leaking into the baseline."""
    tree = _tree(tmp_path, {"prod.py": (
        "import pathlib\n"
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
    )})
    assert _fps(tree) == {
        "prod.py:direct:read_text:a",
        "prod.py:qualified:read_bytes:b",
        "prod.py:aliased:read_text:c",
    }


def test_module_level_read_is_fingerprinted_under_module(tmp_path):
    tree = _tree(tmp_path, {"prod.py": (
        "from pathlib import Path\n"
        "ASSETS = Path(__file__).parent\n"
        "CSS = (ASSETS / 'styles.css').read_text(encoding='utf-8')\n"
        "\n"
        "def render(p):\n"
        "    return p.read_text()\n"
    )})
    assert _fps(tree) == {
        "prod.py:<module>:read_text:ASSETS / 'styles.css'",
        "prod.py:render:read_text:p",
    }


def test_nested_function_takes_the_innermost_name(tmp_path):
    """The read inside `inner` is `inner`'s; the read after `inner`'s def is `outer`'s again
    (the name is scoped, not sticky). An async def names its reads like a def."""
    tree = _tree(tmp_path, {"prod.py": (
        "def outer(p, q):\n"
        "    def inner(r):\n"
        "        return r.read_text()\n"
        "    x = inner(q)\n"
        "    return x, p.read_bytes()\n"
        "\n"
        "async def fetch(s):\n"
        "    return s.read_bytes()\n"
    )})
    assert _fps(tree) == {
        "prod.py:inner:read_text:r",
        "prod.py:outer:read_bytes:p",
        "prod.py:fetch:read_bytes:s",
    }


def test_handle_and_stdin_reads_are_not_flagged(tmp_path):
    """Recorded non-obligation: reads through an open handle (`f.read()`, `open(p).read()`,
    `p.open().read()`, `json.load(f)`), `sys.stdin`, sized reads. `ctl.py` is the positive
    control in the same tree: a path read beside them is still reported."""
    tree = _tree(tmp_path, {
        "handles.py": (
            "import json\n"
            "import sys\n"
            "\n"
            "def from_handle(p):\n"
            "    with open(p, encoding='utf-8') as f:\n"
            "        return f.read()\n"
            "\n"
            "def from_open(p):\n"
            "    return open(p, 'rb').read()\n"
            "\n"
            "def from_path_open(p):\n"
            "    return p.open(encoding='utf-8').read()\n"
            "\n"
            "def from_json(p):\n"
            "    with open(p, encoding='utf-8') as f:\n"
            "        return json.load(f)\n"
            "\n"
            "def from_stdin():\n"
            "    return sys.stdin.read()\n"
            "\n"
            "def from_stdin_bytes():\n"
            "    return sys.stdin.buffer.read()\n"
            "\n"
            "def sized(f):\n"
            "    return f.read(4096)\n"
            "\n"
            "def lines(f):\n"
            "    return f.readlines()\n"
        ),
        "ctl.py": "def f(p):\n    return p.read_text()\n",
    })
    assert _fps(tree) == {"ctl.py:f:read_text:p"}


# --------------------------------------------------------------------------------------------
# exclusions
# --------------------------------------------------------------------------------------------

def test_test_modules_venv_and_the_root_io_py_are_excluded(tmp_path):
    """The same source fires in `prod.py` and nowhere else. The `_io.py` exclusion is the ROOT
    file only: `sub/_io.py` (same stub source, same basename) is scanned like any module — a
    basename exclusion would let any package hide a read in a file called `_io.py`."""
    src = "def f(p):\n    return p.read_text()\n"
    tree = _tree(tmp_path, {
        "prod.py": src,
        "tests/helper.py": src,
        "pkg/tests/deep.py": src,
        "test_prod.py": src,
        "prod_test.py": src,
        "conftest.py": src,
        ".venv/lib/site.py": src,
        "__pycache__/cached.py": src,
    })
    _io_py(tree / "sub")
    assert _fps(tree) == {
        "prod.py:f:read_text:p",
        "sub/_io.py:read_jsonl_rows:read_text:path",
        "sub/_io.py:read_text_utf8:read_text:path",
        "sub/_io.py:_read_followed:read_text:path",
        "sub/_io.py:read_plain:read_bytes:path",
    }


# --------------------------------------------------------------------------------------------
# uncapped
# --------------------------------------------------------------------------------------------

_PRELUDE = (
    "from defender import _io\n"
    "from defender._io import READ_LIMIT, read_jsonl_rows\n"
    "CAP = 1024\n"
    "\n"
)

#: (id, silent call, firing call) — the same call shape under the complementary condition.
_CAP_PAIRS = [
    ("no-limit-kw-vs-none",
     "read_jsonl_rows(p)", "read_jsonl_rows(p, limit=None)"),
    ("read-limit-name-vs-none",
     "read_jsonl_rows(p, limit=READ_LIMIT)", "read_jsonl_rows(p, limit=None)"),
    ("read-limit-attr-vs-arithmetic-on-it",
     "read_jsonl_rows(p, limit=_io.READ_LIMIT)", "read_jsonl_rows(p, limit=_io.READ_LIMIT * 2)"),
    ("small-literal-vs-over-cap-literal",
     "read_jsonl_rows(p, limit=1024)", f"read_jsonl_rows(p, limit={_CAP + 1})"),
    ("literal-at-cap-vs-one-over",
     f"read_jsonl_rows(p, limit={_CAP})", f"read_jsonl_rows(p, limit={_CAP + 1})"),
    # Fail-safe: `_astlib` keeps only str constants, so an int constant is not resolved even
    # when its value (1024) is under the cap. A deliberate site takes a baseline entry.
    ("literal-vs-module-constant",
     "read_jsonl_rows(p, limit=1024)", "read_jsonl_rows(p, limit=CAP)"),
    ("literal-vs-variable",
     "read_jsonl_rows(p, limit=1024)", "read_jsonl_rows(p, limit=n)"),
    ("literal-vs-arithmetic",
     "read_jsonl_rows(p, limit=4194304)", "read_jsonl_rows(p, limit=4 * 1024 * 1024)"),
]


@pytest.mark.parametrize(
    ("silent", "firing"), [(s, f) for _, s, f in _CAP_PAIRS], ids=[i for i, _, _ in _CAP_PAIRS])
def test_cap_forms_silent_vs_uncapped_forms_firing(tmp_path, silent, firing):
    """Silent: no `limit=`, an int literal <= READ_LIMIT, `READ_LIMIT`/`_io.READ_LIMIT`
    resolving to `defender._io.READ_LIMIT`. Fires: `None`, a literal over the cap, anything
    else. The exactly-at-cap literal is silent (<=), which also proves the stub's
    `64 * 1024 * 1024` was evaluated, not compared as text."""
    quiet = _tree(tmp_path / "quiet", {"prod.py": _PRELUDE + f"def f(p, n):\n    return {silent}\n"})
    loud = _tree(tmp_path / "loud", {"prod.py": _PRELUDE + f"def f(p, n):\n    return {firing}\n"})
    assert _fps(quiet) == set()
    assert _fps(loud) == {"prod.py:f:uncapped:read_jsonl_rows"}


def test_read_limit_is_matched_by_origin_not_spelling(tmp_path):
    """`limit=READ_LIMIT` is silent only when that name resolves to `defender._io.READ_LIMIT`.
    A module's own `READ_LIMIT`, or a local rebinding shadowing the import, is just another
    expression and fires."""
    tree = _tree(tmp_path, {
        "imported.py": (
            "from defender._io import READ_LIMIT, read_jsonl_rows\n"
            "def f(p):\n"
            "    return read_jsonl_rows(p, limit=READ_LIMIT)\n"
        ),
        "own.py": (
            "from defender._io import read_jsonl_rows\n"
            "READ_LIMIT = 10 ** 12\n"
            "def f(p):\n"
            "    return read_jsonl_rows(p, limit=READ_LIMIT)\n"
        ),
        "rebound.py": (
            "from defender._io import READ_LIMIT, read_jsonl_rows\n"
            "def f(p, n):\n"
            "    READ_LIMIT = n\n"
            "    return read_jsonl_rows(p, limit=READ_LIMIT)\n"
        ),
    })
    assert _fps(tree) == {
        "own.py:f:uncapped:read_jsonl_rows",
        "rebound.py:f:uncapped:read_jsonl_rows",
    }


def test_uncapped_matches_every_way_the_reader_is_reached(tmp_path):
    """Resolved callee (from-import, `from defender import _io`, `import ... as`, the dotted
    `defender._io.f`, a renamed from-import) and, where the callee cannot resolve, the
    attribute name (an injected `io` parameter, `self.io`). Public and private readers alike.
    The detail is the reader's SHORT NAME in `_io`, never the local alias (`rows`)."""
    tree = _tree(tmp_path, {"prod.py": (
        "import defender._io\n"
        "import defender._io as dio\n"
        "from defender import _io\n"
        "from defender._io import _read_followed, read_jsonl_rows, read_text_utf8\n"
        "from defender._io import read_jsonl_rows as rows\n"
        "\n"
        "def direct(p):\n"
        "    return read_jsonl_rows(p, limit=None)\n"
        "\n"
        "def other_reader(p):\n"
        "    return read_text_utf8(p, limit=None)\n"
        "\n"
        "def via_module(p):\n"
        "    return _io.read_jsonl_rows(p, limit=None)\n"
        "\n"
        "def via_alias(p):\n"
        "    return dio.read_jsonl_rows(p, limit=None)\n"
        "\n"
        "def via_dotted(p):\n"
        "    return defender._io.read_jsonl_rows(p, limit=None)\n"
        "\n"
        "def renamed(p):\n"
        "    return rows(p, limit=None)\n"
        "\n"
        "def private(p):\n"
        "    return _read_followed(p, limit=None, errors='strict')\n"
        "\n"
        "def injected(io, p):\n"
        "    return io.read_jsonl_rows(p, limit=None)\n"
        "\n"
        "class Handle:\n"
        "    def load(self, p):\n"
        "        return self.io.read_text_utf8(p, limit=None)\n"
    )})
    assert _fps(tree) == {
        "prod.py:direct:uncapped:read_jsonl_rows",
        "prod.py:other_reader:uncapped:read_text_utf8",
        "prod.py:via_module:uncapped:read_jsonl_rows",
        "prod.py:via_alias:uncapped:read_jsonl_rows",
        "prod.py:via_dotted:uncapped:read_jsonl_rows",
        "prod.py:renamed:uncapped:read_jsonl_rows",
        "prod.py:private:uncapped:_read_followed",
        "prod.py:injected:uncapped:read_jsonl_rows",
        "prod.py:load:uncapped:read_text_utf8",
    }


def test_injected_reader_with_its_cap_is_silent(tmp_path):
    """The silent twin of the injected-module match: same `io.read_jsonl_rows(...)` shape, no
    `limit=`. Positive control in the same tree: the `limit=None` call fires."""
    tree = _tree(tmp_path, {"prod.py": (
        "def capped(io, p):\n"
        "    return io.read_jsonl_rows(p)\n"
        "\n"
        "def uncapped(io, p):\n"
        "    return io.read_jsonl_rows(p, limit=None)\n"
    )})
    assert _fps(tree) == {"prod.py:uncapped:uncapped:read_jsonl_rows"}


def test_limit_none_on_a_function_outside_io_is_not_flagged(tmp_path):
    """`limit=None` is only a finding on an `_io` reader. A local function or method with a
    `limit` parameter of its own is not one; nor is a same-named function whose callee
    RESOLVES to another module (the attribute-name fallback is for an unresolvable callee
    only). `control` is the same call to the `_io` reader, which fires."""
    tree = _tree(tmp_path, {"prod.py": (
        "from defender._io import read_jsonl_rows\n"
        "from otherpkg import store\n"
        "\n"
        "def load_all(p, *, limit=None):\n"
        "    return [p]\n"
        "\n"
        "def local_def(p):\n"
        "    return load_all(p, limit=None)\n"
        "\n"
        "def other_method(cache, p):\n"
        "    return cache.load_all(p, limit=None)\n"
        "\n"
        "def same_name_elsewhere(p):\n"
        "    return store.read_jsonl_rows(p, limit=None)\n"
        "\n"
        "def control(p):\n"
        "    return read_jsonl_rows(p, limit=None)\n"
    )})
    assert _fps(tree) == {"prod.py:control:uncapped:read_jsonl_rows"}


def test_reader_set_comes_from_the_scanned_io_py(tmp_path):
    """The limit-taking set is parsed from `<root>/_io.py`, not hand-listed: a reader that
    exists only in this stub (`read_widget`) is covered, by import and by attribute; a real
    `defender/_io.py` reader the stub does NOT define (`read_text_soft`) is not one here.
    `present` is the positive control for the same call shape."""
    tree = _tree(
        tmp_path,
        {"prod.py": (
            "from defender._io import read_text_soft, read_text_utf8, read_widget\n"
            "\n"
            "def novel(p):\n"
            "    return read_widget(p, limit=None)\n"
            "\n"
            "def novel_injected(io, p):\n"
            "    return io.read_widget(p, limit=None)\n"
            "\n"
            "def absent(p):\n"
            "    return read_text_soft(p, limit=None)\n"
            "\n"
            "def present(p):\n"
            "    return read_text_utf8(p, limit=None)\n"
        )},
        extra=(
            "\n"
            "\n"
            "def read_widget(path: Path, *, limit: int | None = READ_LIMIT) -> bytes:\n"
            "    return b''\n"
        ),
    )
    assert _fps(tree) == {
        "prod.py:novel:uncapped:read_widget",
        "prod.py:novel_injected:uncapped:read_widget",
        "prod.py:present:uncapped:read_text_utf8",
    }


@pytest.mark.parametrize("read_limit", ["10", "2 * 5"])
def test_read_limit_value_comes_from_the_scanned_io_py(tmp_path, read_limit):
    """With the scanned `_io.py`'s cap at 10, `limit=10` is silent and `limit=11` fires — the
    cap is read (and its arithmetic evaluated), not hardcoded at 64 MiB."""
    tree = _tree(
        tmp_path,
        {"prod.py": (
            "from defender._io import read_jsonl_rows\n"
            "\n"
            "def at_cap(p):\n"
            "    return read_jsonl_rows(p, limit=10)\n"
            "\n"
            "def over_cap(p):\n"
            "    return read_jsonl_rows(p, limit=11)\n"
        )},
        read_limit=read_limit,
    )
    assert _fps(tree) == {"prod.py:over_cap:uncapped:read_jsonl_rows"}


def test_same_fingerprint_twice_in_a_function_is_one_finding(tmp_path):
    """Set semantics, for both kinds: a second identical read in one function is the same
    finding (the accepted blind spot). A different receiver or a different reader is not."""
    tree = _tree(tmp_path, {"prod.py": (
        "from defender._io import read_jsonl_rows, read_text_utf8\n"
        "\n"
        "def twice(p):\n"
        "    return p.read_text(), p.read_text(encoding='utf-8')\n"
        "\n"
        "def two_receivers(p, q):\n"
        "    return p.read_text(), q.read_text()\n"
        "\n"
        "def twice_uncapped(p, q):\n"
        "    return read_jsonl_rows(p, limit=None), read_jsonl_rows(q, limit=None)\n"
        "\n"
        "def two_readers(p):\n"
        "    return read_jsonl_rows(p, limit=None), read_text_utf8(p, limit=None)\n"
    )})
    assert sorted(f.fingerprint for f in _GATE._scan(tree)) == sorted([
        "prod.py:twice:read_text:p",
        "prod.py:two_receivers:read_text:p",
        "prod.py:two_receivers:read_text:q",
        "prod.py:twice_uncapped:uncapped:read_jsonl_rows",
        "prod.py:two_readers:uncapped:read_jsonl_rows",
        "prod.py:two_readers:uncapped:read_text_utf8",
    ])


# --------------------------------------------------------------------------------------------
# _io default drift
# --------------------------------------------------------------------------------------------

def test_drifted_defaults_flags_a_none_default_and_not_read_limit(tmp_path):
    """Same stub, one default flipped. A REQUIRED `limit` (`_read_followed`, no default) is not
    drift: there is no default to flip, and every caller must pass one the gate checks."""
    clean = _io_py(tmp_path / "clean")
    drifted = _io_py(tmp_path / "drifted", jsonl_default="None")
    assert _GATE._drifted_defaults(clean) == []
    assert _GATE._drifted_defaults(drifted) == ["read_jsonl_rows"]


def test_drifted_defaults_names_every_drifted_reader(tmp_path):
    """Keyword-only and positional `limit` alike, public and private; any default that is not
    the bare name `READ_LIMIT` (an expression over it included)."""
    io = _io_py(tmp_path, jsonl_default="None", extra=(
        "\n"
        "\n"
        "def _read_plain_fd(fd: int, *, limit: int = 2 * READ_LIMIT) -> bytes:\n"
        "    return b''\n"
        "\n"
        "\n"
        "def read_positional(path: Path, limit: int | None = None) -> str:\n"
        "    return ''\n"
        "\n"
        "\n"
        "def read_kept(path: Path, limit: int | None = READ_LIMIT) -> str:\n"
        "    return ''\n"
    ))
    assert sorted(_GATE._drifted_defaults(io)) == [
        "_read_plain_fd", "read_jsonl_rows", "read_positional",
    ]


def test_main_fails_on_default_drift_even_when_every_finding_is_baselined(tmp_path):
    """Drift uncaps every caller at once and is not baselinable. Positive control: the same
    tree and baseline with the default left at `READ_LIMIT` passes."""
    prod = {"prod.py": "def f(p):\n    return p.read_text()\n"}
    bp = _write_baseline(tmp_path / "bp.json", {"prod.py:f:read_text:p": "operator-only fixture"})
    clean = _tree(tmp_path / "clean", prod)
    drifted = _tree(tmp_path / "drifted", prod, jsonl_default="None")
    assert _fps(drifted) == {"prod.py:f:read_text:p"}
    assert _GATE.main([], scope=clean, baseline_path=bp) == 0
    assert _GATE.main([], scope=drifted, baseline_path=bp) == 1


def test_main_fails_on_default_drift_with_no_findings_at_all(tmp_path):
    clean = _tree(tmp_path / "clean", {"prod.py": "X = 1\n"})
    drifted = _tree(tmp_path / "drifted", {"prod.py": "X = 1\n"}, jsonl_default="None")
    empty = tmp_path / "absent.json"
    assert _GATE.main([], scope=clean, baseline_path=empty) == 0
    assert _GATE.main([], scope=drifted, baseline_path=empty) == 1


# --------------------------------------------------------------------------------------------
# main: the ratchet
# --------------------------------------------------------------------------------------------

def test_main_ratchet_new_finding_and_reasons(tmp_path):
    """require_reasons: an entry with an empty reason fails like a new finding. An injected
    scope's fingerprints carry no prefix, so a `defender/`-prefixed key does not cover one."""
    tree = _tree(tmp_path, {"prod.py": "def f(p):\n    return p.read_text()\n"})
    fp = "prod.py:f:read_text:p"
    assert _GATE.main([], scope=tree, baseline_path=tmp_path / "absent.json") == 1
    assert _GATE.main([], scope=tree, baseline_path=_write_baseline(
        tmp_path / "empty_reason.json", {fp: ""})) == 1
    assert _GATE.main([], scope=tree, baseline_path=_write_baseline(
        tmp_path / "prefixed.json", {f"defender/{fp}": "operator-only fixture"})) == 1
    reasoned = _write_baseline(tmp_path / "reasoned.json", {fp: "operator-only fixture"})
    assert _GATE.main([], scope=tree, baseline_path=reasoned) == 0

    _pyfile(tree, "new.py", "def g(q):\n    return q.read_bytes()\n")
    assert _GATE.main([], scope=tree, baseline_path=reasoned) == 1, \
        "a new finding beside a baselined one still fails"


def test_uncapped_finding_is_baselined_like_any_other(tmp_path):
    tree = _tree(tmp_path, {"prod.py": (
        "from defender._io import read_jsonl_rows\n"
        "def load(p):\n"
        "    return read_jsonl_rows(p, limit=None)\n"
    )})
    fp = "prod.py:load:uncapped:read_jsonl_rows"
    assert _GATE.main([], scope=tree, baseline_path=_write_baseline(
        tmp_path / "empty_reason.json", {fp: ""})) == 1
    assert _GATE.main([], scope=tree, baseline_path=_write_baseline(
        tmp_path / "reasoned.json", {fp: "host-written log, operator tool"})) == 0


def test_main_is_blind_when_the_scope_is_missing(tmp_path):
    assert _GATE.main([], scope=tmp_path / "nope", baseline_path=tmp_path / "absent.json") == 2


def test_missing_io_py_is_blind_not_clean(tmp_path):
    """A tree with nothing to flag still cannot report clean without `<root>/_io.py`: the gate
    cannot see the reader set or the cap. Control: the same tree with the stub is clean."""
    tree = tmp_path / "scope"
    _pyfile(tree, "prod.py", "X = 1\n")
    empty = tmp_path / "absent.json"
    with pytest.raises(_ASTLIB.ScanBlind) as exc:
        _GATE._scan(tree)
    assert "_io.py" in str(exc.value)
    assert _GATE.main([], scope=tree, baseline_path=empty) == 2

    _io_py(tree)
    assert _GATE._scan(tree) == []
    assert _GATE.main([], scope=tree, baseline_path=empty) == 0


def test_unparseable_file_is_blind(tmp_path):
    tree = _tree(tmp_path, {
        "broken.py": "def f(:\n",
        "prod.py": "def f(p):\n    return p.read_text()\n",
    })
    bp = _write_baseline(tmp_path / "bp.json", {"prod.py:f:read_text:p": "operator-only fixture"})
    with pytest.raises(_ASTLIB.ScanBlind) as exc:
        _GATE._scan(tree)
    assert "broken.py" in str(exc.value)
    assert _GATE.main([], scope=tree, baseline_path=bp) == 2


def test_clean_tree_still_scans(tmp_path):
    """Control for the blind tests: without the unparseable file the same tree scans and the
    baselined finding passes, so neither raises-test can pass against a gate that always
    raises."""
    tree = _tree(tmp_path, {"prod.py": "def f(p):\n    return p.read_text()\n"})
    bp = _write_baseline(tmp_path / "bp.json", {"prod.py:f:read_text:p": "operator-only fixture"})
    assert _fps(tree) == {"prod.py:f:read_text:p"}
    assert _GATE.main([], scope=tree, baseline_path=bp) == 0


# --------------------------------------------------------------------------------------------
# the real tree (`gate`: CI's lint job runs these; the test job deselects them)
# --------------------------------------------------------------------------------------------

#: Real findings the contract names. Unprefixed: `_scan(DEFENDER)` fingerprints.
_KNOWN_REAL = (
    "scripts/visualize/visualize_messages.py:load_messages:uncapped:read_jsonl_rows",
    "_yaml.py:read_reviewed_text:read_text:path",
)

#: investigation.md reads. The run dir is box-writable (bounded by the box fsize cap) AND
#: host-written, and every host writer goes through `validate_artifact` with
#: `INVESTIGATION_FILE_MAX = 65536` — the reason must name that 64 KiB host-writer cap.
_INVESTIGATION_READS = (
    "learning/author/verify_forward/forward.py:load_run_context:read_text:investigation",
    "scripts/visualize/visualize_data.py:split_investigation_phases:read_text:p",
)


def _real_entries() -> dict[str, str]:
    data = json.loads(REAL_BASELINE.read_text(encoding="utf-8"))
    entries = data["entries"]
    assert isinstance(entries, dict)
    return entries


def _real_fps() -> set[str]:
    return {f.fingerprint for f in _GATE._scan(DEFENDER)}


@pytest.mark.gate
def test_real_tree_main_is_clean():
    """Every real finding baselined with a reason, and no `_io` default drift."""
    assert _GATE.main([]) == 0


@pytest.mark.gate
def test_real_scan_holds_the_known_sites_and_skips_io_and_tests():
    fps = _real_fps()
    for fp in (*_KNOWN_REAL, *_INVESTIGATION_READS):
        assert fp in fps, fp
    assert not any(fp.startswith("_io.py:") for fp in fps), "the root _io.py is out of scope"
    assert not any("tests" in Path(fp.split(":", 1)[0]).parts for fp in fps), \
        "test modules are out of scope"


@pytest.mark.gate
def test_real_io_has_no_default_drift():
    """The real `_io.py` has a required-`limit` reader (`_read_followed`); it is not drift."""
    assert _GATE._drifted_defaults(DEFENDER / "_io.py") == []


@pytest.mark.gate
def test_real_baseline_is_exactly_the_current_findings_each_with_a_reason():
    entries = _real_entries()
    current = {f"defender/{fp}" for fp in _real_fps()}
    stale = sorted(set(entries) - current)
    missing = sorted(current - set(entries))
    assert not stale, f"stale baseline entries (no longer a finding): {stale}"
    assert not missing, f"real findings with no baseline entry: {missing}"
    unreasoned = sorted(fp for fp, reason in entries.items() if not reason.strip())
    assert not unreasoned, f"baseline entries with no reason: {unreasoned}"
    for fp in _KNOWN_REAL:
        assert entries[f"defender/{fp}"].strip(), fp


@pytest.mark.gate
def test_real_investigation_reads_name_the_host_writer_cap():
    entries = _real_entries()
    for fp in _INVESTIGATION_READS:
        reason = entries[f"defender/{fp}"]
        assert "64 KiB" in reason, f"{fp}: reason must name the 64 KiB host-writer cap: {reason!r}"


# --------------------------------------------------------------------------------------------
# adversary pass (#1188): shapes the first spec pinned only by the design's example spellings
# --------------------------------------------------------------------------------------------

def test_injected_receiver_is_matched_by_reader_name_not_receiver_spelling(tmp_path):
    """The fallback keys on the attribute (the reader's name), whatever the receiver is called:
    `io_mod.` is a spelling the real tree uses. Control: the same receiver, capped, is silent."""
    tree = _tree(tmp_path, {"prod.py": (
        "def a(io_mod, p):\n"
        "    return io_mod.read_jsonl_rows(p, limit=None)\n"
        "\n"
        "def b(deps, p):\n"
        "    return deps.store.io.read_text_utf8(p, limit=None)\n"
        "\n"
        "def capped(io_mod, p):\n"
        "    return io_mod.read_jsonl_rows(p)\n"
    )})
    assert _fps(tree) == {
        "prod.py:a:uncapped:read_jsonl_rows",
        "prod.py:b:uncapped:read_text_utf8",
    }


def test_a_read_limit_from_anywhere_but_io_fires(tmp_path):
    """Origin, not the trailing name: a `READ_LIMIT` imported from another module, or any
    `<x>.READ_LIMIT` that is not `defender._io`'s, is just another expression."""
    tree = _tree(tmp_path, {"prod.py": (
        "from defender._io import read_jsonl_rows\n"
        "from otherpkg import READ_LIMIT\n"
        "from otherpkg import cfg\n"
        "\n"
        "def other_import(p):\n"
        "    return read_jsonl_rows(p, limit=READ_LIMIT)\n"
        "\n"
        "def other_attr(p):\n"
        "    return read_jsonl_rows(p, limit=cfg.READ_LIMIT)\n"
    )})
    assert _fps(tree) == {
        "prod.py:other_import:uncapped:read_jsonl_rows",
        "prod.py:other_attr:uncapped:read_jsonl_rows",
    }


def test_relative_imports_of_io_resolve(tmp_path):
    """A module inside the package reaching `_io` relatively (`from .._io import ...`,
    `from .. import _io`) is the same reader; so is its `READ_LIMIT` (the silent control)."""
    tree = _tree(tmp_path, {"learning/prod.py": (
        "from .. import _io\n"
        "from .._io import READ_LIMIT, read_jsonl_rows\n"
        "\n"
        "def from_name(p):\n"
        "    return read_jsonl_rows(p, limit=None)\n"
        "\n"
        "def from_module(p):\n"
        "    return _io.read_text_utf8(p, limit=None)\n"
        "\n"
        "def capped(p):\n"
        "    return read_jsonl_rows(p, limit=READ_LIMIT)\n"
    )})
    assert _fps(tree) == {
        "learning/prod.py:from_name:uncapped:read_jsonl_rows",
        "learning/prod.py:from_module:uncapped:read_text_utf8",
    }


def test_a_positional_limit_reader_is_in_the_reader_set(tmp_path):
    """`limit` as a plain positional parameter counts as much as a keyword-only one."""
    tree = _tree(
        tmp_path,
        {"prod.py": (
            "from defender._io import read_pos\n"
            "\n"
            "def f(p):\n"
            "    return read_pos(p, limit=None)\n"
            "\n"
            "def capped(p):\n"
            "    return read_pos(p, limit=10)\n"
        )},
        extra=(
            "\n"
            "\n"
            "def read_pos(path: Path, limit: int | None = READ_LIMIT) -> str:\n"
            "    return ''\n"
        ),
    )
    assert _fps(tree) == {"prod.py:f:uncapped:read_pos"}


def test_a_comment_does_not_suppress(tmp_path):
    """No inline escape: the only way past the gate is a reasoned baseline entry."""
    tree = _tree(tmp_path, {"prod.py": (
        "from defender._io import read_jsonl_rows\n"
        "\n"
        "def f(p):\n"
        "    return p.read_text()  # noqa  lint-unbounded-read: ok\n"
        "\n"
        "def g(p):\n"
        "    return read_jsonl_rows(p, limit=None)  # ok — trusted\n"
    )})
    assert _fps(tree) == {"prod.py:f:read_text:p", "prod.py:g:uncapped:read_jsonl_rows"}


def test_class_qualified_through_an_aliased_module(tmp_path):
    tree = _tree(tmp_path, {"prod.py": (
        "import pathlib as pl\n"
        "\n"
        "def f(p):\n"
        "    return pl.Path.read_text(p)\n"
    )})
    assert _fps(tree) == {"prod.py:f:read_text:p"}


def _independent_real_census() -> set[str]:
    """C11's probe, written apart from the gate: every `<x>.read_text/read_bytes(...)` call in
    `defender/` production code (tests, `.venv`, `__pycache__` and the root `_io.py` out), as
    `rel:kind`. The gate's scan must cover every one, so it cannot narrow its own scope."""
    import ast

    found: set[str] = set()
    for path in DEFENDER.rglob("*.py"):
        rel = path.relative_to(DEFENDER).as_posix()
        parts = Path(rel).parts
        if (rel == "_io.py" or "tests" in parts or ".venv" in parts or "__pycache__" in parts
                or path.name == "conftest.py" or path.name.startswith("test_")
                or path.name.endswith("_test.py")):
            continue
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and node.func.attr in ("read_text", "read_bytes")):
                found.add(f"{rel}:{node.func.attr}")
    return found


@pytest.mark.gate
def test_real_scan_covers_an_independent_census():
    census = _independent_real_census()
    assert len(census) > 30, "the census itself must see the tree"
    scanned = {f"{fp.split(':')[0]}:{fp.split(':')[2]}" for fp in _real_fps()}
    assert census <= scanned, f"reads the gate did not scan: {sorted(census - scanned)}"


@pytest.mark.gate
def test_real_run_fails_on_an_empty_baseline(tmp_path):
    """The real (unprefixed-scope) path ratchets too: with nothing baselined it fails."""
    assert _GATE.main([], baseline_path=tmp_path / "absent.json") == 1


def test_cli_exits_with_the_gate_status():
    """The script's exit code is `main()`'s: CI reads only the process status."""
    import ast

    src = (LINT_DIR / "lint_unbounded_whole_read.py").read_text(encoding="utf-8")
    guards = [n for n in ast.parse(src).body if isinstance(n, ast.If)
              and "__main__" in ast.unparse(n.test)]
    assert [ast.unparse(s) for g in guards for s in g.body] == ["sys.exit(main())"]


@pytest.mark.gate
def test_real_wire_log_reason_names_its_host_writer():
    """The wire log is host-written and routinely past 100 MB: the box fsize limit does not
    bound it, so its reason must say who writes it and must not lean on fsize."""
    reason = _real_entries()[
        "defender/scripts/visualize/visualize_messages.py:load_messages:uncapped:read_jsonl_rows"]
    assert "host-written" in reason, reason
    assert "fsize" not in reason, reason
