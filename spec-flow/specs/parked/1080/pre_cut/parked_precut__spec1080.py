# PRE-CUT COPY 2026-10-04 (scope cut of #1080, human-decided; 94-reconciliation-cut.md F-2): preserved, NOT imported.
# This is defender/tests/scripts_1080_split/_spec1080.py as it stood before the cut, copied verbatim
# from the cut author's scratch backup; the only additions are these `#` comment lines. The
# nodes the cut narrowed carry a `# PRE-CUT …` marker naming the issue(s) that own the cut part.
# The live suite imports the narrowed module; the pre-cut test copies beside this file (and the
# parked tests in ../) were written against this version.
"""Shared machinery for #1080's spec — "split `defender/scripts/` into its homes". NO tests.

The change (`spec-flow/specs/spec_graph_1080-scripts-split.yaml`; the §7 record is the
frontier chain's `70-resolutions.md`): every library module under `defender/scripts/` moves to
the home that owns its concern — investigation code under `defender/runtime/`, the query-id /
request-key / exit-code rules and the venv helper into the flat `defender/_*.py` tier,
pricing under `runtime/providers/`, the generic HTTP check and the fault types into
`defender/integrations/`, Elastic grammar into a product Elastic module, write-back and the
case-mapping format to their homes, the page renderers and their assets into
`defender/reports/`, the lessons engine OUT of `defender/lessons/` (the lesson content folder).
`scripts/` keeps entry points only: `tenant.py`, `policy_cli.py`, `box_image.py`,
`tacit_cli.py`, the two engines' thin wrappers (the files `bin/defender-sql` and
`bin/defender-lessons` exec, which carry exactly one import-root bootstrap, M-H (a)), and
`scripts/adapters/` (eight adapters, `_stub_transport.py`, `README.md`) until #1172 (M-A (a)).

NONE OF THE NEW HOMES EXISTS AT BASE 80888efb. Every moved symbol is reached at CALL time —
through `home_of` / `moved_module` / `moved` below, or through an import inside the test body —
so a missing home is ONE failure per test (an `AssertionError` naming the symbol), never a
collection error that hides every other assertion in the file. A test file imports nothing
from a new home at module level.

HOMES ARE FOUND BY SYMBOL (dF0, human). Only two package paths are pinned by the design:
`defender/integrations/` and `defender/reports/`. Three more are pinned by demand text:
`defender/_exit_codes.py` (m1), `defender/runtime/verbs.py` for `derive_system` (t_derive),
`defender/runtime/providers/` for `usage_cost` (s_observe_pricing). Every other home (the
lessons engine, the sql engine's runtime subpackage, the tenants home, the flat-tier module that
holds the query rules, the write-back module, the product Elastic module) is wherever the
symbol a moved module defines is defined: `home_of(<symbol>)` walks `defender/` (tests and
`defender/scripts/` excluded) for the ONE module-level `def` / `class` / assignment of that
name. Zero definitions outside `scripts/` is "the move has not happened"; two is a duplicate
home (the one-home rule, s008/s025/s028) — both fail.

GOLDENS ARE THE BASE. Every "as today" / "exactly the pre-move behavior" expectation is a value
the BASE code produced for a fixed input, captured once at 80888efb by the phase-E author and
frozen under `goldens/*.json` (each file's `_meta` names the base and how it was captured). A
test never computes its expected side by running old code: after the move the old code does
not exist, and a test that imports the old path is green at base and pins nothing.
`canon()` is the one encoding both sides go through, so a type change (a tuple becoming a
list, `1` becoming `1.0`, `-0.0` becoming `0.0`) is a difference, not a coincidence.

AUTHORING-TIME SELF-CHECK — `SPEC1080_AT_BASE=1`. With this variable set, `home_of` also
accepts the symbol's BASE definition (under `defender/scripts/`, or `runtime/circuit_breaker.py`
for the exit-code vocabulary) and ignores the `under=` home constraint. A behavioural ("as
today") test that PASSES under it at the base proves its expected side is the base's real
behaviour through the same assertions — the positive control for the golden — while the
structural tests (placement, census, direction, lint scopes) stay red under it, since they
read the tree, not the locator. CI never sets it; after the move it changes nothing (the base
definitions are gone). It is the instrument the author used to check every golden, recorded in
the artifact's `handoff.deviations`.

Underscore-prefixed so pytest does not collect it; it defines no tests.
"""
from __future__ import annotations

import ast
import functools
import importlib
import importlib.metadata
import json
import math
import os
import subprocess
import sys
import tomllib
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import Any

# ======================================================================================
# Paths
# ======================================================================================

SUITE = Path(__file__).resolve().parent
REPO_ROOT = SUITE.parents[2]
DEFENDER = REPO_ROOT / "defender"
SCRIPTS = DEFENDER / "scripts"
BIN = DEFENDER / "bin"
LESSONS_CONTENT = DEFENDER / "lessons"
GOLDENS = SUITE / "goldens"

#: The commit the spec branch forked from; every golden was captured here.
BASE_SHA = "80888efb"

#: The authoring-time self-check switch (module docstring). Read once, at import.
AT_BASE = os.environ.get("SPEC1080_AT_BASE") == "1"

# ======================================================================================
# Pinned homes (repo-relative). `under=` takes one of these, or any repo-relative dir/file.
# ======================================================================================

#: dF0 (human): the two package paths the design pins.
INTEGRATIONS = "defender/integrations"
REPORTS = "defender/reports"
#: Pinned by demand text.
RUNTIME = "defender/runtime"
PROVIDERS = "defender/runtime/providers"
VERBS = "defender/runtime/verbs.py"
EXIT_CODES = "defender/_exit_codes.py"
#: The flat tier: a module directly under `defender/` whose name starts with `_`.
FLAT_TIER = "defender/_*.py"

# PRE-CUT 2026-10-04 (scope cut): narrowed in the live suite; the cut part is owned by #1165 (dF11's public rename; 75 records the rename as dropped, s085's seed as parked with #1165).
#: dF11 (auto-resolved, §7): the flat-tier query rules become PUBLIC, their values byte-identical.
#: The design does not spell the public names, so they are COINED here, once, for every file of
#: this suite: if write-code-from-spec spells them differently it renames them HERE, never
#: through a `conceptAliases` entry (which would silently disable `check_binds` for them).
QUERY_RULE_PUBLIC = {"_json_safe_params": "json_safe_params", "_request_key": "request_key"}

#: Directory names no census, locator or scan descends into: tool output, caches, virtualenvs,
#: VCS metadata (s154). A directory holding its own `.git` (a nested checkout) is skipped too.
JUNK_DIRS = frozenset({
    ".venv", "venv", "__pycache__", "node_modules", "build", "dist", ".git", ".mypy_cache",
    ".ruff_cache", ".pytest_cache", ".tox", ".hypothesis", ".eggs", "site-packages",
})


def rel(path: Path, root: Path = REPO_ROOT) -> str:
    """`path` relative to `root`, POSIX-spelled."""
    return path.resolve().relative_to(root.resolve()).as_posix() if path.is_absolute() \
        else path.as_posix()


def is_test_path(relpath: str) -> bool:
    """The O1 test exemption, drawn by LOCATION ([155], auto): any file under a directory
    named `tests`, plus any `conftest.py`. A `test_*.py` beside production code and the repo's
    `scripts/testing/` are NOT exempt."""
    parts = relpath.split("/")
    return "tests" in parts[:-1] or parts[-1] == "conftest.py"


def under(relpath: str, home: str) -> bool:
    """Whether `relpath` sits in `home` — a directory (boundary-matched, never a string prefix:
    `defender/integrations_old/x.py` is not under `defender/integrations`), a file, or the
    `FLAT_TIER` pattern."""
    if home == FLAT_TIER:
        parts = relpath.split("/")
        return len(parts) == 2 and parts[0] == "defender" and parts[1].startswith("_") \
            and parts[1].endswith(".py")
    home = home.rstrip("/")
    return relpath == home or relpath.startswith(home + "/")


def py_files(root: Path = REPO_ROOT, tops: Sequence[str] = ("defender",), *,
             include_tests: bool = False) -> list[str]:
    """Every `.py` under `root/<top>` for each top, repo-relative and sorted — walked from the
    filesystem (not `git ls-files`), skipping `JUNK_DIRS`, nested checkouts and, unless asked,
    the test exemption. Walking the disk is what lets a planted copy of the tree be scanned."""
    out: list[str] = []
    for top in tops:
        base = root / top
        if not base.is_dir():
            continue
        for dirpath, dirnames, filenames in os.walk(base):
            d = Path(dirpath)
            keep = []
            for name in dirnames:
                if name in JUNK_DIRS:
                    continue
                if (d / name / ".git").exists():  # a nested checkout: not this tree's source
                    continue
                keep.append(name)
            dirnames[:] = sorted(keep)
            for fn in filenames:
                if not fn.endswith(".py"):
                    continue
                r = (d / fn).relative_to(root).as_posix()
                if not include_tests and is_test_path(r):
                    continue
                out.append(r)
    return sorted(out)


def dotted(relpath: str) -> str:
    """`defender/a/b.py` → `defender.a.b`; `defender/a/__init__.py` → `defender.a`."""
    parts = relpath[:-3].split("/") if relpath.endswith(".py") else relpath.split("/")
    if parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


# ======================================================================================
# The symbol locator (dF0: homes are found by symbol)
# ======================================================================================


def module_level_names(source: bytes | str, filename: str = "<src>") -> list[str]:
    """Every name a module binds at module level by a `def`, `class` or assignment — including
    one nested in a module-level `if` / `try` / `with`, never one inside a function or class.
    Imports are NOT definitions (d0: "defined as a def, class or module-level assignment")."""
    tree = ast.parse(source, filename=filename)
    out: list[str] = []

    def walk(body: Sequence[ast.stmt]) -> None:
        for n in body:
            out.extend(_bound_here(n))
            for block in _nested_blocks(n):
                walk(block)

    walk(tree.body)
    return list(dict.fromkeys(out))


def _bound_here(n: ast.stmt) -> list[str]:
    """The names one module-level statement binds by definition or assignment."""
    if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return [n.name]
    if isinstance(n, ast.Assign):
        return [x.id for tg in n.targets for x in ast.walk(tg) if isinstance(x, ast.Name)]
    if isinstance(n, (ast.AnnAssign, ast.AugAssign)) and isinstance(n.target, ast.Name):
        return [n.target.id]
    return []


def _nested_blocks(n: ast.stmt) -> list[Sequence[ast.stmt]]:
    """The statement blocks a module-level `if` / `try` / `with` runs at module level."""
    if isinstance(n, ast.If):
        return [n.body, n.orelse]
    if isinstance(n, ast.Try):
        return [n.body, n.orelse, n.finalbody, *(h.body for h in n.handlers)]
    if isinstance(n, ast.With):
        return [n.body]
    return []


@functools.lru_cache(maxsize=8)
def _definition_index(root: str) -> Mapping[str, tuple[str, ...]]:
    """name → every non-test module under `<root>/defender` that defines it at module level.
    One AST pass per root per process; tests never write into the real tree."""
    index: dict[str, list[str]] = {}
    base = Path(root)
    for r in py_files(base, ("defender",)):
        try:
            names = module_level_names((base / r).read_bytes(), r)
        except (SyntaxError, ValueError) as e:  # a file the locator cannot read is a finding
            raise AssertionError(f"the locator cannot parse {r}: {e}") from e
        for n in names:
            index.setdefault(n, []).append(r)
    return {k: tuple(v) for k, v in index.items()}


def definitions(name: str, root: Path = REPO_ROOT) -> tuple[str, ...]:
    """Every module (repo-relative, tests excluded) that defines `name` at module level."""
    return _definition_index(str(root.resolve())).get(name, ())


#: Where each symbol the locator is asked about lives at the BASE outside `defender/scripts/`
#: (the exit-code vocabulary moves out of the circuit breaker, m1). `SPEC1080_AT_BASE` accepts
#: these; nothing else does.
_BASE_HOMES_OUTSIDE_SCRIPTS = ("defender/runtime/circuit_breaker.py",)


def home_of(name: str, *, home: str | None = None, root: Path = REPO_ROOT) -> str:
    """The ONE module outside `defender/scripts/` that defines `name` (optionally inside
    `home`), repo-relative. Fails — with an `AssertionError` naming the symbol — when the
    symbol has no such home (the move has not happened) or more than one (a duplicate
    definition: the one-home rule). See the module docstring for `SPEC1080_AT_BASE`."""
    defs = definitions(name, root)
    if AT_BASE:
        moved_defs = [d for d in defs if not under(d, "defender/scripts")]
        cands = [d for d in moved_defs if home is None or under(d, home)]
        if not cands:
            cands = [d for d in defs if under(d, "defender/scripts")
                     or d in _BASE_HOMES_OUTSIDE_SCRIPTS]
    else:
        cands = [d for d in defs if not under(d, "defender/scripts")
                 and (home is None or under(d, home))]
    where = f" under {home}" if home else ""
    assert cands, (
        f"`{name}` is defined nowhere outside defender/scripts/{where} — the move that gives it "
        f"its new home has not happened (definitions today: {list(defs) or 'none'})")
    assert len(cands) == 1, (
        f"`{name}` has {len(cands)} homes{where}: {cands} — one definition per moved name "
        f"(the one-home rule), never a copy beside the original")
    return cands[0]


def moved_module(name: str, *, home: str | None = None) -> ModuleType:
    """The module object of `home_of(name, home=...)`, imported by its dotted name."""
    return importlib.import_module(dotted(home_of(name, home=home)))


def moved(name: str, *, home: str | None = None) -> Any:
    """The moved object itself: `getattr(moved_module(name), name)`."""
    return getattr(moved_module(name, home=home), name)


# PRE-CUT 2026-10-04 (scope cut): narrowed in the live suite; the cut part is owned by #1165 (dF11's public rename).
def query_rule(base_name: str) -> Any:
    """A flat-tier query rule by its BASE spelling (`_json_safe_params`, `is_reserved_query_id`,
    ...): the object defined under its public spelling (`QUERY_RULE_PUBLIC`, dF11) in a
    flat-tier module. Under `SPEC1080_AT_BASE` a renamed rule with no public definition yet
    falls back to its base definition, so a behavioural test proves its golden at the base."""
    public = QUERY_RULE_PUBLIC.get(base_name, base_name)
    if AT_BASE and public != base_name and not [
            d for d in definitions(public) if under(d, FLAT_TIER)]:
        return moved(base_name)
    return moved(public, home=FLAT_TIER)


def module_at(relpath: str) -> ModuleType:
    """A module at a fixed repo-relative path (a pinned home, or a module that does not move),
    imported by its dotted name. Fails with an `AssertionError` (not a collection error) when
    the file is absent."""
    assert (REPO_ROOT / relpath).is_file(), f"{relpath} does not exist"
    return importlib.import_module(dotted(relpath))


# ======================================================================================
# Goldens
# ======================================================================================


@functools.cache
def golden(name: str) -> Mapping[str, Any]:
    """`goldens/<name>.json`, parsed once. Its `_meta` says what was captured, where, and how."""
    path = GOLDENS / f"{name}.json"
    assert path.is_file(), f"golden {path.name} is missing from the suite"
    data: Mapping[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    return data


def base_inventory() -> Mapping[str, Any]:
    """The base's `defender/scripts/` tree: tracked files, each module's module-level names,
    the subfolders, the flat tier, the shims' hashes and which modules carried a `__main__`."""
    return golden("base_inventory")


def canon(value: Any) -> Any:
    """A JSON-shaped, TYPE-PRESERVING encoding of `value`, the one both sides of a golden
    comparison go through. `True` vs `1`, `1` vs `1.0`, `-0.0` vs `0.0`, NaN, a tuple vs a list,
    dict key order and key type, bytes and sets all survive; anything else is its type name
    plus `repr` (choose inputs whose repr carries no address)."""
    if value is None or isinstance(value, (bool, str)):
        return value
    if isinstance(value, int):
        return {"int": str(value)} if abs(value) > 2**53 else value
    if isinstance(value, float):
        return {"float": "nan" if math.isnan(value) else repr(value)}
    if isinstance(value, tuple):
        return {"tuple": [canon(v) for v in value]}
    if isinstance(value, list):
        return [canon(v) for v in value]
    if isinstance(value, dict):
        return {"dict": [[canon(k), canon(v)] for k, v in value.items()]}
    if isinstance(value, (set, frozenset)):
        return {type(value).__name__: sorted((canon(v) for v in value), key=repr)}
    if isinstance(value, (bytes, bytearray)):
        return {"bytes": bytes(value).hex()}
    if isinstance(value, Path):
        return {"path": value.as_posix()}
    return {"type": type(value).__name__, "repr": repr(value)}


def outcome(fn: Callable[..., Any], /, *args: Any, **kwargs: Any) -> dict[str, Any]:
    """What calling `fn` does, as a golden-comparable record: `{"returns": canon(value)}`, or
    `{"raises": <class short name>, "message": str(exc)}`. Short class names, because a moved
    class keeps its name (GR9) while its module path changes."""
    try:
        value = fn(*args, **kwargs)
    except Exception as e:  # noqa: BLE001 — the exception IS the observed outcome
        return {"raises": type(e).__name__, "message": str(e)}
    return {"returns": canon(value)}


# ======================================================================================
# Child processes (s127: every child is pinned to THIS tree)
# ======================================================================================


def child_env(*, pythonpath: bool = True, inherit: Sequence[str] = ("PATH", "HOME", "LANG",
                                                                     "LC_ALL", "TZ"),
              **extra: str) -> dict[str, str]:
    """A minimal environment for a child: the few inherited keys named, `PYTHONPATH` set to
    THIS checkout's root when `pythonpath` (never another checkout a developer's shell
    names, s127), then `extra`. `pythonpath=False` is the bare-environment shape (the operator
    shell, `run_sql_py`, J-PO3)."""
    env = {k: os.environ[k] for k in inherit if k in os.environ}
    env.setdefault("PATH", "/usr/local/bin:/usr/bin:/bin")
    if pythonpath:
        env["PYTHONPATH"] = str(REPO_ROOT)
    env.update(extra)
    return env


def run(argv: Sequence[str | os.PathLike[str]], *, cwd: Path | str = REPO_ROOT,
        env: Mapping[str, str] | None = None, stdin: bytes | None = None,
        timeout: float = 120) -> subprocess.CompletedProcess[bytes]:
    """`argv` as a child, bytes in and out, never raising on a nonzero status. `cwd` defaults
    to this checkout's root; `env` defaults to `child_env()`."""
    return subprocess.run(  # noqa: S603 — fixed argv built by the test itself
        [os.fspath(a) for a in argv], cwd=os.fspath(cwd), input=stdin, capture_output=True,
        check=False, env=dict(child_env() if env is None else env), timeout=timeout)


def python(*args: str | os.PathLike[str], **kw: Any) -> subprocess.CompletedProcess[bytes]:
    """This interpreter as a child: `run([sys.executable, *args], **kw)`."""
    return run([sys.executable, *args], **kw)


# ======================================================================================
# The box image's import closure (box_closure_*: "derived from pyproject.toml's core
# dependencies and box extra" — through the lock, the way the image is built)
# ======================================================================================


@functools.lru_cache(maxsize=1)
def box_import_allowlist() -> tuple[str, ...]:
    """The top-level import names a box process may load: the standard library (implicit in
    `_import_blocker`'s `allow_only`), `defender`, `__main__`, `_virtualenv` (this venv's
    start-up hook, which no box has), and every import name of the distributions the image
    installs — `runtime.box._image.box_closure(uv.lock, "defender")`, the walk the image build
    itself trusts (core `dependencies` + the `box` extra, transitively), mapped to import names
    through the installed distributions' metadata. NOT whatever the host venv carries (s119)."""
    from defender.runtime.box import _image

    lock = tomllib.loads((DEFENDER / "uv.lock").read_text(encoding="utf-8"))
    dists = {_image.normalized_name(e["name"]) for e in _image.box_closure(lock, "defender")}
    tops = {top for top, ds in importlib.metadata.packages_distributions().items()
            if any(_image.normalized_name(d) in dists for d in ds)}
    # A top-level EXTENSION module (`_duckdb.cpython-311-x86_64-linux-gnu.so`) is misnamed by
    # `packages_distributions()` (it strips only the last suffix); without it duckdb cannot load.
    for dist in importlib.metadata.distributions():
        name = dist.metadata.get("Name")
        if not name or _image.normalized_name(name) not in dists:
            continue
        for f in dist.files or ():
            if len(f.parts) == 1 and f.name.endswith((".so", ".pyd")) \
                    and f.name.split(".")[0].isidentifier():
                tops.add(f.name.split(".")[0])
    assert {"duckdb", "yaml", "pydantic"} <= tops, (
        f"the derived box closure lost a package the image installs: {sorted(tops)}")
    # The interpreter's own build-data module (`_sysconfigdata_*`, reached through
    # sysconfig) ships with every CPython but is absent from `sys.stdlib_module_names`.
    import sysconfig

    build_data = sysconfig._get_sysconfigdata_name()  # noqa: SLF001 — CPython's own name
    return tuple(sorted(tops | {"defender", "__main__", "_virtualenv", build_data}))


#: Packages a box process must never load (box_closure_*): the agent framework, the model
#: providers and the MCP stack. Checked against `sys.modules` in the child as well as refused.
BOX_BLOCKED = ("pydantic_ai", "anthropic", "openai", "mcp", "fastmcp", "logfire", "httpx",
               "fastapi", "uvicorn", "toons")


# ======================================================================================
# Small AST readers shared across files
# ======================================================================================


@dataclass(frozen=True)
class ImportStmt:
    """One import statement, resolved: the file, the line, the module it names (relative
    forms resolved against the importer's package), the names it binds from it (empty for
    `import x`), and whether it sits at module level."""

    path: str
    line: int
    module: str
    names: tuple[str, ...]
    top_level: bool


def import_statements(relpath: str, source: bytes | str) -> Iterator[ImportStmt]:
    """Every `import` / `from … import` in a module, wherever it sits (module level, function
    body, `try`, `if TYPE_CHECKING:`), relative forms resolved against the importer's package.
    Raises `SyntaxError` / `ValueError` for a file that cannot be parsed — the caller decides
    (a census must name it, never skip it: [153])."""
    tree = ast.parse(source, filename=relpath)
    pkg = dotted(relpath).split(".")
    if not relpath.endswith("__init__.py"):
        pkg = pkg[:-1]
    module_level = {id(n) for n in tree.body}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                yield ImportStmt(relpath, node.lineno, a.name, (), id(node) in module_level)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                base = pkg[: len(pkg) - (node.level - 1)] if node.level > 1 else pkg
                mod = ".".join([*base, node.module] if node.module else base)
            else:
                mod = node.module or ""
            yield ImportStmt(relpath, node.lineno, mod, tuple(a.name for a in node.names),
                             id(node) in module_level)


def has_main_block(source: bytes | str) -> bool:
    """Whether a module carries an `if __name__ == "__main__":` block at module level."""
    for n in ast.parse(source).body:
        if isinstance(n, ast.If) and isinstance(n.test, ast.Compare) \
                and isinstance(n.test.left, ast.Name) and n.test.left.id == "__name__" \
                and any(isinstance(c, ast.Constant) and c.value == "__main__"
                        for c in n.test.comparators):
            return True
    return False


def shim_exec_target(shim: str) -> Path:
    """The `.py` file a `bin/` shim execs — read off its `exec "$PY" "<dir var>/<path>"` line,
    with the dir variable taken as `defender/`. Fails when the shim names no such line."""
    text = (BIN / shim).read_text(encoding="utf-8")
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("exec ") and ".py" in s:
            for tok in s.split():
                tok = tok.strip('"')
                if tok.endswith(".py"):
                    tail = tok.split("}", 1)[-1] if "}" in tok else tok.split("/", 1)[-1]
                    return DEFENDER / tail.lstrip("/")
    raise AssertionError(f"bin/{shim} names no `exec ... <file>.py` line")
